"""Credential looting helpers shared by the file-transfer recon handlers.

An export or an FTP account is worth what its files say. Both handlers answer
with the first bytes of the small text files they find, and both need the same
three things: recognise a whole-value base64 blob (``for_you.txt`` in Hijack is
exactly that), pull a ``user``/``password`` pair out of a note, and tell a
*password list* apart from prose. Keeping the rules here means one regex to
review and one answer shape for the model.

Why the password list matters (Bounty Hacker, 2026-10-30): anonymous FTP exposed
a note with an account and a file that was plainly a list of passwords, and the
run never turned either into the next step. A file-shaped list is the input of
``nexus.cred.bruteforce`` on *another* service of the same host -the classic
21 → 22 chain-, so the summary names the tool, the account and the list instead
of leaving the model to re-derive the connection. Nothing here is specific to a
service or a room: the rule is "a list of single-token lines is a wordlist" and
the chain is "reuse it where authentication happens".
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any

#: Cap on the bytes of one file that travel back in the observation.
LOOT_MAX_BYTES = 8_192

#: Conservative credential pairs (``user: x`` / ``password: y``). The preview
#: always travels too, so a miss here never hides the loot, and a false pair
#: would send the agent to a login that cannot work.
CREDENTIAL_USER_RE = re.compile(
    r"(?im)^[^\n]{0,40}?\b(?:user(?:name)?|login|ftp[_-]?user|usuario)\b\s*[:=]\s*"
    r"([A-Za-z0-9_.@\\-]{1,64})"
)
CREDENTIAL_PASS_RE = re.compile(
    r"(?im)^[^\n]{0,40}?\b(?:pass(?:word|wd)?|pwd|contrase[\u00f1n]a)\b\s*[:=]\s*"
    r"([^\s'\"]{1,128})"
)

#: A preview with more undecodable bytes than this is treated as binary.
_TEXT_MIN_RATIO = 0.85

#: Lines a file needs before it can be called a password corpus. Eight is the
#: smallest list a sweep is worth running against a live service.
WORDLIST_MIN_ENTRIES = 8
#: Share of non-empty lines that must be a single bare token. Below this the file
#: is prose or a config, and treating it as a wordlist would spend a sweep on it.
WORDLIST_MIN_ENTRY_RATIO = 0.9
#: Longest single entry that still reads as a password/token rather than a line.
WORDLIST_MAX_ENTRY_CHARS = 64
#: Characters that mark a line as key/value or structured data, never a password.
_WORDLIST_LINE_REJECT = (":", "=", "{", "}", "<", ">", "|", "\t", " ")


def wordlist_entries(text: str) -> int:
    """Number of lines that read as wordlist entries (``0`` when it is not one).

    A corpus is many short single-token lines and nothing else. Prose, ``key:
    value`` notes and structured files are rejected by the ratio rule, so a miss
    here never hides loot (the preview always travels) and a false positive can
    never send the run into a sweep of a file that was never a list.
    """
    lines = [line.strip() for line in str(text or "").splitlines()]
    entries = [line for line in lines if line]
    if len(entries) < WORDLIST_MIN_ENTRIES:
        return 0
    usable = [
        line
        for line in entries
        if len(line) <= WORDLIST_MAX_ENTRY_CHARS
        and not any(marker in line for marker in _WORDLIST_LINE_REJECT)
    ]
    if len(usable) < len(entries) * WORDLIST_MIN_ENTRY_RATIO:
        return 0
    return len(usable)


def looks_like_wordlist(text: str) -> bool:
    """Whether ``text`` is a password corpus (see :func:`wordlist_entries`)."""
    return wordlist_entries(text) > 0


def username_candidates(text: str) -> list[str]:
    """Accounts named in a note (``user: lin``), in order of appearance."""
    found: list[str] = []
    for match in CREDENTIAL_USER_RE.finditer(str(text or "")):
        name = match.group(1)
        if name and name not in found:
            found.append(name)
    return found


def wordlists_in_files(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The files of a loot answer that are password corpora.

    Each entry carries the path a later call can pass as ``password_file`` -the
    saved copy when the handler persisted one, the remote name otherwise- plus
    the number of entries the preview proved.
    """
    found: list[dict[str, Any]] = []
    for item in files or ():
        if not isinstance(item, dict):
            continue
        if str(item.get("content_kind") or "") == "binary":
            continue
        name = str(item.get("path") or item.get("name") or "")
        usable = str(item.get("workspace_path") or item.get("path") or "")
        for handle in (item.get("preview"), item.get("decoded")):
            entries = wordlist_entries(str(handle or ""))
            if not entries:
                continue
            found.append(
                {
                    "name": name,
                    "path": usable,
                    "remote": str(item.get("remote") or item.get("name") or name),
                    "entries": entries,
                    "truncated": bool(item.get("truncated") or item.get("preview_truncated")),
                }
            )
            break
    return found


def decode_base64_text(text: str) -> str | None:
    """Decode a value that is *entirely* base64 into printable ASCII, else ``None``.

    Only whole-value base64 is decoded, so a normal note is never mangled.
    """
    compact = re.sub(r"\s+", "", str(text or ""))
    if len(compact) < 8 or len(compact) % 4:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
        return None
    try:
        raw = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not decoded:
        return None
    printable = sum(char.isprintable() or char in "\n\r\t" for char in decoded)
    if printable < len(decoded) * _TEXT_MIN_RATIO:
        return None
    return decoded.strip()


def is_textual(text: str) -> bool:
    """Whether a preview is worth showing (not a binary blob)."""
    if not text:
        return False
    printable = sum(char.isprintable() or char in "\n\r\t" for char in text)
    return printable >= len(text) * _TEXT_MIN_RATIO


def credentials_in_text(text: str, source: str) -> list[dict[str, str]]:
    """Credential pairs written in a file (``user: x`` / ``password: y``)."""
    users = [match.group(1) for match in CREDENTIAL_USER_RE.finditer(str(text or ""))]
    passwords = [
        match.group(1) for match in CREDENTIAL_PASS_RE.finditer(str(text or ""))
    ]
    if not users or not passwords:
        return []
    return [{"username": users[0], "password": passwords[0], "source": source}]


def loot_summary(files: list[dict[str, Any]]) -> dict[str, Any]:
    """The shared shape of an auto-loot answer (files + creds + next step).

    ``chain`` is the cross-service step, and it is the reason this function
    exists: evidence found on one service is only worth what the *next* service
    does with it. When the loot holds a password corpus it names the account, the
    file to pass as ``password_file`` and the tool that consumes both, so the run
    reuses the list instead of re-reading the same directory.
    """
    credentials: list[dict[str, str]] = []
    usernames: list[dict[str, str]] = []
    for item in files:
        source = str(item.get("path") or item.get("name") or "")
        for handle in (item.get("preview"), item.get("decoded")):
            for found in credentials_in_text(str(handle or ""), source):
                if found not in credentials:
                    credentials.append(found)
            for name in username_candidates(str(handle or "")):
                entry = {"username": name, "source": source}
                if entry not in usernames:
                    usernames.append(entry)
    wordlists = wordlists_in_files(files)
    summary: dict[str, Any] = {
        "files": files,
        "credentials": credentials,
        "usernames": usernames,
        "wordlists": wordlists,
        "files_total": len(files),
    }
    steps: list[str] = []
    for handle in credentials:
        steps.append(
            "Credenciales encontradas en los ficheros: pruébalas en el servicio que "
            "corresponda (SSH/FTP/SMB/web) con la tool de ese servicio -no solo en el "
            "que te las dio-; la tool que las use las deja en la pizarra."
        )
        steps.append(
            f"Primera candidata: username={handle['username']!r} "
            f"password={handle['password']!r} (origen: {handle['source']})."
        )
        break
    if wordlists:
        first = wordlists[0]
        account = (
            credentials[0]["username"]
            if credentials
            else (usernames[0]["username"] if usernames else "")
        )
        summary["chain"] = {
            "tool": "nexus.cred.bruteforce",
            "username": account,
            "password_file": first["path"] or first["remote"],
            "modes": ["ssh", "ftp", "http-post-form"],
            "source": first["name"],
            "entries": first["entries"],
            "truncated": first["truncated"],
        }
        steps.append(
            f"`{first['name']}` es una LISTA DE CONTRASEÑAS ({first['entries']}+ "
            f"entradas{' en el preview, el fichero puede ser mayor' if first['truncated'] else ''}). "
            "Reutilízala en el OTRO servicio autenticable del host: "
            f"nexus.cred.bruteforce con service=\"ssh\" (o \"ftp\"/\"http-post-form\"), "
            f"password_file=\"{first['path'] or first['remote']}\""
            + (f" y username={account!r}" if account else "")  # fmt: skip
            + ". Un barrido contra un servicio no agota el resto: si no hay "
            "acierto aquí, prueba el mismo par en el otro."
        )
    if steps:
        summary["next_steps"] = steps
    return summary


__all__ = [
    "CREDENTIAL_PASS_RE",
    "CREDENTIAL_USER_RE",
    "LOOT_MAX_BYTES",
    "WORDLIST_MIN_ENTRIES",
    "credentials_in_text",
    "decode_base64_text",
    "is_textual",
    "looks_like_wordlist",
    "loot_summary",
    "username_candidates",
    "wordlist_entries",
    "wordlists_in_files",
]
