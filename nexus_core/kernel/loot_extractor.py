"""Deterministic loot extraction shared by every evidence channel.

The verifier must answer one question for every file, HTTP body or captured
output: *does this contain loot, and what exactly is the artifact?* Keeping the
rules here means HTTP, SMB, FTP, workspace reads and Windows reads cannot drift
into five slightly different flag regexes.

Three rules keep the answer honest:

* a flag needs a known prefix and a non-empty body (``flag{...}``, ``HTB{...}``);
* a credential needs an explicit user/password label or a ``user:pass`` line,
  never a lone token;
* free text produced by a model is only evidence when it was reproduced at
  least twice or comes with the raw evidence digest. A single hallucinated
  string is not loot.

The module is pure: it returns candidates, it never writes to the board and it
never stores a secret. The caller decides whether a candidate is represented as
a ``loot`` fact or as a credential handle.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

#: Flag-shaped tokens. The prefixes are explicit on purpose: a generic brace
#: pair is not a flag and would turn every JSON object into loot.
FLAG_RE = re.compile(r"(?:THM|HTB|FLAG|flag|CTF|ctf)\{[^}\s\x00]{4,200}\}")

#: Conventional CTF flag files. The *name* is evidence even when the content
#: has no flag shape (Simple CTF's ``user.txt`` holds ``G00d j0b, keep up!``).
FLAG_FILE_NAME_RE = re.compile(
    r"(?:^|[/\\])(?:user|root|flag|proof|local|system)(?:[._-]?\d+)?\.txt$",
    re.IGNORECASE,
)

#: A short, single-line file is the only shape a conventional flag file may
#: have. A longer answer is an error, a hint or mixed output, not the capture.
MAX_FILE_TEXT = 200

_ERROR_TEXT_RE = re.compile(
    r"permission denied|operation not permitted|no such file|not found|"
    r"cannot open|cannot read|is a directory|command not found|"
    r"^\s*(?:cat|grep|ls|find|sh|bash|/bin/sh|/bin/bash|python[0-9.]*|perl|"
    r"curl|wget):\s",
    re.IGNORECASE,
)

_USER_LABEL_RE = re.compile(
    r"(?im)^[^\n]{0,50}?\b(?:user(?:name)?|login|usuario|account)\b"
    r"\s*[:=]\s*([A-Za-z0-9_.@\\-]{1,64})\s*$"
)
_PASS_LABEL_RE = re.compile(
    r"(?im)^[^\n]{0,50}?\b(?:pass(?:word|wd)?|pwd|contrase[nñ]a)\b"
    r"\s*[:=]\s*([^\s'\"]{1,128})\s*$"
)
#: ``admin:Passw0rd`` as a complete line. Labels are excluded because
#: ``username: admin`` is a note, not a credential pair.
_USER_PASS_LINE_RE = re.compile(
    r"(?im)^\s*(?P<user>[A-Za-z0-9_.@\\-]{1,64})\s*:\s*"
    r"(?P<password>[^\s:{}<>'\"]{3,128})\s*$"
)
_CREDENTIAL_LABELS = {
    "user",
    "username",
    "login",
    "usuario",
    "account",
    "pass",
    "password",
    "passwd",
    "pwd",
    "contraseña",
    "contrasena",
}


@dataclass(frozen=True)
class LootCandidate:
    """One artifact recovered from an observed channel.

    ``kind`` is ``"flag"`` or ``"credential"``. A credential candidate carries
    the plaintext in ``password`` only so the caller can put it in the vault;
    it is never rendered into a fact or a report by this module.
    """

    kind: str
    value: str
    source: str
    path: str = ""
    sha256: str = ""
    username: str = ""
    password: str = ""
    content: str = ""


def extract_flags(text: Any) -> list[str]:
    """Every distinct flag-shaped token in *text*, in order."""
    found: list[str] = []
    for match in FLAG_RE.finditer(str(text or "")):
        value = match.group(0)
        if value not in found:
            found.append(value)
    return found


def extract_credentials(text: Any) -> list[LootCandidate]:
    """Conservative ``user``/``password`` pairs written in *text*."""
    body = str(text or "")
    users = [match.group(1) for match in _USER_LABEL_RE.finditer(body)]
    passwords = [match.group(1) for match in _PASS_LABEL_RE.finditer(body)]
    pairs: list[tuple[str, str]] = []
    if users and passwords:
        pairs.append((users[0], passwords[0]))
    for match in _USER_PASS_LINE_RE.finditer(body):
        user = match.group("user").strip()
        password = match.group("password").strip()
        if user.casefold() in _CREDENTIAL_LABELS or password.casefold() in _CREDENTIAL_LABELS:
            continue
        pair = (user, password)
        if pair not in pairs:
            pairs.append(pair)
    return [
        LootCandidate(
            kind="credential",
            value=username,
            source="text",
            username=username,
            password=password,
        )
        for username, password in pairs
    ]


def is_flag_file(path: Any) -> bool:
    """Whether *path* names a conventional CTF flag file."""
    return bool(FLAG_FILE_NAME_RE.search(str(path or "")))


def short_file_text(text: Any) -> str:
    """The complete content of a one-line flag file, or ``""``.

    A file that prints several lines is not a capture: the first line may be a
    hint and the rest someone else's output. The same rule as the SSH parser.
    """
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    if len(lines) != 1:
        return ""
    value = lines[0]
    if len(value) > MAX_FILE_TEXT or any(ord(char) < 0x20 for char in value):
        return ""
    if _ERROR_TEXT_RE.search(value):
        return ""
    return value


def extract_file_loot(
    content: Any,
    *,
    path: Any = "",
    sha256: Any = "",
    source: str = "file",
    truncated: bool = False,
) -> list[LootCandidate]:
    """Extract flags and credentials from one file's content.

    A conventional flag filename with a single short line is loot even when the
    text has no flag prefix. A file that merely *mentions* a flag in prose is
    not: only a flag-shaped token is extracted from arbitrary content.
    """
    body = str(content or "")
    path_text = str(path or "")
    digest = str(sha256 or "")
    candidates: list[LootCandidate] = []
    flags = extract_flags(body)
    for flag in flags:
        candidates.append(
            LootCandidate(
                kind="flag",
                value=flag,
                source=source,
                path=path_text,
                sha256=digest,
                content=body if len(body) <= MAX_FILE_TEXT else "",
            )
        )
    for credential in extract_credentials(body):
        candidates.append(
            LootCandidate(
                kind="credential",
                value=credential.username,
                source=source,
                path=path_text,
                sha256=digest,
                username=credential.username,
                password=credential.password,
            )
        )
    # A truncated read cannot prove that the first line is the whole file.
    if is_flag_file(path_text) and not flags and not truncated:
        value = short_file_text(body)
        if value:
            candidates.append(
                LootCandidate(
                    kind="flag",
                    value=value,
                    source=source,
                    path=path_text,
                    sha256=digest,
                    content=value,
                )
            )
    return candidates


def extract_http_loot(
    body: Any,
    headers: Any = None,
    *,
    source: str = "http",
) -> list[LootCandidate]:
    """Loot from an HTTP body **and** its response headers (V0-24).

    Headers are searched for flag-shaped tokens only: a cookie or an
    authorization header may contain a secret, but it is not a captured flag.
    """
    candidates = extract_file_loot(body, source=f"{source}:body")
    # An HTML form repeats the words "username" and "password" without
    # carrying a credential. On a page, only flag-shaped tokens are safe.
    if re.search(r"<(?:html|body|form|input)\b", str(body or ""), re.IGNORECASE):
        candidates = [item for item in candidates if item.kind == "flag"]
    header_items: Iterable[tuple[str, Any]]
    if isinstance(headers, dict):
        header_items = headers.items()
    elif isinstance(headers, (list, tuple)):
        header_items = (
            (str(item[0]), item[1])
            for item in headers
            if isinstance(item, (list, tuple)) and len(item) >= 2
        )
    else:
        header_items = ()
    for name, value in header_items:
        text = str(value or "")
        for flag in extract_flags(text):
            candidates.append(
                LootCandidate(
                    kind="flag",
                    value=flag,
                    source=f"{source}:header:{str(name).lower()}",
                    path=f"header:{str(name).lower()}",
                )
            )
    return candidates


def extract_untrusted_text(
    text: Any,
    *,
    source: str = "llm",
    reproduced: int = 0,
    raw_sha256: Any = "",
) -> list[LootCandidate]:
    """Loot from model-generated text, only with independent evidence (V0-27).

    A model can invent a plausible flag. Promotion therefore needs either two
    independent reproductions of the same artifact or the digest of the raw
    output that contains it. Without one of those, the answer is ``[]``.
    """
    digest = str(raw_sha256 or "")
    if int(reproduced) < 2 and not digest:
        return []
    body = str(text or "")
    candidates: list[LootCandidate] = []
    for flag in extract_flags(body):
        candidates.append(
            LootCandidate(
                kind="flag",
                value=flag,
                source=source,
                sha256=digest,
                content=body if len(body) <= MAX_FILE_TEXT else "",
            )
        )
    for credential in extract_credentials(body):
        candidates.append(
            LootCandidate(
                kind="credential",
                value=credential.username,
                source=source,
                sha256=digest,
                username=credential.username,
                password=credential.password,
            )
        )
    return candidates


__all__ = [
    "FLAG_FILE_NAME_RE",
    "FLAG_RE",
    "LootCandidate",
    "extract_credentials",
    "extract_file_loot",
    "extract_flags",
    "extract_http_loot",
    "extract_untrusted_text",
    "is_flag_file",
    "short_file_text",
]
