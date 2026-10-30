"""Credential looting helpers shared by the file-transfer recon handlers.

An export or an FTP account is worth what its files say. Both handlers answer
with the first bytes of the small text files they find, and both need the same
two things: recognise a whole-value base64 blob (``for_you.txt`` in Hijack is
exactly that) and pull a ``user``/``password`` pair out of a note. Keeping the
rules here means one regex to review and one answer shape for the model.
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
    """The shared shape of an auto-loot answer (files + creds + next step)."""
    credentials: list[dict[str, str]] = []
    for item in files:
        source = str(item.get("path") or item.get("name") or "")
        for handle in (item.get("preview"), item.get("decoded")):
            for found in credentials_in_text(str(handle or ""), source):
                if found not in credentials:
                    credentials.append(found)
    summary: dict[str, Any] = {
        "files": files,
        "credentials": credentials,
        "files_total": len(files),
    }
    if credentials:
        handle = credentials[0]
        summary["next_steps"] = [
            "Credenciales encontradas en los ficheros: pruébalas en el servicio que "
            "corresponda (FTP/SMB/SSH/web) con la tool de ese servicio; la tool que "
            "las use las deja en la pizarra.",
            f"Primera candidata: username={handle['username']!r} "
            f"password={handle['password']!r} (origen: {handle['source']}).",
        ]
    return summary


__all__ = [
    "CREDENTIAL_PASS_RE",
    "CREDENTIAL_USER_RE",
    "LOOT_MAX_BYTES",
    "credentials_in_text",
    "decode_base64_text",
    "is_textual",
    "loot_summary",
]
