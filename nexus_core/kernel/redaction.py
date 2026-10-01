"""Credential redaction at persistence boundaries, including malformed text.

This recognizes named credential fields; it is not a general secret detector.
It never repairs input used for execution. Only persisted copies are changed.
"""

from __future__ import annotations

import json
import re
from typing import Any

SECRET_TERMS = frozenset({
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "authorization", "auth", "hash", "hashes", "ntlm_hash", "lm_hash",
    "nthash", "password_hash", "credential", "credentials", "private_key",
    "privatekey", "ssh_key", "sshkey", "bearer", "cookie", "session_id",
})
_KEYS = "|".join(re.escape(key).replace("_", "[_-]") for key in sorted(SECRET_TERMS))
_ASSIGNMENT = re.compile(
    rf'''(?<![\w-])(?P<key>["']?(?:{_KEYS})["']?\s*[:=]\s*)''', re.IGNORECASE
)
_QUOTED = re.compile(r'''"(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$)''', re.DOTALL)
_DECODER = json.JSONDecoder()


def sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if str(key).lower().replace("-", "_") in SECRET_TERMS
            else sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize(item) for item in value]
    if isinstance(value, str):
        return sanitize_text(value)
    return value


def sanitize_text(content: str) -> str:
    """Redact JSON fragments and defensive named assignments in arbitrary text."""
    output = []
    copied = index = 0
    while index < len(content):
        if content[index] not in "{[":
            index += 1
            continue
        try:
            parsed, end = _DECODER.raw_decode(content, index)
        except ValueError:
            index += 1
            continue
        redacted = sanitize(parsed)
        if redacted != parsed:
            output.extend((content[copied:index], json.dumps(redacted, ensure_ascii=False)))
            copied = end
        index = end
    output.append(content[copied:])
    content = "".join(output)
    output = []
    copied = 0
    for match in _ASSIGNMENT.finditer(content):
        if match.start() < copied:
            continue
        start = match.end()
        if content.startswith('[REDACTED]', start):
            end = start + len('[REDACTED]')
            replacement = '[REDACTED]'
        elif quoted := _QUOTED.match(content, start):
            end = quoted.end()
            quote = content[start]
            replacement = quote + '[REDACTED]' + quote
        else:
            # Invalid/unquoted values can contain spaces (e.g. Bearer tokens).
            # Fail closed over the remainder of that line, rather than guess.
            end = content.find('\n', start)
            if end < 0:
                end = len(content)
            replacement = '[REDACTED]'
        output.extend((content[copied:match.start()], match['key'], replacement))
        copied = end
    output.append(content[copied:])
    return ''.join(output)
