"""Credential redaction at persistence boundaries, including malformed text.

This recognizes named credential fields; it is not a general secret detector.
It never repairs input used for execution. Only persisted copies are changed.

:func:`redact_secret_values` covers the other half of the same problem: a secret
whose *value* is known to the caller -resolved from ``credential_ref`` for this
invocation- has to be removed from text even when no named field surrounds it.
Measured in the rerun 13 (V1-46): a ``sudo -n`` command got the vault password
injected on stdin, sudo did not consume it, and the remote pty echoed it as a bare
line of the tool's stdout, which reached the model's context.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
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


#: Shortest literal secret that is redacted *anywhere* in a text. Below it only
#: an exact-line match is redacted: a two-character value would collide with
#: ordinary output and corrupt evidence that has nothing to do with the secret.
MIN_INLINE_SECRET_LENGTH = 8

#: What replaces a redacted secret value.
REDACTED = "[REDACTED]"


def redact_secret_values(content: str, secrets: Iterable[str]) -> str:
    """Remove known secret *values* from text (V1-46).

    Two shapes are redacted, in this order:

    * a whole line that is exactly the secret (optionally indented, with or
      without CR) -the measured echo of a secret written to a remote pty-; and
    * an occurrence inside a longer line (``[sudo] password for lin: <secret>``),
      only for values of at least :data:`MIN_INLINE_SECRET_LENGTH` characters.

    It is a complement to :func:`sanitize_text` (which works by field name), not a
    replacement: this one needs the caller to hand over the literal.
    """
    values = [str(value) for value in (secrets or ()) if value]
    if not content or not values:
        return content
    for value in values:
        escaped = re.escape(value)
        # Keep the indentation and the line ending: only the value is replaced.
        content = re.sub(rf"(?m)^([ \t]*)({escaped})(\r?)$", rf"\g<1>{REDACTED}\g<3>", content)
        if len(value) >= MIN_INLINE_SECRET_LENGTH:
            content = content.replace(value, REDACTED)
    return content


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
    content = re.sub(r"-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
                     "[REDACTED PRIVATE KEY]", content, flags=re.DOTALL)
    content = re.sub(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@", r"\1[REDACTED]@", content)
    content = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", content)
    output: list[str] = []
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
