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
from dataclasses import replace
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

#: Argument names whose *value* is a secret. ``SECRET_TERMS`` is broader on
#: purpose (it also names fields that hold a reference/identifier); redacting a
#: session id from every observation would corrupt evidence without protecting
#: anything.
ARGUMENT_SECRET_FIELDS = SECRET_TERMS - {
    "session_id",
    "credential",
    "credentials",
    # A manually supplied cookie is already in the caller's context, and the
    # handler deliberately returns ``set_cookie`` so the next request can reuse
    # it. Redacting it would destroy that evidence without hiding anything the
    # model did not send itself. Vault handles (``session_ref``) still resolve.
    "cookie",
}

#: Ceiling on how many known secrets one observation may redact. Credential
#: facts accumulate across an engagement; a bounded lookup keeps a long run from
#: paying for a vault read per fact on every tool call.
MAX_CONTEXT_SECRETS = 64


def _vault_secret(ref: Any, tenant_id: str) -> str:
    """Plaintext behind a ``vault:`` handle, or ``""`` when it is not one."""
    from .secret_store import default_secret_store, is_secret_ref

    text = str(ref or "")
    if not is_secret_ref(text):
        return ""
    try:
        return default_secret_store().get(text, tenant_id=tenant_id).decode(
            "utf-8", errors="replace"
        )
    except Exception:  # noqa: BLE001 - a missing handle must never break a tool
        return ""


def _collect_argument_secrets(value: Any, key: str, found: list[str], tenant_id: str) -> None:
    """Collect literals under secret-named fields and every ``vault:`` handle."""
    from .secret_store import is_secret_ref

    name = str(key or "").lower().replace("-", "_")
    if isinstance(value, dict):
        for item_key, item in value.items():
            _collect_argument_secrets(item, str(item_key), found, tenant_id)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _collect_argument_secrets(item, name, found, tenant_id)
        return
    if not isinstance(value, str) or not value:
        return
    if is_secret_ref(value):
        resolved = _vault_secret(value, tenant_id)
        if resolved:
            found.append(resolved)
        return
    if name in ARGUMENT_SECRET_FIELDS:
        found.append(value)


def secrets_for_redaction(
    context: Any,
    arguments: dict[str, Any] | None = None,
    *,
    include_board: bool = True,
) -> tuple[str, ...]:
    """Every secret value this invocation is allowed to know (V1-6).

    Three sources, in order: secret-named arguments (a manual ``password``), any
    ``vault:<hex>`` handle anywhere in the arguments, and the **verified**
    credential facts of the current engagement resolved through the vault. The
    third is what covers a value the model never typed and no argument carries:
    a password the engine proved in an earlier turn and a tool later echoes.

    The lookup is best-effort and bounded: an unreadable board, a missing vault
    entry or an oversized history never blocks the tool. Only values are kept,
    never the handles, and duplicates collapse preserving order.
    """
    tenant_id = str(getattr(context, "tenant_id", "system") or "system")
    found: list[str] = []
    if arguments:
        _collect_argument_secrets(arguments, "", found, tenant_id)
    if include_board:
        store = getattr(context, "store", None)
        engagement_id = str(getattr(context, "engagement_id", "") or "")
        if store is not None and engagement_id:
            try:
                from .blackboard import Blackboard, is_verified_fact

                facts = Blackboard(store).list_facts(
                    tenant_id, engagement_id, fact_type="credential"
                )
            except Exception:  # noqa: BLE001 - redaction is never a gate
                facts = []
            for fact in facts:
                if not is_verified_fact(fact):
                    continue
                ref = (fact.get("value") or {}).get("secret_ref")
                resolved = _vault_secret(ref, tenant_id)
                if resolved:
                    found.append(resolved)
                if len(found) >= MAX_CONTEXT_SECRETS:
                    break
    unique: list[str] = []
    for value in found:
        if value and value not in unique:
            unique.append(value)
        if len(unique) >= MAX_CONTEXT_SECRETS:
            break
    return tuple(unique)


def redact_payload(value: Any, secrets: Iterable[str]) -> Any:
    """Apply value-based redaction to every string of a nested payload."""
    values = tuple(secrets or ())
    if not values:
        return value
    if isinstance(value, dict):
        return {key: redact_payload(item, values) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_payload(item, values) for item in value]
    if isinstance(value, str):
        return redact_secret_values(value, values)
    return value


def redact_result(result: Any, secrets: Iterable[str]) -> Any:
    """Redact a ``ToolResult`` at its four model/ledger boundaries.

    Applied by the handlers that receive a channel (PTY, HTTP, session shell),
    not by the gateway: the gateway keeps its contract and every handler decides
    which secrets it is allowed to know.
    """
    values = tuple(secrets or ())
    if not values:
        return result
    return replace(
        result,
        output=redact_payload(result.output, values),
        evidence=redact_payload(result.evidence, values),
        stdout=redact_secret_values(result.stdout, values),
        stderr=redact_secret_values(result.stderr, values),
    )


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
