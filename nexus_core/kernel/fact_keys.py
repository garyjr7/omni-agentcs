"""Canonical identity of a blackboard fact (V0-33).

A fact is stored under ``(fact_type, key)``. The verifier and the agent do not
always spell the same fact the same way: a validated credential arrives as
``cred:ssh:lin@10.0.0.5`` while the model may register ``lin@10.0.0.5`` or
``ssh:lin@10.0.0.5``. Two spellings of one credential must not become two
findings in the report.

This module is pure and deterministic. It only *identifies* a fact; it never
writes, never reads the store and never invents a component that is missing.
When the key and the value do not carry enough information, the normalized key
is returned unchanged so two different things are never merged by guesswork.
"""

from __future__ import annotations

import re
from typing import Any, Mapping
from urllib.parse import urlsplit

#: Protocols that name one credential corpus. Kept as the vocabulary the
#: handlers and the vault already use; an unknown protocol is lowercased only.
_CREDENTIAL_PROTOCOLS = frozenset(
    {"ssh", "smb", "ftp", "web", "http", "https", "winrm", "rdp", "ldap", "mssql", "mysql"}
)

_CRED_KEY = re.compile(
    r"^(?:cred|pivot):(?P<protocol>[^:@]+):(?P<user>[^@]+)@(?P<host>.+)$",
    re.IGNORECASE,
)
_PROTO_USER_HOST = re.compile(
    r"^(?P<protocol>[^:@]+):(?P<user>[^@]+)@(?P<host>.+)$",
    re.IGNORECASE,
)
_USER_HOST = re.compile(r"^(?P<user>[^@\s]+)@(?P<host>[^@\s]+)$")
_SERVICE_KEY = re.compile(
    r"^(?P<host>.+?):(?P<port>\d{1,5})(?::(?P<protocol>[A-Za-z]+))?$"
)

_HOST_FIELDS = ("host", "hostname", "target", "ip")
_USER_FIELDS = ("username", "user", "account", "login")
_PROTOCOL_FIELDS = ("protocol", "service", "scheme")


def _text(value: Any) -> str:
    return " ".join(str(value or "").split()).strip()


def _host(value: Any) -> str:
    """Normalize a host without losing an IPv6 literal's brackets handling."""
    text = _text(value).strip("[]").rstrip(".,;")
    if not text:
        return ""
    if "://" in text:
        try:
            text = urlsplit(text).hostname or text
        except ValueError:
            return ""
    if text.count(":") == 1 and text.rsplit(":", 1)[1].isdigit():
        text = text.rsplit(":", 1)[0]
    return text.strip("[]").strip().casefold()


def _value_host(value: Mapping[str, Any]) -> str:
    for field in ("url",):
        candidate = _text(value.get(field))
        if candidate:
            host = _host(candidate)
            if host:
                return host
    for field in _HOST_FIELDS:
        host = _host(value.get(field))
        if host:
            return host
    return ""


def _value_user(value: Mapping[str, Any]) -> str:
    for field in _USER_FIELDS:
        candidate = _text(value.get(field))
        if candidate:
            return candidate.casefold()
    return ""


def _value_protocol(value: Mapping[str, Any]) -> str:
    for field in _PROTOCOL_FIELDS:
        candidate = _text(value.get(field)).casefold()
        if candidate:
            return candidate
    return ""


def _protocol(value: str) -> str:
    protocol = _text(value).casefold()
    if protocol in {"http", "https"}:
        return "web"
    return protocol


def _parse_credential(
    key: str, value: Mapping[str, Any]
) -> tuple[str, str, str] | None:
    """``(protocol, user, host)`` when the credential can be identified."""
    protocol = user = host = ""
    for pattern in (_CRED_KEY, _PROTO_USER_HOST):
        match = pattern.match(key)
        if match is not None:
            protocol = _protocol(match.group("protocol"))
            user = _text(match.group("user")).casefold()
            host = _host(match.group("host"))
            break
    else:
        match = _USER_HOST.match(key)
        if match is not None:
            user = _text(match.group("user")).casefold()
            host = _host(match.group("host"))
    protocol = protocol or _protocol(_value_protocol(value))
    user = user or _value_user(value)
    host = host or _value_host(value)
    if not (protocol and user and host):
        return None
    return protocol, user, host


def canonical_fact_key(
    fact_type: Any, key: Any, value: Mapping[str, Any] | None = None
) -> str:
    """Canonical identity of one fact, used to supersede and to deduplicate.

    Credentials (and the ``access`` facts that name an account) are identified
    by ``protocol:user@host``; services by ``host:port/protocol``; hosts by their
    normalized name. Everything else keeps its normalized key, so a path or a
    flag is never case-folded into another one.
    """
    kind = _text(fact_type).casefold()
    raw = _text(key)
    body: Mapping[str, Any] = value if isinstance(value, Mapping) else {}

    if kind in {"credential", "access"}:
        parsed = _parse_credential(raw, body)
        if parsed is not None:
            protocol, user, host = parsed
            return f"{'cred' if kind == 'credential' else 'access'}:{protocol}:{user}@{host}"
        if kind == "access":
            host = _value_host(body)
            user = _value_user(body)
            if host and user:
                return f"access:{user}@{host}"
        return raw.casefold()

    if kind == "service":
        match = _SERVICE_KEY.match(raw)
        if match is not None:
            protocol = _protocol(match.group("protocol") or _value_protocol(body) or "tcp")
            return f"{_host(match.group('host'))}:{int(match.group('port'))}/{protocol}"
        host = _value_host(body)
        port_text = str(body.get("port") or "").strip()
        if host and port_text.isdigit():
            protocol = _protocol(_value_protocol(body) or "tcp")
            return f"{host}:{int(port_text)}/{protocol}"
        return raw.casefold()

    if kind == "host":
        return _host(raw) or raw.casefold()

    if kind == "route":
        return raw.casefold()

    # A loot artifact, a barrier reason or a hint is compared literally: its
    # key can be a flag or a path where case matters. Only surrounding
    # whitespace is normalized.
    return raw


def canonical_fact_identity(fact: Mapping[str, Any]) -> tuple[str, str]:
    """``(fact_type, canonical_key)`` of a stored fact."""
    return (
        _text(fact.get("fact_type")).casefold(),
        canonical_fact_key(
            fact.get("fact_type"),
            fact.get("key"),
            fact.get("value") if isinstance(fact.get("value"), Mapping) else {},
        ),
    )
