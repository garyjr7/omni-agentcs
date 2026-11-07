"""Shared plumbing for the durable Active Directory handlers.

The AD binaries are installed several ways and live in places the sandbox PATH
does not include (pipx exposes them under ``~/.local/bin``, while the sandbox
child PATH is ``/usr/local/bin:/usr/bin:/bin``). The handlers therefore resolve
each binary to an absolute path and hand that path to the sandbox allowlist;
none of them spawn a process directly.
"""

from __future__ import annotations

import re
import shutil
from functools import lru_cache
from pathlib import Path
from typing import Any

from nexus_core.kernel.sandbox import sandbox_for_environment

from ._exec import RECON_ALLOWED_PROGRAMS

#: Base allowlist shared by every AD handler.
AD_BASE_PROGRAMS: tuple[str, ...] = RECON_ALLOWED_PROGRAMS

_HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
_USERNAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._$@\\-]*")
_DOMAIN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")


@lru_cache(maxsize=None)
def resolve_ad_binary(*candidates: str) -> str | None:
    """Return the absolute path of the first candidate found on ``PATH``."""
    for candidate in candidates:
        path = shutil.which(candidate)
        if path:
            return str(Path(path).resolve())
    return None


def ad_allowed_programs(resolved: str | None, *extra: str) -> tuple[str, ...]:
    """Return the sandbox allowlist including the resolved binary path."""
    programs = list(AD_BASE_PROGRAMS) + list(extra)
    if resolved:
        programs.append(resolved)
    return tuple(dict.fromkeys(programs))


def ad_sandbox(workspace_root: str, resolved: str | None, *extra: str):
    """Build the environment sandbox with the AD binary explicitly allowed."""
    return sandbox_for_environment(
        workspace_root, allowed_programs=ad_allowed_programs(resolved, *extra)
    )


def validate_host(value: object, field: str = "target") -> str:
    """Return a single hostname/IPv4 (no shell metacharacters, no spaces)."""
    text = str(value).strip()
    if not text or not _HOST_RE.fullmatch(text):
        raise ValueError(f"{field} must be a single host or IP address")
    return text


def validate_domain(value: object) -> str:
    """Return a single AD domain (DNS style)."""
    text = str(value).strip()
    if not text or not _DOMAIN_RE.fullmatch(text):
        raise ValueError("domain must be a DNS-style name")
    return text


def validate_username(value: object, field: str = "username") -> str:
    """Return a username, tolerating ``DOMAIN\\user`` and machine accounts."""
    text = str(value).strip()
    if not text or not _USERNAME_RE.fullmatch(text):
        raise ValueError(f"{field} contains unsupported characters")
    return text


def canonicalize_flags(
    raw_flags: object,
    allowed: dict[str, bool],
    forbidden: set[str],
) -> list[str]:
    """Validate model-provided flags against an allowlist.

    ``allowed`` maps a flag to whether it consumes the next token as its value.
    Returns the canonical flag list; raises ``ValueError`` for empty, malformed,
    unknown or forbidden flags (fail closed, never guess).
    """
    canonical: list[str] = []
    if raw_flags is None:
        raw: list[Any] = []
    elif isinstance(raw_flags, (list, tuple)):
        raw = list(raw_flags)
    else:
        raise ValueError("flags must be a list")
    index = 0
    while index < len(raw):
        token = str(raw[index]).strip()
        index += 1
        if not token:
            raise ValueError("empty flag is not allowed")
        if not token.startswith("-"):
            raise ValueError(f"flag must start with '-': {token!r}")
        name, separator, inline_value = token.partition("=")
        if token in forbidden or name in forbidden:
            raise ValueError(f"flag is forbidden: {token!r}")
        spec = allowed.get(token)
        if spec is None:
            spec = allowed.get(name)
        if spec is None:
            raise ValueError(f"flag is not allowed: {token!r}")
        if spec:
            if separator:
                value = inline_value.strip()
            else:
                if index >= len(raw):
                    raise ValueError(f"flag requires a value: {token!r}")
                value = str(raw[index]).strip()
                index += 1
            if not value or value.startswith("-"):
                raise ValueError(f"invalid value for flag {token!r}")
            canonical.extend([name, value])
        else:
            if separator:
                raise ValueError(f"flag does not take a value: {token!r}")
            canonical.append(name)
    return canonical


def require_credentials(
    username: object,
    password: object,
    ntlm_hash: object,
) -> tuple[str, str | None, str | None]:
    """Normalize a credential triple used for authentication flags."""
    user = validate_username(username) if username else ""
    secret = str(password) if password not in (None, "") else None
    hash_value = str(ntlm_hash) if ntlm_hash not in (None, "") else None
    return user, secret, hash_value


def validate_hash(value: object) -> str:
    """Return an ``LMHASH:NTHASH`` pair (one side may be empty)."""
    text = str(value).strip()
    if not re.fullmatch(r"[0-9a-fA-F]{0,32}:[0-9a-fA-F]{32}", text):
        raise ValueError("hash must be a LMHASH:NTHASH pair")
    return text
