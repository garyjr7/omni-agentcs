"""Shared helpers for the Sliver C2 durable tools.

Every Sliver handler is fail-closed: an unusable operator config or an
unreachable team server becomes ``ToolResult(verification_method=...)`` with
``verified=False`` and never an exception escaping to the caller.
"""

from __future__ import annotations

from nexus_core.integrations.sliver.client import (
    SliverAuthError,
    SliverClient,
    SliverConfig,
)
from nexus_core.kernel.models import ToolResult

#: Tool that discovers and registers Sliver sessions.
SLIVER_SESSIONS_TOOL = "nexus.c2.sliver_sessions"


def build_client() -> tuple[SliverClient | None, ToolResult | None]:
    """Build a client from the environment, or return a fail-closed result."""
    try:
        config = SliverConfig.from_env()
    except ValueError:
        return None, ToolResult(verification_method="sliver_config_invalid")
    if not str(config.operator_config or "").strip():
        return None, ToolResult(verification_method="sliver_auth_missing")
    return SliverClient(config), None


def error_result(exc: BaseException, *, tool_id: str) -> ToolResult:
    """Map a client failure to a verified=False ToolResult (never leaks text)."""
    method = "sliver_auth_missing" if isinstance(exc, SliverAuthError) else "sliver_unavailable"
    return ToolResult(
        output={"status": method.split("_", 1)[1], "tool": tool_id},
        verification_method=method,
        evidence={"error_type": type(exc).__name__, "tool": tool_id},
    )


def target_host(remote_address: str) -> str:
    """Strip the ephemeral port from Sliver's ``host:port`` remote address.

    The engine scope validator only understands bare IPs/hostnames/CIDRs, so a
    ``10.0.0.5:54321`` peer address must be reduced before it can be registered
    in ``kernel_sessions`` or scope-checked.
    """
    text = str(remote_address or "").strip()
    if not text:
        return ""
    if text.startswith("["):  # [2001:db8::1]:443
        end = text.find("]")
        return text[1:end] if end != -1 else text
    host, separator, port = text.rpartition(":")
    if separator and port.isdigit():
        return host
    return text
