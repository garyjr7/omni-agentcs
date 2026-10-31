"""Safe, distinct diagnostics for Metasploit RPC failures.

The loop used to read every MSF answer that was not a positive result as the
same thing. Measured on a Windows room (2026-10-31): ``msf_auxiliary`` and
``msf_search`` returned ``unavailable`` and neither the operator nor the model
could tell an unset password from a dead daemon, a rejected login, a module the
local catalog does not ship, or a daemon body that was not valid MessagePack.

This module keeps the distinction where it is decidable, and only there:

* credentials absent -> ``msf_credentials_missing`` (nothing was attempted);
* transport/auth/daemon -> ``msf_unavailable``/``msf_auth_failed``;
* the catalog does not serve the requested module -> ``msf_module_unavailable``;
* the daemon answered something unparsable -> ``msf_response_invalid``;
* anything else -> ``msf_rpc_failed``.

Every message is a fixed sentence (never the remote body), so no secret and no
operator path travels back to the model.
"""

from __future__ import annotations

from typing import Any

from nexus_core.integrations.metasploit.client import (
    MetasploitAuthError,
    MetasploitError,
    MetasploitRPCError,
    MetasploitUnavailable,
)
from nexus_core.kernel.models import ToolResult

#: Remote methods whose error means \"the local catalog does not have what was
#: asked for\" rather than \"the daemon is broken\". The method name is the only
#: piece of the RPC envelope this project ever reads for diagnosis.
MODULE_METHODS = frozenset({"module.execute", "module.options", "module.search"})


def msf_failure_result(tool_id: str, exc: BaseException) -> ToolResult:
    """Map one RPC exception to a determinate, safe ``ToolResult``.

    The returned result declares ``unavailable`` for every backend shape: the
    target was never observed, so it must never read as ``negative``. What
    changes is the *cause code*, which the gateway preserves under
    ``evidence.cause_code`` and the prompt renders as the reason to pivot.
    """
    cause = "unexpected_rpc_error"
    method = "msf_rpc_failed"
    message = "the RPC daemon answered with an unexpected error"
    if isinstance(exc, MetasploitAuthError):
        cause = "authentication_failed"
        method = "msf_auth_failed"
        message = "the RPC daemon rejected or is missing the configured credentials"
    elif isinstance(exc, MetasploitUnavailable):
        cause = "rpc_unreachable"
        method = "msf_rpc_unavailable"
        message = "the RPC daemon is not reachable on the configured address"
    elif isinstance(exc, MetasploitRPCError):
        called = str(getattr(exc, "method", "") or "")
        if called in MODULE_METHODS:
            cause = "module_unavailable"
            method = "msf_module_unavailable"
            message = f"the local module catalog did not serve {called}"
        else:
            cause = "rpc_error"
            message = f"the RPC daemon rejected {called or 'the request'}"
    elif not isinstance(exc, MetasploitError):
        cause = "unexpected_error"
        method = "msf_rpc_failed"
        message = f"the tool failed unexpectedly ({type(exc).__name__})"
    extra: dict[str, Any] = {"error_type": type(exc).__name__}
    return ToolResult(
        output={"status": "unavailable", "cause": cause, "message": message},
        verified=False,
        # No declared ``outcome`` on purpose: the gateway re-classifies a
        # provider failure into the established ``*_provider_unavailable``
        # method, and the cause code survives under ``evidence.cause_code``.
        # Declaring ``unavailable`` here would skip that contract and change the
        # method every existing reader matches.
        verification_method=method,
        evidence={**extra, "cause_code": cause, "tool_id": tool_id},
    )
