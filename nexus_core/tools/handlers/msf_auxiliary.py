"""Scoped auxiliary execution using the daemon's asynchronous job API."""

import asyncio
import ipaddress
import math
import re

from nexus_core.integrations.metasploit.client import (
    MetasploitClient,
    MetasploitConfig,
    MetasploitError,
)
from nexus_core.kernel.models import RiskLevel, RunContext, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.kernel.scope_loader import scope_signing_secret
from nexus_core.scope import ScopeValidator
from nexus_core.tools.parsers.metasploit import parse_msf_auxiliary

MODULE_PATTERN = r"auxiliary/[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*"
FORBIDDEN_OPTIONS = {
    "PROXIES",
    "LHOST",
    "LPORT",
    "RHOST",
    "RHOSTS",
    "CHOST",
    "CPORT",
    "SRVHOST",
    "SRVPORT",
    "REVERSELISTENERBINDADDRESS",
    "REVERSELISTENERBINDPORT",
    "PAYLOAD",
    "COMMAND",
    "CMD",
    "EXE",
    "FILENAME",
    "LOCALFILE",
    "OUTPUTPATH",
    "USER_FILE",
    "PASS_FILE",
    "USERPASS_FILE",
    "SESSION",
}
#: Datastore keys the handler itself bounds and sets (RPORT range, THREADS
#: concurrency): the ones worth naming when a forbidden key is refused.
SAFE_EXTRA_OPTIONS = "RPORT, THREADS"


def msf_auxiliary_definition(tenant_id: str = "system") -> ToolDefinition:
    return ToolDefinition(
        tool_id="nexus.exploit.msf_auxiliary",
        name="Run Metasploit auxiliary",
        description="Run a scoped auxiliary module against one validated host via RPC.",
        tenant_id=tenant_id,
        risk=RiskLevel.MEDIUM,
        effect="network_scan",
        scope_required=True,
        scope_target_field="target",
        required_permissions=["execute:tool"],
        timeout_seconds=310,
        input_schema={
            "type": "object",
            "additionalProperties": False,
            "required": ["module", "target"],
            "properties": {
                "module": {"type": "string", "pattern": "^" + MODULE_PATTERN + "$"},
                "target": {"type": "string", "minLength": 1, "maxLength": 253},
                "options": {"type": "object"},
                "timeout_seconds": {"type": "number", "minimum": 1, "maximum": 300},
            },
        },
        # Published so the catalog can show the constraint (Fase 3b): the model
        # used to learn ``RHOSTS`` was refused by being refused.
        forbidden_argument_values={"options": sorted(FORBIDDEN_OPTIONS)},
    )


def validated_options(options: dict) -> dict:
    result = {}
    for key, value in options.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key):
            raise ValueError("invalid option name")
        key = key.upper()
        if key in FORBIDDEN_OPTIONS:
            # Name the offending key: the message reaches the model, and "one of
            # your options is forbidden" is exactly the ambiguity that costs a
            # whole turn (Fase 3b).
            raise ValueError(
                f"option {key!r} is forbidden; the handler sets the host from "
                f"'target'; safe extra options: {SAFE_EXTRA_OPTIONS}"
            )
        if key in result:
            raise ValueError(f"duplicate option {key!r} was already given")
        if type(value) not in {str, int, float, bool}:
            raise ValueError("options must be scalar values")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("invalid numeric option")
        if any(char in str(value) for char in (";", "|", "&", "`", "\n", "\r", "\x00", "$")):
            raise ValueError("unsafe option value")
        result[key] = value
    result.setdefault("THREADS", 1)
    for key, maximum in (("THREADS", 32), ("RPORT", 65535)):
        if key not in result:
            continue
        value = result[key]
        if (
            isinstance(value, bool)
            or not re.fullmatch(r"[0-9]+", str(value))
            or not 1 <= int(value) <= maximum
        ):
            raise ValueError(f"{key} must be between 1 and {maximum}")
        result[key] = int(value)
    return result


async def _poll(client, uuid):
    while True:
        raw = await client.get_module_results(uuid)
        if raw.get("status") not in {"ready", "running"}:
            return {**raw, "uuid": uuid}
        await asyncio.sleep(2)


async def msf_auxiliary_handler(arguments: dict, context: RunContext) -> ToolResult:
    validate(arguments, msf_auxiliary_definition().input_schema)
    module, target = arguments["module"], arguments["target"]
    if not re.fullmatch(MODULE_PATTERN, module):
        raise ValueError("module must be an auxiliary fullname")
    timeout = arguments.get("timeout_seconds", 60)
    if not math.isfinite(timeout) or not 1 <= timeout <= 300:
        raise ValueError("timeout_seconds must be between 1 and 300")
    options = validated_options(arguments.get("options", {}))
    try:
        ipaddress.ip_address(target)
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", target):
            raise ValueError("target must be a single IP or hostname") from None
    if context.scope is None or context.scope.tenant_id != context.tenant_id:
        raise PermissionError("a scope for this tenant is required")
    resolved = ScopeValidator(context.scope, signing_secret=scope_signing_secret()).validate(target)
    # Pin the validated address so msfrpcd cannot resolve the hostname differently.
    addresses = sorted(resolved.resolved_ips, key=lambda addr: ipaddress.ip_address(addr).version)
    if not addresses:
        raise ValueError("target has no validated address")
    options.update(RHOSTS=addresses[0], RHOST=addresses[0])
    secrets = tuple(
        str(v)
        for k, v in options.items()
        if any(word in k for word in ("PASS", "SECRET", "TOKEN", "KEY"))
    )
    job_id = None
    uuid = ""
    try:
        config = MetasploitConfig.from_env()
        if not config.password:
            return ToolResult(verification_method="msf_credentials_missing")
        client = MetasploitClient(config)
        # Covers authentication, execution and polling; cleanup has a separate cap.
        try:
            try:
                async with asyncio.timeout(timeout):
                    await client.authenticate()
                    if not await client.is_available():
                        return ToolResult(verification_method="msf_unavailable")
                    execution = await client.execute_module(module, options)
                    job_id, uuid = execution.get("job_id"), execution["uuid"]
                    raw = await _poll(client, uuid)
                parsed = parse_msf_auxiliary(raw, module, target)
                return ToolResult(
                    output=client.redact(parsed.to_dict(), secrets),
                    verified=parsed.status == "completed",
                    verification_method="msf_auxiliary_rpc_parsed",
                    evidence={
                        "raw_sha256": parsed.raw_sha256,
                        "uuid": uuid,
                        "job_id": job_id,
                        "target_ip": addresses[0],
                        "threads": options["THREADS"],
                    },
                )
            except TimeoutError:
                stopped = False
                if type(job_id) is int:
                    try:
                        async with asyncio.timeout(5):
                            await client.stop_job(job_id)
                            stopped = True
                    except (MetasploitError, TimeoutError):
                        pass
                return ToolResult(
                    output={"status": "timeout", "uuid": uuid},
                    timed_out=True,
                    verification_method="msf_auxiliary_timeout",
                    evidence={"job_id": job_id, "stop_requested": stopped},
                )
        finally:
            await client.aclose()
    except MetasploitError as exc:
        return ToolResult(
            verification_method="msf_rpc_failed",
            evidence={"error_type": type(exc).__name__, "uuid": uuid, "job_id": job_id},
        )
    except (ValueError, TypeError):
        return ToolResult(verification_method="msf_response_invalid")
