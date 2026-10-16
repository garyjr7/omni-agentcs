"""Read-only provisioning inventory."""

import asyncio
from dataclasses import asdict

from nexus_core.kernel.models import RiskLevel, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.provisioner.detector import (
    check_all_tools,
    check_tool,
    detect_managers,
    detect_os,
    verify_tool_in_sandbox,
)


def check_env_definition(tenant_id="system"):
    return ToolDefinition(
        tool_id="nexus.system.check_env",
        effect="read_only",
        name="Check system environment",
        tenant_id=tenant_id,
        description="Report OS, package managers and tool availability without installing anything.",
        input_schema={
            "type": "object",
            "properties": {
                "tools": {
                    "type": "array",
                    "items": {"type": "string", "maxLength": 64},
                    "maxItems": 50,
                },
                "verify_sandbox": {
                    "type": "boolean",
                    "description": (
                        "Run each present tool's verify command inside the sandbox "
                        "to distinguish DETECTED from RUNNABLE (slower)."
                    ),
                },
            },
            "additionalProperties": False,
        },
        risk=RiskLevel.READ_ONLY,
        required_permissions=["execute:tool:nexus.system.check_env"],
        timeout_seconds=30,
        max_output_bytes=500_000,
    )


async def check_env_handler(arguments, context):
    validate(arguments, check_env_definition().input_schema)
    names = arguments.get("tools")
    if names is not None and len(names) > 50:
        raise ValueError("at most 50 tools")
    verify_sandbox = bool(arguments.get("verify_sandbox"))
    if names is None:
        tools = await asyncio.to_thread(check_all_tools)
    else:
        names = list(dict.fromkeys(names))
        statuses = await asyncio.gather(*(asyncio.to_thread(check_tool, name) for name in names))
        tools = dict(zip(names, statuses))

    rendered: dict[str, dict] = {}
    for name, status in tools.items():
        item = dict(asdict(status))
        if verify_sandbox:
            # Host absence says nothing about the configured OCI image.
            verification = await verify_tool_in_sandbox(name)
            item["sandbox_state"] = verification.state
            item["sandbox_exit_code"] = verification.exit_code
            item["sandbox_mode"] = verification.sandbox_mode
        else:
            item["sandbox_state"] = "detected" if status.present else status.state
        rendered[name] = item

    return ToolResult(
        output={
            "os": asdict(detect_os()),
            "managers": list(detect_managers()),
            "tools": rendered,
            "verify_sandbox": verify_sandbox,
        },
        verified=True,
        verification_method="environment_inventory",
        evidence={"tools_checked": len(tools)},
    )
