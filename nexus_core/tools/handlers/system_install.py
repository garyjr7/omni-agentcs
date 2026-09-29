"""Administrative process execution exception: exact-plan human approval only."""

import asyncio
from dataclasses import asdict

from nexus_core.kernel.models import RiskLevel, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.provisioner.installer import execute_install, plan_install, update_shell_path


def install_tool_definition(tenant_id="system"):
    return ToolDefinition(
        tool_id="nexus.system.install_tool",
        name="Install a missing system tool",
        tenant_id=tenant_id,
        description="Install a catalog tool after human approval of its exact recipe command. Never accepts argv from the model.",
        input_schema={
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "minLength": 1, "maxLength": 64},
                "manager": {
                    "type": "string",
                    "enum": [
                        "apt",
                        "dnf",
                        "yum",
                        "pacman",
                        "zypper",
                        "snap",
                        "flatpak",
                        "brew",
                        "port",
                        "go",
                        "cargo",
                        "pipx",
                        "pip",
                    ],
                },
                "dry_run": {"type": "boolean"},
            },
            "required": ["tool_name"],
            "additionalProperties": False,
        },
        risk=RiskLevel.HIGH,
        effect="system_install",
        required_permissions=["execute:tool:nexus.system.install_tool"],
        timeout_seconds=900,
        max_output_bytes=5_000_000,
    )


async def install_tool_handler(arguments, context):
    validate(arguments, install_tool_definition().input_schema)
    dry_run = arguments.get("dry_run", False)
    plan = context.approved_install_plan
    if plan is None:
        if not dry_run:
            raise PermissionError("installation requires an exact plan approved by ToolGateway")
        plan = plan_install(arguments["tool_name"], arguments.get("manager"))
    if (
        plan.tool_name != arguments["tool_name"]
        or arguments.get("manager", plan.manager) != plan.manager
    ):
        raise PermissionError("arguments do not match the approved plan")
    if dry_run:
        return ToolResult(
            output=asdict(plan),
            verified=True,
            verification_method="install_plan_only",
            evidence={"executed": False},
        )
    result = await asyncio.to_thread(execute_install, plan)
    path_updated = False
    if result.success and plan.installs_to:
        path_updated = update_shell_path(plan.installs_to)
    return ToolResult(
        output={
            "tool_name": plan.tool_name,
            "success": result.success,
            "post_install_notes": plan.post_install_notes,
            "path_updated": path_updated,
        },
        verified=result.verify_passed,
        verification_method="installed_tool_verified",
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        evidence={
            "tool_name": plan.tool_name,
            "manager": plan.manager,
            "command": list(plan.command),
            "exit_code": result.exit_code,
            "verify_passed": result.verify_passed,
            "duration_seconds": result.duration_seconds,
        },
    )
