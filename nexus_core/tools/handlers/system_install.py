"""Administrative process execution exception: exact-plan human approval only."""

import asyncio
import os
import shutil
from dataclasses import asdict

from nexus_core.kernel.models import RiskLevel, ToolDefinition, ToolResult
from nexus_core.kernel.schema_validation import validate
from nexus_core.provisioner.installer import execute_install, plan_install, update_shell_path

#: Why an install did not deliver the tool, with the one action that fixes it.
#: Measured in the Hijack sprint: the run received ``success=False`` with an empty
#: ``post_install_notes`` and could not tell a missing sudo from an unknown
#: package, so it retried the same call instead of changing route.
INSTALL_REASON_HINTS = {
    "already_installed": (
        "el binario ya está en PATH, no hace falta instalar: usa la tool directamente."
    ),
    "sudo_required": (
        "requiere sudo -n y no hay passwordless: verifica la regla sudoers o pide al "
        "humano que apruebe/ejecute la instalación."
    ),
    "package_not_found": (
        "el gestor de paquetes no conoce <tool_name>: comprueba el nombre real con "
        "nexus.system.check_env y usa otra ruta."
    ),
    "post_install_path_missing": (
        "se instaló pero no está en PATH: reinicia el shell o revisa la ruta que "
        "añade update_shell_path."
    ),
    "network_error": (
        "el gestor no pudo alcanzar su repositorio: no es un problema del objetivo, "
        "reintenta más tarde o usa otra ruta."
    ),
    "install_failed": (
        "el gestor de paquetes falló: lee `error` (stderr real) antes de reintentar."
    ),
}


def _already_present(plan) -> bool:
    """Whether the tool the plan installs already answers on PATH."""
    name = os.path.basename(str(plan.verify_command[0]))
    return bool(shutil.which(name))


def _install_reason(result, *, already_present: bool) -> str | None:
    """Structured reason for a failed install (``None`` when it worked)."""
    if already_present:
        return "already_installed"
    if result.success and result.verify_passed:
        return None
    stderr = (result.stderr or "").lower()
    if "a password is required" in stderr or "no tty present" in stderr:
        return "sudo_required"
    if any(
        marker in stderr
        for marker in (
            "unable to locate",
            "no such package",
            "no match for argument",
            "target not found",
        )
    ):
        return "package_not_found"
    if any(
        marker in stderr
        for marker in (
            "could not resolve",
            "temporary failure in name resolution",
            "network is unreachable",
            "failed to fetch",
            "connection failed",
        )
    ):
        return "network_error"
    if result.exit_code == 0:
        # The install command succeeded but the verify did not: the binary is not
        # reachable from the engine's PATH.
        return "post_install_path_missing"
    return "install_failed"


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
    if _already_present(plan):
        # Installing a tool that already answers is wasted time and a chance to
        # break a working environment; say so instead of running apt.
        return ToolResult(
            output={
                "tool_name": plan.tool_name,
                "success": True,
                "post_install_notes": plan.post_install_notes,
                "path_updated": False,
                "reason": "already_installed",
                "hint": INSTALL_REASON_HINTS["already_installed"],
            },
            verified=True,
            verification_method="installed_tool_already_present",
            evidence={"tool_name": plan.tool_name, "manager": plan.manager, "executed": False},
        )
    result = await asyncio.to_thread(execute_install, plan)
    path_updated = False
    if result.success and plan.installs_to:
        path_updated = update_shell_path(plan.installs_to)
    reason = _install_reason(result, already_present=False)
    output: dict = {
        "tool_name": plan.tool_name,
        "success": result.success,
        "post_install_notes": plan.post_install_notes,
        "path_updated": path_updated,
        "reason": reason,
    }
    if reason:
        output["hint"] = INSTALL_REASON_HINTS[reason]
        # The real error, bounded: the hint says what to do with it.
        output["error"] = (result.stderr or result.stdout or "")[-500:]
    return ToolResult(
        output=output,
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
