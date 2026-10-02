"""Approved installation orchestration for the operational environment.

Turns the read-only readiness report into executable actions, always through the
same secure loop: detect → plan (fixed argv) → approve → execute → verify.
Nothing here invents a command: binary installs reuse the recipe catalog and
:func:`plan_install`; the Sliver operator config reuses the pinned
``sliver-server operator`` invocation.

``assume_yes`` mirrors the durable-approval model of the agent: without it, the
plan is printed for the operator to run; with it, the exact plan is executed.
Third-party binaries that are not in a distro/language manager (Sliver) are
never installed by a blind shell pipe: the pinned release is downloaded and its
Minisign signature verified before the binary is installed, then the team
server is started and the operator config generated.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
import shutil
import tempfile

from .readiness import SLIVER_DEFAULT_CONFIG, EnvironmentReport, sliver_operator_plan


@dataclass(frozen=True)
class BootstrapAction:
    component_id: str
    kind: str  # "install-binary" | "sliver-operator-config" | "manual"
    command: str
    executed: bool
    success: bool
    detail: str = ""


def plan_binary_installs(report: EnvironmentReport):
    """Return ``(component_id, InstallPlan)`` for missing binaries with a recipe."""
    from .installer import plan_install

    plans = []
    for component in report.missing:
        if component.kind != "binary":
            continue
        try:
            plans.append((component.component_id, plan_install(component.component_id)))
        except ValueError:
            # No recipe / no supported manager (e.g. Sliver) -> manual step.
            continue
    return plans


def run_bootstrap(
    report: EnvironmentReport,
    *,
    assume_yes: bool = False,
    lhost: str = "127.0.0.1",
    echo=print,
) -> list[BootstrapAction]:
    """Plan (and, with ``assume_yes``, execute) the environment setup steps."""
    from .installer import execute_install, format_plan, plan_install

    actions: list[BootstrapAction] = []

    # ---- binaries with an approved recipe ---------------------------------
    for component in report.missing:
        if component.kind != "binary":
            continue
        try:
            plan = plan_install(component.component_id)
        except ValueError:
            continue
        command = format_plan(plan)
        echo(f"[install] {component.component_id}: {command}")
        if not assume_yes:
            actions.append(
                BootstrapAction(component.component_id, "install-binary", command, False, False,
                                "plan impreso (usa --yes para ejecutar)")
            )
            continue
        result = execute_install(plan)
        echo(
            f"          → {'OK' if result.success else 'FALLO'} "
            f"(exit={result.exit_code}, verify={result.verify_passed})"
        )
        actions.append(
            BootstrapAction(
                component.component_id, "install-binary", command, True, result.success,
                (result.stderr or "").strip()[-300:],
            )
        )

    # ---- Sliver: verified install -----------------------------------------
    from . import sliver as sliver_mod

    sliver_binary = shutil.which("sliver-server")
    install_plan = sliver_mod.install_plan_text()
    if sliver_binary is None:
        if not assume_yes:
            echo(f"[install] sliver-server: {install_plan}")
            actions.append(
                BootstrapAction(
                    "sliver-server", "sliver-install", install_plan, False, False,
                    "plan impreso (usa --yes para ejecutar)",
                )
            )
        else:
            echo(f"[sliver] {install_plan}")
            install = sliver_mod.install_sliver_verified(
                target_dir=Path("~/.local/bin").expanduser(), echo=echo
            )
            echo(f"          → {install.status} {install.detail}".rstrip())
            actions.append(
                BootstrapAction(
                    "sliver-server", "sliver-install", install_plan,
                    True, install.ok, install.detail,
                )
            )
            if install.ok and install.path:
                sliver_binary = install.path

    # ---- Sliver operator config + team server -----------------------------
    sliver_missing = any(
        c.component_id == "sliver_operator_config" and not c.ready for c in report.components
    )
    if sliver_missing:
        plan = sliver_operator_plan(lhost=lhost)
        config_path = Path(SLIVER_DEFAULT_CONFIG).expanduser()
        if sliver_binary is None:
            echo(
                "[manual] sliver-server ausente; ejecuta la instalación verificada "
                f"y luego:\n          {plan}"
            )
            actions.append(
                BootstrapAction(
                    "sliver_operator_config", "manual", plan, False, False,
                    "sliver-server ausente; instálalo y ejecuta el comando",
                )
            )
        else:
            echo(f"[sliver] {plan}")
            if not assume_yes:
                actions.append(
                    BootstrapAction(
                        "sliver_operator_config", "sliver-operator-config", plan, False, False,
                        "plan impreso (usa --yes para ejecutar)",
                    )
                )
            else:
                server_up = sliver_mod.start_team_server(binary=sliver_binary, echo=echo)
                ok = sliver_mod.ensure_operator_config(
                    path=config_path, binary=sliver_binary, lhost=lhost, echo=echo
                )
                echo(f"          → {'OK' if ok else 'FALLO'} (team server: {'up' if server_up else 'down'})")
                actions.append(
                    BootstrapAction(
                        "sliver_operator_config", "sliver-operator-config", plan, True, ok,
                        "" if ok else "no se pudo generar el operator config",
                    )
                )

    # ---- services ---------------------------------------------------------
    for component in report.missing:
        if component.kind != "service":
            continue
        if component.component_id == "msfrpcd":
            actions.append(_bootstrap_msfrpcd(component, assume_yes=assume_yes, echo=echo))
            continue
        echo(f"[service] {component.component_id}: {component.setup}")
        actions.append(
            BootstrapAction(component.component_id, "manual", component.setup, False, False,
                            "requiere sudo/daemon; ejecútalo explícitamente")
        )

    return actions


def _bootstrap_msfrpcd(component, *, assume_yes: bool, echo, run=None, env=None) -> BootstrapAction:
    """Install/repair the msfrpcd systemd unit through the exact fixed script.

    The credential never reaches ``argv``: it is written to a 0600 temp file and
    the script seeds the root-owned ``/etc/default/msfrpcd`` from it. Execution
    is non-interactive (``sudo -n``), so an operator without passwordless sudo
    gets the exact command to run instead of a hung prompt.
    """
    if run is None:
        from .installer import probe_command

        run = probe_command
    script = Path(__file__).resolve().parents[2] / "scripts" / "install_msfrpcd_service.sh"
    command = "sudo bash scripts/install_msfrpcd_service.sh"
    if not script.exists():
        echo("[service] msfrpcd: script de servicio no encontrado")
        return BootstrapAction("msfrpcd", "manual", command, False, False, "script no encontrado")
    echo(f"[service] msfrpcd: {command}")
    if not assume_yes:
        return BootstrapAction("msfrpcd", "service-install", command, False, False,
                               "plan impreso (usa --yes para ejecutar)")

    env_map = dict(os.environ if env is None else env)
    password = env_map.get("MSF_RPC_PASSWORD") or env_map.get("MSFRPC_PASSWORD")
    if not password:
        return BootstrapAction(
            "msfrpcd", "manual", command, False, False,
            "define MSF_RPC_PASSWORD antes de instalar el servicio",
        )

    fd, temp_path = tempfile.mkstemp(prefix="omni-msf-", suffix=".env")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(f"MSFRPC_PASSWORD={password}\n")
        outcome = run(
            ["sudo", "-n", "bash", str(script), "--password-file", temp_path],
            timeout=180,
        )
        ok = getattr(outcome, "returncode", 1) == 0
        detail = "" if ok else (
            (getattr(outcome, "stderr", "") or "").strip()[-300:]
            or "sudo no disponible sin contraseña; ejecuta el comando manualmente"
        )
        echo(f"          → {'OK' if ok else 'manual'}"
             + (f" ({detail[:120]})" if detail else ""))
        return BootstrapAction(
            "msfrpcd", "service-install",
            "sudo bash scripts/install_msfrpcd_service.sh --password-file <tmp>",
            True, ok, detail,
        )
    finally:
        try:
            os.unlink(temp_path)
        except OSError:
            pass
