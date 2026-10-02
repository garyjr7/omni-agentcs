"""Approved installation orchestration for the operational environment.

Turns the read-only readiness report into executable actions, always through the
same secure loop: detect → plan (fixed argv) → approve → execute → verify.
Nothing here invents a command: binary installs reuse the recipe catalog and
:func:`plan_install`; the Sliver operator config reuses the pinned
``sliver-server operator`` invocation.

``assume_yes`` mirrors the durable-approval model of the agent: without it, the
plan is printed for the operator to run; with it, the exact plan is executed.
Third-party binaries that are not in a distro/language manager (Sliver) are
never installed by a blind shell pipe: they are reported with the official,
checksum-verifiable path.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from .readiness import EnvironmentReport, sliver_operator_plan


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

    # ---- Sliver operator config -------------------------------------------
    sliver_missing = any(
        c.component_id == "sliver_operator_config" and not c.ready for c in report.components
    )
    if sliver_missing:
        sliver_server = shutil.which("sliver-server")
        plan = sliver_operator_plan(lhost=lhost)
        if sliver_server is None:
            echo(
                "[manual] sliver-server no está instalado. Instálalo desde la "
                "release oficial verificando su checksum y luego ejecuta:\n"
                f"          {plan}"
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
                from .installer import probe_command

                outcome = probe_command(
                    [sliver_server, "operator", "--name", "omni", "--lhost", lhost,
                     "--permissions", "all", "--save",
                     "~/.config/omni/sliver/operator.cfg"],
                    timeout=120,
                )
                ok = outcome.returncode == 0
                echo(f"          → {'OK' if ok else 'FALLO'}")
                actions.append(
                    BootstrapAction(
                        "sliver_operator_config", "sliver-operator-config", plan, True, ok,
                        (outcome.stderr or outcome.stdout or "").strip()[-300:],
                    )
                )

    # ---- services (reported, they need root/background) -------------------
    for component in report.missing:
        if component.kind != "service":
            continue
        echo(f"[service] {component.component_id}: {component.setup}")
        actions.append(
            BootstrapAction(component.component_id, "manual", component.setup, False, False,
                            "requiere sudo/daemon; ejecútalo explícitamente")
        )

    return actions
