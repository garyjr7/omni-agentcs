"""``omni --setup``: assess and (with ``--install``) bootstrap the environment."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from nexus_core.config.loader import apply_environment
from nexus_core.provisioner.binaries import check_binary_identity
from nexus_core.provisioner.readiness import assess_environment, render_report


def run_setup(
    paths,
    config,
    *,
    install: bool = False,
    assume_yes: bool = False,
    as_json: bool = False,
) -> int:
    """Assess the operational environment and optionally install what is missing.

    ``--install`` without ``--yes`` only prints the exact plans (safe default);
    ``--install --yes`` executes them through the approved installer loop.
    Presence is verified **and** so is identity: a same-named wrong binary
    (e.g. the Python ``httpx`` HTTP client) is reported as not ready.
    """
    apply_environment(config, paths)
    report = assess_environment(probe_binary=check_binary_identity)

    actions: list[Any] = []
    if install:
        from nexus_core.provisioner.bootstrap import run_bootstrap

        def _silent(*_args: Any) -> None:  # keep JSON output clean
            return None

        echo = _silent if as_json else print
        actions = run_bootstrap(report, assume_yes=assume_yes, echo=echo)
        report = assess_environment(probe_binary=check_binary_identity)

    if as_json:
        payload = report.to_dict()
        payload["actions"] = [asdict(action) for action in actions]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    print(render_report(report))
    wrong = [
        c for c in report.components
        if c.kind == "binary" and c.identity_ok is False
    ]
    if wrong:
        print("")
        print("BINARIOS EQUIVOCADOS (misma ruta, herramienta equivocada):")
        for component in wrong:
            print(f"  ✗ {component.component_id}: {component.detail}")
            if component.setup:
                print(f"      → instala el binario correcto: {component.setup}")
        print(
            "Estos binarios harán fallar los tools correspondientes; "
            "un run autónomo se detendrá en el preflight hasta corregirlo."
        )
    if actions:
        installed = [a for a in actions if a.executed and a.success]
        failed = [a for a in actions if a.executed and not a.success]
        pending = [a for a in actions if not a.executed]
        print("")
        print(
            f"Acciones: {len(installed)} aplicadas, {len(failed)} fallidas, "
            f"{len(pending)} pendientes de aprobación."
        )
        if not assume_yes and pending:
            print("Ejecuta de nuevo con --install --yes para aplicar los planes.")
    return 0
