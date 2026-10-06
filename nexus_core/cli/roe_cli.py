"""``omni --roe`` and ``/roe``: visualize and control a Rules of Engagement.

The RoE file lives in the XDG state directory and is written by the API
(``nexus_core.scope.roe.save_roe``); this module is the read/control surface:
show the current policy and state, print its path, and arm or clear the kill
switch. Keeping the logic here means the CLI flag and the REPL command cannot
drift apart.
"""

from __future__ import annotations

from typing import Any

from nexus_core.scope.roe import (
    RoEEnforcer,
    kill_switch_path,
    load_roe,
    roe_path,
)

ACTIONS = ("show", "status", "kill", "arm", "reset", "path")


def run_roe_action(
    action: str, engagement_id: str | None, *, paths: Any = None
) -> tuple[int, list[str]]:
    """Apply one RoE action; return ``(exit_code, printable_lines)``.

    ``show``/``status`` describe the policy and its live state, ``path`` prints
    the files, ``kill`` creates the sentinel file (halt everything) and
    ``arm``/``reset`` removes it. An unknown action is a usage error.
    """
    if not engagement_id:
        return 2, ["error: se requiere un engagement activo para usar la RoE"]
    normalized = (action or "show").strip().lower()
    if normalized not in ACTIONS:
        return 2, [f"error: acción desconocida: {action} (usa show|kill|arm|path)"]
    if normalized == "path":
        return 0, [
            f"RoE: {roe_path(engagement_id, paths)}",
            f"kill switch: {kill_switch_path(engagement_id, paths)}",
        ]

    if normalized == "kill":
        target = kill_switch_path(engagement_id, paths)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_text("stop\n")
        target.chmod(0o600)
        return 0, [
            f"⛔ kill switch activado: toda acción se detiene de inmediato "
            f"({target})",
            "  rearma con: omni --roe arm",
        ]
    if normalized in {"arm", "reset"}:
        target = kill_switch_path(engagement_id, paths)
        existed = target.exists()
        if existed:
            target.unlink()
        return 0, [
            "✓ kill switch desarmado; el engagement puede continuar"
            if existed
            else "✓ el kill switch ya estaba desarmado"
        ]

    roe = load_roe(engagement_id, paths)
    if roe is None:
        return 0, [
            f"sin RoE configurada para {engagement_id}",
            "  la RoE es opcional: sin ella manda solo el scope firmado",
            f"  ruta esperada: {roe_path(engagement_id, paths)}",
        ]
    enforcer = RoEEnforcer(roe)
    snapshot = enforcer.snapshot()
    lines = roe.describe().splitlines()
    lines.append(
        "  estado: " + ("DETENIDA (kill switch)" if snapshot["stopped"] else "activa")
    )
    if not snapshot["window_open"]:
        lines.append("  ⚠ fuera de la ventana autorizada en este momento")
    lines.append(
        f"  acciones en el último minuto: {snapshot['actions_last_minute']}"
        f" · concurrentes: {snapshot['active']}"
    )
    return 0, lines


__all__ = ["ACTIONS", "run_roe_action"]
