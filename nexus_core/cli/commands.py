"""Meta commands of the ``omni`` REPL.

Every command takes ``(session, args)`` and returns ``None``: it prints, it
never raises on bad arguments and it never breaks the session. The durable
audit and the persisted conversation are never modified by a meta command.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from nexus_core.kernel.approvals import ApprovalService

from . import render

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .session import OmniSession

DEFAULT_HISTORY_LIMIT = 20


def _tool_catalog(session: "OmniSession") -> dict[str, Any]:
    from nexus_core.tools.registry import durable_tool_definitions

    try:
        return durable_tool_definitions(session.tenant_id)
    except Exception:  # noqa: BLE001 - a broken catalog must not kill the REPL
        return {}


def cmd_scope(session: "OmniSession", args: list[str]) -> None:
    """Muestra el engagement activo (scope firmado)."""
    render.render_engagement(session.engagement)
    if session.engagement is None:
        print("   (las tools que exigen scope serán denegadas hasta fijar uno)")


def cmd_tools(session: "OmniSession", args: list[str]) -> None:
    """Lista las tools durables con su riesgo y si exigen scope."""
    catalog = _tool_catalog(session)
    if not catalog:
        print("(no hay tools durables disponibles)")
        return
    for tool_id in sorted(catalog):
        entry = catalog[tool_id]
        definition = entry[0] if isinstance(entry, tuple) else entry
        risk = getattr(definition.risk, "value", str(getattr(definition, "risk", "unknown")))
        scope_required = bool(getattr(definition, "scope_required", False))
        print(
            f"  {tool_id:<26} riesgo={render.paint(risk, render.noise_color(risk)):<18}"
            f" scope={'sí' if scope_required else 'no':<3}"
            f" timeout={getattr(definition, 'timeout_seconds', '?')}s"
        )


def cmd_history(session: "OmniSession", args: list[str]) -> None:
    """Muestra los últimos mensajes del run actual."""
    limit = DEFAULT_HISTORY_LIMIT
    if args:
        try:
            limit = max(1, min(int(args[0]), 500))
        except (TypeError, ValueError):
            render.render_error(f"límite inválido: {args[0]!r} (usa un entero)")
            return
    messages: list[dict[str, Any]] = []
    if session.conversation_id:
        try:
            messages = session.store.list_messages(
                session.tenant_id, session.conversation_id, limit=limit
            )
        except Exception as exc:  # noqa: BLE001 - report and keep the session alive
            render.render_error(f"no se pudo leer el historial: {exc}")
            return
    if not messages and session.history:
        for line in session.history[-limit:]:
            print(line)
        return
    render.render_messages(messages)


def cmd_clear(session: "OmniSession", args: list[str]) -> None:
    """Limpia el contexto local de la sesión (mantiene el engagement)."""
    cleared = len(getattr(session, "history", []) or [])
    session.history.clear()
    if hasattr(session, "reset_context"):
        session.reset_context()
    print(
        f"Contexto local limpiado ({cleared} línea(s)). "
        "El engagement y la auditoría durable no se tocan."
    )


def _export_markdown(session: "OmniSession", messages: list[dict[str, Any]]) -> str:
    engagement = session.engagement
    lines = [
        "# Sesión omni",
        "",
        f"- tenant: `{session.tenant_id}`",
        f"- run: `{session.run_id or '(sin run)'}`",
        f"- conversación: `{session.conversation_id or '(sin conversación)'}`",
        f"- engagement: `{getattr(engagement, 'engagement_id', '(ninguno)')}`",
        f"- cliente: `{getattr(engagement, 'client', '(ninguno)')}`",
        "",
        "## Historial",
        "",
    ]
    if messages:
        for message in messages:
            metadata = message.get("metadata") or {}
            kind = metadata.get("kind") or ""
            role = message.get("role") or "?"
            content = str(message.get("content") or "")
            lines.append(f"### {role}{f' ({kind})' if kind else ''}")
            lines.append("")
            lines.append("```")
            lines.append(content[:4000])
            lines.append("```")
            lines.append("")
    elif session.history:
        for line in session.history:
            lines.append(f"- {line}")
    else:
        lines.append("_Sin actividad registrada._")
    return "\n".join(lines) + "\n"


def cmd_export(session: "OmniSession", args: list[str]) -> None:
    """Exporta la sesión actual a un archivo Markdown."""
    messages: list[dict[str, Any]] = []
    if session.conversation_id:
        try:
            messages = session.store.list_messages(
                session.tenant_id, session.conversation_id, limit=500
            )
        except Exception as exc:  # noqa: BLE001 - export degrades to local history
            render.render_error(f"no se pudo leer la conversación durable: {exc}")
    default_name = f"omni-session-{session.run_id or 'local'}.md"
    target = Path(args[0]) if args else Path(session.export_dir or Path.cwd()) / default_name
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_export_markdown(session, messages), encoding="utf-8")
    except OSError as exc:
        render.render_error(f"no se pudo escribir {target}: {exc}")
        return
    print(f"Sesión exportada a {target}")


def cmd_approvals(session: "OmniSession", args: list[str]) -> None:
    """Lista las aprobaciones durables pendientes del tenant."""
    try:
        pending = ApprovalService(session.store).list_pending(session.tenant_id)
    except Exception as exc:  # noqa: BLE001 - never break the REPL
        render.render_error(f"no se pudieron leer las aprobaciones: {exc}")
        return
    if not pending:
        print("(no hay aprobaciones pendientes)")
        return
    for approval in pending:
        print(
            f"  {approval.get('id')}  {approval.get('action')}  "
            f"run={approval.get('run_id')}  por={approval.get('requested_by')}  "
            f"{approval.get('created_at')}"
        )


def _read_answer(session: "OmniSession", prompt: str) -> str:
    """Read one line, turning Ctrl+C/Ctrl+D into an empty (cancel) answer."""
    try:
        return str((session.input_reader or input)(prompt) or "").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def cmd_sessions(session: "OmniSession", args: list[str]) -> None:
    """Lista las sesiones activas (uuid, tipo, peer, vía, usuario)."""
    sessions = session.fetch_sessions()
    if sessions is None:
        render.render_error("no se pudo consultar msfrpcd (¿está vivo?)")
        return
    render.render_session_list(sessions)


def cmd_session(session: "OmniSession", args: list[str]) -> None:
    """Muestra o cambia la sesión activa: /session [attach <uuid>|info]."""
    action = str(args[0]).lower() if args else "info"
    if action == "attach":
        if len(args) < 2:
            render.render_error("uso: /session attach <uuid>")
            return
        session.attach_session(args[1])
        return
    if action == "info":
        if not session.active_session_uuid:
            print("(sin sesión activa: usa /sessions y /session attach <uuid>)")
            return
        info = session.refresh_active_session()
        if info is None:
            render.render_error(
                f"la sesión {session.active_session_uuid} ya no está activa"
            )
            return
        session.active_session_info = dict(info)
        render.render_session_attached(info)
        return
    render.render_error(f"subcomando desconocido: {action!r} (usa attach o info)")


def cmd_detach(session: "OmniSession", args: list[str]) -> None:
    """Sale del modo sesión; la sesión sigue activa en msfrpcd."""
    if session.detach_session() is None:
        print("(no había sesión activa)")


def _kill_one(session: "OmniSession", session_uuid: str) -> bool:
    """Terminate one session through the governed tool; detach if it was ours."""
    result = session.invoke_tool("nexus.session.kill", {"session_uuid": session_uuid})
    if result is None:
        return False
    output = result.get("output") or {}
    if not output.get("success"):
        render.render_error(
            f"no se pudo terminar {session_uuid}: "
            f"{output.get('verification_method') or 'error'}"
        )
        return False
    print(f"Sesión {session_uuid} terminada.")
    if session.active_session_uuid == session_uuid:
        session.detach_session(notify=False)
    return True


def cmd_kill_session(session: "OmniSession", args: list[str]) -> None:
    """Termina una sesión: /kill-session [uuid], o todas con 'all'."""
    sessions = session.fetch_sessions()
    if sessions is None:
        render.render_error("no se pudo consultar msfrpcd (¿está vivo?)")
        return
    known = [
        str(record.get("uuid"))
        for record in sessions.values()
        if isinstance(record, dict) and record.get("uuid")
    ]
    request = str(args[0]) if args else (session.active_session_uuid or "")
    if request.lower() == "all":
        targets = known
    elif request:
        targets = [request]
    else:
        print("(no hay sesión activa; indica un uuid)")
        render.render_session_list(sessions)
        return
    if not targets:
        print("(no hay sesiones que terminar)")
        return
    record = next(
        (
            value
            for value in sessions.values()
            if isinstance(value, dict) and str(value.get("uuid")) == targets[0]
        ),
        None,
    )
    label = targets[0] if len(targets) == 1 else f"{len(targets)} sesiones"
    detail = f" ({record.get('type')}, {record.get('session_host')})" if record else ""
    print(render.paint(f"⚠️  Kill session {label}{detail}?", render.YELLOW))
    print("    [Y] Yes  [N] No  [E] Kill all sessions")
    answer = _read_answer(session, "    > ")
    if answer in {"y", "yes", "s", "si", "sí"}:
        for uuid in targets:
            _kill_one(session, uuid)
        return
    if answer in {"e", "all", "todas"}:
        if not known:
            print("(no hay sesiones que terminar)")
            return
        for uuid in known:
            _kill_one(session, uuid)
        return
    print("cancelado")


def cmd_trust(session: "OmniSession", args: list[str]) -> None:
    """Muestra o cambia trust mode (on/off) sin reiniciar el REPL."""
    if not args:
        print(f"trust mode: {'ON' if session.trust_mode else 'OFF'}")
        print("  (on: auto-aprueba tools de alto riesgo; nunca las destructivas)")
        return
    value = str(args[0]).strip().lower()
    if value in {"on", "1", "true", "yes", "si", "sí"}:
        session.trust_mode = True
    elif value in {"off", "0", "false", "no"}:
        session.trust_mode = False
    else:
        render.render_error(f"valor inválido para /trust: {args[0]!r} (usa on u off)")
        return
    print(
        f"trust mode: {'ON' if session.trust_mode else 'OFF'}"
        " (se aplica al siguiente objetivo)"
    )


def cmd_help(session: "OmniSession", args: list[str]) -> None:
    """Muestra esta ayuda."""
    print(render.paint("Comandos disponibles:", render.BOLD))
    for name in sorted(COMMANDS):
        doc = (COMMANDS[name].__doc__ or "").strip().splitlines()
        print(f"  {name:<12} {doc[0] if doc else ''}")
    print("  (cualquier otra línea se envía como objetivo al agente)")


def cmd_exit(session: "OmniSession", args: list[str]) -> None:
    """Sale del REPL."""
    session.should_exit = True
    print("Cerrando sesión omni. La auditoría durable permanece.")


COMMANDS: dict[str, Callable[["OmniSession", list[str]], None]] = {
    "/scope": cmd_scope,
    "/tools": cmd_tools,
    "/history": cmd_history,
    "/clear": cmd_clear,
    "/export": cmd_export,
    "/approvals": cmd_approvals,
    "/sessions": cmd_sessions,
    "/session": cmd_session,
    "/detach": cmd_detach,
    "/kill-session": cmd_kill_session,
    "/trust": cmd_trust,
    "/help": cmd_help,
    "/exit": cmd_exit,
    "/quit": cmd_exit,
}


def parse_command(line: str) -> tuple[str, list[str]]:
    """Split ``/cmd a b`` into ``("/cmd", ["a", "b"])``."""
    parts = str(line or "").strip().split(maxsplit=1)
    name = parts[0] if parts else ""
    args = parts[1].split() if len(parts) > 1 else []
    return name, args


def run_command(session: "OmniSession", line: str) -> bool:
    """Run a meta command; return ``False`` when it is not a known command."""
    name, args = parse_command(line)
    command = COMMANDS.get(name)
    if command is None:
        render.render_error(f"comando desconocido: {name} (usa /help)")
        return False
    try:
        command(session, args)
    except Exception as exc:  # noqa: BLE001 - a broken command must not kill the REPL
        render.render_error(f"{name} falló: {type(exc).__name__}: {exc}")
    return True


def command_names() -> list[str]:
    """Sorted list of registered meta commands."""
    return sorted(COMMANDS)


__all__ = [
    "COMMANDS",
    "cmd_approvals",
    "cmd_clear",
    "cmd_exit",
    "cmd_export",
    "cmd_help",
    "cmd_history",
    "cmd_scope",
    "cmd_tools",
    "cmd_trust",
    "command_names",
    "parse_command",
    "run_command",
]
