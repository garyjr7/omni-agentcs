"""Meta commands of the ``omni`` REPL.

Every command takes ``(session, args)`` and returns ``None``: it prints, it
never raises on bad arguments and it never breaks the session. The durable
audit and the persisted conversation are never modified by a meta command.
"""

from __future__ import annotations

import getpass
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from nexus_core.kernel.approvals import ApprovalService

from . import render
from .tool_result import tool_method, tool_payload, tool_success
from .tui.markdown import DEFAULT_READING_WIDTH
from .tui.output import routed

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .session import OmniSession

DEFAULT_HISTORY_LIMIT = 20

#: Internal trace of the CLI. Successful slash commands that only change state
#: (``/engage_use``, ``/engage_create``) do not echo into the transcript: the
#: header badge and the status bar already name the engagement.
log = logging.getLogger("omni.tui")

#: System prompt of ``/ask``: conversational, never executes anything.
ASK_SYSTEM_PROMPT = (
    "Eres OmniAgentCS, un asistente experto en ciberseguridad ofensiva. "
    "Respondes con información técnica precisa y práctica. No ejecutas "
    "herramientas: solo explicas, aconsejas y respondes preguntas."
)
#: How many previous /ask exchanges stay in the local conversational context.
ASK_HISTORY_LIMIT = 20


def _tool_catalog(session: "OmniSession") -> dict[str, Any]:
    from nexus_core.tools.registry import durable_tool_definitions

    try:
        return dict(durable_tool_definitions(session.tenant_id))
    except Exception:  # noqa: BLE001 - a broken catalog must not kill the REPL
        return {}


def _build_ask_system_prompt(session: "OmniSession") -> str:
    """Build the ``/ask`` system prompt from the *real* CLI state.

    ``/ask`` must describe *this* CLI — the commands registered right now, the
    durable tools, the active engagement and the resolved LLM provider — instead
    of generic pentest advice. Everything is read locally and nothing is
    persisted or executed.
    """
    from nexus_core.cli.main import PROGRAM_VERSION

    tools = _tool_catalog(session)
    tool_lines = []
    # Keep the whole durable catalog (compact: one line per tool); the cap only
    # guards against a runaway catalog, so it must exceed the current size.
    for tool_id, entry in sorted(tools.items())[:64]:
        definition = entry[0] if isinstance(entry, tuple) else entry
        description = str(getattr(definition, "description", "") or "").replace("\n", " ")[:80]
        tool_lines.append(f"  - {tool_id}: {description}")

    command_lines = []
    for name in sorted(COMMANDS):
        doc = (COMMANDS[name].__doc__ or "").strip().splitlines()
        command_lines.append(f"  - {name}: {doc[0][:80] if doc else ''}")

    engagement = session.engagement
    if engagement is None:
        engagement_context = "Sin engagement activo (las tools con scope serán denegadas)."
    else:
        domains = ", ".join(getattr(engagement, "domains", ()) or ()) or "(sin dominios)"
        cidrs = ", ".join(getattr(engagement, "cidrs", ()) or ()) or "(sin CIDRs)"
        engagement_context = (
            f"id={getattr(engagement, 'engagement_id', '?')} · "
            f"nombre={getattr(engagement, 'name', '?')} · dominios={domains} · CIDRs={cidrs}"
        )

    return (
        f"{ASK_SYSTEM_PROMPT}\n\n"
        f"Eres la CLI OmniAgentCS v{PROGRAM_VERSION}. El usuario está en el REPL y usa "
        "/ask para consultar sin ejecutar herramientas. Responde con ayuda CONCRETA y "
        "BREVE sobre esta CLI, no teoría genérica de pentesting.\n\n"
        f"Engagement activo: {engagement_context}\n"
        f"Proveedor LLM resuelto: {session._llm_summary()}\n\n"
        f"Comandos meta disponibles ({len(COMMANDS)}):\n" + "\n".join(command_lines) + "\n\n"
        f"Tools durables disponibles ({len(tools)}):\n"
        + ("\n".join(tool_lines) if tool_lines else "  (catálogo no disponible)")
        + "\n\nSi preguntan qué puedes hacer, lista capacidades específicas y el comando "
        "exacto (/nombre) o el objetivo en lenguaje natural que las activa. Si preguntan "
        "cómo hacer algo, indica el comando o el objetivo concreto. Tono directo y "
        "técnico, sin preámbulos; máximo 400 palabras salvo que pidan detalle. Usa "
        "markdown con encabezados, listas y bloques de código."
    )


def cmd_scope(session: "OmniSession", args: list[str]) -> None:
    """Muestra el engagement activo (scope firmado)."""
    render.render_engagement(session.engagement)
    if session.engagement is None:
        render.write("   (las tools que exigen scope serán denegadas hasta fijar uno)")


def _engage_list(session: "OmniSession", engage: Any) -> None:
    scopes = engage.list_engagements(session.store, session.tenant_id)
    if not scopes:
        render.write(
            "(no hay engagements; crea uno con "
            "/engage_create <nombre> <dominios/CIDRs>)"
        )
        return
    active = session.engagement_id
    for scope in scopes:
        marker = render.paint("*", render.GREEN) if scope.engagement_id == active else " "
        render.write(f" {marker} {scope.engagement_id}  {render.paint(scope.name, render.YELLOW)}")
        cidrs = ", ".join(scope.cidrs) or "(ninguno)"
        domains = ", ".join(scope.domains) or "(ninguno)"
        render.write(f"     cidrs={cidrs} · dominios={domains} · hasta {scope.valid_until}")


def _engage_create(session: "OmniSession", engage: Any, rest: list[str]) -> None:
    usage = "uso: /engage_create <nombre> <dominios/CIDRs> [--hours N]"
    hours = engage.DEFAULT_VALID_HOURS
    if "--hours" in rest:
        index = rest.index("--hours")
        try:
            hours = int(rest[index + 1])
        except (IndexError, ValueError):
            render.render_error(usage)
            return
        del rest[index : index + 2]
    if len(rest) < 2:
        render.render_error(usage)
        return
    name, entries = rest[0], " ".join(rest[1:])
    try:
        scope = engage.create_engagement(
            session.store, name, entries, tenant_id=session.tenant_id, hours=hours
        )
    except ValueError as exc:
        render.render_error(f"no se pudo crear el engagement: {exc}")
        return
    session.set_engagement(scope)
    log.debug(
        "[omni.tui] engagement creado: %s · %s · cidrs=%s · dominios=%s",
        scope.engagement_id, scope.name, list(scope.cidrs), list(scope.domains),
    )
    log.debug("[omni.tui] engagement activo: %s (%s)", scope.engagement_id, scope.name)


def _engage_use(session: "OmniSession", engage: Any, rest: list[str]) -> None:
    if not rest:
        render.render_error("uso: /engage_use <engagement_id>")
        return
    scope = engage.get_engagement(session.store, session.tenant_id, rest[0])
    if scope is None:
        render.render_error(f"engagement no encontrado: {rest[0]}")
        return
    session.set_engagement(scope)
    log.debug("[omni.tui] engagement activo: %s (%s)", scope.engagement_id, scope.name)


def cmd_engage_list(session: "OmniSession", args: list[str]) -> None:
    """Lista los engagements del tenant: /engage_list."""
    from . import engage as engage_module

    _engage_list(session, engage_module)


def cmd_engage_create(session: "OmniSession", args: list[str]) -> None:
    """Crea y activa un engagement: /engage_create <nombre> <dominios/CIDRs> [--hours N]."""
    from . import engage as engage_module

    _engage_create(session, engage_module, list(args))


def cmd_engage_use(session: "OmniSession", args: list[str]) -> None:
    """Activa un engagement existente: /engage_use <engagement_id>."""
    from . import engage as engage_module

    _engage_use(session, engage_module, list(args))


def cmd_engage_current(session: "OmniSession", args: list[str]) -> None:
    """Muestra el engagement activo (scope firmado): /engage_current."""
    render.render_engagement(session.engagement)
    if session.engagement is None:
        render.write(
            "   (las tools que exigen scope serán denegadas hasta fijar uno; "
            "usa /engage_create o /engage_use)"
        )


def cmd_engage(session: "OmniSession", args: list[str]) -> None:
    """Gestiona engagements (dispatcher): /engage [list | create | use | current].

    Prefer the top-level ``/engage_list``, ``/engage_create``, ``/engage_use`` and
    ``/engage_current``: they are individually discoverable in autocomplete. This
    dispatcher stays for backward compatibility.
    """
    action = args[0].lower() if args else "list"
    if action in {"list", "ls"}:
        cmd_engage_list(session, [])
    elif action in {"create", "new"}:
        cmd_engage_create(session, list(args[1:]))
    elif action in {"use", "switch", "select"}:
        cmd_engage_use(session, list(args[1:]))
    elif action in {"current", "show"}:
        cmd_engage_current(session, [])
    else:
        render.render_error(
            "uso: /engage [list | create <nombre> <dominios/CIDRs> [--hours N] | use <id>] "
            "(o usa /engage_list, /engage_create, /engage_use, /engage_current)"
        )


def cmd_tools(session: "OmniSession", args: list[str]) -> None:
    """Lista las tools durables con su riesgo y si exigen scope."""
    catalog = _tool_catalog(session)
    if not catalog:
        render.write("(no hay tools durables disponibles)")
        return
    for tool_id in sorted(catalog):
        entry = catalog[tool_id]
        definition = entry[0] if isinstance(entry, tuple) else entry
        risk = getattr(definition.risk, "value", str(getattr(definition, "risk", "unknown")))
        scope_required = bool(getattr(definition, "scope_required", False))
        render.write(
            f"  {tool_id:<26} riesgo={render.paint(risk, render.noise_color(risk)):<18}"
            f" scope={'sí' if scope_required else 'no':<3}"
            f" timeout={getattr(definition, 'timeout_seconds', '?')}s"
        )


def _work_conversations(session: "OmniSession") -> list[dict[str, Any]]:
    """Durable work sessions of this agent (active first, by updated_at)."""
    from nexus_core.agent import memory

    try:
        conversations = session.store.list_conversations(session.tenant_id, session.agent_id)
    except Exception:  # noqa: BLE001
        return []
    return [
        item
        for item in conversations
        if str(item.get("title") or "").startswith(memory.WORK_SESSION_PREFIX)
    ]


def cmd_history(session: "OmniSession", args: list[str]) -> None:
    """Muestra los últimos mensajes del run actual (/history [n] | --archive)."""
    if args and args[0] == "--archive":
        conversations = _work_conversations(session)
        if not conversations:
            render.write("(no hay sesiones de trabajo archivadas)")
            return
        render.write("Sesiones de trabajo (la primera es la activa):")
        for item in conversations:
            try:
                count = len(
                    session.store.list_messages(
                        session.tenant_id, str(item["id"]), limit=500
                    )
                )
            except Exception:  # noqa: BLE001
                count = 0
            render.write(
                f"  {item['id']}  {item.get('title')}  "
                f"mensajes={count}  actualizado={item.get('updated_at')}"
            )
        return
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
        from .tui.presentation import input_chip, render_rich
        for line in session.history[-limit:]:
            render.write(render_rich(input_chip(line), no_color=session.no_color or not session._tui.use_tui))
        return
    # Copies affect display only; durable history retains the complete input.
    from .tui.presentation import input_chip
    visible = [{**message, "content": input_chip(str(message.get("content") or "")).plain}
               if message.get("role") == "user" else message for message in messages]
    render.render_messages(visible)


def cmd_clear(session: "OmniSession", args: list[str]) -> None:
    """Rota a una sesión de trabajo nueva (mantiene el engagement y archiva)."""
    cleared = len(getattr(session, "history", []) or [])
    session.history.clear()
    previous = getattr(session, "conversation_id", None)
    new_session = None
    if hasattr(session, "rotate_work_session"):
        new_session = session.rotate_work_session()
    if hasattr(session, "reset_context"):
        session.reset_context()
    render.write(
        f"Contexto local limpiado ({cleared} línea(s)). Nueva sesión de trabajo "
        f"{new_session or '(sin store)'}: el historial anterior queda archivado "
        f"(consúltalo con /history --archive). El engagement y la auditoría durable "
        f"no se tocan."
    )
    if previous:
        render.write(f"  (sesión anterior: {previous})")


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
    render.write(f"Sesión exportada a {target}")


def cmd_approvals(session: "OmniSession", args: list[str]) -> None:
    """Lista las aprobaciones durables pendientes del tenant."""
    try:
        pending = ApprovalService(session.store).list_pending(session.tenant_id)
    except Exception as exc:  # noqa: BLE001 - never break the REPL
        render.render_error(f"no se pudieron leer las aprobaciones: {exc}")
        return
    if not pending:
        render.write("(no hay aprobaciones pendientes)")
        return
    for approval in pending:
        render.write(
            f"  {approval.get('id')}  {approval.get('action')}  "
            f"run={approval.get('run_id')}  por={approval.get('requested_by')}  "
            f"{approval.get('created_at')}"
        )


def _read_answer(session: "OmniSession", prompt: str) -> str:
    """Read one line, turning Ctrl+C/Ctrl+D into an empty (cancel) answer."""
    try:
        reader = session.input_reader or (session._tui.prompt if session._tui.use_tui else input)
        return str(reader(prompt) or "").strip().lower()
    except (EOFError, KeyboardInterrupt):
        render.write()
        return ""


def _render_sliver_sessions(session: "OmniSession") -> None:
    """Table of the Sliver sessions/beacons of the current engagement."""
    sessions = session.fetch_sliver_sessions()
    if sessions is None:
        render.render_error("no se pudo consultar el team server de Sliver (¿está vivo?)")
        return
    if not sessions:
        render.write("(no hay sesiones Sliver activas)")
        return
    render.write(render.paint("Active Sliver sessions:", render.BOLD))
    for record in sessions.values():
        render.write(
            f"  {str(record.get('uuid') or '?'):<12} "
            f"{str(record.get('type') or '?'):<8} "
            f"{record.get('remote_address') or '?'} "
            f"{record.get('username') or '?'}"
        )


def cmd_sessions(session: "OmniSession", args: list[str]) -> None:
    """Lista las sesiones activas (uuid, tipo, peer, vía, usuario).

    Uso: /sessions [--sliver] para listar las sesiones del team server Sliver.
    """
    if args and str(args[0]).lower() in {"--sliver", "sliver"}:
        _render_sliver_sessions(session)
        return
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
            render.write("(sin sesión activa: usa /sessions y /session attach <uuid>)")
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
        render.write("(no había sesión activa)")


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
    render.write(f"Sesión {session_uuid} terminada.")
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
        render.write("(no hay sesión activa; indica un uuid)")
        render.render_session_list(sessions)
        return
    if not targets:
        render.write("(no hay sesiones que terminar)")
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
    render.write(render.paint(f"⚠️  Kill session {label}{detail}?", render.YELLOW))
    render.write("    [Y] Yes  [N] No  [E] Kill all sessions")
    answer = _read_answer(session, "    > ")
    if answer in {"y", "yes", "s", "si", "sí"}:
        for uuid in targets:
            _kill_one(session, uuid)
        return
    if answer in {"e", "all", "todas"}:
        if not known:
            render.write("(no hay sesiones que terminar)")
            return
        for uuid in known:
            _kill_one(session, uuid)
        return
    render.write("cancelado")


def _report_tools(session: "OmniSession") -> Any:
    """Import the report layer lazily (the REPL must survive an import error)."""
    from nexus_core.report import extractor as extractor_module
    from nexus_core.report import markdown as markdown_module

    return extractor_module, markdown_module


def cmd_findings(session: "OmniSession", args: list[str]) -> None:
    """Lista los hallazgos verificados del engagement activo (sin generar informe)."""
    if session.engagement is None:
        render.render_error("no hay engagement activo (usa /scope)")
        return
    try:
        extractor_module, markdown_module = _report_tools(session)
        findings, failed = extractor_module.extract_findings_sync(
            session.store, session.tenant_id, session.engagement_id
        )
    except KeyError:
        render.render_error(f"engagement desconocido: {session.engagement_id}")
        return
    except Exception as exc:  # noqa: BLE001 - never break the REPL
        render.render_error(f"no se pudieron extraer hallazgos: {type(exc).__name__}: {exc}")
        return
    if not findings and not failed:
        render.write(f"(sin hallazgos verificados en {session.engagement_id})")
        return
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    render.write(f"Hallazgos del engagement {session.engagement_id}:")
    render.write(markdown_module.findings_table(findings))
    render.write()
    breakdown = ", ".join(
        f"{counts[level]} {level}" for level in ("critical", "high", "medium", "low", "info") if counts.get(level)
    ) or "0"
    render.write(f"Total: {len(findings)} findings ({breakdown})")
    if failed:
        render.write(f"Intentos sin hallazgo: {len(failed)} (ver /report)")


def cmd_facts(session: "OmniSession", args: list[str]) -> None:
    """Lista los hechos registrados (blackboard): /facts [tipo]."""
    engagement_id = session.engagement_id
    if engagement_id is None:
        render.render_error("no hay engagement activo (usa /scope)")
        return
    from nexus_core.kernel.blackboard import FACT_TYPES, Blackboard

    fact_type = args[0] if args else None
    if fact_type is not None and fact_type not in FACT_TYPES:
        render.render_error(
            f"tipo desconocido: {fact_type!r} (tipos: {', '.join(FACT_TYPES)})"
        )
        return
    try:
        board = Blackboard(session.store)
        facts = board.list_facts(
            session.tenant_id, engagement_id, fact_type=fact_type
        )
    except Exception as exc:  # noqa: BLE001 - never break the REPL
        render.render_error(f"no se pudo leer el blackboard: {type(exc).__name__}: {exc}")
        return
    if not facts:
        render.write(f"(sin hechos registrados en {engagement_id})")
        return
    render.write(f"Hechos del engagement {engagement_id} ({len(facts)}):")
    for fact in facts:
        mark = "" if fact.get("verified") else " [sin verificar]"
        render.write(
            f"  [{fact['fact_type']}] {fact['key']}{mark} via {fact.get('source', '?')}"
        )
    summary = board.summary(session.tenant_id, engagement_id)
    render.write(f"Resumen: {summary['counts']}")


def cmd_mode(session: "OmniSession", args: list[str]) -> None:
    """Permisos persistentes: /mode show | /mode plan on|off (aprobar revisión)."""
    from nexus_core.agent.planner import plan_from_summary
    from nexus_core.kernel.blackboard import Blackboard
    from nexus_core.kernel.models import Identity
    from nexus_core.kernel.operator_mode import OperatorMode

    if args not in ([], ['show'], ['plan','on'], ['plan','off']):
        render.render_error('uso: /mode show | /mode plan on|off')
        return
    context = session.build_run_context()
    modes = OperatorMode(session.store)
    state = modes.get(context)
    if args == ['plan','on']:
        engagement_id = session.engagement_id or ''
        summary = Blackboard(session.store).summary(session.tenant_id, engagement_id)
        plan = plan_from_summary(summary, engagement_id=engagement_id)
        state = modes.plan(context,plan.render())
    elif args == ['plan','off']:
        if state['mode'] != 'plan':
            render.render_error('no hay un plan pendiente de aprobación')
            return
        render.write(state['plan_text'])
        render.write('Revisión: '+state['plan_hash'])
        prompt = 'Escribe aprobar '+state['plan_hash']+' para pasar a exec: '
        reader = session.input_reader or session._tui.prompt
        if reader(prompt).strip() != 'aprobar '+state['plan_hash']:
            render.write('Plan conservado; aprobación no otorgada.')
            return
        modes.approve(context,state['plan_hash'],Identity(session.operator_id,session.tenant_id,
                     kind='human',roles=('operator',)))
        state = modes.get(context)
    render.write('Modo: '+state['mode']+' · sesión '+modes.key(context))


def cmd_plan(session: "OmniSession", args: list[str]) -> None:
    """Muestra el plan por fases; /plan on|off abre el panel lateral (F2)."""
    if args and args[0] in {"on", "off"}:
        cmd_panel(session, args)
        return
    if session.engagement is None:
        render.render_error("no hay engagement activo (usa /scope)")
        return
    from nexus_core.agent.planner import attack_surface, plan_from_summary
    from nexus_core.agent.subagents import select_for_plan
    from nexus_core.kernel.blackboard import Blackboard

    engagement_id = session.engagement.engagement_id
    board = Blackboard(session.store)
    try:
        summary = board.summary(session.tenant_id, engagement_id)
        facts = board.list_facts(session.tenant_id, engagement_id)
    except Exception as exc:  # noqa: BLE001 - never break the REPL
        render.render_error(f"no se pudo calcular el plan: {type(exc).__name__}: {exc}")
        return
    plan = plan_from_summary(summary, engagement_id=engagement_id)
    session._tui.set_plan(plan.to_dict())
    render.write(plan.render())
    render.write(attack_surface(facts).render())
    try:
        profile = select_for_plan(plan, override=session.subagent_override)
    except ValueError:
        profile = None
    if profile is not None:
        render.write(
            render.paint(
                f"ESTRATEGIA OPERATIVA · perfil táctico: {profile.id} "
                f"({profile.label}) — {profile.focus}",
                render.BOLD,
            )
        )
    render.write("  (usa /plan on o F2 para el panel lateral en vivo)")


def cmd_interview(session: "OmniSession", args: list[str]) -> None:
    """Intake guiado: objetivo, targets, RoE y restricciones (persistido)."""
    from .interview import run_interview

    if session.engagement is None:
        render.render_error(
            "no hay engagement activo (usa /scope o /engage_create)"
        )
        return
    if args and args[0] not in {"show", "run"}:
        render.render_error("uso: /interview [show]")
        return
    if args and args[0] == "show":
        brief = session.engagement_brief
        if not brief:
            render.write("(sin brief registrado; usa /interview)")
            return
        for key in ("objectives", "client", "authorized_targets", "restrictions"):
            render.write(f"  {key}: {brief.get(key) or '(sin definir)'}")
        return
    result = run_interview(session)
    if result.cancelled:
        render.write("entrevista cancelada: no se registró nada")
        return
    render.write(
        render.paint(f"Engagement brief {session.engagement_id}", render.BOLD)
    )
    render.write(f"  objetivo: {result.objectives or '(sin definir)'}")
    render.write(f"  cliente: {result.client or '(sin definir)'}")
    render.write(
        f"  targets autorizados: {', '.join(result.authorized_targets) or '(ninguno)'}"
    )
    if result.rejected_targets:
        render.write(
            render.paint(
                "  ⚠ fuera de scope (no registrados): "
                + ", ".join(result.rejected_targets),
                render.RED,
            )
        )
    if result.restrictions:
        render.write(f"  restricciones: {result.restrictions}")
    render.write(
        "  RoE: "
        + (
            f"guardada en {result.roe_path}"
            if result.roe_saved
            else "sin límites adicionales"
        )
    )
    render.write(
        "  brief durable: "
        + ("registrado" if result.brief_recorded else "NO registrado (store no disponible)")
    )
    render.write("  (el brief se inyecta como hecho 'hint' en cada iteración)")


def cmd_review(session: "OmniSession", args: list[str]) -> None:
    """/review: valida evidencia, integridad y limpieza; entrega opcional."""
    from .review import render_review, run_review

    deliver = "--deliver" in args
    llm_cvss = "--llm-cvss" in args
    output_format = "both"
    if "--format" in args:
        index = args.index("--format")
        if index + 1 >= len(args) or args[index + 1].lower() not in REPORT_FORMATS:
            render.render_error(
                f"uso: /review [--deliver] [--llm-cvss] [--format {REPORT_FORMAT_USAGE}]"
            )
            return
        output_format = args[index + 1].lower()
    report = run_review(
        session, deliver=deliver, output_format=output_format, llm_cvss=llm_cvss
    )
    render_review(report)


def cmd_panel(session: "OmniSession", args: list[str]) -> None:
    """Muestra u oculta el panel lateral del plan: /panel [on|off]."""
    if len(args) > 1 or (args and args[0] not in {"on", "off"}):
        render.render_error("uso: /panel [on|off]")
        return
    if args:
        enabled = session._tui.set_panel(args[0] == "on")
    elif not session._tui.use_tui:
        enabled = session._tui.set_panel(True)
    else:
        enabled = session._tui.set_panel(not session._tui.panel_enabled)
    render.write(
        f"panel de plan: {'ON' if enabled else 'OFF'}"
        + (" · F2 lo alterna" if session._tui.use_tui else " (solo TUI)")
    )


def cmd_playbook(session: "OmniSession", args: list[str]) -> None:
    """Muestra los playbooks aplicables y su siguiente paso: /playbook [show <id>]."""
    if session.engagement is None:
        render.render_error("no hay engagement activo (usa /scope)")
        return
    from nexus_core.agent.playbooks import (
        is_applicable,
        playbook_by_id,
        registered_playbooks,
        select_playbooks,
    )
    from nexus_core.kernel.blackboard import Blackboard

    engagement_id = session.engagement.engagement_id
    try:
        facts = Blackboard(session.store).list_facts(
            session.tenant_id, engagement_id
        )
    except Exception as exc:  # noqa: BLE001 - never break the REPL
        render.render_error(f"no se pudieron leer los hechos: {type(exc).__name__}: {exc}")
        return
    if args and args[0] == "show":
        if len(args) < 2:
            render.render_error("uso: /playbook show <playbook_id>")
            return
        playbook = playbook_by_id(args[1])
        if playbook is None:
            known = ", ".join(sorted(item.playbook_id for item in registered_playbooks()))
            render.render_error(f"playbook desconocido: {args[1]!r} (disponibles: {known})")
            return
        render.write(f"PLAYBOOK {playbook.playbook_id} — {playbook.title} [{playbook.phase}]")
        render.write(f"  requiere: {playbook.requires}")
        for step in playbook.steps:
            render.write(f"   → {step.step_id}: {step.title} ({step.tool_id})")
        return
    matches = select_playbooks(facts, only_ready=False)
    if not matches:
        render.write("(sin playbooks definidos)")
        return
    for match in matches:
        ready = is_applicable(match.playbook.playbook_id, facts)
        state = "listo" if ready else "no aplica (faltan hechos)"
        render.write(f"  [{match.playbook.phase}] {match.playbook.playbook_id} — {state}")
        if match.next_step is not None:
            render.write(
                f"      siguiente: {match.next_step.tool_id} — {match.next_step.title}"
            )


def cmd_loot(session: "OmniSession", args: list[str]) -> None:
    """Lista el loot del team server con su SHA256 (cadena de custodia): /loot."""
    result = session.invoke_tool("nexus.c2.sliver_loot", {"action": "list"})
    if result is None:
        return
    if not tool_success(result):
        render.render_error(
            f"no se pudo listar el loot ({tool_method(result) or 'error'})"
        )
        return
    payload = tool_payload(result)
    entries = payload.get("loot") or []
    if not entries:
        render.write("(sin loot registrado en el team server)")
        return
    render.write(f"Loot ({len(entries)}):")
    for entry in entries:
        digest = str(entry.get("sha256") or "")[:16]
        render.write(
            f"  [{entry.get('kind')}] {entry.get('name')} "
            f"sha256={digest} size={entry.get('size')}"
        )


def cmd_expand(session: "OmniSession", args: list[str]) -> None:
    """Expande/pliega todas las tarjetas: /expand [on|off] (clic = una tarjeta)."""
    if len(args) > 1 or (args and args[0] not in {"on", "off"}):
        render.render_error("uso: /expand [on|off]")
        return
    if args:
        enabled = session._tui.set_expand(args[0] == "on")
    elif not session._tui.use_tui:
        enabled = session._tui.set_expand(True)
    else:
        enabled = session._tui.set_expand(not session._tui.expand_cards)
    from nexus_core.cli.tui.strings import EXPAND_HINT

    render.write(
        f"tarjetas de tool: {'expandidas' if enabled else 'plegadas'}"
        + (f" · {EXPAND_HINT}" if session._tui.use_tui else " (solo TUI)")
    )


#: Formats ``nexus.report.generate`` accepts (kept in sync with the handler).
REPORT_FORMATS = ("markdown", "html", "both", "sarif")
REPORT_FORMAT_USAGE = "|".join(REPORT_FORMATS)


def cmd_report(session: "OmniSession", args: list[str]) -> None:
    """Genera el reporte: /report [export <dir>] [--llm-cvss] [--format F].

    ``--format sarif`` emite SARIF 2.1.0 (GitHub Advanced Security, SonarQube,
    VS Code SARIF Viewer); ``--format`` también aplica a ``export``.
    """
    args = list(args)
    output_format = "both"
    if "--format" in args:
        index = args.index("--format")
        if index + 1 >= len(args) or args[index + 1].lower() not in REPORT_FORMATS:
            render.render_error(
                f"uso: /report [export <dir>] [--llm-cvss] [--format {REPORT_FORMAT_USAGE}]"
            )
            return
        output_format = args[index + 1].lower()
        del args[index:index + 2]
    llm_cvss = "--llm-cvss" in args
    args = [item for item in args if item != "--llm-cvss"]
    if not args:
        _report_generate(session, llm_cvss=llm_cvss, output_format=output_format)
        return
    verb = str(args[0]).lower()
    if verb == "export":
        if len(args) < 2:
            render.render_error(
                f"uso: /report export <directorio> [--llm-cvss] [--format {REPORT_FORMAT_USAGE}]"
            )
            return
        _report_export(
            session, args[1], llm_cvss=llm_cvss, output_format=output_format
        )
        return
    render.render_error(
        f"subcomando desconocido: {args[0]!r} "
        "(usa /report, /report export <dir>, /report --format sarif)"
    )


def _report_arguments(
    session: "OmniSession",
    output_dir: str | None,
    llm_cvss: bool,
    output_format: str = "both",
) -> dict[str, Any]:
    arguments: dict[str, Any] = {"engagement_id": session.engagement_id, "format": output_format}
    if output_dir:
        arguments["output_dir"] = output_dir
    if llm_cvss:
        arguments["llm_cvss"] = True
    return arguments


def _run_report_tool(session: "OmniSession", arguments: dict[str, Any]) -> dict[str, Any] | None:
    """Run ``nexus.report.generate`` through the gateway and report failures.

    ``invoke_tool`` returns ``{"tool_id": ..., "output": <ToolResult>}`` (the
    same shape ``_kill_one`` reads), so this unwraps the ToolResult and returns
    it directly: ``output`` + ``evidence`` live inside it.
    """
    result = session.invoke_tool("nexus.report.generate", arguments)
    if result is None:
        return None
    tool_result = result.get("output") if isinstance(result, dict) else None
    if not isinstance(tool_result, dict) or not tool_result.get("success"):
        render.render_error(
            "el reporte no se pudo verificar: "
            f"{(tool_result or {}).get('verification_method') or 'error'}"
        )
        return None
    return tool_result


def _report_generate(
    session: "OmniSession", *, llm_cvss: bool, output_format: str = "both"
) -> None:
    """Generate the report for the active engagement and print the summary."""
    if session.engagement is None:
        render.render_error("no hay engagement activo (usa /scope)")
        return
    render.write(f"Generating report for engagement {session.engagement.name}...")
    result = _run_report_tool(
        session, _report_arguments(session, None, llm_cvss, output_format)
    )
    if result is None:
        return
    output = result.get("output") or {}
    evidence = result.get("evidence") or {}
    session.last_report_directory = str(output.get("directory") or "")
    session.last_report_sha256 = str(output.get("report_sha256") or "")
    breakdown = output.get("severity_breakdown") or {}
    render.write(
        f"  ✓ {output.get('findings_count', 0)} findings de "
        f"{evidence.get('audit_events_used', 0)} eventos de auditoría"
    )
    render.write(
        "  ✓ severidad: "
        + ", ".join(
            f"{breakdown.get(level, 0)} {level}"
            for level in ("critical", "high", "medium", "low", "info")
        )
    )
    # ``--llm-cvss`` asks for LLM scoring, but the handler falls back to the
    # deterministic heuristic when no provider is reachable. The label reports
    # the request without claiming the LLM was actually used.
    render.write(
        "  ✓ CVSS: "
        + (
            "LLM solicitado (vector validado localmente; heurística si no hay proveedor)"
            if llm_cvss
            else "heurística determinista (/report --llm-cvss)"
        )
    )
    render.write(
        "  ✓ cadena de auditoría: "
        + ("válida" if evidence.get("audit_chain_valid") else "NO VERIFICADA")
    )
    render.write(
        f"  ✓ Markdown ({_kb(output.get('markdown_size_bytes'))}) "
        f"+ HTML ({_kb(output.get('html_size_bytes'))})"
    )
    for name, digest in (evidence.get("artifact_sha256") or {}).items():
        render.write(f"  ✓ artifact {name}: {str(digest)[:16]}…")
    render.write()
    render.write(f"Report: {output.get('directory')}")
    for key, name in (
        ("report_path_md", "report.md"),
        ("report_path_html", "report.html"),
        ("report_path_json", "report.json"),
        ("report_path_sarif", "report.sarif"),
    ):
        if output.get(key):
            render.write(f"  - {name}")
    render.write()
    render.write(f"Report SHA256: {output.get('report_sha256')}")
    if output.get("failed_attempts"):
        render.write(f"Intentos fallidos documentados: {output['failed_attempts']}")
    if session._tui.use_tui and output.get("report_path_md"):
        try:
            with Path(output["report_path_md"]).open(encoding="utf-8") as report:
                text = report.read(65537)
            if len(text) > 65536:
                text = text[:65536] + "\n\n(Vista truncada; consulta el archivo completo.)"
            from .tui.markdown import render_markdown

            session._output.write(render_markdown(
                text, no_color=session._tui.no_color,
                max_width=session._tui._session.output.get_size().columns,
            ))
        except (OSError, UnicodeError):
            render.render_status("No se pudo abrir la vista Markdown; consulta el artefacto generado.")


def _report_export(
    session: "OmniSession",
    directory: str,
    *,
    llm_cvss: bool,
    output_format: str = "both",
) -> None:
    """Write the report plus a verifiable manifest to a deliverable directory."""
    if session.engagement is None:
        render.render_error("no hay engagement activo (usa /scope)")
        return
    target = Path(directory).expanduser()
    render.write(f"Exporting {session.engagement.name} report to {target}...")
    result = _run_report_tool(
        session, _report_arguments(session, str(target), llm_cvss, output_format)
    )
    if result is None:
        return
    output = result.get("output") or {}
    evidence = result.get("evidence") or {}
    for key, name in (
        ("report_path_md", "report.md"),
        ("report_path_html", "report.html"),
        ("report_path_json", "report.json"),
        ("report_path_sarif", "report.sarif"),
    ):
        if output.get(key):
            render.write(f"  ✓ {name}")
    manifest: dict[str, Any] = {
        "engagement_id": output.get("engagement_id"),
        "report_sha256": output.get("report_sha256"),
        "findings": output.get("findings_count"),
        "severity_breakdown": output.get("severity_breakdown"),
        "artifacts": evidence.get("artifact_sha256") or {},
        "artifact_ids": evidence.get("artifacts") or [],
    }
    try:
        target.mkdir(parents=True, exist_ok=True)
        from nexus_core.report.checksums import write_checksums

        write_checksums(target, manifest["artifacts"])
        (target / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        render.render_error(f"no se pudo escribir el manifiesto: {exc}")
        return
    session.last_report_directory = str(target)
    session.last_report_sha256 = str(output.get("report_sha256") or "")
    render.write(f"  ✓ report.sha256 + manifest.json ({len(manifest['artifacts'])} artifacts)")
    render.write(f"Done. {target}")


def _kb(value: Any) -> str:
    try:
        return f"{int(value) / 1024:.1f} KB"
    except (TypeError, ValueError):
        return "? KB"


def cmd_timeline(session: "OmniSession", args: list[str]) -> None:
    """Muestra la cronología de acciones del engagement (desde el audit trail)."""
    if session.engagement is None:
        render.render_error("no hay engagement activo (usa /scope)")
        return
    try:
        extractor_module, _ = _report_tools(session)
        run_ids = [args[0]] if args else None
        entries = extractor_module.timeline_for(
            session.store, session.tenant_id, session.engagement_id, run_ids
        )
    except KeyError:
        render.render_error(f"engagement desconocido: {session.engagement_id}")
        return
    except Exception as exc:  # noqa: BLE001
        render.render_error(f"no se pudo leer la cronología: {type(exc).__name__}: {exc}")
        return
    if not entries:
        render.write("(sin eventos de auditoría para este engagement)")
        return
    for entry in entries:
        detail = f"  ({entry.detail})" if entry.detail else ""
        tool_id = entry.tool_id.replace("nexus.", "") if entry.tool_id else "-"
        render.write(
            f"{entry.occurred_at[:19].replace('T', ' ')}  {tool_id:<20} "
            f"{entry.target[:30]:<30} {entry.decision or '-'}{detail}"
        )
    render.write(f"\n{len(entries)} evento(s).")


#: Observation kinds that carry no useful conversational context for ``/ask``.
_ASK_SKIP_KINDS = frozenset(
    {"react.action", "react.observation", "react.correction", "react.history_summary"}
)
#: Kinds that do carry context: completion summaries and clarifications.
_ASK_CONTEXT_KINDS = frozenset({"", "ask", "react.final", "react.clarification"})


def _ask_context_messages(session: "OmniSession", limit: int) -> list[Any]:
    """Recent user/assistant turns of the shared work session."""
    from nexus_core.llm.abstraction import LLMMessage

    conversation_id = None
    if hasattr(session, "_ensure_work_session"):
        try:
            conversation_id = session._ensure_work_session()
        except Exception:  # noqa: BLE001 - /ask must survive a store failure
            conversation_id = None
    if not conversation_id:
        return []
    try:
        stored = session.store.list_messages(
            session.tenant_id, conversation_id, limit=500
        )
    except Exception:  # noqa: BLE001
        return []
    context: list[Any] = []
    for message in stored:
        role = str(message.get("role") or "")
        if role not in {"user", "assistant"}:
            continue
        metadata = message.get("metadata") or {}
        kind = str(metadata.get("kind") or "")
        if kind in _ASK_SKIP_KINDS or kind not in _ASK_CONTEXT_KINDS:
            continue
        content = str(message.get("content") or "")
        if content:
            context.append(LLMMessage(role=role, content=content))
    return context[-limit:]


def _persist_ask(session: "OmniSession", question: str, answer: str) -> None:
    """Append the /ask exchange to the engagement's durable work session."""
    from nexus_core.agent import memory

    conversation_id = None
    if hasattr(session, "_ensure_work_session"):
        try:
            conversation_id = session._ensure_work_session()
        except Exception:  # noqa: BLE001
            conversation_id = None
    if not conversation_id:
        return
    for role, content in (("user", question), ("assistant", answer)):
        try:
            memory.append_step(
                session.store,
                session.tenant_id,
                conversation_id,
                role,
                content,
                {"source": memory.ASK_SOURCE, "kind": "ask"},
            )
        except Exception:  # noqa: BLE001 - persistence must not break /ask
            return


def _ask_messages(session: "OmniSession", question: str) -> list[Any]:
    """System prompt + shared work-session context + the new question.

    ``/ask`` shares the engagement's durable work session with the objectives,
    so the model sees the previous directives, summaries and questions. The
    system prompt is rebuilt locally and nothing is executed.
    """
    from nexus_core.llm.abstraction import LLMMessage

    messages: list[Any] = [LLMMessage(role="system", content=_build_ask_system_prompt(session))]
    messages.extend(_ask_context_messages(session, ASK_HISTORY_LIMIT))
    messages.append(LLMMessage(role="user", content=question))
    return messages


def _supports_streaming(client: Any) -> bool:
    """True when the client can emit real token deltas (not a single dump)."""
    return bool(getattr(client, "supports_streaming", False)) and hasattr(client, "stream")


def cmd_ask(session: "OmniSession", args: list[str]) -> None:
    """Pregunta al LLM sin ejecutar tools: /ask <pregunta en lenguaje natural>."""
    question = " ".join(str(part) for part in args).strip()
    if not question:
        render.render_error("uso: /ask <pregunta>")
        return
    try:
        llm = session._llm
    except Exception as exc:  # noqa: BLE001 - a missing provider must not kill the REPL
        render.render_error(f"no se pudo construir el cliente LLM: {type(exc).__name__}: {exc}")
        return
    if llm is None:
        render.render_error("LLM no configurado. Revisa tu .env.")
        return

    import asyncio

    from .spinner import Spinner, spinner_enabled

    messages = _ask_messages(session, question)
    metered = session._metered_client(llm, durable=False)
    # Stream token by token into the live overlay when the TUI is active and the
    # provider supports it; otherwise keep the single complete() call.
    streaming = session._tui.use_tui and _supports_streaming(metered)
    try:
        with session._busy("Consultando al modelo"), Spinner(
            "Consultando al modelo",
            enabled=not session._tui.use_tui and spinner_enabled(),
            use_ascii=not session._supports_unicode(),
        ):
            if streaming:
                tui = session._tui
                tui.begin_answer()
                collected: list[str] = []

                async def consume() -> None:
                    async for chunk in metered.stream(messages):
                        collected.append(chunk)
                        tui.append_answer(chunk)

                asyncio.run(session._with_cancel(consume(), None, cooperative=False))
                answer = "".join(collected)
            else:
                response = asyncio.run(session._with_cancel(
                    metered.complete(messages), None, cooperative=False,
                ))
                answer = str(getattr(response, "content", response) or "")
    except asyncio.CancelledError:
        session._tui.end_answer()
        render.render_status("consulta cancelada")
        return
    except Exception as exc:  # noqa: BLE001 - the REPL survives a failed call
        session._tui.end_answer()
        render.render_error(f"la consulta falló: {type(exc).__name__}: {exc}")
        return
    _persist_ask(session, question, answer)
    max_width = None
    if session._tui.use_tui:
        columns = session._tui._session.output.get_size().columns
        max_width = max(20, min(DEFAULT_READING_WIDTH, columns - 4))
    render.render_answer(
        answer, no_color=session.no_color, markdown=session._tui.use_tui,
        max_width=max_width,
    )
    # Commit is done: hide the live overlay so the transcript shows the answer.
    session._tui.end_answer()


def cmd_chat(session: "OmniSession", args: list[str]) -> None:
    """Alias conversacional de /ask (mismo comportamiento, sin tools)."""
    cmd_ask(session, args)


def cmd_trust(session: "OmniSession", args: list[str]) -> None:
    """Muestra o cambia trust mode (on/off) sin reiniciar el REPL."""
    if not args:
        render.write(f"trust mode: {'ON' if session.trust_mode else 'OFF'}")
        render.write("  (on: auto-aprueba tools de alto riesgo; nunca las destructivas)")
        return
    value = str(args[0]).strip().lower()
    if value in {"on", "1", "true", "yes", "si", "sí"}:
        session.trust_mode = True
    elif value in {"off", "0", "false", "no"}:
        session.trust_mode = False
    else:
        render.render_error(f"valor inválido para /trust: {args[0]!r} (usa on u off)")
        return
    render.write(
        f"trust mode: {'ON' if session.trust_mode else 'OFF'}"
        " (se aplica al siguiente objetivo)"
    )


def cmd_subagent(session: "OmniSession", args: list[str]) -> None:
    """/subagent [ID|auto]: fija o limpia el perfil de subagente del próximo run."""
    from nexus_core.agent import subagents

    value = str(args[0]).strip() if args else ""
    if not value:
        render.write(
            f"subagente: {session.subagent_override or '(automático)'} · "
            f"disponibles: {', '.join(subagents.SUBAGENT_IDS)}"
        )
        render.write(
            "  alias: "
            + ", ".join(
                f"{alias}→{target}"
                for alias, target in sorted(subagents.SUBAGENT_ALIASES.items())
            )
        )
        return
    if value.lower() in {"auto", "off", "none", "clear"}:
        session.subagent_override = None
        render.write("subagente: (automático, lo elige el planner)")
        return
    resolved = subagents.resolve_subagent_id(value)
    if resolved is None:
        render.render_error(
            f"perfil desconocido: {value} (usa /subagent sin argumentos)"
        )
        return
    session.subagent_override = resolved
    note = f" (alias de {value})" if resolved != value else ""
    render.write(f"subagente: {resolved}{note} (se aplica al siguiente objetivo)")


def cmd_status(session: "OmniSession", args: list[str]) -> None:
    """/status [on|off|show]: muestra u oculta la barra (preferencia persistente)."""
    from .tui.status import render_status_plain, save_status_fields, save_status_preference

    if len(args) == 2 and args[0] == 'fields':
        fields = args[1].split(',')
        try:
            save_status_fields(fields)
        except ValueError as exc:
            render.render_error(str(exc))
            return
        session._tui.set_status(fields=tuple(fields))
        session._output.write('HUD: '+', '.join(fields)+' (alert/phase protegidos)')
        return
    if len(args) > 1 or (args and args[0] not in {"on", "off", "show"}):
        render.render_error("uso: /status [on|off|show]")
        return
    if args and args[0] in {"on", "off"}:
        enabled = args[0] == "on"
        save_status_preference(enabled)
        session._tui.set_status_bar_enabled(enabled)
    if args == ["show"]:
        session._update_status_bar(force=True)
        session._output.write(render_status_plain(session._tui._status))
    else:
        session._output.write(
            f"status bar: {'ON' if session._tui.status_bar_enabled else 'OFF'}"
            + ("" if session._tui.use_tui else " (fallback readline)")
        )
    # Engine bookkeeping lives here, not in the transcript: the run id, the
    # active engagement and the iteration ceiling are only needed on demand.
    session._output.write(
        f"run: {session.run_id or '(ninguno)'} · "
        f"engagement: {session.engagement_id or '(ninguno)'} · "
        f"max_iterations: {session.max_iterations}"
    )


def cmd_razonamiento(session: "OmniSession", args: list[str]) -> None:
    """/razonamiento: exporta los `thought` del run actual a reports/<run>/reasoning.md.

    The reasoning is already durable in every ``react.action``; this only
    collects it in order so an operator (or a reviewer) can read how the run
    decided, next to the reports of the same engagement.
    """
    run_id = str(session.run_id or "")
    conversation = str(session.conversation_id or "")
    if not run_id or not conversation:
        render.render_error("no hay un run del que exportar razonamiento")
        return
    try:
        messages = session.store.list_messages(
            session.tenant_id, conversation, limit=500
        )
    except Exception as exc:  # noqa: BLE001 - a broken store must not kill the REPL
        render.render_error(f"no se pudo leer la conversación: {type(exc).__name__}")
        return
    entries: list[tuple[str, str]] = []
    for message in messages:
        metadata = message.get("metadata") or {}
        if metadata.get("kind") != "react.action":
            continue
        if str(message.get("run_id") or run_id) != run_id:
            continue
        thought = str(metadata.get("thought") or "").strip()
        if thought:
            entries.append((str(message.get("created_at") or ""), thought))
    if not entries:
        render.render_error("el run actual no tiene razonamiento registrado")
        return
    path = Path.cwd() / "reports" / run_id / "reasoning.md"
    body = [f"# Razonamiento · {run_id}", ""]
    for stamp, thought in entries:
        body.extend([f"## {stamp}" if stamp else "## turno", "", thought, ""])
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(body), encoding="utf-8")
    except OSError as exc:
        render.render_error(f"no se pudo escribir el razonamiento: {exc}")
        return
    render.write(f"razonamiento exportado: {path} ({len(entries)} turnos)")


def cmd_exploit(session: "OmniSession", args: list[str]) -> None:
    """/exploit view-live <job_uuid>: vista de estado MSF en otra terminal (solo lectura)."""
    from .live_jobs import show_job

    show_job(session, args)


def cmd_sliver(session: "OmniSession", args: list[str]) -> None:
    """Estado del team server de Sliver (versión, operadores, jobs)."""
    result = session.invoke_tool("nexus.c2.sliver_server", {})
    if result is None:
        render.render_error("no se pudo consultar el team server de Sliver")
        return
    if not tool_success(result):
        render.render_error(
            f"Sliver no está disponible: {tool_method(result) or 'error'}"
        )
        return
    output = tool_payload(result)
    render.write(render.paint(f"Sliver {output.get('version') or '?'}", render.BOLD))
    render.write(
        f"  operadores: {output.get('operators_count', 0)}  "
        f"jobs: {output.get('jobs_count', 0)}"
    )
    for operator in output.get("operators") or []:
        if not isinstance(operator, dict):
            continue
        status = "online" if operator.get("online") else "offline"
        render.write(f"  - {operator.get('name') or '?'} ({status})")


def cmd_implants(session: "OmniSession", args: list[str]) -> None:
    """Lista builds y profiles de implants de Sliver (solo lectura)."""
    result = session.invoke_tool("nexus.c2.sliver_implants", {"kind": "both"})
    if result is None:
        render.render_error("no se pudo consultar el team server de Sliver")
        return
    if not tool_success(result):
        render.render_error(
            f"Sliver no está disponible: {tool_method(result) or 'error'}"
        )
        return
    output = tool_payload(result)
    builds = output.get("builds") or {}
    profiles = output.get("profiles") or []
    render.write(
        render.paint(
            f"Builds: {output.get('builds_count', 0)}  Profiles: {output.get('profiles_count', 0)}",
            render.BOLD,
        )
    )
    for name in sorted(builds):
        render.write(f"  build   {name}")
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        render.write(f"  profile {profile.get('Name') or profile.get('name') or '?'}")


def _read_secret(session: "OmniSession" | None, prompt: str) -> str:
    """Read a secret without echoing it or leaking it into shell history.

    Prefers the session's own secure input (TUI-aware, so it cannot deadlock
    against the running interface); falls back to ``getpass`` when there is no
    session, e.g. a headless or test call.
    """
    reader = getattr(session, "secure_input", None)
    if callable(reader):
        return str(reader(prompt))
    return getpass.getpass(prompt)


def cmd_secrets(session: "OmniSession", args: list[str]) -> None:
    """Gestiona secretos (API keys) fuera del .env: list|set|rotate|delete|import-env."""
    from nexus_core.config.secrets import SecretStore, import_from_env

    store = SecretStore()
    action = (args[0].lower() if args else "list")
    if action in {"list", "ls"}:
        render.write(render.paint(f"backend de secretos: {store.backend_name}", render.BOLD))
        names = store.names()
        if not names:
            render.write("  (sin secretos guardados)")
        for name in names:
            render.write(f"  {name}")
        render.write("  usa /secrets set NOMBRE (el valor se pide oculto, nunca se imprime)")
        return
    if action in {"set", "rotate"}:
        if len(args) < 2:
            render.render_error("uso: /secrets set NOMBRE")
            return
        name = args[1]
        existing = name in store.names()
        # The value is read through the session's secure input: masked in the
        # TUI, never printed, never in readline/prompt_toolkit history.
        value = _read_secret(session, f"valor para {name}: ")
        if not value:
            render.render_error(f"valor vacío; {name} no se modificó")
            return
        try:
            store.set(name, value)
        except Exception as exc:  # noqa: BLE001 - report, never crash the REPL
            render.render_error(
                f"✗ no se pudo guardar {name}: {type(exc).__name__}: {exc}"
            )
            return
        verb = "rotado" if action == "rotate" else "guardado"
        render.write(
            render.paint(
                f"✓ Secreto {name} {verb} correctamente ({store.backend_name})",
                render.GREEN,
            )
        )
        if action == "rotate" and not existing:
            render.write(f"  nota: {name} no existía antes; se ha creado.")
        render.write(
            "  si la clave estuvo expuesta, considérala comprometida: rota el valor "
            "en el proveedor y reinicia los procesos que la leyeron."
        )
        return
    if action in {"delete", "rm"}:
        if len(args) < 2:
            render.render_error("uso: /secrets delete NOMBRE")
            return
        if store.delete(args[1]):
            render.write(f"✓ {args[1]} eliminado del store")
        else:
            render.write(f"  {args[1]} no estaba guardado")
        return
    if action == "import-env":
        imported = import_from_env()
        if not imported:
            render.write("  no había claves conocidas en el entorno para importar")
            return
        render.write(
            render.paint(
                f"✓ importadas {len(imported)} claves al store ({store.backend_name}):",
                render.GREEN,
            )
        )
        for name in imported:
            render.write(f"  {name}")
        render.write("  ahora puedes borrarlas del .env; el store tiene prioridad sobre él.")
        return
    render.render_error(f"acción desconocida: {action} (usa list|set|rotate|delete|import-env)")


def cmd_auth(session: "OmniSession", args: list[str]) -> None:
    """Configura la API key de un proveedor sin escribirla en el `.env` (/auth).

    Es el mismo flujo que ``omni auth login``: menú de proveedor, valor pedido
    de forma oculta y guardado en el store. La selección del proveedor usa
    ``visible_input`` (no ``input()``) para no bloquearse contra la TUI, y el
    valor usa ``secure_input``.
    """
    from .auth_cli import run_auth_command

    text_reader = getattr(session, "visible_input", None)
    code = run_auth_command(
        ["login", *[str(item) for item in args]],
        text_reader=text_reader if callable(text_reader) else None,
        secret_reader=lambda prompt: _read_secret(session, prompt),
        out=render.write,
    )
    if code:
        render.render_error("no se guardó ninguna clave")


def cmd_roe(session: "OmniSession", args: list[str]) -> None:
    """Muestra las Reglas de Encuentro (RoE) y controla su kill switch."""
    from .roe_cli import run_roe_action

    action = args[0].lower() if args else "show"
    code, lines = run_roe_action(action, getattr(session, "engagement_id", None))
    for line in lines:
        render.write(line)
    if code:
        render.render_error("uso: /roe [show|kill|arm|path]")


def cmd_skills(session: "OmniSession", args: list[str]) -> None:
    """Lista, previsualiza y activa skills (`.agents/skills/<nombre>/SKILL.md`)."""
    from nexus_core.agent.skills import (
        TRUST_SIGNED,
        default_skills_root,
        discover_skills,
        load_skill,
    )
    from nexus_core.kernel.scope_loader import scope_signing_secret

    secret = scope_signing_secret()
    action = args[0].lower() if args else "list"
    if action in {"list", "ls"}:
        found = discover_skills(secret=secret)
        if not found:
            # Name the directory: run from an engagement workspace, the old
            # message made an empty catalogue indistinguishable from a wrong
            # root (measured in the Bounty Hacker run).
            render.write(f"  (sin skills en {default_skills_root()})")
            return
        active_names = set(getattr(session, "active_skills", None) or [])
        for name, skill in sorted(found.items()):
            marker = "*" if name in active_names else " "
            label = "firmada" if skill.trust == TRUST_SIGNED else skill.trust
            render.write(f" {marker} {name:<18} {label:<9} {skill.sha256[:12]}…")
        render.write("  /skills show NOMBRE para previsualizar · /skills use NOMBRE para activar")
        return
    if action in {"show", "preview"}:
        if len(args) < 2:
            render.render_error("uso: /skills show NOMBRE")
            return
        skill = load_skill(args[1], secret=secret)
        if skill is None:
            render.render_error(f"skill no encontrada: {args[1]}")
            return
        if not skill.usable:
            render.render_error(
                f"skill '{skill.name}': firma HMAC inválida; se rechaza y no se carga"
            )
            return
        render.write(
            render.paint(
                f"skill {skill.name} · {skill.trust} · sha256={skill.sha256} · {skill.path}",
                render.BOLD,
            )
        )
        if skill.signals:
            render.write(f"  ⚠ señales de inyección: {', '.join(skill.signals)}")
        for line in skill.content.splitlines():
            render.write(f"  {line}")
        render.write(
            "  se enviará al modelo delimitado como datos no confiables; "
            "actívala con /skills use NOMBRE"
        )
        return
    if action in {"use", "on"}:
        if len(args) < 2:
            render.render_error("uso: /skills use NOMBRE")
            return
        skill = load_skill(args[1], secret=secret)
        if skill is None:
            render.render_error(f"skill no encontrada: {args[1]}")
            return
        if not skill.usable:
            render.render_error(f"skill '{skill.name}': firma inválida; no se activa")
            return
        active = list(getattr(session, "active_skills", None) or [])
        if skill.name not in active:
            active.append(skill.name)
        session.active_skills = active
        render.write(render.paint(f"✓ skill '{skill.name}' activada", render.GREEN))
        return
    if action in {"off", "clear", "reset"}:
        session.active_skills = []
        render.write("skills desactivadas")
        return
    render.render_error(f"acción desconocida: {action} (usa list|show|use|off)")


def cmd_help(session: "OmniSession", args: list[str]) -> None:
    """Muestra esta ayuda."""
    render.write(render.paint("Comandos disponibles:", render.BOLD))
    for name in sorted(COMMANDS):
        doc = (COMMANDS[name].__doc__ or "").strip().splitlines()
        render.write(f"  {name:<16} {doc[0] if doc else ''}")
    render.write("  (cualquier otra línea se envía como objetivo al agente)")


def cmd_exit(session: "OmniSession", args: list[str]) -> None:
    """Sale del REPL."""
    session.should_exit = True
    render.write("Cerrando sesión omni. La auditoría durable permanece.")


COMMANDS: dict[str, Callable[["OmniSession", list[str]], None]] = {
    "/scope": cmd_scope,
    "/engage": cmd_engage,
    "/engage_list": cmd_engage_list,
    "/engage_create": cmd_engage_create,
    "/engage_use": cmd_engage_use,
    "/engage_current": cmd_engage_current,
    "/tools": cmd_tools,
    "/history": cmd_history,
    "/clear": cmd_clear,
    "/export": cmd_export,
    "/approvals": cmd_approvals,
    "/sessions": cmd_sessions,
    "/session": cmd_session,
    "/detach": cmd_detach,
    "/kill-session": cmd_kill_session,
    "/findings": cmd_findings,
    "/facts": cmd_facts,
    "/plan": cmd_plan,
    "/interview": cmd_interview,
    "/review": cmd_review,
    "/mode": cmd_mode,
    "/panel": cmd_panel,
    "/expand": cmd_expand,
    "/playbook": cmd_playbook,
    "/loot": cmd_loot,
    "/report": cmd_report,
    "/timeline": cmd_timeline,
    "/ask": cmd_ask,
    "/chat": cmd_chat,
    "/trust": cmd_trust,
    "/subagent": cmd_subagent,
    "/status": cmd_status,
    "/razonamiento": cmd_razonamiento,
    "/secrets": cmd_secrets,
    "/auth": cmd_auth,
    "/roe": cmd_roe,
    "/skills": cmd_skills,
    "/exploit": cmd_exploit,
    "/sliver": cmd_sliver,
    "/implants": cmd_implants,
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


#: State changes that print nothing on success. The operator's turn is not
#: echoed for these: the badge/status bar already show the new state, and the
#: echoed command used to stay in the transcript while the response did not.
SILENT_COMMANDS = frozenset({"/engage_use", "/engage_create"})


def is_silent_command(line: str) -> bool:
    """True when ``line`` is a slash-command that must not be echoed."""
    name, _ = parse_command(line)
    return name in SILENT_COMMANDS


@routed
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
    "cmd_ask",
    "cmd_auth",
    "cmd_chat",
    "cmd_facts",
    "cmd_clear",
    "cmd_engage",
    "cmd_engage_create",
    "cmd_engage_current",
    "cmd_engage_list",
    "cmd_engage_use",
    "cmd_exit",
    "cmd_export",
    "cmd_findings",
    "cmd_help",
    "cmd_history",
    "cmd_expand",
    "cmd_implants",
    "cmd_interview",
    "cmd_loot",
    "cmd_panel",
    "cmd_plan",
    "cmd_razonamiento",
    "cmd_review",
    "cmd_playbook",
    "cmd_report",
    "cmd_sliver",
    "cmd_scope",
    "cmd_timeline",
    "cmd_tools",
    "cmd_trust",
    "command_names",
    "parse_command",
    "run_command",
    "SILENT_COMMANDS",
    "is_silent_command",
]
