"""Meta commands of the ``omni`` REPL.

Every command takes ``(session, args)`` and returns ``None``: it prints, it
never raises on bad arguments and it never breaks the session. The durable
audit and the persisted conversation are never modified by a meta command.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from nexus_core.kernel.approvals import ApprovalService

from . import render
from .tui.markdown import DEFAULT_READING_WIDTH
from .tui.output import routed

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .session import OmniSession

DEFAULT_HISTORY_LIMIT = 20

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
        return durable_tool_definitions(session.tenant_id)
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
    for tool_id, entry in sorted(tools.items())[:24]:
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
        for line in session.history[-limit:]:
            render.write(line)
        return
    render.render_messages(messages)


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


def _report_tools(session: "OmniSession"):
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
    counts = {}
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


def cmd_report(session: "OmniSession", args: list[str]) -> None:
    """Genera el reporte del engagement: /report [export <dir>] [--llm-cvss]."""
    if not args:
        _report_generate(session, [], llm_cvss=False)
        return
    verb = str(args[0]).lower()
    if verb == "export":
        if len(args) < 2:
            render.render_error("uso: /report export <directorio>")
            return
        _report_export(session, args[1], llm_cvss="--llm-cvss" in args)
        return
    if verb == "--llm-cvss":
        _report_generate(session, [], llm_cvss=True)
        return
    render.render_error(f"subcomando desconocido: {args[0]!r} (usa /report, /report export <dir>)")


def _report_arguments(session: "OmniSession", output_dir: str | None, llm_cvss: bool) -> dict:
    arguments: dict = {"engagement_id": session.engagement_id, "format": "both"}
    if output_dir:
        arguments["output_dir"] = output_dir
    if llm_cvss:
        arguments["llm_cvss"] = True
    return arguments


def _run_report_tool(session: "OmniSession", arguments: dict) -> dict | None:
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


def _report_generate(session: "OmniSession", extra: list[str], *, llm_cvss: bool) -> None:
    """Generate the report for the active engagement and print the summary."""
    if session.engagement is None:
        render.render_error("no hay engagement activo (usa /scope)")
        return
    render.write(f"Generating report for engagement {session.engagement.name}...")
    result = _run_report_tool(session, _report_arguments(session, None, llm_cvss))
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


def _report_export(session: "OmniSession", directory: str, *, llm_cvss: bool) -> None:
    """Write the report plus a verifiable manifest to a deliverable directory."""
    if session.engagement is None:
        render.render_error("no hay engagement activo (usa /scope)")
        return
    target = Path(directory).expanduser()
    render.write(f"Exporting {session.engagement.name} report to {target}...")
    result = _run_report_tool(session, _report_arguments(session, str(target), llm_cvss))
    if result is None:
        return
    output = result.get("output") or {}
    evidence = result.get("evidence") or {}
    for key, name in (
        ("report_path_md", "report.md"),
        ("report_path_html", "report.html"),
        ("report_path_json", "report.json"),
    ):
        if output.get(key):
            render.write(f"  ✓ {name}")
    manifest = {
        "engagement_id": output.get("engagement_id"),
        "report_sha256": output.get("report_sha256"),
        "findings": output.get("findings_count"),
        "severity_breakdown": output.get("severity_breakdown"),
        "artifacts": evidence.get("artifact_sha256") or {},
        "artifact_ids": evidence.get("artifacts") or [],
    }
    try:
        target.mkdir(parents=True, exist_ok=True)
        (target / "report.sha256").write_text(
            f"{output.get('report_sha256')}  report.json\n", encoding="utf-8"
        )
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
    try:
        with session._busy("Consultando al modelo"), Spinner(
            "Consultando al modelo",
            enabled=not session._tui.use_tui and spinner_enabled(),
            use_ascii=not session._supports_unicode(),
        ):
            response = asyncio.run(session._with_cancel(
                session._metered_client(llm, durable=False).complete(messages),
                None, cooperative=False,
            ))
    except asyncio.CancelledError:
        render.render_status("consulta cancelada")
        return
    except Exception as exc:  # noqa: BLE001 - the REPL survives a failed call
        render.render_error(f"la consulta falló: {type(exc).__name__}: {exc}")
        return
    answer = str(getattr(response, "content", response) or "")
    _persist_ask(session, question, answer)
    max_width = None
    if session._tui.use_tui:
        columns = session._tui._session.output.get_size().columns
        max_width = max(20, min(DEFAULT_READING_WIDTH, columns - 4))
    render.render_answer(
        answer, no_color=session.no_color, markdown=session._tui.use_tui,
        max_width=max_width,
    )


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


def cmd_status(session: "OmniSession", args: list[str]) -> None:
    """/status [on|off|show]: muestra u oculta la barra (preferencia persistente)."""
    from .tui.status import render_status_plain, save_status_preference

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
    output = result.get("output") or {}
    if not result.get("success"):
        render.render_error(
            f"Sliver no está disponible: {result.get('verification_method') or 'error'}"
        )
        return
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
    output = result.get("output") or {}
    if not result.get("success"):
        render.render_error(
            f"Sliver no está disponible: {result.get('verification_method') or 'error'}"
        )
        return
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


def cmd_help(session: "OmniSession", args: list[str]) -> None:
    """Muestra esta ayuda."""
    render.write(render.paint("Comandos disponibles:", render.BOLD))
    for name in sorted(COMMANDS):
        doc = (COMMANDS[name].__doc__ or "").strip().splitlines()
        render.write(f"  {name:<12} {doc[0] if doc else ''}")
    render.write("  (cualquier otra línea se envía como objetivo al agente)")


def cmd_exit(session: "OmniSession", args: list[str]) -> None:
    """Sale del REPL."""
    session.should_exit = True
    render.write("Cerrando sesión omni. La auditoría durable permanece.")


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
    "/findings": cmd_findings,
    "/report": cmd_report,
    "/timeline": cmd_timeline,
    "/ask": cmd_ask,
    "/chat": cmd_chat,
    "/trust": cmd_trust,
    "/status": cmd_status,
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
    "cmd_chat",
    "cmd_clear",
    "cmd_exit",
    "cmd_export",
    "cmd_findings",
    "cmd_help",
    "cmd_history",
    "cmd_implants",
    "cmd_report",
    "cmd_sliver",
    "cmd_scope",
    "cmd_timeline",
    "cmd_tools",
    "cmd_trust",
    "command_names",
    "parse_command",
    "run_command",
]
