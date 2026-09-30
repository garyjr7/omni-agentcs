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
        print(f"(sin hallazgos verificados en {session.engagement_id})")
        return
    counts = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    print(f"Hallazgos del engagement {session.engagement_id}:")
    print(markdown_module.findings_table(findings))
    print()
    breakdown = ", ".join(
        f"{counts[level]} {level}" for level in ("critical", "high", "medium", "low", "info") if counts.get(level)
    ) or "0"
    print(f"Total: {len(findings)} findings ({breakdown})")
    if failed:
        print(f"Intentos sin hallazgo: {len(failed)} (ver /report)")


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
    print(f"Generating report for engagement {session.engagement.name}...")
    result = _run_report_tool(session, _report_arguments(session, None, llm_cvss))
    if result is None:
        return
    output = result.get("output") or {}
    evidence = result.get("evidence") or {}
    session.last_report_directory = str(output.get("directory") or "")
    session.last_report_sha256 = str(output.get("report_sha256") or "")
    breakdown = output.get("severity_breakdown") or {}
    print(
        f"  ✓ {output.get('findings_count', 0)} findings de "
        f"{evidence.get('audit_events_used', 0)} eventos de auditoría"
    )
    print(
        "  ✓ severidad: "
        + ", ".join(
            f"{breakdown.get(level, 0)} {level}"
            for level in ("critical", "high", "medium", "low", "info")
        )
    )
    print(
        "  ✓ CVSS: "
        + ("LLM (vector validado localmente)" if llm_cvss else "heurística determinista (/report --llm-cvss)")
    )
    print(
        "  ✓ cadena de auditoría: "
        + ("válida" if evidence.get("audit_chain_valid") else "NO VERIFICADA")
    )
    print(
        f"  ✓ Markdown ({_kb(output.get('markdown_size_bytes'))}) "
        f"+ HTML ({_kb(output.get('html_size_bytes'))})"
    )
    for name, digest in (evidence.get("artifact_sha256") or {}).items():
        print(f"  ✓ artifact {name}: {str(digest)[:16]}…")
    print()
    print(f"Report: {output.get('directory')}")
    for key, name in (
        ("report_path_md", "report.md"),
        ("report_path_html", "report.html"),
        ("report_path_json", "report.json"),
    ):
        if output.get(key):
            print(f"  - {name}")
    print()
    print(f"Report SHA256: {output.get('report_sha256')}")
    if output.get("failed_attempts"):
        print(f"Intentos fallidos documentados: {output['failed_attempts']}")


def _report_export(session: "OmniSession", directory: str, *, llm_cvss: bool) -> None:
    """Write the report plus a verifiable manifest to a deliverable directory."""
    if session.engagement is None:
        render.render_error("no hay engagement activo (usa /scope)")
        return
    target = Path(directory).expanduser()
    print(f"Exporting {session.engagement.name} report to {target}...")
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
            print(f"  ✓ {name}")
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
    print(f"  ✓ report.sha256 + manifest.json ({len(manifest['artifacts'])} artifacts)")
    print(f"Done. {target}")


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
        print("(sin eventos de auditoría para este engagement)")
        return
    for entry in entries:
        detail = f"  ({entry.detail})" if entry.detail else ""
        tool_id = entry.tool_id.replace("nexus.", "") if entry.tool_id else "-"
        print(
            f"{entry.occurred_at[:19].replace('T', ' ')}  {tool_id:<20} "
            f"{entry.target[:30]:<30} {entry.decision or '-'}{detail}"
        )
    print(f"\n{len(entries)} evento(s).")


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
    "/findings": cmd_findings,
    "/report": cmd_report,
    "/timeline": cmd_timeline,
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
    "cmd_findings",
    "cmd_help",
    "cmd_history",
    "cmd_report",
    "cmd_scope",
    "cmd_timeline",
    "cmd_tools",
    "cmd_trust",
    "command_names",
    "parse_command",
    "run_command",
]
