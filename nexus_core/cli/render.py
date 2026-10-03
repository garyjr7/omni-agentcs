"""ANSI rendering for the ``omni`` REPL (stdlib only, no rich/colorama).

Every function prints to stdout and degrades to uncoloured text when colour is
disabled (``--no-color`` or the ``NO_COLOR`` environment variable).
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Iterable

from .tui.output import write

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"

#: Noise levels of the offensive tools, mapped to a traffic-light colour.
NOISE_COLORS = {
    "read_only": GREEN,
    "low": GREEN,
    "medium": YELLOW,
    "high": RED,
    "destructive": RED,
}

_COLOR_ENABLED = True


def set_color_enabled(enabled: bool) -> None:
    """Force the colour switch (used by ``--no-color`` and by tests)."""
    global _COLOR_ENABLED
    _COLOR_ENABLED = bool(enabled)


def color_enabled() -> bool:
    """Return whether ANSI sequences are currently emitted."""
    return _COLOR_ENABLED


def configure_color(*, no_color: bool = False) -> None:
    """Disable ANSI when requested or when ``NO_COLOR`` is present."""
    set_color_enabled(not no_color and os.getenv("NO_COLOR") is None)


def paint(text: Any, *codes: str) -> str:
    """Wrap ``text`` in ANSI ``codes`` (no-op when colour is disabled)."""
    value = str(text)
    if not _COLOR_ENABLED or not codes:
        return value
    return f"{''.join(codes)}{value}{RESET}"


def noise_color(noise_level: str | None) -> str:
    """ANSI colour for a tool noise level."""
    return NOISE_COLORS.get(str(noise_level or "").lower(), CYAN)


def _first_line(text: str, limit: int = 200) -> str:
    line = str(text or "").strip().splitlines()[0] if str(text or "").strip() else ""
    return line[:limit]


def render_thought(text: str) -> None:
    """Show the model reasoning of one iteration."""
    write(paint(f"💭 {_first_line(text, 400)}", DIM))


def render_tool_call(tool_id: str, arguments: dict[str, Any], noise_level: str = "") -> None:
    """Show one requested tool call with its target, flags and noise level."""
    write(paint("⚙️  ", BOLD) + paint(tool_id, BOLD))
    for key in ("target", "targets", "host"):
        if key in (arguments or {}):
            write(f"     {key}: {arguments[key]}")
    flags = (arguments or {}).get("flags")
    if flags is not None:
        write(f"     flags:  {flags}")
    other = [key for key in (arguments or {}) if key not in {"target", "targets", "host", "flags"}]
    for key in other:
        write(f"     {key}:  {arguments[key]}")
    if noise_level:
        level = str(noise_level)
        write("     noise:  " + paint(level, noise_color(level)))


def render_tool_result(tool_id: str, result: dict[str, Any]) -> None:
    """Show a one-line outcome of a tool call, plus any findings it reported."""
    if not isinstance(result, dict):
        write(paint(f"✓ {tool_id}", GREEN))
        return
    if not result.get("success"):
        reason = result.get("error") or result.get("reason") or result.get("status") or "tool failed"
        write(paint(f"✗ {tool_id} — {reason}", RED))
        return

    evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
    output = result.get("output") if isinstance(result.get("output"), dict) else {}
    summary: list[str] = []
    hosts_up = evidence.get("hosts_up")
    host_count = evidence.get("host_count")
    if hosts_up is not None:
        summary.append(f"✓ {hosts_up} host(s) up")
    if host_count is not None and hosts_up is not None and host_count > hosts_up:
        summary.append(f"✗ {host_count - hosts_up} host(s) down")
    ports = evidence.get("ports_open_total")
    if ports is not None:
        summary.append(f"{ports} puerto(s) abierto(s)")
    if not summary:
        summary.append("ok")
    noise = evidence.get("noise_level")
    if noise:
        summary.append("noise: " + paint(str(noise), noise_color(str(noise))))
    write(paint(f"✓ {tool_id} — ", GREEN) + " | ".join(summary))

    findings = result.get("findings") or output.get("findings") or []
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "info")
            title = finding.get("title") or finding.get("summary") or ""
            write("   " + paint(f"[{severity}]", YELLOW) + f" {title}")


def render_approval_prompt(
    tool_id: str,
    arguments: dict[str, Any],
    decision: Any,
    reader: Callable[[str], str] | None = None,
    risk: str = "",
) -> str:
    """Show the human approval request and return the operator's raw answer.

    With the TUI the request becomes a dedicated modal overlay (exact tool,
    risk, reason and arguments) instead of scrolling text; the answer is read
    through the normal input bar and the modal is hidden right after.
    """
    reason = getattr(decision, "reason", "") or ""
    requires = getattr(decision, "requires_approval", False)
    declared_risk = risk or ("alto (requiere aprobación)" if requires else "normal")
    question = "   Opción [y/n/e/?]: "
    tui = getattr(getattr(reader, "__self__", None), "use_tui", False)
    if tui:
        tui_session = reader.__self__
        write(paint(f"⚠️  aprobación pendiente: {tool_id}", YELLOW, BOLD))
        tui_session.set_approval({
            "tool_id": tool_id,
            "risk": declared_risk,
            "reason": reason,
            "arguments": dict(arguments or {}),
        })
        try:
            return reader(question)
        finally:
            tui_session.clear_approval()
    write()
    write(paint("⚠️  APROBACIÓN HUMANA REQUERIDA", YELLOW, BOLD))
    write(f"   tool:   {tool_id}")
    write(f"   riesgo: {declared_risk}")
    write(f"   motivo: {reason}")
    write(f"   args:   {json.dumps(arguments or {}, ensure_ascii=False, default=str)}")
    write("   opciones: [y] aprobar  [n] rechazar  [e] editar argumentos  [?] ver definición")
    if reader is None:
        return input(question)
    write(question, end="", flush=True)
    return reader(question)


def render_trust_mode(tool_id: str, arguments: dict[str, Any], operator: str) -> None:
    """Announce an automatic high-risk authorization made under ``--trust-mode``."""
    write()
    write(paint("⚠️  TRUST MODE · AUTO-APROBACIÓN DE ALTO RIESGO", YELLOW, BOLD))
    write(f"   tool:     {tool_id}")
    write(f"   operador: {operator}")
    for key in ("target", "targets", "module", "payload", "url", "domain"):
        if isinstance(arguments, dict) and key in arguments:
            write(f"   {key + ':':<9}{arguments[key]}")
    write(paint("   args:     " + json.dumps(arguments or {}, ensure_ascii=False, default=str), DIM))
    write(paint("   se ejecuta sin pausa; la aprobación durable queda auditada", RED))


def _box_line(text: str, width: int) -> str:
    return "│ " + str(text)[: width - 2].ljust(width - 2) + " │"


def render_summary(text: str, findings: Iterable[dict[str, Any]] = ()) -> None:
    """Print the final summary of a run inside a box."""
    findings = list(findings or [])
    width = 68
    border = "├" + "─" * width + "┤"
    write()
    write(paint("┌" + "─" * width + "┐", BOLD))
    write(_box_line(paint("RESULTADO", BOLD), width))
    write(paint(border, BOLD))
    for line in str(text or "(sin resumen)").splitlines() or [""]:
        write(_box_line(line, width))
    if findings:
        write(paint(border, BOLD))
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "info")
            title = str(finding.get("title") or finding.get("summary") or "")
            write(_box_line(paint(f"[{severity}]", YELLOW) + f" {title}", width))
    write(paint("└" + "─" * width + "┘", BOLD))


def render_answer(text: str, *, no_color: bool = False, markdown: bool = False, max_width=None) -> None:
    """Print a conversational ``/ask`` answer, preserving its paragraphs."""
    write()
    write(paint("OmniAgent", CYAN, BOLD) + paint(" ·", DIM))
    body = str(text or "(sin respuesta)")
    if markdown:
        from .tui.markdown import render_markdown

        body = render_markdown(body, no_color=no_color or not color_enabled(), max_width=max_width)
    for line in body.splitlines():
        write("  " + line if line.strip() else "")
    write()


def render_error(text: str) -> None:
    """Print an error line in red."""
    write(paint(f"✗ {text}", RED))


def render_status(text: str) -> None:
    """Print a neutral status line."""
    write(paint(f"• {text}", CYAN))


def render_clarification(question: str) -> None:
    """Show a question the agent needs answered by the human."""
    write(paint("❓ El agente necesita una aclaración:", YELLOW, BOLD))
    write(f"   {question}")


def render_engagement(scope: Any) -> None:
    """Print the active engagement scope."""
    if scope is None:
        write("(sin engagement activo)")
        return
    write(paint("ENGAGEMENT", BOLD))
    write(f"  id:        {getattr(scope, 'engagement_id', '?')}")
    write(f"  nombre:    {getattr(scope, 'name', '?')}")
    write(f"  cliente:   {getattr(scope, 'client', '?')}")
    write(f"  owner:     {getattr(scope, 'owner_id', '?')}")
    write(f"  vigencia:  {getattr(scope, 'valid_from', '?')} → {getattr(scope, 'valid_until', '?')}")
    for label, attribute in (
        ("cidrs", "cidrs"),
        ("dominios", "domains"),
        ("urls", "urls"),
        ("exclusiones", "exclusions"),
    ):
        values = getattr(scope, attribute, ()) or ()
        if values:
            write(f"  {label + ':':<11}{', '.join(str(item) for item in values)}")
    notes = getattr(scope, "notes", "")
    if notes:
        write(f"  notas:     {notes}")


def render_messages(messages: Iterable[dict[str, Any]], limit: int = 200) -> None:
    """Print persisted conversation messages (used by ``/history``)."""
    messages = list(messages)
    if not messages:
        write("(sin historial todavía)")
        return
    for message in messages:
        metadata = message.get("metadata") or {}
        kind = str(metadata.get("kind") or "")
        role = str(message.get("role") or "?")
        content = str(message.get("content") or "").replace("\n", " ")
        write(paint(f"[{role}]", BLUE) + (paint(f" {kind}", DIM) if kind else "") + f" {content[:limit]}")


def render_findings(findings: Iterable[dict[str, Any]]) -> None:
    """Print the findings of a finished run."""
    for finding in findings or ():
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "info")
        title = str(finding.get("title") or finding.get("summary") or "")
        write(paint(f"  [{severity}]", YELLOW) + f" {title}")


SESSION_TABLE_HEADERS = ("UUID", "Type", "Peer", "Via", "User")


def _session_rows(sessions: dict[str, Any]) -> list[tuple[str, ...]]:
    """One display row per session, ordered by numeric sid when possible."""
    def sort_key(item: tuple[Any, Any]) -> tuple[int, str]:
        key = str(item[0])
        return (int(key), "") if key.isdigit() else (0, key)

    rows = []
    for sid, record in sorted((sessions or {}).items(), key=sort_key):
        if not isinstance(record, dict):
            continue
        rows.append(
            (
                str(record.get("uuid") or sid)[:12],
                str(record.get("type") or "?"),
                str(record.get("tunnel_peer") or record.get("session_host") or "?"),
                str(record.get("via_exploit") or "?").split("/")[-1][:22],
                str(record.get("username") or "?"),
            )
        )
    return rows


def render_session_list(sessions: dict[str, Any]) -> None:
    """Print a table of active sessions (uuid, type, peer, exploit, user)."""
    rows = _session_rows(sessions)
    if not rows:
        write("(no hay sesiones activas)")
        return
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(SESSION_TABLE_HEADERS)
    ]

    def line(values: tuple[str, ...]) -> str:
        return "  ".join(value.ljust(widths[index]) for index, value in enumerate(values)).rstrip()

    write(paint("Active Metasploit sessions:", BOLD))
    write("  " + paint(line(SESSION_TABLE_HEADERS), DIM))
    for row in rows:
        write("  " + line(row))


def render_session_attached(info: dict[str, Any]) -> None:
    """Banner shown when the REPL attaches to one session."""
    record = info or {}
    write(
        paint(
            f"Attached to session {record.get('uuid') or '?'} ({record.get('type') or '?'})",
            GREEN,
            BOLD,
        )
    )
    write(f"  Target: {record.get('target_host') or record.get('session_host') or '?'}")
    write(f"  User:   {record.get('username') or '?'}")
    write("  Escribe comandos directamente; /help para comandos Omni; /detach para salir.")


def render_session_died(uuid: str, last_seen_seconds: float | None = None) -> None:
    """Warn that the attached session is gone and the REPL is back to normal."""
    detail = f" (última señal hace {last_seen_seconds:.1f}s)" if last_seen_seconds else ""
    write(paint(f"✗ la sesión {uuid} ya no está activa{detail}", RED))
    write("  vuelvo a modo normal: el target pudo reiniciarse o cerrar el canal")


def render_session_output(
    output: str, max_lines: int = 500, numbered: bool = False
) -> None:
    """Print session output, trimming very long bursts."""
    text = str(output or "")
    lines = text.splitlines()
    total = len(lines)
    if total > max_lines:
        lines = lines[:max_lines] + [f"... ({total - max_lines} líneas más)"]
    for index, line_text in enumerate(lines, start=1):
        write(paint(f"{index:>4} │ ", DIM) + line_text if numbered else line_text)
