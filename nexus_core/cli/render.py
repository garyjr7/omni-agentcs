"""ANSI rendering for the ``omni`` REPL (stdlib only, no rich/colorama).

Every function prints to stdout and degrades to uncoloured text when colour is
disabled (``--no-color`` or the ``NO_COLOR`` environment variable).
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable, Iterable

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
    print(paint(f"💭 {_first_line(text, 400)}", DIM))


def render_tool_call(tool_id: str, arguments: dict[str, Any], noise_level: str = "") -> None:
    """Show one requested tool call with its target, flags and noise level."""
    print(paint("⚙️  ", BOLD) + paint(tool_id, BOLD))
    for key in ("target", "targets", "host"):
        if key in (arguments or {}):
            print(f"     {key}: {arguments[key]}")
    flags = (arguments or {}).get("flags")
    if flags is not None:
        print(f"     flags:  {flags}")
    other = [key for key in (arguments or {}) if key not in {"target", "targets", "host", "flags"}]
    for key in other:
        print(f"     {key}:  {arguments[key]}")
    if noise_level:
        level = str(noise_level)
        print("     noise:  " + paint(level, noise_color(level)))


def render_tool_result(tool_id: str, result: dict[str, Any]) -> None:
    """Show a one-line outcome of a tool call, plus any findings it reported."""
    if not isinstance(result, dict):
        print(paint(f"✓ {tool_id}", GREEN))
        return
    if not result.get("success"):
        reason = result.get("error") or result.get("reason") or result.get("status") or "tool failed"
        print(paint(f"✗ {tool_id} — {reason}", RED))
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
    print(paint(f"✓ {tool_id} — ", GREEN) + " | ".join(summary))

    findings = result.get("findings") or output.get("findings") or []
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "info")
            title = finding.get("title") or finding.get("summary") or ""
            print("   " + paint(f"[{severity}]", YELLOW) + f" {title}")


def render_approval_prompt(
    tool_id: str,
    arguments: dict[str, Any],
    decision: Any,
    reader: Callable[[str], str] | None = None,
) -> str:
    """Show the human approval block and return the operator's raw answer."""
    reason = getattr(decision, "reason", "") or ""
    risk = getattr(decision, "requires_approval", False)
    print()
    print(paint("⚠️  APROBACIÓN HUMANA REQUERIDA", YELLOW, BOLD))
    print(f"   tool:   {tool_id}")
    print(f"   riesgo: {'alto (requiere aprobación)' if risk else 'normal'}")
    print(f"   motivo: {reason}")
    print(f"   args:   {json.dumps(arguments or {}, ensure_ascii=False, default=str)}")
    print("   opciones: [y] aprobar  [n] rechazar  [e] editar argumentos  [?] ver definición")
    question = "   Opción [y/n/e/?]: "
    if reader is None:
        return input(question)
    print(question, end="", flush=True)
    return reader(question)


def render_trust_mode(tool_id: str, arguments: dict[str, Any], operator: str) -> None:
    """Announce an automatic high-risk authorization made under ``--trust-mode``."""
    print()
    print(paint("⚠️  TRUST MODE · AUTO-APROBACIÓN DE ALTO RIESGO", YELLOW, BOLD))
    print(f"   tool:     {tool_id}")
    print(f"   operador: {operator}")
    for key in ("target", "targets", "module", "payload", "url", "domain"):
        if isinstance(arguments, dict) and key in arguments:
            print(f"   {key + ':':<9}{arguments[key]}")
    print(paint("   args:     " + json.dumps(arguments or {}, ensure_ascii=False, default=str), DIM))
    print(paint("   se ejecuta sin pausa; la aprobación durable queda auditada", RED))


def _box_line(text: str, width: int) -> str:
    return "│ " + str(text)[: width - 2].ljust(width - 2) + " │"


def render_summary(text: str, findings: Iterable[dict[str, Any]] = ()) -> None:
    """Print the final summary of a run inside a box."""
    findings = list(findings or [])
    width = 68
    border = "├" + "─" * width + "┤"
    print()
    print(paint("┌" + "─" * width + "┐", BOLD))
    print(_box_line(paint("RESULTADO", BOLD), width))
    print(paint(border, BOLD))
    for line in str(text or "(sin resumen)").splitlines() or [""]:
        print(_box_line(line, width))
    if findings:
        print(paint(border, BOLD))
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "info")
            title = str(finding.get("title") or finding.get("summary") or "")
            print(_box_line(paint(f"[{severity}]", YELLOW) + f" {title}", width))
    print(paint("└" + "─" * width + "┘", BOLD))


def render_error(text: str) -> None:
    """Print an error line in red."""
    print(paint(f"✗ {text}", RED))


def render_status(text: str) -> None:
    """Print a neutral status line."""
    print(paint(f"• {text}", CYAN))


def render_clarification(question: str) -> None:
    """Show a question the agent needs answered by the human."""
    print(paint("❓ El agente necesita una aclaración:", YELLOW, BOLD))
    print(f"   {question}")


def render_engagement(scope: Any) -> None:
    """Print the active engagement scope."""
    if scope is None:
        print("(sin engagement activo)")
        return
    print(paint("ENGAGEMENT", BOLD))
    print(f"  id:        {getattr(scope, 'engagement_id', '?')}")
    print(f"  nombre:    {getattr(scope, 'name', '?')}")
    print(f"  cliente:   {getattr(scope, 'client', '?')}")
    print(f"  owner:     {getattr(scope, 'owner_id', '?')}")
    print(f"  vigencia:  {getattr(scope, 'valid_from', '?')} → {getattr(scope, 'valid_until', '?')}")
    for label, attribute in (
        ("cidrs", "cidrs"),
        ("dominios", "domains"),
        ("urls", "urls"),
        ("exclusiones", "exclusions"),
    ):
        values = getattr(scope, attribute, ()) or ()
        if values:
            print(f"  {label + ':':<11}{', '.join(str(item) for item in values)}")
    notes = getattr(scope, "notes", "")
    if notes:
        print(f"  notas:     {notes}")


def render_messages(messages: Iterable[dict[str, Any]], limit: int = 200) -> None:
    """Print persisted conversation messages (used by ``/history``)."""
    messages = list(messages)
    if not messages:
        print("(sin historial todavía)")
        return
    for message in messages:
        metadata = message.get("metadata") or {}
        kind = str(metadata.get("kind") or "")
        role = str(message.get("role") or "?")
        content = str(message.get("content") or "").replace("\n", " ")
        print(paint(f"[{role}]", BLUE) + (paint(f" {kind}", DIM) if kind else "") + f" {content[:limit]}")


def render_findings(findings: Iterable[dict[str, Any]]) -> None:
    """Print the findings of a finished run."""
    for finding in findings or ():
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "info")
        title = str(finding.get("title") or finding.get("summary") or "")
        print(paint(f"  [{severity}]", YELLOW) + f" {title}")


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
        print("(no hay sesiones activas)")
        return
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(SESSION_TABLE_HEADERS)
    ]

    def line(values: tuple[str, ...]) -> str:
        return "  ".join(value.ljust(widths[index]) for index, value in enumerate(values)).rstrip()

    print(paint("Active Metasploit sessions:", BOLD))
    print("  " + paint(line(SESSION_TABLE_HEADERS), DIM))
    for row in rows:
        print("  " + line(row))


def render_session_attached(info: dict[str, Any]) -> None:
    """Banner shown when the REPL attaches to one session."""
    record = info or {}
    print(
        paint(
            f"Attached to session {record.get('uuid') or '?'} ({record.get('type') or '?'})",
            GREEN,
            BOLD,
        )
    )
    print(f"  Target: {record.get('target_host') or record.get('session_host') or '?'}")
    print(f"  User:   {record.get('username') or '?'}")
    print("  Escribe comandos directamente; /help para comandos Omni; /detach para salir.")


def render_session_died(uuid: str, last_seen_seconds: float | None = None) -> None:
    """Warn that the attached session is gone and the REPL is back to normal."""
    detail = f" (última señal hace {last_seen_seconds:.1f}s)" if last_seen_seconds else ""
    print(paint(f"✗ la sesión {uuid} ya no está activa{detail}", RED))
    print("  vuelvo a modo normal: el target pudo reiniciarse o cerrar el canal")


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
        print(paint(f"{index:>4} │ ", DIM) + line_text if numbered else line_text)
