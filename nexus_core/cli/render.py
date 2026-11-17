"""ANSI rendering for the ``omni`` REPL (stdlib only, no rich/colorama).

Every function prints to stdout and degrades to uncoloured text when colour is
disabled (``--no-color`` or the ``NO_COLOR`` environment variable).
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Callable, Iterable

from .theme import (
    AQUA,
    AQUA_DIM,
    BLUE,
    BOLD,
    CYAN,
    DIM,
    GREEN,
    MAGENTA,  # noqa: F401 - re-exported: the prompt and commands use render.MAGENTA
    OFFWHITE,
    RED,
    RED_DIM,
    RESET,
    WHITE,
    YELLOW,
)
from .tui.output import block_break, write

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
    """Show the model reasoning of one iteration (agent thinking, in red)."""
    write(paint(f"💭 {_first_line(text, 400)}", RED))


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

    raw_evidence = result.get("evidence")
    evidence: dict[Any, Any] = raw_evidence if isinstance(raw_evidence, dict) else {}
    raw_output = result.get("output")
    output: dict[Any, Any] = raw_output if isinstance(raw_output, dict) else {}
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


def display_arguments(arguments: Any) -> dict[str, Any]:
    """Arguments as they may be shown to the operator (V1-30).

    Any value under a name in :data:`nexus_core.kernel.redaction.SECRET_TERMS`
    becomes ``[REDACTED]`` -including a stored-credential handle, which is only
    ever reachable through its own ``credential_ref`` key- so a banner, a prompt
    or an error can never echo a plaintext. Measured in rerun 8, iteration 10:
    the trust-mode banner printed ``"password": "R3dDRaG0Nsynd1c@T3"`` in clear.
    """
    if not isinstance(arguments, dict):
        return {}
    from nexus_core.kernel.redaction import sanitize

    return sanitize(arguments)


def render_approval_prompt(
    tool_id: str,
    arguments: dict[str, Any],
    decision: Any,
    reader: Callable[[str], str] | None = None,
    risk: str = "",
) -> str:
    """Show the human approval request and return the operator's raw answer.

    With the TUI the request is the dock's permission menu (exact tool, risk,
    reason and redacted arguments) and the answer is read through the normal
    input bar. Nothing is echoed into the transcript and the editor keeps its
    standard chevron, so no raw ``[y/n/a/e/?]`` question is interleaved with the
    log while the operator decides.
    """
    reason = getattr(decision, "reason", "") or ""
    requires = getattr(decision, "requires_approval", False)
    declared_risk = risk or ("alto (requiere aprobación)" if requires else "normal")
    question = "   Opción [y/n/a/e/?]: "
    safe = display_arguments(arguments)
    owner = getattr(reader, "__self__", None)
    tui_session = owner if getattr(owner, "use_tui", False) else None
    if tui_session is not None:
        from .tui.session import PROMPT_PREFIX

        tui_session.set_approval({
            "tool_id": tool_id,
            "risk": declared_risk,
            "reason": reason,
            "arguments": safe,
        })
        try:
            return str(tui_session.prompt(PROMPT_PREFIX))
        finally:
            tui_session.clear_approval()
    write()
    write(paint("⚠️  APROBACIÓN HUMANA REQUERIDA", YELLOW, BOLD))
    write(f"   tool:   {tool_id}")
    write(f"   riesgo: {declared_risk}")
    write(f"   motivo: {reason}")
    write(f"   args:   {json.dumps(safe, ensure_ascii=False, default=str)}")
    write(
        "   opciones: [y] aprobar una vez  [a] aprobar en este engagement  "
        "[n] rechazar  [e] editar argumentos  [?] ver definición"
    )
    if reader is None:
        return input(question)
    write(question, end="", flush=True)
    return reader(question)


def render_trust_mode(tool_id: str, arguments: dict[str, Any], operator: str) -> None:
    """Announce an automatic high-risk authorization made under ``--trust-mode``.

    The arguments are shown **redacted** (V1-30): announcing a call must never
    echo the secret it will use.
    """
    safe = display_arguments(arguments)
    write()
    write(paint("⚠️  TRUST MODE · AUTO-APROBACIÓN DE ALTO RIESGO", YELLOW, BOLD))
    write(f"   tool:     {tool_id}")
    write(f"   operador: {operator}")
    for key in ("target", "targets", "module", "payload", "url", "domain"):
        if key in safe:
            write(f"   {key + ':':<9}{safe[key]}")
    write(paint("   args:     " + json.dumps(safe, ensure_ascii=False, default=str), DIM))
    write(paint("   se ejecuta sin pausa; la aprobación durable queda auditada", RED))


#: SGR sequences, so box padding counts visible cells, not escape bytes.
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

#: Historical fixed box width; the live width is terminal-aware.
BOX_ROW_WIDTH = 70


def _cell_width(char: str) -> int:
    """Terminal cells of one character (stdlib only: no prompt_toolkit here)."""
    import unicodedata

    if unicodedata.combining(char):
        return 0
    return 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1


def _box_line(text: str, width: int) -> str:
    """One box row, truncated and padded by *visible* cells (ANSI-aware)."""
    limit = max(0, width - 2)
    source = str(text)
    pieces: list[str] = []
    visible = 0
    index = 0
    while index < len(source):
        match = _ANSI_RE.match(source, index)
        if match is not None:
            pieces.append(match.group())
            index = match.end()
            continue
        cells = _cell_width(source[index])
        if visible + cells > limit:
            break
        pieces.append(source[index])
        visible += cells
        index += 1
    body = "".join(pieces)
    if "\033[" in body:
        body += RESET
    return "│ " + body + " " * (limit - visible) + " │"


def summary_width() -> int:
    """Box width for this terminal: never below 60, never above 100."""
    import shutil

    return max(60, min(100, shutil.get_terminal_size((80, 24)).columns - 4))


#: Severity → palette, shared by the summary box and findings lists.
SEVERITY_COLORS = {
    "critical": RED,
    "high": RED_DIM,
    "medium": YELLOW,
    "low": GREEN,
    "info": AQUA_DIM,
}


def _summary_rows(text: str, width: int) -> list[str]:
    """Wrap the summary inside the box: content is never clipped.

    The terminal sentence of a run carries the verified facts, the findings and
    the open branches in one line; truncating it to the box width hid exactly
    the part that tells an incomplete run from a finished one. Wrapping keeps
    every character and leaves the box geometry unchanged.
    """
    import textwrap

    limit = max(8, width - 2)
    rows: list[str] = []
    for raw in str(text).splitlines() or [""]:
        plain = _ANSI_RE.sub("", raw)
        if not plain.strip():
            rows.append("")
            continue
        rows.extend(
            textwrap.wrap(
                plain, width=limit, break_long_words=False, break_on_hyphens=False
            )
            or [""]
        )
    return rows


def render_summary(text: str, findings: Iterable[dict[str, Any]] = (),
                   width: int | None = None) -> None:
    """Print the final summary of a run inside a responsive coloured box."""
    import textwrap

    findings = list(findings or [])
    total = summary_width() if width is None else max(60, min(100, int(width)))
    inner = total - 2
    border = "├" + "─" * inner + "┤"
    write(block_break() + paint("  ── resultado final " + "─" * max(0, total - 21), DIM))
    # The box is the plain-terminal path only; its border stays neutral so the
    # palette keeps a single accent (the header, the rail and the pulse).
    write(paint("┌" + "─" * inner + "┐", BOLD))
    write(_box_line(paint("RESULTADO · OmniAgentCS", BOLD), inner))
    write(paint(border, BOLD))
    for line in _summary_rows(str(text or "(sin resumen)"), inner):
        write(_box_line(paint(line, OFFWHITE) if line.strip() else "", inner))
    if findings:
        write(paint(border, AQUA, BOLD))
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("severity") or "info")
            title = str(finding.get("title") or finding.get("summary") or "")
            tag = paint(f"[{severity}]", SEVERITY_COLORS.get(severity.lower(), YELLOW), BOLD)
            # 9 = "       " continuation indent + the two padding cells the box
            # row adds. Wrapping wider than that made ``_box_line`` clip the end
            # of the finding instead of wrapping it.
            wrapped = textwrap.wrap(
                title, width=max(8, inner - 9), break_long_words=False,
                break_on_hyphens=False,
            ) or [""]
            write(_box_line(f"{tag} {paint(wrapped[0], WHITE)}", inner))
            for row in wrapped[1:]:
                write(_box_line("       " + paint(row, WHITE), inner))
    write(paint("└" + "─" * inner + "┘", BOLD))


def render_answer(text: str, *, no_color: bool = False, markdown: bool = False, max_width=None) -> None:
    """Print a conversational ``/ask`` answer, preserving its paragraphs.

    In the TUI, Markdown answers are committed as a framed block instead of a
    naked paragraph with a two-cell indent: the result reads like every other
    card in the transcript. The plain fallback keeps the historical label.
    """
    body = str(text or "(sin respuesta)")
    if markdown:
        from .tui.markdown import render_markdown
        from .tui.presentation import answer_panel

        body = render_markdown(body, no_color=no_color or not color_enabled(), max_width=max_width)
        width = max(20, (int(max_width) if max_width else 74) + 6)
        gap = block_break()
        if gap:
            write(gap, end="")
        write(answer_panel(body, width=width, no_color=no_color or not color_enabled()))
        # The answer is a block: keep the next turn from starting against its
        # bottom border. ``_block_break`` sees this blank line and does not add
        # a second one.
        write()
        return
    write()
    write(paint("OmniAgent", AQUA, BOLD) + paint(" ·", DIM))
    for line in body.splitlines():
        write("  " + line if line.strip() else "")
    write()


def render_error(text: str) -> None:
    """Print an error line in red."""
    write(paint(f"✗ {text}", RED))


def render_status(text: str) -> None:
    """Print a neutral status line (secondary, never an accent colour)."""
    write(paint(f"• {text}", DIM))


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

    rows: list[tuple[str, ...]] = []
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
