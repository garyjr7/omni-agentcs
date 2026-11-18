"""Compact, evidence-based presentation of durable tool messages."""

import json
import re
import shlex
from typing import Any

from ..theme import BOLD, DIM, GREEN, OFFWHITE, RESET
from .presentation import clean_text, render_rich, result_diff, trace_block

PREFIXES = {
    "nexus.recon.nmap": "Recon-NMAP", "nexus.recon.dns": "Recon-DNS",
    "nexus.recon.subfinder": "Recon-Subfinder",
    "nexus.recon.httpx": "Web-HTTPS", "nexus.web.nuclei": "Web-Nuclei",
    "nexus.web.ffuf": "Web-Ffuf", "nexus.exploit.msf_search": "Exploit-Search",
    "nexus.exploit.msf_auxiliary": "Exploit-Auxiliary", "nexus.exploit.msf_exploit": "Exploit-MSF",
    "nexus.session.interact": "Session-CMD", "nexus.session.list": "Session-List",
    "nexus.session.kill": "Session-Kill", "nexus.report.generate": "Report",
    "nexus.system.install_tool": "System-Install", "nexus.system.check_env": "System-Check",
    "nexus.system.status": "System-Status", "nexus.workspace.search": "Workspace-Search",
}


def tool_prefix(tool_id: str) -> str:
    return f"[{PREFIXES.get(str(tool_id or '').lower(), 'Tool')}]"


def _line(text: Any, width: int | None = None) -> str:
    value = " ".join(clean_text(str(text)).splitlines())
    if width is None or len(value) <= width:
        return value
    return value[:max(0, width - 1)] + "…"


def data_lines(output: str, *, width: int | None = 100) -> tuple[list[str], bool]:
    """Clean data lines of a tool output, plus whether any line was clipped.

    Empty/separator lines and adjacent duplicate progress lines are discarded;
    every kept line is bounded to ``width`` when one is given. ``width=None``
    keeps every character: the card wraps at the transcript width instead of
    losing tokens.
    """
    lines: list[str] = []
    clipped = False
    for raw in str(output or "").splitlines():
        if not raw.strip() or re.fullmatch(r"[\s\-_=─━]+", raw):
            continue
        if lines and raw.lstrip().startswith("[+]") and raw == lines[-1]:
            continue
        line = _line(raw, width)
        clipped |= line != raw
        lines.append(line)
    return lines, clipped


def truncate_output(output: str, max_lines: int = 3, *, width: int = 100) -> tuple[str, bool]:
    """Keep head and tail data lines, with one extra omission marker.

    max_lines counts data lines, not the marker. Width is bounded independently.
    """
    if max_lines < 1:
        raise ValueError("max_lines must be positive")
    lines, clipped = data_lines(output, width=width)
    if len(lines) <= max_lines:
        return "\n".join(lines), clipped
    tail = lines[-(max_lines - 1):] if max_lines > 1 else []
    return "\n".join([lines[0], "...", *tail]), True


def render_thought(text: str, *, width: int = 180, expanded: bool = False,
                   no_color: bool = False) -> str:
    """Muted reasoning summary as its own framed block.

    The thought is durable (``react.action`` metadata) and is emitted *before*
    the tool it justifies, so the human sees the intent before the action.
    """
    text = str(text or "").strip()
    if not text:
        return ""
    from .presentation import thinking_block

    return thinking_block(text, expanded=expanded, width=width, no_color=no_color)


#: Keys that make a path worth naming in a summary, most specific first.
_PATH_KEYS = ("report_path_md", "report_path_html", "report_path_json",
              "directory", "path", "output_path")
_DIGEST_KEYS = ("report_sha256", "sha256")


def _argument_value(value: Any) -> str:
    """One argument value as text: no braces, quoting only when it is needed."""
    if isinstance(value, (list, tuple)):
        return shlex.join(str(item) for item in value)
    if isinstance(value, dict):
        return " ".join(f"{key}={_argument_value(value[key])}" for key in sorted(value))
    text = " ".join(clean_text(str(value)).splitlines())
    return shlex.quote(text) if not text or any(char.isspace() for char in text) else text


def invocation_arguments(arguments: Any) -> str:
    """``key=value`` pairs: the request as the handler receives it.

    A structured tool is not a shell command, so it is not rendered as one.
    Secrets are masked by the existing ``display_arguments`` policy, and the
    text is never clipped: the scrollback wraps it at the real width, so a long
    command keeps every token.
    """
    from ..render import display_arguments

    safe = display_arguments(arguments if isinstance(arguments, dict) else {})
    return " · ".join(f"{key}={_argument_value(safe[key])}" for key in sorted(safe))


#: Prefix of a wrapped invocation's continuation rows. A discrete marker ties
#: them to the arguments without reading as a second tool call.
INVOCATION_CONTINUATION = "  ↳ "


def _invocation_lines(text: str, *, width: int | None, prefix: str) -> list[str]:
    """Wrap one invocation body, leaving room for ``prefix`` on every row.

    The block is pre-wrapped so a continuation sits under the arguments instead
    of falling back to column zero; the scrollback only wraps it again if the
    terminal becomes narrower than the width used here.

    Rows are packed by *cells* (a wide character counts as the cells it paints)
    and a word moves to the next row before it is ever cut, so a redaction
    marker such as ``[REDACTED]`` never arrives in two pieces. Only a token
    wider than a whole row is folded, and nothing is dropped.
    """
    if not width or int(width) < 24:
        return [text]
    from rich.cells import cell_len, chop_cells

    limit = max(12, int(width) - cell_len(prefix))
    rest = max(12, int(width) - cell_len(INVOCATION_CONTINUATION))
    lines: list[str] = []
    current = ""
    for word in text.split():
        candidate = f"{current} {word}" if current else word
        if cell_len(candidate) <= limit:
            current = candidate
            continue
        if current:
            lines.append(current)
            current, limit = "", rest
        while cell_len(word) > limit:
            chunks = chop_cells(word, limit)
            if not chunks:
                break
            lines.extend(chunks[:-1])
            word = chunks[-1]
        current = word
    if current:
        lines.append(current)
    return lines or [text]


def _command_line(tool_id: str, safe: dict[str, Any]) -> str | None:
    """The real argv a handler builds, when the invocation *is* a command.

    Only the tools whose handler builds an argv from the durable request are
    rendered as a shell command; every other call keeps the honest
    ``key=value`` request, because a command the handler may not execute would
    be an invented one.
    """
    if tool_id == "nexus.recon.nmap":
        flags = safe.get("flags") or []
        flags = flags if isinstance(flags, list) else [flags]
        # ``-oX -`` is the handler's own XML plumbing, not what the operator
        # asked for: the card shows the command they would type.
        return shlex.join(["nmap", *map(str, flags), str(safe.get("target", ""))])
    return None


#: Contract ceiling per tool, read once from the same durable catalog the
#: gateway registers. ``None`` means the catalog does not know the tool, and the
#: card simply omits the suffix instead of inventing a number.
_TOOL_TIMEOUTS: dict[str, int] | None = None


#: Plan tools are a contract, not a shell command: their card names what the plan
#: promises, never the raw ``todos`` JSON the model sent.
PLAN_TOOLS = frozenset({
    "nexus.orchestrator.create_plan",
    "nexus.orchestrator.update_plan",
})

_PLAN_MARKS = {
    "done": "[x]",
    "in_progress": "[>]",
    "pending": "[ ]",
    "failed": "[!]",
}


def tool_timeout_seconds(tool_id: str) -> int | None:
    """Seconds the tool's own contract publishes (``None`` when unknown)."""
    global _TOOL_TIMEOUTS
    if _TOOL_TIMEOUTS is None:
        timeouts: dict[str, int] = {}
        try:
            from nexus_core.tools.registry import durable_tool_definitions

            for key, entry in durable_tool_definitions("system").items():
                definition = entry[0] if isinstance(entry, tuple) and entry else entry
                seconds = int(getattr(definition, "timeout_seconds", 0) or 0)
                if seconds > 0:
                    timeouts[str(key)] = seconds
        except Exception:  # noqa: BLE001 - cosmetic metadata only
            timeouts = {}
        _TOOL_TIMEOUTS = timeouts
    return _TOOL_TIMEOUTS.get(str(tool_id or "")) or None


def plan_invocation(tool_id: str, arguments: Any) -> str:
    """One readable line for a plan call: what it proposes, not the TODO JSON."""
    args = arguments if isinstance(arguments, dict) else {}
    adding = args.get("todos") or args.get("add") or []
    count = len(adding) if isinstance(adding, (list, tuple)) else 0
    changes = args.get("status") or []
    change_count = len(changes) if isinstance(changes, (list, tuple)) else 0
    parts: list[str] = []
    if count:
        parts.append(f"{count} TODO(s)")
    if change_count:
        parts.append(f"{change_count} cambio(s)")
    detail = " · ".join(parts) or "sin cambios"
    if args.get("replace"):
        detail += " · reemplaza el plan"
    return f"• plan  {detail}"


def plan_card_body(tool_id: str, arguments: Any, result: dict[str, Any] | None) -> str:
    """Body of a plan card: the contract in words, never the request payload.

    The summary line is the same shape as every other tool card (a verdict and
    the counts), and the TODOs are listed with their real state so the operator
    reads what the engagement promised without a 4 000-character JSON line.
    """
    head = plan_invocation(tool_id, arguments)
    timeout = tool_timeout_seconds(tool_id)
    if timeout:
        head += f"  (timeout: {timeout}s)"
    if result is None:
        return f"{head}\n\n  · en ejecución…"
    output = result.get("output") if isinstance(result.get("output"), dict) else {}
    if is_guardrail(result) or not result.get("success"):
        detail = str(
            result.get("guidance")
            or result.get("error")
            or output.get("guidance")
            or output.get("error")
            or "el plan no se actualizó"
        )
        return f"{head}\n\n  ⚠ {detail}"
    counts = output.get("counts") if isinstance(output.get("counts"), dict) else {}
    todos = output.get("todos") if isinstance(output.get("todos"), list) else []
    verb = "Plan creado" if tool_id.endswith("create_plan") else "Plan actualizado"
    done = int(counts.get("done") or 0)
    pending = int(counts.get("pending") or 0)
    failed = int(counts.get("failed") or 0)
    line = (
        f"  ✓ {verb}: {len(todos)} TODO(s) · {done} hechos · "
        f"{pending} pendientes"
    )
    if failed:
        line += f" · {failed} fallidos"
    lines = [head, "", line]
    for todo in todos[:10]:
        if not isinstance(todo, dict):
            continue
        mark = _PLAN_MARKS.get(str(todo.get("status") or "pending"), "[ ]")
        description = " ".join(str(todo.get("description") or "").split())[:90]
        lines.append(f"  {mark} {todo.get('id') or '?'} — {description}")
    if len(todos) > 10:
        lines.append(f"  … {len(todos) - 10} TODO(s) más")
    return "\n".join(lines)


def format_tool_invocation(tool_id: str, arguments: Any, *,
                           width: int | None = None,
                           no_color: bool = False) -> str:
    """One tool invocation, framed when a transcript width is available.

    The sentence stays conversational (``> Ejecutando nmap en 10.0.0.1...``);
    the frame around it is what makes the call a block instead of a loose line.
    A renderer without a width keeps the plain one-line export. Secrets are
    masked by the same ``display_arguments`` policy.
    """
    from .presentation import execution_block, tool_call_line

    content_width = max(20, int(width) - 6) if width is not None else None
    line = tool_call_line(str(tool_id or ""), arguments, width=content_width)
    if width is None:
        return line
    return execution_block(line, width=width, no_color=no_color)


def detailed_tool_invocation(tool_id: str, arguments: Any, *,
                             width: int | None = None,
                             timeout_seconds: int | None = None) -> str:
    """One tool header. A shell command reads ``$ nmap …``; a structured call
    reads ``• tool_id  key=value``. ``timeout_seconds`` appends the ceiling the
    tool's own contract publishes, so the operator sees how long it may run.

    Every branch reads ``display_arguments`` first, so a credential cannot reach
    the transcript through a flag, a path, a nested value or free text. With
    ``width`` the argument text is pre-wrapped and its continuations carry a
    ``↳`` marker; without it the block stays a single line (exports, tests).
    Nothing is clipped: the operator can read every token the tool receives.
    """
    args = arguments if isinstance(arguments, dict) else {}
    from ..render import display_arguments

    safe = display_arguments(args)
    operation = str(tool_id or "").rsplit(".", 1)[-1].lower()
    file_operations = {
        "read", "create", "write", "edit", "update", "write_file",
        "edit_file", "read_file",
    }
    command = _command_line(str(tool_id or ""), safe)
    if command is not None:
        text = command
    elif operation in file_operations and any(
        marker in str(tool_id).lower() for marker in ("workspace", "file", "filesystem")
    ):
        text = clean_text(str(safe.get("path") or safe.get("file_path") or "?"))
    else:
        # Other handlers may transform arguments. Display the durable request
        # honestly rather than inventing a shell command they may not execute.
        text = invocation_arguments(safe)

    from .strings import TOOL_FALLBACK
    name = clean_text(str(tool_id or TOOL_FALLBACK))
    suffix = f"  (timeout: {int(timeout_seconds)}s)" if timeout_seconds else ""
    if command is not None:
        head, plain_prefix, body_style = f"{GREEN}$ {RESET}{OFFWHITE}", "$ ", OFFWHITE
    else:
        head, plain_prefix, body_style = f"{BOLD}• {name}{RESET}{DIM}  ", f"• {name}  ", DIM
    if not text:
        return f"{BOLD}• {name}{RESET}{DIM}  (sin argumentos){suffix}{RESET}"
    text = f"{text}{suffix}"
    lines = _invocation_lines(text, width=width, prefix=plain_prefix)
    continuation = "".join(
        f"\n{DIM}{INVOCATION_CONTINUATION}{RESET}{body_style}{line}{RESET}"
        for line in lines[1:]
    )
    return f"{head}{lines[0]}{RESET}{continuation}"


def output_text(result: dict[str, Any]) -> str:
    streams = [(name, result.get(name)) for name in ("stdout", "stderr")]
    present = [(name, value) for name, value in streams if isinstance(value, str) and value]
    if present:
        return "\n".join((f"[{name}]\n" if len(present) > 1 else "") + str(value)
                         for name, value in present)
    output = result.get("output") or ""
    if isinstance(output, str):
        return str(output)
    if isinstance(output, dict) and isinstance(output.get("scan"), dict):
        scan = output["scan"]
        lines = []
        for host in scan.get("hosts", []):
            lines.append(f"Host {host.get('state', '?')}: {host.get('ip', '?')}")
            for port in host.get("ports", []):
                number = port.get("port", port.get("portid", "?"))
                protocol = port.get("protocol", "tcp")
                detail = " ".join(
                    str(part).strip() for part in (
                        port.get("service"), port.get("product"),
                        port.get("version"), port.get("extra_info"),
                    ) if str(part or "").strip()
                )
                lines.append(
                    f"{number}/{protocol} {port.get('state', '?')}: {detail}".rstrip(" :")
                )
        lines.append(f"Nmap done: {scan.get('hosts_up', '?')} host(s) up · {scan.get('elapsed_seconds', '?')}s")
        return "\n".join(lines)
    return json.dumps(output, ensure_ascii=False, indent=2, default=str) if output else ""


def structured_output(result: dict[str, Any]) -> Any:
    """The part of a result that ``output_text`` prints as pretty JSON, if any.

    ``None`` means the body is already readable (a stream, a diff, the mapped
    nmap scan), so the folded card can show it directly.
    """
    if result.get("stdout") or result.get("stderr") or result_diff(result):
        return None
    output = result.get("output")
    if isinstance(output, str):
        return None
    if isinstance(output, dict) and isinstance(output.get("scan"), dict):
        return None
    return output or None


def structured_detail(result: dict[str, Any]) -> bool:
    """Whether the collapsed card would otherwise print raw JSON."""
    return structured_output(result) is not None


def _output_facts(result: dict[str, Any]) -> list[str]:
    """Readable facts of a successful result: where it was written, its digest.

    Only fields the handler actually reports, and only on success: a path is
    named as saved when the call succeeded *and* returned it.
    """
    if not result.get("success"):
        return []
    raw_output = result.get("output")
    output: dict[Any, Any] = raw_output if isinstance(raw_output, dict) else {}
    facts: list[str] = []
    path = next((str(output[key]) for key in _PATH_KEYS if output.get(key)), "")
    if path:
        label = "informe guardado" if result.get("tool_id") == "nexus.report.generate" else "guardado"
        facts.append(f"{label}: {_line(path, 120)}")
    digest = next((output[key] for key in _DIGEST_KEYS
                   if isinstance(output.get(key), str) and output[key]), "")
    if digest:
        facts.append(f"sha256: {digest[:12]}…")
    return facts


#: Fields where a tool states something in its own words. They are shown as
#: delivered: never re-worded, never turned into a stronger claim.
_NOTE_KEYS = ("message", "reason")


def _notes(result: dict[str, Any]) -> list[str]:
    """The tool's own message/reason text, when it delivered any.

    Nothing here is interpreted: a *negative* verification (``success: true``
    with a message saying nothing was found) keeps its words and its success
    colour, and never becomes a failure.
    """
    raw_output = result.get("output")
    output: dict[Any, Any] = raw_output if isinstance(raw_output, dict) else {}
    notes: list[str] = []
    for key in _NOTE_KEYS:
        value = output.get(key)
        if not isinstance(value, str) or not value.strip():
            value = result.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        text = " ".join(clean_text(value).split())
        if text and text not in notes:
            notes.append(text)
    return notes


def summarize_tool_result(result: dict[str, Any]) -> str:
    from .strings import FAILED, NOISE

    evidence = result.get("evidence") or {}
    output = result.get("output") or {}
    evidence = evidence if isinstance(evidence, dict) else {}
    if not result.get("success"):
        error = result.get("error") or (output.get("error") if isinstance(output, dict) else None) or FAILED
        parts = [_line(str(error))]
        parts.extend(note for note in _notes(result) if note not in parts)
        method = result.get("verification_method")
        if method:
            parts.append(f"verification_method={method}")
        return _line(" · ".join(parts))
    parts = []
    for field, label in (("ports_open_total", "puertos abiertos"), ("hosts_up", "hosts up"),
                         ("subdomain_count", "subdominios"), ("findings_count", "hallazgos")):
        if field in evidence:
            parts.append(f"{evidence[field]} {label}")
    if evidence.get("noise_level"):
        parts.append(f"{NOISE}: {evidence['noise_level']}")
    if evidence.get("elapsed_seconds") is not None:
        parts.append(f"{evidence['elapsed_seconds']}s")
    parts.extend(_output_facts(result))
    parts.extend(_notes(result))
    structured = structured_output(result)
    if not parts and structured is not None:
        # Unknown schema: say what is true (there is a structured body of N
        # fields) instead of claiming a meaning the evidence does not support.
        count = len(structured) if isinstance(structured, (dict, list)) else 1
        parts.append(f"resultado estructurado · {count} campo(s)")
    if not parts:
        # A shell result with no evidence field still answered something: its
        # first data line is the honest one-line summary ("completado" hides
        # the output the operator asked for).
        body, _ = trace_text(result)
        first = next(
            (row.strip() for row in clean_text(body).splitlines() if row.strip()), ""
        )
        if first:
            parts.append(first[:160])
    return _line(" · ".join(parts) or str(result.get("verification_method") or "completado"), width=None)


def hidden_detail_lines(result: dict[str, Any], *, max_lines: int = 4) -> int:
    """How many lines the collapsed one-liner hides behind the expansion.

    Structured payloads count their pretty JSON (the document *is* the detail);
    everything else counts data lines past the fold. Zero means there is nothing
    to expand and the card gets no affordance.
    """
    structured = structured_output(result)
    if structured is not None:
        return len(
            json.dumps(structured, ensure_ascii=False, indent=2, default=str).splitlines()
        )
    value, _ = trace_text(result)
    rows = [row for row in clean_text(value).splitlines() if row.strip()]
    return max(0, len(rows) - max_lines) if len(rows) > max_lines else 0


def trace_text(result: dict[str, Any]) -> tuple[str, bool]:
    """A diff must not hide accompanying stdout/stderr diagnostics."""
    diff = result_diff(result)
    raw = output_text(result)
    if diff is None:
        return raw, False
    if (result.get("stdout") or result.get("stderr")) and raw != diff:
        return raw + "\n" + diff, True
    return diff, True


#: Outcomes that are an orchestrator correction, never a tool failure.
GUARDRAIL_OUTCOMES = frozenset({
    "plan_status_unchanged", "repeated_action", "scope_denied",
    "branch_closed_recent",
    # A plan TODO named an unknown fact type: the handler answered with the
    # closed list, so the next call can be right. Amber correction, never a red
    # tool failure.
    "invalid_fact_type",
})


def is_guardrail(result: dict[str, Any]) -> bool:
    """True when the observation is a pre-execution correction of the loop.

    ``failure_kind="input"`` is the coordinator's classification of a
    ``ValueError`` raised by argument/schema validation, before the handler
    touched the target (for example ``update_plan`` refusing a declaration that
    needs evidence). It is guidance for the next turn, not a tool failure; a
    ``failure_kind="tool"`` stays red because the tool really broke.
    """
    if not isinstance(result, dict):
        return False
    return bool(
        result.get("refused_before_execution")
        or str(result.get("outcome") or "") in GUARDRAIL_OUTCOMES
        or str(result.get("failure_kind") or "") in {"repeated_action", "input"}
    )


def tool_result_content(result: dict[str, Any], *, expanded: bool = False,
                        max_lines: int = 4, width: int = 100,
                        no_color: bool = False, compact: bool = True) -> tuple[str, bool, bool]:
    """The body of a tool card (no frame), plus its verdict and guardrail flag.

    ``compact`` keeps the historical collapsed voice of a standalone card: one
    conversational verdict line and an inline ``Ver N líneas más`` footer. The
    combined invocation + result card sets it to ``False`` so the parsed body
    of the tool is visible even before expanding it -the operator asked for the
    tool's real output, not only the orchestrator's one-line interpretation.
    """
    guardrail = is_guardrail(result)
    content_width = max(20, int(width) - 6)
    success = bool(result.get("success"))
    if compact and not expanded and not guardrail:
        from rich.cells import cell_len

        from .presentation import tool_result_line

        hidden = hidden_detail_lines(result, max_lines=max_lines)
        # The expansion has to be discoverable, or the body is lost: the footer
        # stays inline so the default result is still one conversational line.
        footer = f" · Ver {hidden} líneas más" if hidden else ""
        line = tool_result_line(
            result,
            summary=summarize_tool_result(result),
            # Reserve the footer's cells before fitting, or the verdict overflows
            # the card and wraps into two rows (D1).
            width=max(1, content_width - cell_len(footer)) if footer else content_width,
        )
        return f"{line}{footer}", success, guardrail
    structured = structured_output(result)
    value, is_diff = trace_text(result)
    guidance = ""
    if guardrail:
        value = ""
        guidance = str(result.get("guidance") or result.get("error") or "")
    elif structured is not None:
        value = json.dumps(structured, ensure_ascii=False, indent=2, default=str) if expanded else ""
    elif not is_diff:
        # Empty lines and separators are not data; the hidden count must name
        # what the operator would actually reveal.
        value = "\n".join(data_lines(value, width=None)[0])
    table = ""
    if (expanded and not guardrail and structured is None and not is_diff
            and not result.get("stdout") and not result.get("stderr")):
        from .presentation import render_port_table

        table = render_port_table(result, width=content_width, no_color=no_color)
        if table:
            # The table *is* the body: the mapped ``Puerto …`` lines would say
            # the same thing twice, one per line and without the versions.
            value = ""
    rendered = render_rich(trace_block(
        value,
        success=success, tool_id=str(result.get("tool_id") or ""),
        summary=summarize_tool_result(result), expanded=expanded, limit=max_lines,
        diff=is_diff, defer_detail=structured is not None, structured=structured,
        guardrail=guardrail, guidance=guidance, width=content_width,
    ), width=content_width, no_color=no_color)
    if table:
        rendered = f"{rendered}\n{table}"
    return rendered, success, guardrail


def render_tool_result(result: dict[str, Any], *, expanded: bool = False,
                       max_lines: int = 4, width: int = 100, no_color: bool = False,
                       title: str | None = None) -> str:
    """A tool result as one framed block, collapsed or expanded.

    The default flow is still conversational (``✓ nmap: 3 puertos abiertos``),
    but the verdict lives inside a bordered card instead of floating as a bare
    line. ``expanded=True`` keeps the reviewed card: folded body, diff syntax,
    hidden line count and clickable footer. A guardrail is a correction, not a
    result, so it keeps its own amber title. ``title`` overrides the identity
    derived from ``tool_id`` (used for numbered subagent cards).
    """
    from .presentation import subagent_title, tool_result_block

    identity = title or subagent_title(str(result.get("tool_id") or ""))
    rendered, success, guardrail = tool_result_content(
        result, expanded=expanded, max_lines=max_lines, width=width,
        no_color=no_color, compact=True,
    )
    return tool_result_block(
        rendered, success=success, width=width, no_color=no_color,
        guardrail=guardrail, title=identity,
    )


def format_tool_card(tool_id: str, arguments: Any, result: dict[str, Any] | None, *,
                     expanded: bool = False, max_lines: int = 6, width: int = 100,
                     no_color: bool = False, title: str | None = None) -> str:
    """One subagent card: the invocation *and* its result inside the same box.

    The subagent owns the whole block -``• nexus.recon.nmap  nmap …`` followed
    by the parsed output- so the call never floats outside the identity that
    ran it. ``result is None`` draws the pending state while the tool runs.

    The body is the tool's own data (parsed scan rows, stdout, diff), not the
    orchestrator's interpretation: OMNI's reading of the evidence belongs to its
    reasoning block, never to the tool card.
    """
    from .presentation import subagent_title, tool_result_block

    base = title or subagent_title(tool_id) or (
        'Plan' if tool_id in PLAN_TOOLS else 'Resultado'
    )
    content_width = max(20, int(width) - 6)
    if tool_id in PLAN_TOOLS:
        # The plan card owns its body: the invocation is a sentence and the
        # result is a contract, not the raw TODO JSON or the handler's payload.
        return tool_result_block(
            plan_card_body(tool_id, arguments, result),
            success=bool(isinstance(result, dict) and result.get("success")),
            width=width, no_color=no_color, pending=result is None,
            guardrail=bool(isinstance(result, dict) and is_guardrail(result)),
            title=base, force_title=True,
        )
    invocation = detailed_tool_invocation(
        tool_id, arguments, width=content_width,
        timeout_seconds=tool_timeout_seconds(tool_id),
    )
    if result is None:
        body = f"{invocation}\n\n  · en ejecución…"
        return tool_result_block(
            body, success=True, width=width, no_color=no_color,
            title=base, pending=True,
        )
    rendered, success, guardrail = tool_result_content(
        result, expanded=expanded, max_lines=max_lines, width=width,
        no_color=no_color, compact=False,
    )
    body = f"{invocation}\n\n{rendered}" if rendered else invocation
    return tool_result_block(
        body, success=success, width=width, no_color=no_color,
        guardrail=guardrail, title=base, force_title=True,
    )


def plain_result_text(result: dict[str, Any]) -> str:
    """The evidence of one tool result as plain text, for the clipboard.

    The operator wants what the tool said, not the frame, the ANSI colouring or
    the clickable ``Ver más`` footer. The summary line stays on top so a copied
    nmap run is understandable without the surrounding conversation.
    """
    summary = summarize_tool_result(result)
    structured = structured_output(result)
    value, is_diff = trace_text(result)
    if structured is not None:
        value = json.dumps(structured, ensure_ascii=False, indent=2, default=str)
    elif not is_diff:
        value = "\n".join(data_lines(value, width=None)[0])
    parts = [summary] if summary else []
    body = clean_text(value).strip("\n")
    if body:
        parts.append(body)
    if is_guardrail(result):
        guidance = clean_text(str(
            result.get("guidance") or result.get("error") or ""
        )).strip()
        if guidance:
            parts.append(guidance)
    return "\n\n".join(part for part in parts if part)


def observation(message: dict[str, Any]) -> dict[str, Any]:
    metadata = message.get("metadata") or {}
    result = metadata.get("tool_result") or {}
    try:
        parsed = json.loads(message.get("content") or "")
    except (ValueError, TypeError):
        parsed = None
    if isinstance(parsed, dict):
        result = {**parsed, **result}
    normalized = dict(result) if isinstance(result, dict) else {"success": False}
    normalized.setdefault("tool_id", str(metadata.get("tool_id") or "tool"))
    return normalized


def render_message(message: dict[str, Any], *, expanded: bool = False,
                   width: int | None = None, no_color: bool = False) -> str:
    meta = message.get("metadata") or {}
    kind = meta.get("kind")
    if kind == "react.action":
        thought = render_thought(str(meta.get("thought") or ""), expanded=expanded,
                                 width=width or 180, no_color=no_color)
        if meta.get("action") == "tool_call":
            call = format_tool_invocation(meta.get("tool_id", "?"),
                                          meta.get("arguments", {}), width=width,
                                          no_color=no_color)
            return f"{thought}\n{call}" if thought else call
        # task_complete / request_clarification carry reasoning too: show it so
        # the cognitive loop is visible even when no tool runs.
        return thought
    if kind == "react.observation":
        return render_tool_result(observation(message), expanded=expanded,
                                  width=width or 100, no_color=no_color)
    return ""
