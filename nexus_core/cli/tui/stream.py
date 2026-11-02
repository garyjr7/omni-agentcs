"""Compact, evidence-based presentation of durable tool messages."""

import json
import re
import shlex
from typing import Any

from ..theme import AQUA, AQUA_DIM, OFFWHITE, RESET
from .presentation import clean_text, render_rich, result_diff, thinking, trace_block

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


def _line(text: Any, width: int = 100) -> str:
    value = " ".join(clean_text(str(text)).splitlines())
    return value if len(value) <= width else value[:max(0, width - 1)] + "…"


def data_lines(output: str, *, width: int = 100) -> tuple[list[str], bool]:
    """Clean data lines of a tool output, plus whether any line was clipped.

    Empty/separator lines and adjacent duplicate progress lines are discarded;
    every kept line is bounded to ``width``.
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


def render_thought(text: str, *, width: int = 180, expanded: bool = False) -> str:
    """Muted, single-line reasoning summary, expandable without changing history.

    The thought is durable (``react.action`` metadata) and is emitted *before*
    the tool it justifies, so the human sees the intent before the action.
    """
    text = str(text or "").strip()
    if not text:
        return ""
    return render_rich(thinking(text, expanded=expanded), width=width)


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


def format_tool_invocation(tool_id: str, arguments: Any, *,
                           width: int | None = None) -> str:
    """The call as its own block: phase, tool, then the arguments it received.

    Every branch reads ``display_arguments`` first, so a credential cannot reach
    the transcript through a flag, a path, a nested value or free text. With
    ``width`` the argument text is pre-wrapped and its continuations carry a
    ``↳`` marker; without it the block stays a single line (exports, tests).
    """
    args = arguments if isinstance(arguments, dict) else {}
    from ..render import display_arguments

    safe = display_arguments(args)
    operation = str(tool_id or "").rsplit(".", 1)[-1].lower()
    file_operations = {
        "read": "Read", "create": "Create", "write": "Create",
        "edit": "Edit", "update": "Edit", "write_file": "Create",
        "edit_file": "Edit", "read_file": "Read",
    }
    if operation in file_operations and any(
        marker in str(tool_id).lower() for marker in ("workspace", "file", "filesystem")
    ):
        label = f"• {file_operations[operation]} "
        path = clean_text(str(safe.get("path") or safe.get("file_path") or "?"))
        lines = _invocation_lines(path, width=width, prefix=label)
        return label + lines[0] + "".join(
            f"\n{INVOCATION_CONTINUATION}{line}" for line in lines[1:])
    if tool_id == "nexus.recon.nmap":
        # This is the argv constructed by the existing handler, including XML.
        flags = safe.get("flags") or []
        flags = flags if isinstance(flags, list) else [flags]
        text = shlex.join(["nmap", *map(str, flags), "-oX", "-", str(safe.get("target", ""))])
    else:
        # Other handlers may transform arguments. Display the durable request
        # honestly rather than inventing a shell command they may not execute.
        text = invocation_arguments(safe) or "sin argumentos"
    from .presentation import tactical_phase
    prefix = f"  {tool_prefix(tool_id)} "
    lines = _invocation_lines(text, width=width, prefix=prefix)
    # The tool being invoked is the one aqua element of the line; its output is
    # off-white and the phase stays muted, so the eye follows the action. The
    # exact identifier stays as secondary dispatch metadata.
    continuation = "".join(
        f"\n{AQUA_DIM}{INVOCATION_CONTINUATION}{RESET}{OFFWHITE}{line}{RESET}"
        for line in lines[1:]
    )
    return (f"{AQUA_DIM}· {tactical_phase(tool_id)} · {RESET}{AQUA}[{tool_id}]{RESET}\n"
            f"{AQUA_DIM}  {RESET}{AQUA}{tool_prefix(tool_id)}{RESET} "
            f"{OFFWHITE}{lines[0]}{RESET}{continuation}")


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
                lines.append(f"Puerto {port.get('port', port.get('portid', '?'))}/{port.get('protocol', 'tcp')} "
                             f"{port.get('state', '?')}: {port.get('service', '')}")
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
    output = result.get("output") if isinstance(result.get("output"), dict) else {}
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
    output = result.get("output") if isinstance(result.get("output"), dict) else {}
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
    evidence = result.get("evidence") or {}
    output = result.get("output") or {}
    evidence = evidence if isinstance(evidence, dict) else {}
    if not result.get("success"):
        error = result.get("error") or (output.get("error") if isinstance(output, dict) else None) or "falló"
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
        parts.append(f"noise: {evidence['noise_level']}")
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
    return _line(" · ".join(parts) or str(result.get("verification_method") or "completado"))


def trace_text(result: dict[str, Any]) -> tuple[str, bool]:
    """A diff must not hide accompanying stdout/stderr diagnostics."""
    diff = result_diff(result)
    raw = output_text(result)
    if diff is None:
        return raw, False
    if (result.get("stdout") or result.get("stderr")) and raw != diff:
        return raw + "\n" + diff, True
    return diff, True


def render_tool_result(result: dict[str, Any], *, expanded: bool = False,
                       max_lines: int = 5, width: int = 100, no_color: bool = False) -> str:
    """Fold tool output at five lines with a literal, interactive card toggle."""
    value, is_diff = trace_text(result)
    return render_rich(trace_block(
        value,
        success=bool(result.get("success")), tool_id=str(result.get("tool_id") or "tool"),
        summary=summarize_tool_result(result), expanded=expanded, limit=max_lines,
        diff=is_diff, defer_detail=structured_detail(result)), width=width, no_color=no_color)


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
                   width: int | None = None) -> str:
    meta = message.get("metadata") or {}
    kind = meta.get("kind")
    if kind == "react.action":
        thought = render_thought(str(meta.get("thought") or ""), expanded=expanded)
        if meta.get("action") == "tool_call":
            call = format_tool_invocation(meta.get("tool_id", "?"),
                                          meta.get("arguments", {}), width=width)
            return f"{thought}\n{call}" if thought else call
        # task_complete / request_clarification carry reasoning too: show it so
        # the cognitive loop is visible even when no tool runs.
        return thought
    if kind == "react.observation":
        return render_tool_result(observation(message), expanded=expanded)
    return ""
