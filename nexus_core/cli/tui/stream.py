"""Compact, evidence-based presentation of durable tool messages."""

import json
import re
import shlex

from ..theme import AQUA, AQUA_DIM, GRAY, GREEN, OFFWHITE, RED, RESET

PREFIXES = {
    "nexus.recon.nmap": "Recon-NMAP", "nexus.recon.subfinder": "Recon-Subfinder",
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


def _line(text, width=100):
    text = "".join(c if c.isprintable() else " " for c in str(text))
    return text if len(text) <= width else text[:max(0, width - 1)] + "…"


def data_lines(output: str, *, width: int = 100) -> tuple[list[str], bool]:
    """Clean data lines of a tool output, plus whether any line was clipped.

    Empty/separator lines and adjacent duplicate progress lines are discarded;
    every kept line is bounded to ``width``.
    """
    lines = []
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


def render_thought(text, *, width: int = 180):
    """The model's reasoning of one ReAct iteration (agent thinking, in red).

    The thought is durable (``react.action`` metadata) and is emitted *before*
    the tool it justifies, so the human sees the intent before the action.
    """
    text = str(text or "").strip()
    if not text:
        return ""
    return f"{RED}💭 {_line(text, width)}{RESET}"


def format_tool_invocation(tool_id, arguments):
    args = arguments if isinstance(arguments, dict) else {}
    if tool_id == "nexus.recon.nmap":
        # This is the argv constructed by the existing handler, including XML.
        flags = args.get("flags") or []
        flags = flags if isinstance(flags, list) else [flags]
        text = shlex.join(["nmap", *map(str, flags), "-oX", "-", str(args.get("target", ""))])
    else:
        # Other handlers may transform arguments. Display the durable request
        # honestly rather than inventing a shell command they may not execute.
        text = str(tool_id) + " " + json.dumps(args, ensure_ascii=False, default=str)
    # Tool calls: gear glyph in aqua, dim tool tag, aqua command line.
    return f"{AQUA}⚙{RESET}{AQUA_DIM} {tool_prefix(tool_id)}{RESET} {AQUA}{_line(text)}{RESET}"


def output_text(result):
    if isinstance(result.get("stdout"), str) and result["stdout"]:
        return result["stdout"]
    output = result.get("output") or ""
    if isinstance(output, str):
        return output
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


def summarize_tool_result(result):
    evidence = result.get("evidence") or {}
    output = result.get("output") or {}
    evidence = evidence if isinstance(evidence, dict) else {}
    if not result.get("success"):
        error = result.get("error") or (output.get("error") if isinstance(output, dict) else None) or "falló"
        method = result.get("verification_method")
        return _line(str(error) + (f" · verification_method={method}" if method else ""))
    parts = []
    for field, label in (("ports_open_total", "puertos abiertos"), ("hosts_up", "hosts up"),
                         ("subdomain_count", "subdominios"), ("findings_count", "hallazgos")):
        if field in evidence:
            parts.append(f"{evidence[field]} {label}")
    if evidence.get("noise_level"):
        parts.append(f"noise: {evidence['noise_level']}")
    if evidence.get("elapsed_seconds") is not None:
        parts.append(f"{evidence['elapsed_seconds']}s")
    return _line(" · ".join(parts) or str(result.get("verification_method") or "completado"))


def render_tool_result(result, *, expanded: bool = False, max_lines: int = 5):
    """Render one tool result as a collapsible card (show more / show less).

    Collapsed (default) keeps ``max_lines`` head/tail data lines and reports how
    many were hidden; ``expanded`` prints the whole output. The last line is a
    clickable footer so the TUI can expand just this card; the summary and
    success marker are always shown. Output is off-white, structure is aqua.
    """
    output = output_text(result)
    total = len(data_lines(output)[0])
    if expanded:
        lines, _ = data_lines(output)
        hidden = 0
    else:
        text, _ = truncate_output(output, max_lines)
        lines = text.splitlines()
        hidden = max(0, total - (len(lines) - (1 if "..." in lines else 0)))
    body = []
    for line in lines:
        if line == "...":
            body.append(f"{GRAY}   ...{RESET}")
        else:
            body.append(f"{OFFWHITE}   -> {line}{RESET}")
    ok = bool(result.get("success"))
    summary = summarize_tool_result(result)
    body.append(f"{GREEN if ok else RED}   {'✓' if ok else '✗'} {summary}{RESET}")
    if hidden:
        body.append(f"{AQUA}   ▼ mostrar {hidden} línea(s) más{RESET}")
    elif expanded and total > max_lines:
        body.append(f"{AQUA}   ▲ mostrar menos{RESET}")
    return "\n".join(body)


def observation(message):
    metadata = message.get("metadata") or {}
    result = metadata.get("tool_result") or {}
    try:
        parsed = json.loads(message.get("content") or "")
    except (ValueError, TypeError):
        parsed = None
    if isinstance(parsed, dict):
        result = {**parsed, **result}
    return result if isinstance(result, dict) else {"success": False}


def render_message(message, *, expanded: bool = False):
    meta = message.get("metadata") or {}
    kind = meta.get("kind")
    if kind == "react.action":
        thought = render_thought(str(meta.get("thought") or ""))
        if meta.get("action") == "tool_call":
            call = format_tool_invocation(meta.get("tool_id", "?"), meta.get("arguments", {}))
            return f"{thought}\n{call}" if thought else call
        # task_complete / request_clarification carry reasoning too: show it so
        # the cognitive loop is visible even when no tool runs.
        return thought
    if kind == "react.observation":
        return render_tool_result(observation(message), expanded=expanded)
    return ""
