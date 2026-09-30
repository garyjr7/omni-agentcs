"""Compact, evidence-based presentation of durable tool messages."""

import json
import re
import shlex

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


def truncate_output(output: str, max_lines: int = 3, *, width: int = 100) -> tuple[str, bool]:
    """Keep head and tail data lines, with one extra omission marker.

    max_lines counts data lines, not the marker. Width is bounded independently.
    Empty/separator lines and adjacent duplicate progress lines are discarded.
    """
    if max_lines < 1:
        raise ValueError("max_lines must be positive")
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
    if len(lines) <= max_lines:
        return "\n".join(lines), clipped
    tail = lines[-(max_lines - 1):] if max_lines > 1 else []
    return "\n".join([lines[0], "...", *tail]), True


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
    return _line(f"⚙️  {tool_prefix(tool_id)} {text}")


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


def render_tool_result(result):
    text, _ = truncate_output(output_text(result))
    lines = [("   ..." if line == "..." else "   -> " + line) for line in text.splitlines()]
    lines.append(f"   {'✓' if result.get('success') else '✗'} {summarize_tool_result(result)}")
    return "\n".join(lines)


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


def render_message(message):
    meta = message.get("metadata") or {}
    if meta.get("kind") == "react.action" and meta.get("action") == "tool_call":
        return format_tool_invocation(meta.get("tool_id", "?"), meta.get("arguments", {}))
    if meta.get("kind") == "react.observation":
        return render_tool_result(observation(message))
    return ""
