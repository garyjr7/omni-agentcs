"""Welcome header: a compact branded block by default, big ASCII art on demand.

The header is presentation-only: every value it shows is read from state the
session already has (tool catalog, LLM resolution, audit chain, engagement,
sandbox mode). It never writes to the durable record and it degrades to plain
ASCII text when colour is disabled or the terminal is too narrow.

Startup shows a three-line compact header (brand, scope/validity, sandbox +
audit) so the engagement lives in exactly one place. The legacy big ASCII art is
only built when explicitly requested (``compact=False``, used by
``omni --about``/``--banner``).
"""

from __future__ import annotations

import os
import random
import re
import shutil
import sys

from . import render

#: Product owner shown in the compact header.
BRAND = "BAJIOWARE"
#: Red-team identity mark (shield/diamond accent).
TEAM_RED = "Team Red ◈"

BANNER_ASCII = r"""
 ██████╗ ███╗   ███╗███╗   ██╗██╗
██╔═══██╗████╗ ████║████╗  ██║██║
██║   ██║██╔████╔██║██╔██╗ ██║██║
██║   ██║██║╚██╔╝██║██║╚██╗██║██║
╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║
 ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝
   A G E N T C S   ·   C L I
"""

TIPS = (
    "Use /ask <question> for conversational help without executing tools.",
    "Use /trust on to auto-approve high-risk actions during an engagement.",
    "Use /report to generate a client-ready report with CVSS and MITRE.",
    "Use /session attach <uuid> to interact with an open Meterpreter session.",
    "Use /scope to review the current engagement scope.",
    "Use /tools to list all available durable tools.",
    "Use /findings to see a summary of discovered vulnerabilities.",
    "Use /timeline to review the audit chain chronologically.",
    "Use /export to dump the current session to Markdown.",
    "Use /approvals to review pending high-risk authorizations.",
    "Use /help for the full list of meta-commands.",
    "Use Ctrl+C to interrupt input without killing the session.",
    "Use /detach to leave a session without killing it.",
)

#: Human note per sandbox mode; makes the guarantees visible at a glance.
SANDBOX_NOTES: dict[str, str] = {
    "local": "sin aislamiento",
    "local_strict": "sin aislamiento de red",
    "oci": "container aislado · sin red",
    "oci_network": "container · red filtrada por scope",
}

#: Below this width the ASCII art is dropped and only the stats block is shown.
MIN_WIDTH_FOR_ART = 80
#: Default inner width of the compact header (columns between the corners).
DEFAULT_HEADER_WIDTH = 68
#: Prefixes of the Metasploit-style stats block (one character shorter on top).
HEADER_PREFIX = "       =[ "
STATS_PREFIX = " + -- --=[ "
TIP_PREFIX = " Tip: "

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")


def pick_tip() -> str:
    """Return one tip. Deterministic when ``NEXUS_TIP_SEED`` is an integer."""
    seed = os.getenv("NEXUS_TIP_SEED")
    if seed is not None and str(seed).strip():
        try:
            return TIPS[int(str(seed).strip()) % len(TIPS)]
        except (TypeError, ValueError):
            pass
    return random.choice(TIPS)


def _terminal_width(width: int | None = None) -> int:
    """Effective terminal width: explicit argument, then the real terminal."""
    if width is not None:
        try:
            return max(1, int(width))
        except (TypeError, ValueError):
            pass
    try:
        return max(1, int(shutil.get_terminal_size().columns))
    except Exception:  # noqa: BLE001 - cosmetic only, never break the REPL
        return 80


def _art_lines() -> list[str]:
    """The ASCII art, tagline included as the last line."""
    return [line for line in BANNER_ASCII.strip("\n").splitlines() if line.strip()]


def _paint(text: str, *codes: str, colored: bool = True) -> str:
    """ANSI-wrap ``text`` only when this banner was asked to use colour."""
    if not colored:
        return str(text)
    return render.paint(text, *codes)


def _highlight(text: str, needle: str, *codes: str, colored: bool = True) -> str:
    """Wrap the first occurrence of ``needle`` in ANSI codes (alignment kept)."""
    if not needle or not codes or not colored:
        return text
    index = text.find(needle)
    if index < 0:
        return text
    return text[:index] + render.paint(needle, *codes) + text[index + len(needle) :]


def _fit(text: str, width: int) -> str:
    """Truncate ``text`` to ``width`` visible columns (ASCII ellipsis)."""
    text = str(text)
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "…"


# --------------------------------------------------------------------- compact
def _row(left: str, right: str, total: int) -> str:
    """One ``│ left ...right │`` row padded/truncated to ``total`` columns."""
    inner = max(1, total - 4)  # "│ " + content + " │"
    left = _fit(left, inner)
    right = _fit(right, max(0, inner - len(left) - 1))
    gap = max(1, inner - len(left) - len(right))
    content = left + " " * gap + right
    return "│ " + _fit(content, inner) + " │"


def _top(text: str, total: int) -> str:
    """Top border: ``╭─ text ─────╮`` padded/truncated to ``total`` columns."""
    inner = max(1, total - 2)
    body = _fit(f"─ {text} ", inner)
    return "╭" + body + "─" * max(0, inner - len(body)) + "╮"


def _bottom(total: int) -> str:
    return "╰" + "─" * max(1, total - 2) + "╯"


def build_header(
    *,
    version: str,
    engagement_name: str | None,
    scope_summary: str | None = None,
    valid_until: str | None = None,
    sandbox_mode: str | None = None,
    audit_chain_valid: bool = True,
    no_color: bool = False,
    width: int | None = None,
    include_tip: bool = True,
) -> str:
    """Build the three-line compact header shown at REPL startup.

    The engagement (and the model) live here, once; the prompt and the status
    bar no longer repeat them.
    """
    colored = not no_color
    name = str(engagement_name) if engagement_name else "sin engagement"
    scope = str(scope_summary) if scope_summary else "alcance no disponible"
    valid = f"hasta {valid_until}" if valid_until else ""
    if sandbox_mode is None:
        from nexus_core.kernel.sandbox_modes import active_mode

        sandbox_mode = active_mode().value
    note = SANDBOX_NOTES.get(str(sandbox_mode), "")
    sandbox = f"sandbox {sandbox_mode}" + (f" ({note})" if note else "")
    marker = (
        ("audit ✓ ok" if audit_chain_valid else "audit ✗ INVALID")
        if colored
        else ("audit ok" if audit_chain_valid else "audit INVALID")
    )

    if width is None:
        # Follow the real terminal so a narrow window never wraps the header,
        # but never grow past the designed width on a very wide one.
        total = max(40, min(DEFAULT_HEADER_WIDTH, _terminal_width() - 2))
    else:
        total = max(40, min(100, int(width) - 2))

    top = _top(f"{BRAND} · OMNIAGENTCS ── {TEAM_RED} ── {name}", total)
    row_scope = _row(f"scope  {scope}", valid, total)
    row_sandbox = _row(sandbox, marker, total)
    lines = [top, row_scope, row_sandbox, _bottom(total)]

    if colored:
        lines[0] = _highlight(lines[0], BRAND, render.AQUA, render.BOLD, colored=True)
        lines[0] = _highlight(lines[0], TEAM_RED, render.RED, render.BOLD, colored=True)
        if engagement_name:
            lines[0] = _highlight(lines[0], name, render.YELLOW, colored=True)
        lines[2] = _highlight(
            lines[2],
            "✓ ok" if audit_chain_valid else "✗ INVALID",
            render.GREEN if audit_chain_valid else render.RED,
            colored=True,
        )
        lines[2] = _highlight(lines[2], sandbox_mode, render.AQUA, colored=True)

    if include_tip:
        tip = TIP_PREFIX + pick_tip()
        lines.append("")
        lines.append(_paint(tip, render.DIM, colored=colored))
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------- legacy
def _build_art_banner(
    *,
    version: str,
    tools_count: int,
    providers_count: int,
    engagement_name: str | None,
    audit_chain_valid: bool,
    msfrpcd_version: str | None,
    llm_summary: str,
    sandbox_mode: str | None,
    no_color: bool,
    width: int | None,
    include_tip: bool,
) -> str:
    """The legacy big ASCII banner (only shown with ``--about``/``--banner``)."""
    colored = not no_color
    name = str(engagement_name) if engagement_name else "none"
    if sandbox_mode is None:
        from nexus_core.kernel.sandbox_modes import active_mode

        sandbox_mode = active_mode().value
    header = f"OmniAgentCS v{version}"
    tools_line = (
        f"{int(tools_count)} tools · {int(providers_count)} providers · "
        f"sandbox: {sandbox_mode} · engagement: {name}"
    )
    marker = ("✓" if audit_chain_valid else "✗") if colored else (
        "ok" if audit_chain_valid else "INVALID"
    )
    audit_line = (
        f"audit-chain {marker} · msfrpcd {msfrpcd_version or 'n/a'} · {llm_summary}"
    )

    inner = max(len(header), len(tools_line), len(audit_line))
    top = HEADER_PREFIX + header.ljust(inner + 1) + " ]"
    middle = STATS_PREFIX + tools_line.ljust(inner) + " ]"
    bottom = STATS_PREFIX + audit_line.ljust(inner) + " ]"
    if colored:
        top = _highlight(top, header, render.BOLD, colored=colored)
        middle = _highlight(middle, f"{int(tools_count)} tools", render.BOLD, colored=colored)
        middle = _highlight(
            middle, f"{int(providers_count)} providers", render.BOLD, colored=colored
        )
        middle = _highlight(middle, name, render.YELLOW, colored=colored)
        bottom = _highlight(
            bottom,
            marker,
            render.GREEN if audit_chain_valid else render.RED,
            colored=colored,
        )
        bottom = _highlight(bottom, str(llm_summary), render.BOLD, colored=colored)

    lines: list[str] = []
    if _terminal_width(width) >= MIN_WIDTH_FOR_ART:
        art = _art_lines()
        # Let the terminal theme provide contrast: bold cyan can map to an
        # intense bright palette and obscure the block-letter shapes.
        lines.extend(art)
        lines.append("")
    lines.extend((top, middle, bottom))
    if include_tip:
        tip = TIP_PREFIX + pick_tip()
        lines.append("")
        lines.append(_paint(tip, render.DIM, colored=colored))
    return "\n".join(lines) + "\n"


def build_banner(
    *,
    version: str,
    tools_count: int,
    providers_count: int,
    engagement_name: str | None,
    audit_chain_valid: bool,
    msfrpcd_version: str | None,
    llm_summary: str,
    sandbox_mode: str | None = None,
    no_color: bool = False,
    width: int | None = None,
    include_tip: bool = True,
    compact: bool = True,
    scope_summary: str | None = None,
    valid_until: str | None = None,
) -> str:
    """Build the startup header.

    ``compact`` (default) returns the three-line branded header; ``compact=False``
    returns the legacy big ASCII art (``omni --about``/``--banner``).
    """
    if compact:
        return build_header(
            version=version,
            engagement_name=engagement_name,
            scope_summary=scope_summary,
            valid_until=valid_until,
            sandbox_mode=sandbox_mode,
            audit_chain_valid=audit_chain_valid,
            no_color=no_color,
            width=width,
            include_tip=include_tip,
        )
    return _build_art_banner(
        version=version,
        tools_count=tools_count,
        providers_count=providers_count,
        engagement_name=engagement_name,
        audit_chain_valid=audit_chain_valid,
        msfrpcd_version=msfrpcd_version,
        llm_summary=llm_summary,
        sandbox_mode=sandbox_mode,
        no_color=no_color,
        width=width,
        include_tip=include_tip,
    )


def render_banner(text: str, *, no_color: bool = False) -> None:
    """Print the banner to stdout, stripping ANSI when colour is off."""
    output = str(text or "")
    if no_color or not render.color_enabled():
        output = _ANSI_RE.sub("", output)
    try:
        sys.stdout.write(output)
        sys.stdout.flush()
    except (ValueError, OSError):  # pragma: no cover - closed/broken stdout
        pass


def describe_scope(scope: object) -> str:
    """``"1 CIDR · 1 dominio · 0 URLs"`` one-liner for the compact header."""
    if scope is None:
        return ""
    cidrs = getattr(scope, "cidrs", ()) or ()
    domains = getattr(scope, "domains", ()) or ()
    urls = getattr(scope, "urls", ()) or ()
    exclusions = getattr(scope, "exclusions", ()) or ()
    parts = [
        f"{len(cidrs)} CIDR{'s' if len(cidrs) != 1 else ''}",
        f"{len(domains)} dominio{'s' if len(domains) != 1 else ''}",
        f"{len(urls)} URL{'s' if len(urls) != 1 else ''}",
    ]
    if exclusions:
        parts.append(f"{len(exclusions)} exclusión{'es' if len(exclusions) != 1 else ''}")
    return " · ".join(parts)


__all__ = [
    "BANNER_ASCII",
    "BRAND",
    "DEFAULT_HEADER_WIDTH",
    "MIN_WIDTH_FOR_ART",
    "SANDBOX_NOTES",
    "TEAM_RED",
    "TIPS",
    "build_banner",
    "build_header",
    "describe_scope",
    "pick_tip",
    "render_banner",
]
