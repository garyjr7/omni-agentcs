"""Welcome banner with live stats and rotating tips (stdlib + raw ANSI only).

The banner is presentation-only: every value it shows is read from state the
session already has (tool catalog, LLM resolution, audit chain, engagement). It
never writes to the durable record and it degrades to plain ASCII text when
colour is disabled or the terminal is too narrow.
"""

from __future__ import annotations

import os
import random
import re
import shutil
import sys

from . import render

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

#: Below this width the ASCII art is dropped and only the stats block is shown.
MIN_WIDTH_FOR_ART = 80
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
) -> str:
    """Build the full banner (art, stats block and rotating tip).

    ``no_color`` switches both the ANSI codes and the audit marker to plain
    text (``ok`` / ``INVALID``); otherwise the marker is ``✓`` / ``✗``.
    """
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


__all__ = [
    "BANNER_ASCII",
    "MIN_WIDTH_FOR_ART",
    "TIPS",
    "build_banner",
    "pick_tip",
    "render_banner",
]
