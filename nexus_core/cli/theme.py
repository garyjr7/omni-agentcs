"""Cyberpunk palette shared by the ``omni`` REPL and its TUI.

Red + aqua + off-white, with a small amount of green/yellow for verdicts. The
semantic roles live once in :data:`THEME`; renderers name a role instead of a
hex value. The ANSI constants below are compatibility aliases derived from it.
"""

from __future__ import annotations

from dataclasses import dataclass

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def ansi(hex_color: str) -> str:
    """Convert ``#rrggbb`` to the truecolor sequence Rich and the REPL share."""
    value = hex_color.lstrip("#")
    red, green, blue = (int(value[index : index + 2], 16) for index in (0, 2, 4))
    return f"\033[38;2;{red};{green};{blue}m"


@dataclass(frozen=True)
class Theme:
    """Semantic palette. Values are display colours, never layout decisions."""

    #: Operator rail, badges, focus and the single interactive accent.
    primary: str = "#ff0055"
    #: Input panel and ordinary dark surfaces.
    surface: str = "#202226"
    #: Neutral block surface, one step darker than the input panel.
    surface_alt: str = "#16181b"
    #: Quiet frame of a transcript block. Red is reserved for real failures
    #: and the operator's own rail, never for ordinary conversation.
    frame_border: str = "#343941"
    #: High-contrast headings and selected labels.
    text: str = "#ffffff"
    #: The legacy near-white output token, kept separate from pure white.
    white: str = "#f0f4f8"
    #: Secondary prose, timestamps and metadata.
    muted: str = "#787e86"
    #: Disabled states and empty hints.
    subtle: str = "#6a6f76"
    #: Live reasoning and collapsed thought rows.
    thinking: str = "#787e86"
    #: Successful/verified verdicts.
    ok: str = "#56e696"
    #: Real failures, never an orchestrator correction.
    error: str = "#ff4054"
    #: Warnings and pre-execution corrections.
    warn: str = "#ffc950"
    #: Side-panel overlay surface (engagement plan) and its body text.
    overlay: str = "#0d1117"
    overlay_text: str = "#d0d4da"
    #: Approval menu body text and hints on ``surface_alt``.
    approval_text: str = "#e0e4ea"
    approval_hint: str = "#9aa0a6"
    #: Syntax highlighting follows a named Rich theme, not a literal colour.
    syntax_theme: str = "ansi_dark"
    syntax_background: str = "default"
    #: The remaining legacy accents, kept as roles so nothing imports a hex.
    aqua: str = "#00e5ff"
    aqua_dim: str = "#0096af"
    red_dim: str = "#be2d3c"
    offwhite: str = "#d0d4da"
    gray: str = "#787e86"
    blue: str = "#5a96ff"
    magenta: str = "#d26eff"

    # -- prompt_toolkit style fragments ----------------------------------
    @property
    def panel_style(self) -> str:
        return f"bg:{self.surface}"

    @property
    def panel_bar_style(self) -> str:
        return f"fg:{self.primary} bg:{self.surface}"

    @property
    def approval_surface_style(self) -> str:
        return f"bg:{self.surface_alt}"

    @property
    def badge_style(self) -> str:
        return self.primary

    @property
    def hints_style(self) -> str:
        return self.text

    @property
    def secondary_style(self) -> str:
        return f"dim {self.muted}"

    @property
    def thinking_style(self) -> str:
        return f"{self.muted} italic"

    @property
    def keycap_style(self) -> str:
        return f"{self.muted} on {self.surface}"

    @property
    def app_background_style(self) -> str:
        """Default surface behind every region of the TUI.

        Cards are painted one step lighter (``surface``) so a frame reads as a
        card over the screen instead of black-on-black; the transcript never
        relies on the terminal's own background.
        """
        return f"bg:{self.surface_alt}"

    @property
    def result_panel_style(self) -> str:
        # The card surface, one step lighter than ``app_background_style``:
        # a panel has to be distinguishable from the global background.
        return f"on {self.surface}"

    @property
    def result_border_style(self) -> str:
        return self.frame_border

    @property
    def frame_border_style(self) -> str:
        return self.frame_border

    @property
    def dim_style(self) -> str:
        return "dim"

    @property
    def link_style(self) -> str:
        return "dim underline"

    @property
    def primary_bold(self) -> str:
        return f"{self.primary} bold"

    @property
    def title_style(self) -> str:
        return f"bold {self.text}"

    def prompt_toolkit_styles(self) -> dict[str, str]:
        """Named styles registered on the persistent prompt_toolkit app."""
        return {
            "busy": self.primary,
            "scroll": self.primary,
            "placeholder": f"{self.subtle} italic",
        }


THEME = Theme()

#: Aqua: commands, structure, headings and interactive affordances.
AQUA = ansi(THEME.aqua)
AQUA_DIM = ansi(THEME.aqua_dim)
#: Red: agent thinking, risk and failures.
RED = ansi(THEME.error)
RED_DIM = ansi(THEME.red_dim)
#: Off-white: command output and results (readable, low-glare).
OFFWHITE = ansi(THEME.offwhite)
WHITE = ansi(THEME.white)
GRAY = ansi(THEME.gray)
#: Verdicts / accents.
GREEN = ansi(THEME.ok)
YELLOW = ansi(THEME.warn)
BLUE = ansi(THEME.blue)
MAGENTA = ansi(THEME.magenta)
CYAN = AQUA

__all__ = [
    "AQUA",
    "AQUA_DIM",
    "BLUE",
    "BOLD",
    "CYAN",
    "DIM",
    "GRAY",
    "GREEN",
    "MAGENTA",
    "OFFWHITE",
    "RED",
    "RED_DIM",
    "RESET",
    "THEME",
    "Theme",
    "WHITE",
    "YELLOW",
    "ansi",
]
