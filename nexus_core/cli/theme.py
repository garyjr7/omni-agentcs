"""Cyberpunk palette shared by the ``omni`` REPL and its TUI.

Red + aqua + off-white, with a small amount of green/yellow for verdicts. The
values are ANSI truecolor sequences so they survive ``prompt_toolkit``'s ``ANSI``
parser (which maps them to style attributes); ``--no-color`` strips them, so
every renderer keeps degrading to plain text.
"""

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

#: Aqua: commands, structure, headings and interactive affordances.
AQUA = "\033[38;2;0;229;255m"
AQUA_DIM = "\033[38;2;0;150;175m"
#: Red: agent thinking, risk and failures.
RED = "\033[38;2;255;64;84m"
RED_DIM = "\033[38;2;190;45;60m"
#: Off-white: command output and results (readable, low-glare).
OFFWHITE = "\033[38;2;208;212;218m"
WHITE = "\033[38;2;240;244;248m"
GRAY = "\033[38;2;120;126;134m"
#: Verdicts / accents.
GREEN = "\033[38;2;86;230;150m"
YELLOW = "\033[38;2;255;201;80m"
BLUE = "\033[38;2;90;150;255m"
MAGENTA = "\033[38;2;210;110;255m"
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
    "WHITE",
    "YELLOW",
]
