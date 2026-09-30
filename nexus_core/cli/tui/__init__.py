"""Optional terminal UI; importing this package never requires prompt_toolkit."""

from .session import TuiSession, should_use_tui

__all__ = ["TuiSession", "should_use_tui"]
