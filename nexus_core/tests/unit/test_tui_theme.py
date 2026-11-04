"""The palette has one owner: renderers must not carry hex literals."""

import inspect
import re

from nexus_core.cli import theme
from nexus_core.cli.tui import layout, presentation


def test_renderers_delegate_colours_to_the_theme() -> None:
    hex_literal = re.compile(r"#[0-9a-fA-F]{6}")
    for module in (presentation, layout):
        source = inspect.getsource(module)
        assert not hex_literal.search(source), module.__name__


def test_theme_exposes_the_semantic_roles() -> None:
    for role in ("primary", "surface", "surface_alt", "text", "muted", "thinking",
                 "ok", "error", "warn", "subtle"):
        assert getattr(theme.THEME, role)
    assert theme.THEME.panel_style == "bg:#2a2a2a"
    assert theme.THEME.panel_bar_style == "fg:#ff0055 bg:#2a2a2a"


def test_compatibility_ansi_tokens_are_derived_from_the_theme() -> None:
    assert theme.RED == theme.ansi(theme.THEME.error)
    assert theme.GREEN == theme.ansi(theme.THEME.ok)
    assert theme.YELLOW == theme.ansi(theme.THEME.warn)
