"""Markdown must break lines, honour ``<br>`` and fit tables to the terminal."""

from __future__ import annotations

from nexus_core.cli.tui.markdown import DEFAULT_READING_WIDTH, render_markdown


def test_markdown_br_becomes_newline():
    rendered = render_markdown("linea1<br>linea2", no_color=True)
    assert "\n" in rendered
    assert "<br" not in rendered
    assert rendered.splitlines() == ["linea1", "linea2"]


def test_markdown_br_variants_and_case():
    for tag in ("<br>", "<br/>", "<br />", "<BR>"):
        rendered = render_markdown(f"a{tag}b", no_color=True)
        assert rendered.splitlines() == ["a", "b"]


def test_markdown_long_paragraph_wraps_at_reading_width():
    rendered = render_markdown("palabra " * 120)
    lines = rendered.splitlines()
    assert len(lines) > 1
    assert all(len(line) <= DEFAULT_READING_WIDTH for line in lines)
    assert " ".join(lines).split() == ["palabra"] * 120


def test_markdown_wrap_respects_a_narrow_width():
    rendered = render_markdown("una frase bastante larga para partir", no_color=True, max_width=20)
    assert all(len(line) <= 20 for line in rendered.splitlines())


def test_markdown_wide_table_truncates_cells():
    table = "| col1 | col2 |\n|---|---|\n| " + "x" * 200 + " | y |"
    rendered = render_markdown(table, no_color=True, max_width=60)
    assert "…" in rendered
    assert all(len(line) <= 60 for line in rendered.splitlines())


def test_markdown_table_never_exceeds_width():
    table = "| a | b | c |\n|---|---|---|\n| " + "z" * 90 + " | " + "w" * 90 + " | " + "q" * 90 + " |"
    rendered = render_markdown(table, no_color=True, max_width=100)
    assert all(len(line) <= 100 for line in rendered.splitlines())


def test_markdown_br_inside_a_table_keeps_the_row_intact():
    table = "| Area | Detalle |\n| --- | --- |\n| Recon | uno <br> dos |"
    rendered = render_markdown(table, no_color=True, max_width=60)
    lines = rendered.splitlines()
    # Every line is still part of the table: no row was split into prose.
    assert all(line.startswith(("+", "|")) for line in lines)
    assert "uno" in rendered and "dos" in rendered
    assert "<br" not in rendered


def test_markdown_headers_use_cyan():
    rendered = render_markdown("# Uno\n## Dos\n### Tres")
    assert "\x1b[1;4;36mUno" in rendered
    assert "\x1b[1;36mDos" in rendered
    assert "\x1b[1mTres" in rendered


def test_markdown_keeps_blank_lines_between_paragraphs():
    assert render_markdown("primero\n\nsegundo", no_color=True) == "primero\n\nsegundo"


def test_markdown_list_continuation_is_indented():
    rendered = render_markdown("- " + "palabra " * 40, no_color=True, max_width=40)
    lines = rendered.splitlines()
    assert lines[0].startswith("  • palabra")
    assert lines[1].startswith("    palabra")
    assert all(len(line) <= 40 for line in lines)


def test_markdown_no_color_has_no_ansi_after_wrapping():
    rendered = render_markdown("# Titulo\n" + "**negrita** " * 40, no_color=True, max_width=30)
    assert "\x1b" not in rendered
    assert all(len(line) <= 30 for line in rendered.splitlines())
