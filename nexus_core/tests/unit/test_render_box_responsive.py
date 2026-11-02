"""The final summary box follows the terminal and never splits a border."""

from nexus_core.cli import render


def test_box_width_follows_the_terminal(monkeypatch):
    monkeypatch.setenv("COLUMNS", "80")
    assert render.summary_width() == 76
    monkeypatch.setenv("COLUMNS", "120")
    assert render.summary_width() == 100
    monkeypatch.setenv("COLUMNS", "40")
    assert render.summary_width() == 60


def test_box_rows_never_exceed_the_width(monkeypatch, capsys):
    render.set_color_enabled(False)
    monkeypatch.setenv("COLUMNS", "80")
    render.render_summary("una frase corta", width=76)
    rows = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert all(len(row) <= 76 for row in rows)
    assert rows[0].strip().startswith("── resultado final")
    render.set_color_enabled(True)


def test_long_findings_wrap_inside_the_box(capsys):
    render.set_color_enabled(False)
    title = "hallazgo muy largo " * 12
    render.render_summary("resumen", [{"severity": "high", "title": title}], width=70)
    rows = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert all(len(row) <= 70 for row in rows)
    assert sum("[high]" in row for row in rows) == 1
    render.set_color_enabled(True)


def test_wide_characters_count_as_two_cells():
    from prompt_toolkit.utils import get_cwidth

    row = render._box_line("界" * 40, 20)
    assert get_cwidth(row) == 22  # │ + 18 cells + │
