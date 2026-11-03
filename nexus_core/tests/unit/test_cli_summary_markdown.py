"""Final result: Markdown on the dedicated screen, box on the plain terminal."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from nexus_core.cli.tui.presentation import clean_text, summary_markdown


def _result(**overrides: Any) -> SimpleNamespace:
    values = {
        "status": "completed",
        "iterations": 14,
        "final_summary": "Acceso root verificado y flag capturada.",
        "findings": [{"severity": "critical", "title": "SQLi en /login"}],
        "plan": {
            "phases": [
                {"id": "recon", "label": "Reconocimiento", "status": "done"},
                {"id": "reporting", "label": "Reporte", "status": "pending"},
            ]
        },
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_summary_markdown_lists_facts_findings_branches_and_status():
    text = summary_markdown(_result())
    assert text.startswith("## Resultado")
    assert "Acceso root verificado" in text
    assert "- **[critical]** SQLi en /login" in text
    assert "- Reporte" in text and "- Reconocimiento" not in text
    assert "- estado: completed" in text
    assert "- iteraciones: 14" in text


def test_summary_markdown_keeps_the_empty_summary_readable():
    text = summary_markdown(_result(final_summary=""))
    assert "_(sin resumen)_" in text


def test_tui_renders_the_summary_as_markdown_not_as_a_box(tui_factory: Any):
    session = tui_factory(enable_completion=False).session
    session._session = SimpleNamespace(output=__import__(
        "prompt_toolkit.output", fromlist=["DummyOutput"]
    ).DummyOutput())

    class _Owner:
        use_tui = True

        def __init__(self, tui: Any) -> None:
            self._tui = tui
            self.no_color = True

        def _render_final_markdown(self, result: Any) -> None:
            from nexus_core.cli.session import OmniSession

            OmniSession._render_final_markdown(self, result)  # type: ignore[arg-type]

    owner = _Owner(session)
    owner._render_final_markdown(_result())
    session.flush()
    transcript = clean_text(session.transcript)
    assert "Resultado" in transcript
    assert "Acceso root verificado" in transcript
    assert "[critical] SQLi en /login" in transcript
    assert "┌" not in transcript and "│" not in transcript
    assert max(len(line) for line in transcript.splitlines()) <= 100
