"""Final result: Markdown on the dedicated screen, box on the plain terminal."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from nexus_core.cli.tui.presentation import clean_text, summary_markdown
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore


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


def test_summary_markdown_renders_services_below_the_summary():
    facts = [
        {"fact_type": "service", "key": "10.67.178.116:135/tcp",
         "value": {"service": "msrpc", "state": "open"}},
        {"fact_type": "service", "key": "10.67.178.116:445/tcp",
         "value": {"service": "microsoft-ds", "state": "open"}},
    ]
    text = summary_markdown(_result(), service_facts=facts,
                            report_path="reports/lab-1")
    assert text.index("Acceso root verificado") < text.index("### Servicios")
    assert "| 135 | msrpc | open |" in text
    assert "| 445 | microsoft-ds | open |" in text
    assert "*Informe completo en reports/lab-1*" in text


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
            self.store = None
            self.tenant_id = "system"
            self.engagement_id = None

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


def test_tui_completed_run_reads_services_from_the_blackboard(tui_factory: Any, tmp_path: Any):
    store = ControlStore(tmp_path / "summary.db")
    store.initialize()
    board = Blackboard(store)
    board.record(
        tenant_id="system", engagement_id="eng-1", fact_type="service",
        key="10.67.178.116:135/tcp",
        value={"service": "msrpc", "state": "open"},
        source="nexus.recon.nmap", created_by="tester",
    )
    board.record(
        tenant_id="system", engagement_id="eng-1", fact_type="service",
        key="10.67.178.116:445/tcp",
        value={"service": "microsoft-ds", "state": "open"},
        source="nexus.recon.nmap", created_by="tester",
    )
    session = tui_factory(enable_completion=False).session

    class _Owner:
        use_tui = True

        def __init__(self, tui: Any) -> None:
            self._tui = tui
            self.no_color = True
            self.store = store
            self.tenant_id = "system"
            self.engagement_id = "eng-1"

        def _render_final_markdown(self, result: Any) -> None:
            from nexus_core.cli.session import OmniSession

            OmniSession._render_final_markdown(self, result)  # type: ignore[arg-type]

    owner = _Owner(session)
    owner._render_final_markdown(_result(
        report_artifact={"directory": "reports/lab-1"},
    ))
    session.flush()
    transcript = clean_text(session.transcript)
    assert "Servicios" in transcript
    assert "msrpc" in transcript and "microsoft-ds" in transcript
    assert "Informe completo en reports/lab-1" in transcript
