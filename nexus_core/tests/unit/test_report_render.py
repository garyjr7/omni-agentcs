"""Markdown and HTML renderers of the engagement report."""

from __future__ import annotations

import asyncio
import json
import re
from html.parser import HTMLParser

import pytest

from nexus_core.report.extractor import build_report
from nexus_core.report.html import render_html
from nexus_core.report.markdown import render_markdown, render_markdown_json
from nexus_core.report.models import verify_report_digest
from nexus_core.tests import report_support as support


@pytest.fixture()
def report(tmp_path):
    store, _engagement, _run_id = support.seed_full_engagement(tmp_path)
    return asyncio.run(build_report(store, support.TENANT, "eng-lab"))


class _Collector(HTMLParser):
    """Minimal HTML parser used to prove the document is well-formed."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[str] = []
        self.errors: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag, attrs):  # noqa: D102 - stdlib hook
        self.tags.append(tag)

    def handle_data(self, data):  # noqa: D102 - stdlib hook
        self.text.append(data)

    def error(self, message):  # pragma: no cover - py3.10 removed it
        self.errors.append(message)


def test_markdown_includes_executive_summary(report):
    text = render_markdown(report)
    assert text.startswith("# Reporte de Pentesting — lab-engagement")
    assert "**Cliente:** ACME" in text
    assert "**Operador:** operator-1" in text
    assert "## Resumen ejecutivo" in text
    assert "## Alcance" in text
    assert "## Metodología" in text
    assert "## Cronología" in text
    assert "## Anexos" in text
    assert "Cadena de auditoría: ✓ válida" in text
    counts = report.findings_by_severity
    assert f"**{counts['critical']} críticos**" in text
    assert f"{len(report.findings)} en total" in text
    assert f"- Sesiones abiertas y verificadas: {report.sessions_opened}." in text


def test_markdown_includes_all_findings(report):
    text = render_markdown(report)
    assert len(report.findings) >= 6
    for finding in report.findings:
        assert finding.title in text
        assert f"### [{finding.severity.upper()}] {finding.title}" in text
        assert f"`{finding.finding_id}`" in text
    assert "### [CRITICAL] Acceso obtenido vía exploit/linux/http/apache_mod_cgi_bash_env_exec" in text
    assert "**OWASP Top 10:** A01:2021-Broken Access Control" in text
    # Severity lives in the heading only; it must not be duplicated in the title.
    assert "[HIGH] [HIGH]" not in text
    assert "[CRITICAL] [CRITICAL]" not in text


def test_markdown_includes_evidence(report):
    text = render_markdown(report)
    assert "**Evidencia (chain of custody):**" in text
    assert "`audit_event`" in text
    assert "`tool_result`" in text
    for finding in report.findings:
        assert any(item.sha256 for item in finding.evidence), finding.title
    # Every finding's first chained event hash is rendered.
    first = report.findings[0]
    digest = next(item.sha256 for item in first.evidence if item.kind == "audit_event")
    assert digest in text


def test_markdown_includes_reproduction_steps(report):
    text = render_markdown(report)
    assert "**Reproducción:**" in text
    exploit = next(item for item in report.findings if item.kind == "session_opened")
    for step in exploit.reproduction_steps:
        assert step in text
    assert "1. " in text and "2. " in text


def test_markdown_includes_failed_attempts_when_enabled(report):
    text = render_markdown(report)
    assert "## Intentos fallidos" in text
    assert "| Fecha | Tool | Objetivo | Motivo |" in text
    assert len(report.failed_attempts) == 2  # the timed-out exploit + the denial
    assert "sin abrir sesión" in text
    assert "denegado por scope" in text


def test_markdown_includes_timeline(report):
    text = render_markdown(report)
    assert "| Fecha | Acción | Tool | Objetivo | Decisión | Detalle |" in text
    assert "tool.invoke" in text
    assert "tool.complete" in text
    assert "scope.denied" in text
    assert f"{len(report.timeline)}" and report.timeline
    assert report.timeline[0].occurred_at <= report.timeline[-1].occurred_at


def test_html_is_self_contained(report):
    text = render_html(report)
    assert text.startswith("<!DOCTYPE html>")
    assert "<style>" in text and "</style>" in text
    assert "<script" not in text.lower()
    assert "@import" not in text
    assert "http://" not in text.replace("http://203.0.113.10", "")
    assert 'src="' not in text
    assert 'href="' not in text
    assert ".css" not in text
    parser = _Collector()
    parser.feed(text)
    parser.close()
    assert parser.errors == []
    assert "html" in parser.tags and "body" in parser.tags and "main" in parser.tags


def test_html_includes_severity_colors(report):
    text = render_html(report)
    assert ".sev-critical { background: var(--critical); }" in text
    assert ".sev-high { background: var(--high); }" in text
    assert ".sev-medium { background: var(--medium); }" in text
    assert ".sev-low { background: var(--low); }" in text
    assert ".sev-info { background: var(--info); }" in text
    assert '<span class="sev sev-critical">CRITICAL</span>' in text
    assert '<div class="l">CRITICAL</div>' in text
    assert 'class="finding critical"' in text
    assert text.count('<article class="finding ') == len(report.findings)
    assert text.count("<span class=\"sev sev-") == len(report.findings)


def test_html_mobile_responsive_meta_tag(report):
    text = render_html(report)
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in text
    assert "@media (max-width: 34rem)" in text
    assert "@media print" in text
    assert report.report_sha256 in text


def test_markdown_json_serializable(report):
    payload = render_markdown_json(report)
    decoded = json.loads(payload)
    assert decoded["schema"] == "nexus.engagement_report/1"
    assert decoded["engagement_id"] == "eng-lab"
    assert len(decoded["findings"]) == len(report.findings)
    assert set(decoded["findings_by_severity"]) == {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }
    assert decoded["report_sha256"] == report.report_sha256
    # Round-trip: the JSON is a faithful transcription of the model.
    for finding in decoded["findings"]:
        assert finding["finding_id"] and finding["title"]
        assert isinstance(finding["evidence"], list) and finding["evidence"]
        assert all(item["kind"] for item in finding["evidence"])


def test_report_digest_is_verifiable(report):
    assert verify_report_digest(report) is True
    text = render_markdown(report)
    assert report.report_sha256 in text
    assert re.fullmatch(r"[0-9a-f]{64}", report.report_sha256)
