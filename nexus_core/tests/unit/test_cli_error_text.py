"""Provider failures reach the operator as prose, never as an SDK JSON body."""

from __future__ import annotations

import pytest

from nexus_core.cli import errors


class _AuthError(Exception):
    status_code = 401

    def __init__(self) -> None:
        super().__init__(
            "Error code: 401 - {'error': {'message': 'Incorrect API key provided', "
            "'type': 'invalid_request_error'}}"
        )


class _RateLimitError(Exception):
    status_code = 429

    def __init__(self) -> None:
        super().__init__("Error code: 429 - {'error': {'message': 'rate limit exceeded'}}")


def test_auth_error_is_actionable_and_never_contains_the_payload():
    report = errors.describe_error(_AuthError(), operation="la consulta")
    text = "\n".join(report.lines())
    assert "Error de autenticación" in report.title
    assert "401" in report.summary
    assert "omni auth login" in text
    assert "Error code:" not in text
    assert "{" not in text
    assert "Incorrect API key provided" not in text


def test_rate_limit_has_its_own_message():
    report = errors.describe_error(_RateLimitError())
    text = "\n".join(report.lines())
    assert "Límite de peticiones" in report.title
    assert "429" in report.summary
    assert "{" not in text


def test_provider_failure_summary_recognizes_authentication():
    report = errors.describe_provider_failure(
        "all LLM providers failed: openai: authentication (status 401)"
    )
    assert "autenticación" in report.title.lower()
    assert "401" in report.summary


def test_unknown_error_does_not_echo_json():
    exc = RuntimeError('upstream said {"error": {"message": "secret"}}')
    report = errors.describe_error(exc)
    text = "\n".join(report.lines())
    assert "{" not in text
    assert "secret" not in text
    assert "omni doctor" in text


def test_clean_detail_drops_payloads():
    assert errors.clean_detail('{"error": "x"}') == ""
    assert errors.clean_detail("connection reset") == "connection reset"


class _FakeTui:
    use_tui = True
    text_width = 80

    def __init__(self) -> None:
        self.text: list[str] = []

    def append_scrollback(self, text: str) -> None:
        self.text.append(text)


class _FakeSession:
    no_color = True

    def __init__(self) -> None:
        self._tui = _FakeTui()


def test_tui_renders_an_error_panel_without_raw_json():
    session = _FakeSession()
    report = errors.report_error(session, _AuthError(), operation="la consulta")
    body = "".join(session._tui.text)
    assert report.title in body
    assert "omni auth login" in body
    assert "Error code:" not in body
    assert "{" not in body
    # The panel is a Rich surface, not a bare traceback line.
    assert "╭" in body or "┌" in body


@pytest.mark.parametrize(
    "exc",
    [TimeoutError("timed out"), ConnectionError("connection refused")],
)
def test_transport_errors_are_classified(exc):
    report = errors.describe_error(exc)
    assert "no respondió" in report.title.lower() or "contactar" in report.title.lower()
