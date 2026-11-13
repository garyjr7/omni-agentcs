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


class _StatusError(Exception):
    def __init__(self, status: int, message: str = "") -> None:
        super().__init__(message)
        self.status_code = status


class _ResponseError(Exception):
    def __init__(self, status: int) -> None:
        super().__init__("upstream rejected the request")
        self.response = type("Response", (), {"status_code": status})()


def test_status_can_come_from_the_response_object():
    report = errors.describe_error(_ResponseError(403))
    assert "autenticación" in report.title.lower()


def test_quota_is_distinct_from_a_plain_rate_limit():
    report = errors.describe_error(_StatusError(429, "quota exceeded"))
    assert "cuota" in report.title.lower()


def test_server_errors_are_reported_as_temporary():
    report = errors.describe_error(_StatusError(503, "service unavailable"))
    assert "no está disponible" in report.title.lower()


def test_invalid_json_is_reported_as_a_model_answer_problem():
    report = errors.describe_error(RuntimeError("invalid JSON from model"))
    assert "respuesta inválida" in report.title.lower()


def test_400_with_json_is_reported_as_invalid_answer():
    report = errors.describe_error(_StatusError(400, "invalid json body"))
    assert "respuesta inválida" in report.title.lower()


def test_missing_api_key_is_a_configuration_error():
    report = errors.describe_error(RuntimeError("OpenAI API key is required"))
    assert "configuración" in report.title.lower()


def test_unknown_detail_is_kept_but_never_as_json():
    report = errors.describe_error(RuntimeError("upstream failed"))
    assert "upstream failed" in report.summary


def test_llm_chain_causes_carry_provider_and_status():
    from nexus_core.llm.abstraction import LLMChainExhausted

    exc = LLMChainExhausted(
        [
            {
                "provider": "openai",
                "status_code": 401,
                "reason": "authentication",
                "message": "raw SDK body {'error': 'secret'}",
            }
        ]
    )
    report = errors.describe_error(exc)
    assert "autenticación" in report.title.lower()
    assert "openai" in report.summary.lower()
    assert "secret" not in "\n".join(report.lines())


def test_report_provider_failure_and_plain_error_are_renderable(capsys):
    errors.report_provider_failure(None, "all LLM providers failed: status 401")
    errors.report_plain_error(RuntimeError("no provider configured"))
    out = capsys.readouterr().out
    assert "autenticación" in out.lower() or "configuración" in out.lower()
    assert "Error code:" not in out
