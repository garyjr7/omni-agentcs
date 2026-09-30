"""Status contents, timing and cell-width truncation."""

from unittest.mock import patch

from prompt_toolkit.formatted_text import fragment_list_to_text
from prompt_toolkit.utils import get_cwidth

from nexus_core.cli.tui.status import StatusState, render_status_bar, render_status_plain


def test_status_renders_engagement():
    assert "lab" in render_status_plain(StatusState(engagement_name="lab"))


def test_status_renders_trust_flag():
    assert "TRUST" in render_status_plain(StatusState(trust_mode=True))


def test_status_renders_session_info():
    assert "session abc/shell" in render_status_plain(StatusState(session_uuid="abc", session_type="shell"))


def test_status_renders_provider_model():
    assert "groq/model" in render_status_plain(StatusState(provider_model="groq/model"))


def test_status_renders_tokens_and_cost():
    text = render_status_plain(StatusState(tokens_input=2000, tokens_output=300, cost_usd=0.02))
    assert "2.3k tok" in text and "$0.0200" in text


def test_status_renders_elapsed_human_seconds():
    with patch("time.monotonic", return_value=105):
        assert StatusState(started_at=100).elapsed_human == "5s"


def test_status_renders_elapsed_human_minutes():
    with patch("time.monotonic", return_value=412):
        assert StatusState(started_at=100).elapsed_human == "5m12s"


def test_status_renders_elapsed_human_hours():
    with patch("time.monotonic", return_value=7420):
        assert StatusState(started_at=100).elapsed_human == "2h02m"


def test_status_truncates_to_width():
    state = StatusState(engagement_name="界" * 20)
    text = fragment_list_to_text(render_status_bar(state, width=11))
    assert get_cwidth(text) <= 11
    assert text == "界" * 5


def test_status_plain_version_no_ansi():
    assert "\x1b" not in render_status_plain(StatusState(trust_mode=True))


def test_unknown_cost_is_not_reported_as_zero():
    assert "$n/d" in render_status_plain(StatusState(cost_known=False))


def test_status_zero_width():
    assert not fragment_list_to_text(render_status_bar(StatusState(), width=0))
