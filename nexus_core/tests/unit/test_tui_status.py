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


def test_status_renders_facts_count():
    assert "3 facts" in render_status_plain(StatusState(facts_count=3))


def test_status_hides_facts_when_zero_or_unknown():
    assert "facts" not in render_status_plain(StatusState(facts_count=0))
    assert "facts" not in render_status_plain(StatusState())


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
    # The provider is high priority, so it is kept and cell-truncated at 11 cols.
    state = StatusState(provider_model="界" * 20)
    text = fragment_list_to_text(render_status_bar(state, width=11))
    assert get_cwidth(text) <= 11
    assert text == "界" * 5


def test_status_drops_engagement_first_when_narrow():
    state = StatusState(engagement_name="very-long-engagement-name", provider_model="groq/m")
    text = fragment_list_to_text(render_status_bar(state, width=16))
    assert "groq/m" in text
    assert "very-long-engagement-name" not in text


def _alert_and_phase_state() -> StatusState:
    """A dense state with an alert, a phase and every droppable segment."""
    return StatusState(
        trust_mode=True,
        plan_phase="Recon",
        plan_progress="1/5",
        provider_model="groq/" + "x" * 40,
        tokens_input=123_456,
        tokens_output=7_890,
        cost_usd=1.2345,
        facts_count=42,
        engagement_name="very-long-engagement-name",
    )


def test_status_alert_and_phase_survive_every_width():
    """Property: alert (TRUST) and phase are never dropped, only truncated."""
    state = _alert_and_phase_state()
    minimum = get_cwidth("TRUST · ▸ Recon 1/5")  # both protected segments fit
    for width in range(minimum, 121):
        text = fragment_list_to_text(render_status_bar(state, width=width))
        assert "TRUST" in text, f"alert dropped at width={width}"
        assert "▸ Recon 1/5" in text, f"phase dropped at width={width}"


def test_status_never_exceeds_width_for_any_width():
    state = _alert_and_phase_state()
    for width in range(0, 201):
        text = fragment_list_to_text(render_status_bar(state, width=width))
        assert get_cwidth(text) <= width, f"overflow at width={width}"


def test_status_drops_droppable_before_protected():
    state = StatusState(trust_mode=True, plan_phase="Recon", provider_model="p" * 60)
    text = fragment_list_to_text(render_status_bar(state, width=20))
    assert "TRUST" in text and "▸ Recon" in text
    assert "pppp" not in text


def test_status_plain_version_no_ansi():
    assert "\x1b" not in render_status_plain(StatusState(trust_mode=True))


def test_unknown_cost_is_not_reported_as_zero():
    assert "$—" in render_status_plain(StatusState(cost_known=False))


def test_status_zero_width():
    assert not fragment_list_to_text(render_status_bar(StatusState(), width=0))
