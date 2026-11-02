"""Step headers: number, tactical phase and a line that fills the width."""

from nexus_core.cli.tui.presentation import turn_header


def test_turn_header_names_step_and_phase():
    text = turn_header(3, "Post-Exploitation", width=60).plain
    assert text.startswith("── paso 3 · Post-Exploitation ──")
    assert len(text) == 60


def test_turn_header_fills_exactly_the_requested_width():
    for width in (40, 80, 120):
        text = turn_header(2, "Enumeration", width=width).plain
        assert len(text) == width
        assert text.endswith("─" * 5)
