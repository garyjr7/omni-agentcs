import threading
from unittest.mock import patch


def test_no_full_screen_clear_during_tool(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    with patch.object(ui.output, "erase_screen") as erase, patch.object(ui.output, "enter_alternate_screen") as alternate:
        ui.session.set_busy()
        for _ in range(100):
            ui.session.print("line")
        ui.session.flush()
        ui.session.clear_busy()
    erase.assert_not_called()
    alternate.assert_not_called()


def test_invalidate_count_bounded_per_second(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    done = threading.Event()
    def burst():
        with patch.object(ui.session._app, "invalidate", wraps=ui.session._app.invalidate) as count:
            for _ in range(1000):
                ui.session.print("event\n")
            ui.session._flush_scrollback()
            assert count.call_count <= 4
        done.set()
    ui.session._dispatch(burst)
    assert done.wait(3)


def test_scrollback_batched_under_heavy_load(tui_factory):
    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    done = threading.Event()
    def burst():
        before = ui.session._scrollback.text
        for n in range(1000):
            ui.session.print(f"event {n}")
        assert ui.session._scrollback.text == before
        ui.session._flush_scrollback()
        assert "event 999" in ui.session._scrollback.text
        done.set()
    ui.session._dispatch(burst)
    assert done.wait(3)


def test_refresh_interval_disabled_when_idle(tui_factory):
    ui = tui_factory()
    ui.session.set_busy()
    ui.session.clear_busy()
    assert ui.session._app.refresh_interval is None


def test_render_rate_limited_during_continuous_output(tui_factory):
    import time
    ui = tui_factory()
    ui.pipe.send_text("start\r")
    ui.session.prompt()
    frames = []
    # PTK throttles frame starts; completion time varies under CPU contention.
    ui.session._app.before_render += lambda _: frames.append(time.monotonic())
    ui.session.set_busy()
    started = time.monotonic()
    until = started + 1.1
    while time.monotonic() < until:
        ui.session.print("event")
        time.sleep(.01)
    ui.session.flush()
    assert len(frames) <= int((time.monotonic() - started) * 10) + 2
