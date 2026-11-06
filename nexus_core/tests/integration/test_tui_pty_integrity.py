"""Integrity of the TUI on a real pseudo-terminal.

``DummyOutput`` and byte-counting cannot show whether a log bypassed the
renderer; only a real PTY reproduces cursor movement. This drives a live
``TuiSession`` under a PTY with ``NEXUS_LOG_LEVEL=info`` and checks that the
INFO line was drawn *by* the TUI (once, inside the scrollback) instead of
scribbled onto the terminal behind its back.
"""

from __future__ import annotations

import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

DRIVER = '''
from nexus_core.cli.tui.session import TuiSession
from nexus_core.cli.tui.output import capture_output
from nexus_core.utils.logger import get_logger

session = TuiSession(use_tui=True)
probe = get_logger("pty.probe")
probe.logger.setLevel(20)  # logging.INFO
probe.logger.propagate = False
with capture_output(session):
    probe.info("PROBE-INFO-LINE")
    try:
        session.prompt("--> ")
    except (EOFError, KeyboardInterrupt):
        pass
session.close()
'''


def _resize(fd: int, rows: int = 35, columns: int = 110) -> None:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))


@pytest.mark.pty
def test_logs_stay_inside_the_router_on_a_real_pty(tmp_path):
    driver = tmp_path / "pty_driver.py"
    driver.write_text(DRIVER, encoding="utf-8")
    master, slave = pty.openpty()
    _resize(master)
    env = {
        **os.environ,
        "NEXUS_LOG_LEVEL": "info",
        "NO_COLOR": "1",
        "TERM": "xterm-256color",
        "PYTHONPATH": str(REPO_ROOT),
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
    }
    proc = subprocess.Popen(
        [sys.executable, str(driver)], stdin=slave, stdout=slave, stderr=slave,
        env=env, cwd=str(REPO_ROOT), close_fds=True,
    )
    os.close(slave)
    output = b""
    try:
        deadline = time.time() + 20
        sent = False
        while time.time() < deadline:
            if not sent and time.time() > deadline - 19:
                time.sleep(1.0)
                os.write(master, b"hola\r")
                sent = True
            readable, _, _ = select.select([master], [], [], 0.5)
            if readable:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output += chunk
            elif proc.poll() is not None:
                break
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            proc.kill()
        os.close(master)

    text = output.decode("utf-8", errors="replace")
    assert proc.returncode == 0, text[-2000:]
    # The INFO log reached the screen through the router.
    assert "PROBE-INFO-LINE" in text
    # prompt_toolkit repaints the whole inline region after the submitted line
    # (``\x1b[J`` erases to end of screen), so the raw byte stream holds every
    # frame. Inspect the frame that accepted the input: it is what the operator
    # sees, and it must contain the log line exactly once, with no duplicates.
    frames = text.split("\x1b[J")
    # The prompt is drawn inside the branded panel: the placeholder hint sits
    # between the ``--> `` marker and the typed text, so the literal
    # ``--> hola`` no longer exists in the byte stream. Anchor on a drawn frame
    # that carries both the prompt marker and the submitted text, and keep the
    # invariant: that frame must show the router's log line exactly once.
    submitted = [
        frame for frame in frames if "-->" in frame and "hola" in frame
    ]
    assert submitted, text[-2000:]
    final_frame = submitted[-1]
    assert final_frame.count("PROBE-INFO-LINE") == 1
