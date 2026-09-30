"""The dedicated MSF job view never executes tools or interpolates a shell."""

import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from nexus_core.cli import commands, live_jobs
from nexus_core.cli.session import OmniSession
from nexus_core.cli.tui.output import TuiOutput, route_output


@pytest.fixture
def session(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    value = OmniSession(store=None, use_tui=False,
                        engagement=SimpleNamespace(name="lab", engagement_id="eng"))
    monkeypatch.setattr(live_jobs, "sys", SimpleNamespace(
        executable=sys.executable, stdin=SimpleNamespace(isatty=lambda: True),
        stdout=SimpleNamespace(isatty=lambda: True), stderr=sys.stderr,
    ))
    monkeypatch.setattr(live_jobs, "read_job", lambda uuid: {"status": "running", "result": {}})
    monkeypatch.setattr(live_jobs.shutil, "which", lambda name: "/usr/bin/" + name)
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.delenv("DISPLAY", raising=False)
    return value


def test_cmd_view_live_requires_job_uuid(session, capsys):
    commands.cmd_exploit(session, ["view-live"])
    assert "uso:" in capsys.readouterr().out


def test_cmd_view_live_tmux_when_tmux_available(session, monkeypatch):
    monkeypatch.setenv("TMUX", "socket")
    monkeypatch.setenv("DISPLAY", ":1")
    with patch.object(live_jobs.subprocess, "Popen") as spawn:
        commands.cmd_exploit(session, ["view-live", "job-123"])
    argv = spawn.call_args.args[0]
    assert argv[:4] == ["tmux", "new-window", "-n", "msf-job-123"]
    assert argv[-2:] == ["--watch", "job-123"]
    assert spawn.call_args.kwargs["shell"] is False


def test_cmd_view_live_xterm_when_display_available(session, monkeypatch):
    monkeypatch.setenv("DISPLAY", ":1")
    with patch.object(live_jobs.subprocess, "Popen") as spawn:
        commands.cmd_exploit(session, ["view-live", "job-123"])
    assert spawn.call_args.args[0][:2] == ["x-terminal-emulator", "-e"]


def test_cmd_view_live_fallback_shows_current_state(session, capsys):
    with patch.object(live_jobs.subprocess, "Popen") as spawn:
        commands.cmd_exploit(session, ["view-live", "job-123"])
    text = capsys.readouterr().out
    assert '"status": "running"' in text and "sin seguimiento" in text
    spawn.assert_not_called()


def test_cmd_view_live_handles_missing_job(session, monkeypatch, capsys):
    monkeypatch.setattr(live_jobs, "read_job", Mock(side_effect=LookupError("job no encontrado")))
    with patch.object(live_jobs.subprocess, "Popen") as spawn:
        commands.cmd_exploit(session, ["view-live", "missing"])
    assert "no encontrado" in capsys.readouterr().out
    spawn.assert_not_called()


@pytest.mark.parametrize("uuid", ["bad;id", "$(id)", "../../secret", "-e", "job\ncmd"])
def test_cmd_view_live_no_shell_injection(session, monkeypatch, uuid):
    read = Mock()
    monkeypatch.setattr(live_jobs, "read_job", read)
    with patch.object(live_jobs.subprocess, "Popen") as spawn:
        commands.cmd_exploit(session, ["view-live", uuid])
    spawn.assert_not_called()
    read.assert_not_called()


def test_cmd_view_live_help_listed(session, capsys):
    commands.cmd_help(session, [])
    assert "/exploit view-live" in capsys.readouterr().out


def test_cmd_view_live_no_subprocess_when_denied(session, monkeypatch):
    monkeypatch.setenv("TMUX", "socket")
    monkeypatch.setattr(live_jobs, "read_job", Mock(side_effect=PermissionError("denegado")))
    with patch.object(live_jobs.subprocess, "Popen") as spawn:
        commands.cmd_exploit(session, ["view-live", "job-123"])
    spawn.assert_not_called()


def test_job_fallback_through_pipe_tui(session, tui_factory):
    ui = tui_factory()
    session._tui = ui.session
    session._output = TuiOutput(ui.session)
    ui.pipe.send_text("/exploit view-live job-123\r")
    line = ui.session.prompt()
    with route_output(session._output):
        commands.run_command(session, line)
    ui.session.flush()
    assert '"status": "running"' in ui.session.transcript


def test_pipe_never_launches_window(session, monkeypatch):
    monkeypatch.setenv("TMUX", "socket")
    monkeypatch.setattr(live_jobs.sys.stdin, "isatty", lambda: False)
    with patch.object(live_jobs.subprocess, "Popen") as spawn:
        commands.cmd_exploit(session, ["view-live", "job-123"])
    spawn.assert_not_called()


def test_read_only_rpc_never_executes_module(monkeypatch):
    class Client:
        def __init__(self, config):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get_module_results(self, uuid):
            assert uuid == "job-123"
            return {"status": "running"}
        def redact(self, value):
            return value
    monkeypatch.setenv("MSF_RPC_PASSWORD", "test-only")
    monkeypatch.setattr("nexus_core.integrations.metasploit.client.MetasploitClient", Client)
    assert asyncio.run(live_jobs.fetch_job("job-123")) == {"status": "running"}


def test_watch_stops_when_job_completes(monkeypatch, capsys):
    snapshots = iter([{"status": "running"}, {"status": "completed"}])
    monkeypatch.setattr(live_jobs, "read_job", lambda uuid: next(snapshots))
    monkeypatch.setattr(live_jobs.time, "sleep", lambda interval: None)
    assert live_jobs.watch("job-123") == 0
    text = capsys.readouterr().out
    assert "running" in text and "completed" in text


def test_unconfigured_rpc_cannot_launch_view(session, monkeypatch):
    monkeypatch.setenv("MSF_RPC_PASSWORD", "")
    with pytest.raises(PermissionError):
        asyncio.run(live_jobs.fetch_job("job-123"))


def test_rpc_denial_cannot_launch_view(session, monkeypatch):
    async def denied(_):
        raise PermissionError("denied")
    monkeypatch.setattr(live_jobs, "read_job", lambda uuid: asyncio.run(denied(uuid)))
    with patch.object(live_jobs, "open_view") as launch:
        commands.cmd_exploit(session, ["view-live", "job-123"])
    launch.assert_not_called()
