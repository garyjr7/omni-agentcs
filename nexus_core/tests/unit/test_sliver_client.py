"""``SliverClient``: config, connect lifecycle, fail-closed health and secrets.

The real team server is never contacted: the underlying ``sliver.SliverClient``
is replaced with a mock, so these tests run anywhere.
"""

from __future__ import annotations

import asyncio
import json
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from nexus_core.integrations.sliver.client import (
    SliverAuthError,
    SliverClient,
    SliverConfig,
    SliverError,
    SliverUnavailable,
)
from nexus_core.tests.sliver_support import VALID_CONFIG_JSON

SECRET = "SUPERSECRETTOKEN"


def _write_config(tmp_path, *, payload: str = VALID_CONFIG_JSON) -> str:
    path = tmp_path / "operator.cfg"
    path.write_text(payload)
    return str(path)


def _patch_py_client(monkeypatch, *, connect_error: Exception | None = None):
    """Replace ``sliver.SliverClient`` with a connected-looking mock."""
    instance = MagicMock()
    instance.connect = AsyncMock(side_effect=connect_error)
    instance.version = AsyncMock(return_value={})
    instance._channel = MagicMock()
    instance._channel.close = AsyncMock()
    factory = MagicMock(return_value=instance)
    monkeypatch.setattr("sliver.SliverClient", factory)
    return instance


def _connected_client(tmp_path, monkeypatch, *, connect_error=None):
    monkeypatch.setenv("SLIVER_OPERATOR_CONFIG", _write_config(tmp_path))
    instance = _patch_py_client(monkeypatch, connect_error=connect_error)
    return SliverClient(SliverConfig.from_env()), instance


def test_config_from_env_defaults(monkeypatch):
    for name in ("SLIVER_OPERATOR_CONFIG", "SLIVER_TIMEOUT", "SLIVER_LHOST", "SLIVER_LPORT"):
        monkeypatch.delenv(name, raising=False)
    config = SliverConfig.from_env()
    assert config.operator_config == ""
    assert config.timeout_seconds == 30.0
    assert config.lhost == "127.0.0.1"
    assert config.lport == 31337


def test_config_from_env_overrides(monkeypatch):
    monkeypatch.setenv("SLIVER_OPERATOR_CONFIG", "/tmp/op.cfg")
    monkeypatch.setenv("SLIVER_TIMEOUT", "12")
    monkeypatch.setenv("SLIVER_LHOST", "10.0.0.1")
    monkeypatch.setenv("SLIVER_LPORT", "40000")
    config = SliverConfig.from_env()
    assert config.operator_config == "/tmp/op.cfg"
    assert config.timeout_seconds == 12.0
    assert config.lhost == "10.0.0.1"
    assert config.lport == 40000


def test_config_rejects_out_of_range_port():
    with pytest.raises(ValueError):
        SliverConfig(operator_config="/tmp/op.cfg", lport=70000)


def test_connect_fails_without_operator_config(monkeypatch):
    monkeypatch.delenv("SLIVER_OPERATOR_CONFIG", raising=False)
    client = SliverClient(SliverConfig.from_env())
    with pytest.raises(SliverAuthError) as error:
        asyncio.run(client.connect())
    assert "SLIVER_OPERATOR_CONFIG" in str(error.value)


def test_connect_fails_with_invalid_config(tmp_path, monkeypatch):
    monkeypatch.setenv("SLIVER_OPERATOR_CONFIG", _write_config(tmp_path, payload="not-json"))
    client = SliverClient(SliverConfig.from_env())
    with pytest.raises(SliverAuthError):
        asyncio.run(client.connect())


def test_connect_fails_when_config_path_is_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("SLIVER_OPERATOR_CONFIG", str(tmp_path / "nope.cfg"))
    client = SliverClient(SliverConfig.from_env())
    with pytest.raises(SliverAuthError):
        asyncio.run(client.connect())


def test_connect_idempotent(tmp_path, monkeypatch):
    client, instance = _connected_client(tmp_path, monkeypatch)
    asyncio.run(client.connect())
    asyncio.run(client.connect())
    assert instance.connect.await_count == 1
    assert client.is_connected() is True


def test_connect_wraps_transport_errors(tmp_path, monkeypatch):
    client, _ = _connected_client(tmp_path, monkeypatch, connect_error=RuntimeError("refused"))
    with pytest.raises(SliverUnavailable):
        asyncio.run(client.connect())
    assert client.is_connected() is False


def test_disconnect_safe_when_not_connected():
    client = SliverClient(SliverConfig(operator_config=""))
    asyncio.run(client.disconnect())
    assert client.is_connected() is False


def test_disconnect_closes_channel(tmp_path, monkeypatch):
    client, instance = _connected_client(tmp_path, monkeypatch)
    asyncio.run(client.connect())
    asyncio.run(client.disconnect())
    instance._channel.close.assert_awaited_once()
    assert client.is_connected() is False


def test_is_available_false_when_server_down(tmp_path, monkeypatch):
    client, _ = _connected_client(tmp_path, monkeypatch, connect_error=RuntimeError("down"))
    assert asyncio.run(client.is_available()) is False


def test_is_available_false_without_config(monkeypatch):
    monkeypatch.delenv("SLIVER_OPERATOR_CONFIG", raising=False)
    client = SliverClient(SliverConfig.from_env())
    assert asyncio.run(client.is_available()) is False


def test_is_available_true_when_server_up(tmp_path, monkeypatch):
    client, _ = _connected_client(tmp_path, monkeypatch)
    assert asyncio.run(client.is_available()) is True


def test_version_returns_dict(tmp_path, monkeypatch):
    from sliver.protobuf import client_pb2

    client, instance = _connected_client(tmp_path, monkeypatch)
    instance.version = AsyncMock(
        return_value=client_pb2.Version(Major=1, Minor=6, Patch=2, Commit="abc")
    )
    asyncio.run(client.connect())
    result = asyncio.run(client.version())
    assert isinstance(result, dict)
    assert result["Major"] == 1


def test_execute_command_uses_posix_shell_for_linux(tmp_path, monkeypatch):
    client, _ = _connected_client(tmp_path, monkeypatch)
    interactive = MagicMock()
    interactive.os = "linux"
    interactive.execute = AsyncMock(return_value=_execute_message())
    client.interact_session = AsyncMock(return_value=interactive)
    asyncio.run(client.connect())
    raw = asyncio.run(client.execute_command("sess-1", "id", kind="session"))
    interactive.execute.assert_awaited_once_with("/bin/sh", ["-c", "id"])
    assert raw["stdout"] == "uid=0\n"
    assert raw["status_code"] == 0


def test_execute_command_uses_cmd_for_windows(tmp_path, monkeypatch):
    client, _ = _connected_client(tmp_path, monkeypatch)
    interactive = MagicMock()
    interactive.os = "windows"
    interactive.execute = AsyncMock(return_value=_execute_message())
    client.interact_beacon = AsyncMock(return_value=interactive)
    asyncio.run(client.connect())
    asyncio.run(client.execute_command("beac-1", "whoami", kind="beacon"))
    interactive.execute.assert_awaited_once_with("cmd.exe", ["/c", "whoami"])


def test_execute_command_rejects_unknown_kind(tmp_path, monkeypatch):
    client, _ = _connected_client(tmp_path, monkeypatch)
    asyncio.run(client.connect())
    with pytest.raises(ValueError):
        asyncio.run(client.execute_command("sess-1", "id", kind="shell"))


def test_execute_command_missing_session_is_error(tmp_path, monkeypatch):
    client, _ = _connected_client(tmp_path, monkeypatch)
    client.interact_session = AsyncMock(return_value=None)
    asyncio.run(client.connect())
    with pytest.raises(SliverError):
        asyncio.run(client.execute_command("ghost", "id"))


def test_redacts_operator_config_path(tmp_path, monkeypatch):
    config_path = _write_config(tmp_path)
    monkeypatch.setenv("SLIVER_OPERATOR_CONFIG", config_path)
    _patch_py_client(monkeypatch)
    client = SliverClient(SliverConfig.from_env())
    redacted = client.redact({"path": config_path, "nested": [config_path]})
    assert config_path not in json.dumps(redacted)
    assert "[REDACTED]" in json.dumps(redacted)


def test_never_logs_operator_config_content(tmp_path, monkeypatch, caplog):
    payload = VALID_CONFIG_JSON.replace("TOKEN", SECRET)
    path = _write_config(tmp_path, payload=payload)
    monkeypatch.setenv("SLIVER_OPERATOR_CONFIG", path)
    _patch_py_client(monkeypatch)
    client = SliverClient(SliverConfig.from_env())
    with caplog.at_level(logging.DEBUG):
        asyncio.run(client.connect())
        asyncio.run(client.version())
    logged = "\n".join(record.getMessage() for record in caplog.records)
    assert SECRET not in logged
    assert SECRET not in repr(client)
    assert SECRET not in repr(client._config)
    assert path not in repr(client._config)


def _execute_message(status: int = 0, stdout: bytes = b"uid=0\n", stderr: bytes = b""):
    from sliver.protobuf import sliver_pb2

    return sliver_pb2.Execute(Status=status, Stdout=stdout, Stderr=stderr, Pid=7)
