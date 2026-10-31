"""``nexus.c2.sliver_download``: typed file pull with chain of custody.

The bytes are evidence: they go to the artifact store content-addressed, the
tool result carries only metadata plus the SHA256, the size ceiling is enforced,
and the session must belong to the current engagement.
"""

from __future__ import annotations

import asyncio
import hashlib
from unittest.mock import AsyncMock

import pytest

from nexus_core.tools.handlers import sliver_download
from nexus_core.tests.sliver_support import fake_client, owned_context

#: The shared Sliver fixtures use an unsigned lab scope (as the other Sliver
#: handler tests do); every assertion here is about the download, not signing.
pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("lab_scope")]

TOOL = "nexus.c2.sliver_download"
SESSION = "sess-1"
PAYLOAD = b"root:x:0:0:root:/root:/bin/bash\n"


@pytest.fixture(autouse=True)
def _artifacts(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_ARTIFACT_ROOT", str(tmp_path / "artifacts"))
    monkeypatch.delenv("NEXUS_ARTIFACT_MODE", raising=False)
    return tmp_path / "artifacts"


def _ctx(tmp_path, register=True):
    return owned_context(
        tmp_path,
        register=(
            [
                {
                    "id": SESSION,
                    "session_type": "sliver:session",
                    "target_host": "203.0.113.10",
                }
            ]
            if register
            else []
        ),
    )


def _download_client(monkeypatch, data: bytes = PAYLOAD, **overrides):
    client = fake_client(monkeypatch)
    payload = {
        "session_id": SESSION,
        "kind": "session",
        "path": "/etc/passwd",
        "encoder": "",
        "is_dir": False,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "data": data,
    }
    payload.update(overrides)
    client.download_file = AsyncMock(return_value=payload)
    return client


def test_the_handler_is_registered_and_scoped(tmp_path):
    from nexus_core.tools.registry import durable_tool_definitions

    definition, _ = durable_tool_definitions()["nexus.c2.sliver_download"]
    assert definition.scope_required is True
    assert definition.effect == "post_exploitation"
    assert definition.risk.value in {"medium", "high"}


def test_download_stores_an_artifact_and_never_returns_the_bytes(tmp_path, monkeypatch):
    client = _download_client(monkeypatch)
    context, store = _ctx(tmp_path)

    result = asyncio.run(
        sliver_download.sliver_download_handler(
            {"session_id": SESSION, "remote_path": "/etc/passwd"}, context
        )
    )

    assert result.success and result.verified
    assert result.verification_method == "sliver_download_stored"
    assert result.evidence["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
    assert result.evidence["size"] == len(PAYLOAD)
    assert result.evidence["artifact_id"].startswith("artifact_")
    serialized = str(result.output)
    assert "root:x:0:0" not in serialized
    assert result.output["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()

    from nexus_core.kernel.artifacts import configured_artifact_store
    from nexus_core.tools.handlers.report_generate import default_artifact_root

    stored = configured_artifact_store(store, default_artifact_root()).get(
        "system", result.evidence["artifact_id"]
    )
    assert stored == PAYLOAD
    client.disconnect.assert_awaited_once()


def test_an_empty_file_is_reported_without_an_artifact(tmp_path, monkeypatch):
    _download_client(monkeypatch, data=b"")
    context, _ = _ctx(tmp_path)

    result = asyncio.run(
        sliver_download.sliver_download_handler(
            {"session_id": SESSION, "remote_path": "/tmp/empty"}, context
        )
    )

    assert result.verified is False
    assert result.verification_method == "sliver_download_empty"
    assert result.output["empty"] is True


def test_a_session_outside_the_engagement_is_refused(tmp_path, monkeypatch):
    client = _download_client(monkeypatch)
    context, _ = _ctx(tmp_path, register=False)

    result = asyncio.run(
        sliver_download.sliver_download_handler(
            {"session_id": SESSION, "remote_path": "/etc/passwd"}, context
        )
    )

    assert result.verified is False
    assert "session" in result.verification_method
    client.download_file.assert_not_awaited()


def test_a_path_pattern_is_refused_before_any_rpc(tmp_path, monkeypatch):
    client = _download_client(monkeypatch)
    context, _ = _ctx(tmp_path)

    with pytest.raises(ValueError):
        asyncio.run(
            sliver_download.sliver_download_handler(
                {"session_id": SESSION, "remote_path": "/etc/*.conf"}, context
            )
        )
    client.download_file.assert_not_awaited()


def test_a_size_refusal_is_reported_as_a_refusal(tmp_path, monkeypatch):
    client = _download_client(monkeypatch)
    client.download_file.side_effect = ValueError("download exceeds the 16-byte ceiling")
    context, _ = _ctx(tmp_path)

    result = asyncio.run(
        sliver_download.sliver_download_handler(
            {"session_id": SESSION, "remote_path": "/var/log/big"}, context
        )
    )

    assert result.verification_method == "sliver_download_refused"
    assert "ceiling" in result.output["reason"]


def test_the_unavailable_bridge_stays_fail_closed(tmp_path, monkeypatch):
    from nexus_core.integrations.sliver.client import SliverUnavailable

    client = _download_client(monkeypatch)
    client.connect.side_effect = SliverUnavailable("down")
    context, _ = _ctx(tmp_path)

    result = asyncio.run(
        sliver_download.sliver_download_handler(
            {"session_id": SESSION, "remote_path": "/etc/passwd"}, context
        )
    )

    assert result.verified is False
    assert result.verification_method == "sliver_unavailable"
    assert result.evidence["error_type"] == "SliverUnavailable"


def test_the_definition_bounds_the_download_size():
    schema = sliver_download.sliver_download_definition().input_schema
    assert schema["properties"]["max_bytes"]["maximum"] == 16 * 1024 * 1024
    assert schema["additionalProperties"] is False
    assert schema["required"] == ["session_id", "remote_path"]


# ------------------------------------------------------------------ the client
class _FakeStream:
    """Async iterator over the messages one ``Download`` RPC returns."""

    def __init__(self, chunks):
        self._chunks = list(chunks)

    def __aiter__(self):
        async def generator():
            for chunk in self._chunks:
                yield chunk

        return generator()


class _Message:
    def __init__(self, data: bytes = b"", *, is_dir: bool = False, encoder: str = ""):
        self.Data = data
        self.IsDir = is_dir
        self.Encoder = encoder


class _Stub:
    def __init__(self, chunks, *, delay: float = 0.0):
        self.chunks = chunks
        self.delay = delay
        self.requests: list = []

    def Download(self, request, timeout=None):
        self.requests.append(request)

        class _Bound:
            def __init__(self, inner):
                self._inner = inner

            def __aiter__(self):
                async def generator():
                    if self._inner.delay:
                        await asyncio.sleep(self._inner.delay)
                    for chunk in self._inner.chunks:
                        yield chunk

                return generator()

        return _Bound(self)


def _real_client(stub):
    from nexus_core.integrations.sliver.client import SliverClient, SliverConfig

    client = SliverClient(SliverConfig(operator_config="/tmp/fake.cfg"))
    client._client = type("_C", (), {"_stub": stub})()
    client._connected = True
    return client


def _fake_proto(monkeypatch):
    """``sliver_pb2.DownloadReq`` without importing sliver-py."""
    import sys
    import types

    module = types.ModuleType("sliver.protobuf")

    class _Owner:
        SessionID = ""
        BeaconID = ""

    class _Req:
        def __init__(self, Path=""):
            self.Path = Path
            # ``SliverClient._bind_request`` writes the owning session here.
            self.Request = _Owner()

    module.sliver_pb2 = types.SimpleNamespace(DownloadReq=_Req)
    package = types.ModuleType("sliver")
    package.protobuf = module
    monkeypatch.setitem(sys.modules, "sliver", package)
    monkeypatch.setitem(sys.modules, "sliver.protobuf", module)


def test_the_client_accumulates_chunks_and_hashes_them(monkeypatch):
    _fake_proto(monkeypatch)
    stub = _Stub([_Message(b"abc"), _Message(b"def")])
    client = _real_client(stub)

    result = asyncio.run(client.download_file("sess-1", "/etc/passwd"))

    assert result["data"] == b"abcdef"
    assert result["size"] == 6
    assert result["sha256"] == hashlib.sha256(b"abcdef").hexdigest()
    assert result["path"] == "/etc/passwd"
    assert stub.requests[0].Path == "/etc/passwd"


def test_the_client_enforces_the_byte_ceiling(monkeypatch):
    _fake_proto(monkeypatch)
    stub = _Stub([_Message(b"abc"), _Message(b"def")])
    client = _real_client(stub)

    with pytest.raises(ValueError):
        asyncio.run(client.download_file("sess-1", "/etc/passwd", max_bytes=4))


def test_the_client_reports_a_timeout(monkeypatch):
    from nexus_core.integrations.sliver import client as client_module
    from nexus_core.integrations.sliver.client import SliverUnavailable

    # The RPC slack exists so a slow-but-alive server answers cleanly; here the
    # point is the ceiling, so the slack is reduced instead of waiting 5 s.
    monkeypatch.setattr(client_module, "RPC_SLACK_SECONDS", 0.01)
    _fake_proto(monkeypatch)
    stub = _Stub([_Message(b"abc")], delay=5)
    client = _real_client(stub)

    with pytest.raises(SliverUnavailable):
        asyncio.run(client.download_file("sess-1", "/etc/passwd", timeout_seconds=0.01))
