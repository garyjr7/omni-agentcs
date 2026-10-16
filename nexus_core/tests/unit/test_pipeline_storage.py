"""Phase 2 regression tests: bounded capture, references and failure boundaries."""
from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from nexus_core.agent.observations import prepare_observation
from nexus_core.kernel.artifacts import LocalArtifactStore, configured_artifact_store
from nexus_core.kernel.blackboard import Blackboard
from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.result_references import decode_result, encode_result
from nexus_core.kernel.sandbox import LocalSandbox, OCISandbox


@pytest.fixture
def store(tmp_path: Path) -> ControlStore:
    result = ControlStore(tmp_path / "state.db")
    result.initialize()
    return result


@pytest.mark.parametrize("limit", [0, 127, 65536])
def test_bounded_dual_channel_capture(tmp_path: Path, limit: int) -> None:
    sandbox = LocalSandbox(tmp_path, [sys.executable], max_output_bytes=limit)
    size = 3 * 1024 * 1024
    result = asyncio.run(sandbox.run([sys.executable, "-c",
        f"import os; os.write(1,b'a'*{size}); os.write(2,b'b'*{size})"]))
    assert result.exit_code == 0
    for text, manifest, character in [(result.stdout, result.stdout_manifest, b"a"),
                                      (result.stderr, result.stderr_manifest, b"b")]:
        assert len(text) == limit
        assert manifest is not None and manifest.complete and manifest.truncated
        assert manifest.total_bytes == size and manifest.discarded_bytes == size - limit
        assert manifest.sha256 == hashlib.sha256(character * size).hexdigest()
        assert manifest.retained_sha256 == hashlib.sha256(character * limit).hexdigest()


def test_oci_uses_bounded_capture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original = asyncio.create_subprocess_exec
    async def spawn(*args, **kwargs):
        return await original(sys.executable, "-c", "import os; os.write(1,b'x'*2000000)", **kwargs)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    result = asyncio.run(OCISandbox(tmp_path, ["image"], max_output_bytes=123).run("image", ["cmd"]))
    assert len(result.stdout) == 123
    assert result.stdout_manifest is not None and result.stdout_manifest.total_bytes == 2000000


def test_shared_repository_concurrent_workers(store: ControlStore, tmp_path: Path) -> None:
    root = tmp_path / "shared"
    workers = [LocalArtifactStore(store, root) for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        refs = list(pool.map(lambda worker: worker.put("system", b"same", "text/plain"), workers))
    assert len({ref["sha256"] for ref in refs}) == 1
    for ref in refs:
        assert workers[-1].get("system", ref["id"]) == b"same"
        with pytest.raises(KeyError):
            workers[-1].get("other", ref["id"])
    assert len(list(root.rglob("*.tmp"))) == 0


def test_artifact_traversal_symlinks_and_limits(store: ControlStore, tmp_path: Path) -> None:
    artifacts = LocalArtifactStore(store, tmp_path / "blobs", max_bytes=10)
    with pytest.raises(ValueError):
        artifacts.put("../escape", b"x", "text/plain")
    outside = tmp_path / "outside"
    outside.mkdir()
    (artifacts.root / "system").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        artifacts.put("system", b"x", "text/plain")
    with pytest.raises(ValueError):
        artifacts.put("other", b"x" * 11, "text/plain")
    assert not list(outside.iterdir())


def test_legacy_address_maps_to_current_mount(store: ControlStore, tmp_path: Path) -> None:
    artifacts = LocalArtifactStore(store, tmp_path / "new-mount")
    ref = artifacts.put("system", b"data", "text/plain")
    with store.connect() as conn:
        conn.execute("UPDATE kernel_artifacts SET storage_uri=? WHERE id=?",
                     (f"/old-mount/system/{ref['sha256'][:2]}/{ref['sha256']}", ref["id"]))
    assert artifacts.get("system", ref["id"]) == b"data"
    with store.connect() as conn:
        conn.execute("UPDATE kernel_artifacts SET storage_uri=? WHERE id=?",
                     (f"/old-mount/other/{ref['sha256'][:2]}/{ref['sha256']}", ref["id"]))
    with pytest.raises(RuntimeError):
        artifacts.get("system", ref["id"])


def test_shared_configuration_fails_closed(store: ControlStore, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NEXUS_ARTIFACT_MODE", "shared")
    monkeypatch.delenv("NEXUS_ARTIFACT_ROOT", raising=False)
    with pytest.raises(ValueError):
        configured_artifact_store(store, "/unused")


def test_inline_pipe_legacy_and_integrity() -> None:
    payload = {"output": "a|b|c", "evidence": {"password": "secret-value"}}
    reference = encode_result(payload, "system", None)
    assert decode_result(reference, "system", None)["output"] == "a|b|c"
    assert "secret-value" not in reference
    raw = json.dumps(payload)
    legacy = raw + "|" + hashlib.sha256(raw.encode()).hexdigest()
    assert decode_result(legacy, "system", None)["output"] == "a|b|c"
    with pytest.raises(RuntimeError):
        decode_result(legacy[:-64] + "0" * 64, "system", None)
    ref = json.loads(reference)
    ref["payload"]["output"] = "tampered"
    with pytest.raises(RuntimeError):
        decode_result(json.dumps(ref), "system", None)


@pytest.mark.parametrize("payload", [{"evidence": "bad"}, {"success": "yes"},
                                     {"output": float("nan")}, {"output": object()}])
def test_strict_result_payload(payload: dict) -> None:
    with pytest.raises(ValueError):
        encode_result(payload, "system", None)


def test_observation_failure_is_bounded_and_redacted() -> None:
    class BrokenStore:
        def get(self, tenant_id: str, artifact_id: str) -> bytes:
            raise OSError("unavailable")

        def put(self, *args, **kwargs):
            assert b"secret-value" not in args[1]
            raise OSError("password=secret-value")
    content, compacted, artifact = prepare_observation("tool", {
        "stdout": "x" * 100000, "password": "secret-value",
        "evidence": {"output": "x" * 100000}},
        artifact_store=BrokenStore(), tenant_id="system", limit_chars=512)
    assert len(content) <= 512 and compacted and artifact is None
    assert json.loads(content)["storage"] == {"status": "failed", "error_code": "OSError"}
    assert "secret-value" not in content
    small, _, _ = prepare_observation("tool", {"output": "https://user:secret-value@host/"})
    assert "secret-value" not in small


def test_blackboard_sanitizes_before_persistence(store: ControlStore) -> None:
    board = Blackboard(store)
    board.record(tenant_id="system", engagement_id="eng", fact_type="credential",
                 key="account", value={"password": "secret-value"},
                 source="Authorization: Bearer secret-value", created_by="test")
    with store.connect() as conn:
        rows = conn.execute("SELECT content, metadata FROM kernel_knowledge_documents").fetchall()
    assert rows and "secret-value" not in str([dict(row) for row in rows])
    assert "secret-value" not in board.render("system", "eng")


def test_capture_memory_does_not_scale_with_output(tmp_path: Path) -> None:
    import tracemalloc
    sandbox = LocalSandbox(tmp_path, [sys.executable], max_output_bytes=1024)
    tracemalloc.start()
    try:
        result = asyncio.run(sandbox.run([sys.executable, "-c",
            "import os; chunk=b'x'*65536; [os.write(1,chunk) for _ in range(512)]"]))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 * 1024 * 1024
    assert result.stdout_manifest is not None
    assert result.stdout_manifest.total_bytes == 32 * 1024 * 1024
    assert result.stdout_manifest.retained_bytes == 1024


def test_oversized_observation_has_explicit_error() -> None:
    content, compacted, ref = prepare_observation("tool", {"stdout": "x" * (17 * 1024 * 1024)})
    assert compacted and ref is None
    assert json.loads(content)["storage"]["error_code"] == "PayloadTooLarge"


def test_reference_rejects_cross_tenant_and_invalid_schema(store: ControlStore, tmp_path: Path) -> None:
    artifacts = LocalArtifactStore(store, tmp_path / "refs")
    reference = encode_result({"output": "ok"}, "system", artifacts)
    with pytest.raises(ValueError):
        decode_result(reference, "other", artifacts)
    value = json.loads(reference)
    value["version"] = True
    with pytest.raises(ValueError):
        decode_result(json.dumps(value), "system", artifacts)
    with pytest.raises(ValueError):
        decode_result('{"version":1,"version":2}', "system", artifacts)


def test_blob_symlink_and_corruption_are_rejected(store: ControlStore, tmp_path: Path) -> None:
    artifacts = LocalArtifactStore(store, tmp_path / "safe")
    ref = artifacts.put("system", b"ok", "text/plain")
    blob = artifacts.root / "system" / ref["sha256"][:2] / ref["sha256"]
    blob.write_bytes(b"no")
    with pytest.raises(RuntimeError):
        artifacts.get("system", ref["id"])
    with pytest.raises(RuntimeError):
        artifacts.put("system", b"ok", "text/plain")
    blob.unlink()
    outside = tmp_path / "secret"
    outside.write_bytes(b"ok")
    blob.symlink_to(outside)
    with pytest.raises(OSError):
        artifacts.get("system", ref["id"])


def test_oci_cancellation_removes_daemon_container(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    original = asyncio.create_subprocess_exec
    calls: list[tuple] = []
    async def spawn(*args, **kwargs):
        calls.append(args)
        script = "pass" if args[1] == "rm" else "import time; print('start',flush=True); time.sleep(20)"
        return await original(sys.executable, "-c", script, **kwargs)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    result = asyncio.run(OCISandbox(tmp_path, ["image"]).run(
        "image", ["cmd"], timeout_seconds=0.2, grace_seconds=0.1))
    assert result.timed_out
    assert any(call[1:3] == ("rm", "--force") for call in calls)
    assert result.stdout_manifest is not None and result.stdout_manifest.complete


def test_malformed_large_observation_still_returns_valid_json() -> None:
    content, compacted, _ = prepare_observation("nexus.recon.httpx", {
        "output": {"probes": [{"tech": 123, "title": "x" * 30000}]}})
    assert compacted and len(content) <= 20000
    assert json.loads(content)["output_summary"]["summary_error"] == "InvalidShape"
