"""P2-D4 closure: invocation results are content-addressed artifacts.

The journal stores a versioned JSON artifact reference; the payload is read back from
the artifact store, so a large or sensitive observation never bloats the journal
and an integrity mismatch is detected instead of silently served.
"""
from __future__ import annotations

import asyncio
import hashlib
import json

import pytest

from nexus_core.kernel.artifacts import LocalArtifactStore
from nexus_core.kernel.invocation_journal import InvocationJournal
from nexus_core.kernel.models import ToolResult
from nexus_core.tests.unit.test_hooks_lifecycle import context
from nexus_core.tests.unit.test_invocation_journal import gateway


def finished_invocation(ctx, artifact_store, result):
    journal = InvocationJournal(ctx.store)
    item = journal.prepare(ctx, "probe", {}, "")
    journal.start(item["invocation_id"], "system")
    journal.finish(item["invocation_id"], "system", result, artifact_store=artifact_store)
    return journal, journal.get(item["invocation_id"], "system")


def test_result_ref_points_to_artifact_store(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    artifacts = LocalArtifactStore(ctx.store, tmp_path / "artifacts")
    journal, row = finished_invocation(ctx, artifacts, {"ok": True})
    ref = json.loads(row["result_ref"])["artifact"]
    reference, digest = ref["id"], ref["sha256"]
    assert reference.startswith("artifact_")
    assert json.loads(artifacts.get("system", reference)) == {"ok": True}
    assert hashlib.sha256(artifacts.get("system", reference)).hexdigest() == digest
    assert journal.result_of(row, artifact_store=artifacts) == {"ok": True}


def test_artifact_sha256_matches_journal(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    artifacts = LocalArtifactStore(ctx.store, tmp_path / "artifacts")
    _, row = finished_invocation(ctx, artifacts, {"evidence": {"text": "22/tcp open ssh"}})
    ref = json.loads(row["result_ref"])["artifact"]
    reference, digest = ref["id"], ref["sha256"]
    with ctx.store.connect() as conn:
        stored = conn.execute(
            "SELECT sha256 FROM kernel_artifacts WHERE id=?", (reference,)).fetchone()
    assert stored["sha256"] == digest


def test_artifact_integrity_mismatch_is_detected(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    artifacts = LocalArtifactStore(ctx.store, tmp_path / "artifacts")
    journal, row = finished_invocation(ctx, artifacts, {"ok": True})
    ref = json.loads(row["result_ref"])["artifact"]
    (artifacts.root / "system" / ref["sha256"][:2] / ref["sha256"]).write_bytes(b"tampered")
    with pytest.raises(RuntimeError):
        journal.result_of(row, artifact_store=artifacts)


def test_artifact_survives_run_restart(tmp_path, monkeypatch):
    ctx = context(tmp_path, monkeypatch)
    root = tmp_path / "artifacts"
    journal, row = finished_invocation(ctx, LocalArtifactStore(ctx.store, root), {"ok": True})
    # A fresh store instance (a restarted process) reads the same bytes from disk.
    restarted = LocalArtifactStore(ctx.store, root)
    assert journal.result_of(row, artifact_store=restarted) == {"ok": True}


def test_gateway_result_ref_uses_artifact_store(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    ctx = context(tmp_path, monkeypatch)
    calls = []

    def handler(arguments, context_):
        calls.append(1)
        return ToolResult({"effect_count": len(calls)}, True, "probe")

    governed = gateway(ctx, handler)
    first = asyncio.run(governed.invoke("probe", {}, ctx))
    row = InvocationJournal(ctx.store).get(first["invocation_id"], "system")
    assert json.loads(row["result_ref"])["kind"] == "artifact"
    # A replay returns the stored artifact without repeating the effect.
    second = asyncio.run(governed.invoke("probe", {}, ctx))
    assert first["output"]["effect_count"] == 1
    assert second["output"]["effect_count"] == 1
    assert len(calls) == 1
