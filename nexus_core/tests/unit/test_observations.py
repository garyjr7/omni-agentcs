"""Regression tests for B4: budget sizing and tool-output compaction.

Run #1 measured ~7k tokens re-sent per iteration against a 20k budget, and
``nmap -p- -sV -sC`` can emit tens of KB. The fix is bigger budgets plus a
bounded, structured summary with the full payload archived.
"""

from __future__ import annotations

import json
import hashlib

from nexus_core.agent.observations import (
    MAX_OBSERVATION_CHARS,
    bounded_context,
    compact_observation,
    prepare_observation,
)
from nexus_core.agent.subagents import (
    SUBAGENTS_BY_ID,
    apply_budget_overrides,
    budget_env_name,
    select_subagent,
)


class RecordingArtifactStore:
    def __init__(self):
        self.puts = []

    def put(self, tenant_id, content, media_type, run_id=None, metadata=None):
        self.puts.append((tenant_id, len(content), media_type, metadata))
        return {"id": "artifact_" + "a" * 32, "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": len(content), "tenant_id": tenant_id, "media_type": media_type}


def _big_nmap_observation(ports=400):
    return {
        "success": True,
        "verification_method": "nmap_xml_parsed",
        "evidence": {"hosts_up": 1, "ports_open_total": ports},
        "output": {
            "target": "10.0.0.5",
            "scan": {
                "hosts_up": 1,
                "elapsed_seconds": 42.0,
                "hosts": [
                    {
                        "ip": "10.0.0.5",
                        "hostname": "victim",
                        "state": "up",
                        "ports": [
                            {
                                "port": 1000 + index,
                                "protocol": "tcp",
                                "state": "open",
                                "service": "svc",
                                "product": "Product " + (str(index) * 50),
                                "version": "1.0",
                            }
                            for index in range(ports)
                        ],
                    }
                ],
            },
        },
    }


def test_small_observation_is_not_touched():
    observation = {"success": True, "output": {"target": "10.0.0.5"}}
    content, compacted, artifact = prepare_observation("nexus.recon.nmap", observation)
    assert compacted is False
    assert artifact is None
    assert json.loads(content)["output"]["target"] == "10.0.0.5"


def test_large_nmap_observation_is_summarized_and_archived():
    observation = _big_nmap_observation()
    store = RecordingArtifactStore()
    content, compacted, artifact = prepare_observation(
        "nexus.recon.nmap",
        observation,
        artifact_store=store,
        tenant_id="system",
        run_id="run-1",
    )
    assert compacted is True
    assert artifact is not None and store.puts
    assert len(content) <= MAX_OBSERVATION_CHARS
    payload = json.loads(content)
    summary = payload["output_summary"]
    assert summary["hosts_up"] == 1
    assert summary["ports_total"] == 400
    assert summary["ports_truncated"] is True
    assert len(summary["hosts"][0]["ports"]) <= 80
    assert summary["hosts"][0]["ports"][0]["service"] == "svc"
    # The full payload went to the store, and the sha is pinned to the summary.
    assert payload["artifact"]["sha256"] == artifact["sha256"]
    assert store.puts[0][1] >= len(content)


def test_a_50kb_stdout_reaches_the_model_as_a_summary_and_a_reference():
    """Pillar 2: raw tool output lives in the artifact store, not in the prompt.

    A shell command dumping 60 KB is the measured case: the model must read a
    bounded summary plus the SHA256 of what was stored, never the dump.
    """
    stdout = "\n".join(f"line {index:06d} " + "x" * 40 for index in range(1200))
    assert len(stdout) > 50_000
    observation = {
        "success": True,
        "verification_method": "exit_code",
        "output": {"stdout": stdout, "target": "10.0.0.5"},
    }
    store = RecordingArtifactStore()

    content, compacted, artifact = prepare_observation(
        "nexus.shell.exec",
        observation,
        artifact_store=store,
        tenant_id="system",
        run_id="run-50kb",
    )

    assert compacted is True
    assert artifact is not None
    assert len(content) <= MAX_OBSERVATION_CHARS
    assert "line 001199" not in content
    payload = json.loads(content)
    assert payload["artifact"]["sha256"] == artifact["sha256"]
    assert payload["artifact"]["size_bytes"] >= 50_000
    assert store.puts and store.puts[0][1] >= 50_000
    assert store.puts[0][2] == "application/json"


def test_the_archive_is_content_addressed():
    """Two identical oversized outputs resolve to the same digest."""
    observation = {"success": True, "output": {"stdout": "y" * 60_000}}
    first = RecordingArtifactStore()
    second = RecordingArtifactStore()

    _, _, left = prepare_observation(
        "nexus.shell.exec", observation, artifact_store=first, tenant_id="system"
    )
    _, _, right = prepare_observation(
        "nexus.shell.exec", observation, artifact_store=second, tenant_id="system"
    )

    assert left is not None and right is not None
    assert left["sha256"] == right["sha256"]


def test_compact_nmap_shrinks_the_payload_substantially():
    observation = _big_nmap_observation()
    full = len(json.dumps(observation, default=str))
    compact = len(json.dumps(compact_observation("nexus.recon.nmap", observation)))
    assert compact < full / 2


def test_bounded_context_keeps_the_newest_within_budget():
    messages = [{"role": "user", "content": "x" * 100, "id": index} for index in range(100)]
    kept = bounded_context(messages, max_chars=250)
    assert kept[-1]["id"] == 99
    assert sum(len(message["content"]) for message in kept) <= 250
    assert len(kept) < len(messages)


def test_bounded_context_never_drops_the_only_message():
    messages = [{"role": "user", "content": "y" * 5000}]
    assert bounded_context(messages, max_chars=100) == messages


def test_compaction_never_raises_on_unknown_shapes():
    for tool_id in ("nexus.recon.httpx", "nexus.recon.whatweb", "nexus.unknown.tool"):
        content, compacted, _ = prepare_observation(
            tool_id, {"success": False, "output": {"weird": [1, 2, 3]}}
        )
        assert compacted is False
        assert "weird" in content


def test_budgets_are_sized_for_real_engagements():
    # 5x the pre-B4 values, which only bought ~3 iterations.
    assert SUBAGENTS_BY_ID["recon"].token_budget == 100_000
    assert SUBAGENTS_BY_ID["web"].token_budget == 80_000
    assert SUBAGENTS_BY_ID["cred"].token_budget == 60_000
    assert SUBAGENTS_BY_ID["reporter"].token_budget == 30_000


def test_budget_can_be_overridden_per_engagement():
    recon = SUBAGENTS_BY_ID["recon"]
    assert budget_env_name("recon") == "NEXUS_SUBAGENT_BUDGET_RECON"
    overridden = apply_budget_overrides(recon, env={"NEXUS_SUBAGENT_BUDGET_RECON": "150000"})
    assert overridden.token_budget == 150_000
    # Bad values fall back to the calibrated default (never disable the budget).
    assert apply_budget_overrides(recon, env={"NEXUS_SUBAGENT_BUDGET_RECON": "abc"}).token_budget == 100_000
    assert apply_budget_overrides(recon, env={"NEXUS_SUBAGENT_BUDGET_RECON": "-5"}).token_budget == 100_000


def test_select_subagent_honours_the_env_override():
    profile = select_subagent("recon", env={"NEXUS_SUBAGENT_BUDGET_RECON": "123456"})
    assert profile.id == "recon"
    assert profile.token_budget == 123_456
