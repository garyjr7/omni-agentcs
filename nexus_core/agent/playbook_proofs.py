"""Read-only, integrity-checked execution evidence for playbook progress."""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from nexus_core.kernel.result_references import decode_result


@dataclass(frozen=True)
class ExecutionProof:
    invocation_id: str
    tool_id: str
    target: str
    fact_types: frozenset[str]


def target_key(target: str) -> str:
    """URLs and host:port references bind to the same host, never another host."""
    if not target:
        return ""
    try:
        return (urlsplit(target if "://" in target else "//" + target).hostname or target).lower().rstrip(".")
    except ValueError:
        return target.lower()


def execution_proofs(store: Any, tenant_id: str, run_id: str,
                     engagement_id: str) -> tuple[ExecutionProof, ...]:
    """Only successful journal entries of this run count, in completion order.

    A missing legacy envelope, bad digest or unavailable storage gives no
    progress. Never instantiate a journal here: guidance must not run migrations.
    The gateway-stamped engagement binds even no-fact steps to its scope.
    """
    if store is None or not run_id or not engagement_id:
        return ()
    try:
        with store.connect() as conn:
            rows = conn.execute(
                "SELECT invocation_id,tool_id,target,result_ref FROM kernel_invocations "
                "WHERE tenant_id=? AND run_id=? AND state='succeeded' "
                "ORDER BY ended_at,invocation_id LIMIT 1000", (tenant_id, run_id),
            ).fetchall()
    except Exception:
        return ()  # A run before its first tool may not have a journal yet.
    from nexus_core.kernel.tool_gateway import _journal_artifact_store

    proofs: list[ExecutionProof] = []
    job_results: list[tuple[str, dict[str, Any]]] = []
    for row in rows:
        try:
            result = decode_result(row["result_ref"], tenant_id, _journal_artifact_store(store))
            if (result.get("success") is not True or result.get("verified") is not True
                    or result.get("outcome") != "success"
                    or result.get("run_id") != run_id
                    or result.get("engagement_id") != engagement_id
                    or result.get("invocation_id") != row["invocation_id"]
                    or result.get("tool_id") != row["tool_id"]):
                continue
            # Enqueue/status acknowledges a task, not execution of its payload.
            if row["tool_id"] == "nexus.post.job":
                job_results.append((str(row["invocation_id"]), result))
                continue
            assertions = result.get("assertions") or []
            kinds: set[str] = set()
            targets: set[str] = set()
            for assertion in assertions:
                if (assertion.get("verified") is True and assertion.get("asserted_by") == "verifier"
                        and assertion.get("verification_method")
                        and assertion.get("run_id") == run_id
                        and assertion.get("invocation_id") == row["invocation_id"]):
                    kinds.add(str(assertion["fact_type"]))
                    if assertion.get("target"):
                        targets.add(target_key(str(assertion["target"])))
            target = target_key(str(row["target"] or ""))
            if not target and len(targets) == 1:
                target = next(iter(targets))
            proofs.append(ExecutionProof(str(row["invocation_id"]), str(row["tool_id"]),
                                         target, frozenset(kinds)))
        except Exception:
            continue  # corrupt/unreadable evidence never becomes completion
    by_invocation = {proof.invocation_id: proof for proof in proofs}
    for invocation_id, result in job_results:
        if result.get("verification_method") != "durable_job_enqueued":
            continue
        job_id = (result.get("output") or {}).get("job_id")
        try:
            with store.connect() as conn:
                task = conn.execute(
                    "SELECT payload,result FROM kernel_tasks WHERE tenant_id=? AND run_id=? "
                    "AND id=? AND status='completed'", (tenant_id, run_id, job_id),
                ).fetchone()
            if task is None:
                continue
            payload = json.loads(task["payload"])
            child_result = json.loads(task["result"])["output"]
            child = by_invocation.get(child_result.get("invocation_id"))
            if (child is not None and payload.get("engagement_id") == engagement_id
                    and payload.get("tool_id") == child.tool_id and payload.get("job_authority")):
                proofs.insert(proofs.index(child) + 1, ExecutionProof(
                    invocation_id, "nexus.post.job", child.target, child.fact_types))
        except Exception:
            continue
    return tuple(proofs)
