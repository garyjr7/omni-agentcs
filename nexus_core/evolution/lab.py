"""State machine for evidence-based, separation-of-duty improvements."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List
from uuid import uuid4

from nexus_core.kernel.control_store import ControlStore
from nexus_core.kernel.models import utc_now


class EvolutionState(str, Enum):
    PROPOSED = "proposed"
    IMPLEMENTING = "implementing"
    EVALUATING = "evaluating"
    AWAITING_APPROVAL = "awaiting_approval"
    CANARY = "canary"
    PROMOTED = "promoted"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"


TRANSITIONS = {
    EvolutionState.PROPOSED: {EvolutionState.IMPLEMENTING, EvolutionState.REJECTED},
    EvolutionState.IMPLEMENTING: {EvolutionState.EVALUATING, EvolutionState.REJECTED},
    EvolutionState.EVALUATING: {EvolutionState.AWAITING_APPROVAL, EvolutionState.REJECTED},
    EvolutionState.AWAITING_APPROVAL: {EvolutionState.CANARY, EvolutionState.REJECTED},
    EvolutionState.CANARY: {EvolutionState.PROMOTED, EvolutionState.ROLLED_BACK},
}


class EvolutionLab:
    def __init__(self, store: ControlStore):
        self.store = store

    def propose(
        self,
        *,
        tenant_id: str,
        title: str,
        hypothesis: str,
        evidence: Dict[str, Any],
        acceptance_criteria: Dict[str, Any],
        risk: str,
        proposed_by: str,
        baseline_version: str,
    ) -> Dict[str, Any]:
        proposal_id = f"evo_{uuid4().hex}"
        now = utc_now()
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO evolution_proposals
                (id,tenant_id,title,hypothesis,evidence,acceptance_criteria,risk,status,
                 proposed_by,baseline_version,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (proposal_id, tenant_id, title, hypothesis, json.dumps(evidence),
                 json.dumps(acceptance_criteria), risk, EvolutionState.PROPOSED.value,
                 proposed_by, baseline_version, now, now),
            )
        return self.get(proposal_id)

    def get(self, proposal_id: str) -> Dict[str, Any]:
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM evolution_proposals WHERE id=?", (proposal_id,)
            ).fetchone()
        if not row:
            raise KeyError("evolution proposal not found")
        value = dict(row)
        value["evidence"] = json.loads(value["evidence"])
        value["acceptance_criteria"] = json.loads(value["acceptance_criteria"])
        return value

    def list(self, tenant_id: str) -> List[Dict[str, Any]]:
        with self.store.connect() as conn:
            ids = [row["id"] for row in conn.execute(
                "SELECT id FROM evolution_proposals WHERE tenant_id=? ORDER BY created_at DESC",
                (tenant_id,),
            ).fetchall()]
        return [self.get(proposal_id) for proposal_id in ids]

    def transition(
        self,
        proposal_id: str,
        target: EvolutionState,
        actor_id: str,
        *,
        candidate_version: str | None = None,
    ) -> Dict[str, Any]:
        proposal = self.get(proposal_id)
        current = EvolutionState(proposal["status"])
        if target not in TRANSITIONS.get(current, set()):
            raise ValueError(f"invalid evolution transition: {current.value} -> {target.value}")
        if current is EvolutionState.EVALUATING and target is EvolutionState.AWAITING_APPROVAL:
            with self.store.connect() as conn:
                evaluation = conn.execute(
                    "SELECT passed FROM evolution_evaluations WHERE proposal_id=? ORDER BY created_at DESC LIMIT 1",
                    (proposal_id,),
                ).fetchone()
            if not evaluation or not evaluation["passed"]:
                raise PermissionError("a passing independent evaluation is required")
        if current is EvolutionState.CANARY and target is EvolutionState.PROMOTED:
            raise PermissionError("promotion is decided from canary metrics, not a direct transition")

        role_column = None
        if target is EvolutionState.IMPLEMENTING:
            role_column = "implementation_actor"
        elif target is EvolutionState.AWAITING_APPROVAL:
            role_column = "evaluation_actor"
        elif target is EvolutionState.CANARY:
            role_column = "approval_actor"

        prior_actors = {
            proposal.get("implementation_actor"),
            proposal.get("evaluation_actor"),
        }
        if role_column in {"evaluation_actor", "approval_actor"} and actor_id in prior_actors:
            raise PermissionError("separation of duties requires a different actor")

        assignments = ["status=?", "updated_at=?"]
        values: list[Any] = [target.value, utc_now()]
        if role_column:
            assignments.append(f"{role_column}=?")
            values.append(actor_id)
        if candidate_version:
            assignments.append("candidate_version=?")
            values.append(candidate_version)
        values.append(proposal_id)
        with self.store.connect() as conn:
            conn.execute(
                f"UPDATE evolution_proposals SET {','.join(assignments)} WHERE id=?", values
            )
        return self.get(proposal_id)

    def start_campaign(self, proposal_id: str, max_iterations: int,
                       token_budget: int, duration_minutes: int = 60) -> Dict[str, Any]:
        if max_iterations < 1 or token_budget < 0 or duration_minutes < 1:
            raise ValueError("campaign limits must be positive")
        self.get(proposal_id)
        deadline = (datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)).isoformat()
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO evolution_campaigns
                (proposal_id,max_iterations,token_budget,deadline,created_at)
                VALUES(?,?,?,?,?)""",
                (proposal_id, max_iterations, token_budget, deadline, utc_now()),
            )
        return self.campaign(proposal_id)

    def consume_iteration(self, proposal_id: str, tokens: int) -> Dict[str, Any]:
        if tokens < 0:
            raise ValueError("tokens cannot be negative")
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT * FROM evolution_campaigns WHERE proposal_id=? AND status='active'",
                (proposal_id,),
            ).fetchone()
            if not row:
                raise PermissionError("campaign is not active")
            if datetime.fromisoformat(row["deadline"]) <= datetime.now(timezone.utc):
                conn.execute("UPDATE evolution_campaigns SET status='expired' WHERE proposal_id=?", (proposal_id,))
                raise PermissionError("campaign deadline exceeded")
            if row["iterations_used"] + 1 > row["max_iterations"] or row["tokens_used"] + tokens > row["token_budget"]:
                conn.execute("UPDATE evolution_campaigns SET status='exhausted' WHERE proposal_id=?", (proposal_id,))
                raise PermissionError("campaign budget exhausted")
            conn.execute(
                """UPDATE evolution_campaigns SET iterations_used=iterations_used+1,
                tokens_used=tokens_used+? WHERE proposal_id=?""", (tokens, proposal_id),
            )
        return self.campaign(proposal_id)

    def campaign(self, proposal_id: str) -> Dict[str, Any]:
        with self.store.connect() as conn:
            row = conn.execute("SELECT * FROM evolution_campaigns WHERE proposal_id=?", (proposal_id,)).fetchone()
        if not row:
            raise KeyError("campaign not found")
        return dict(row)

    def record_canary(self, proposal_id: str, actor_id: str, metrics: Dict[str, float],
                      thresholds: Dict[str, float]) -> Dict[str, Any]:
        proposal = self.get(proposal_id)
        if proposal["status"] != EvolutionState.CANARY.value:
            raise ValueError("proposal is not in canary")
        required = {"success_rate", "error_rate", "latency_ms", "cost"}
        if required - set(metrics):
            raise ValueError("incomplete canary metrics")
        passed = (
            metrics["success_rate"] >= thresholds.get("min_success_rate", 1.0)
            and metrics["error_rate"] <= thresholds.get("max_error_rate", 0.0)
            and metrics["latency_ms"] <= thresholds.get("max_latency_ms", float("inf"))
            and metrics["cost"] <= thresholds.get("max_cost", float("inf"))
        )
        target = EvolutionState.PROMOTED if passed else EvolutionState.ROLLED_BACK
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO evolution_canary_samples
                (id,proposal_id,success_rate,error_rate,latency_ms,cost,decision,created_at)
                VALUES(?,?,?,?,?,?,?,?)""",
                (f"canary_{uuid4().hex}", proposal_id, metrics["success_rate"],
                 metrics["error_rate"], metrics["latency_ms"], metrics["cost"], target.value, utc_now()),
            )
            conn.execute(
                "UPDATE evolution_proposals SET status=?,updated_at=? WHERE id=?",
                (target.value, utc_now(), proposal_id),
            )
        return {"proposal_id": proposal_id, "status": target.value, "actor_id": actor_id, "metrics": metrics}

    def record_evaluation(
        self,
        proposal_id: str,
        evaluator_id: str,
        passed: bool,
        metrics: Dict[str, Any],
        report_uri: str | None = None,
    ) -> str:
        proposal = self.get(proposal_id)
        if proposal["status"] != EvolutionState.EVALUATING.value:
            raise ValueError("proposal is not in evaluating state")
        if evaluator_id == proposal.get("implementation_actor"):
            raise PermissionError("implementer cannot evaluate the same proposal")
        evaluation_id = f"eval_{uuid4().hex}"
        with self.store.connect() as conn:
            conn.execute(
                """INSERT INTO evolution_evaluations
                (id,proposal_id,evaluator_id,passed,metrics,report_uri,created_at)
                VALUES(?,?,?,?,?,?,?)""",
                (evaluation_id, proposal_id, evaluator_id, int(passed),
                 json.dumps(metrics, sort_keys=True), report_uri, utc_now()),
            )
        return evaluation_id
