"""Governed Evolution Lab API. No endpoint deploys directly to production."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from nexus_api.auth.deps import ensure_tenant_access, require_admin
from nexus_api.config import NEXUS_DB_PATH
from nexus_core.evolution import EvolutionLab, EvolutionState
from nexus_core.kernel.store_factory import get_control_store

router = APIRouter(
    prefix="/evolution", tags=["Evolution"], dependencies=[Depends(require_admin)]
)
lab = EvolutionLab(get_control_store(NEXUS_DB_PATH))


class ProposalCreate(BaseModel):
    tenant_id: str
    title: str = Field(min_length=4, max_length=200)
    hypothesis: str = Field(min_length=10)
    evidence: dict
    acceptance_criteria: dict
    risk: str = "medium"
    baseline_version: str


class TransitionRequest(BaseModel):
    target: EvolutionState
    candidate_version: str | None = None


class EvaluationRequest(BaseModel):
    passed: bool
    metrics: dict
    report_uri: str | None = None


class CampaignRequest(BaseModel):
    max_iterations: int = Field(ge=1, le=100)
    token_budget: int = Field(ge=0)
    duration_minutes: int = Field(default=60, ge=1, le=10080)


class CanaryRequest(BaseModel):
    metrics: dict[str, float]
    thresholds: dict[str, float]


@router.get("/proposals")
def list_proposals(tenant_id: str, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, tenant_id)
    return {"items": lab.list(tenant_id)}


@router.post("/proposals", status_code=201)
def create_proposal(body: ProposalCreate, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    return lab.propose(**body.model_dump(), proposed_by=str(user["id"]))


@router.post("/proposals/{proposal_id}/transition")
def transition(
    proposal_id: str, body: TransitionRequest, user: dict = Depends(require_admin)
):
    try:
        proposal = lab.get(proposal_id)
        ensure_tenant_access(user, proposal["tenant_id"])
        return lab.transition(
            proposal_id, body.target, str(user["id"]),
            candidate_version=body.candidate_version,
        )
    except (KeyError, ValueError, PermissionError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/proposals/{proposal_id}/campaign")
def start_campaign(proposal_id: str, body: CampaignRequest, user: dict = Depends(require_admin)):
    proposal = lab.get(proposal_id)
    ensure_tenant_access(user, proposal["tenant_id"])
    return lab.start_campaign(proposal_id, **body.model_dump())


@router.post("/proposals/{proposal_id}/evaluations", status_code=201)
def record_evaluation(proposal_id: str, body: EvaluationRequest, user: dict = Depends(require_admin)):
    proposal = lab.get(proposal_id)
    ensure_tenant_access(user, proposal["tenant_id"])
    try:
        evaluation_id = lab.record_evaluation(proposal_id, str(user["id"]), **body.model_dump())
        return {"evaluation_id": evaluation_id}
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/proposals/{proposal_id}/canary")
def canary(proposal_id: str, body: CanaryRequest, user: dict = Depends(require_admin)):
    proposal = lab.get(proposal_id)
    ensure_tenant_access(user, proposal["tenant_id"])
    try:
        return lab.record_canary(proposal_id, str(user["id"]), body.metrics, body.thresholds)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
