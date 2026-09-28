"""Tenant-scoped audit export and chain verification API."""

from fastapi import APIRouter, Depends

from nexus_api.auth.deps import ensure_tenant_access, require_admin
from nexus_api.config import NEXUS_DB_PATH
from nexus_core.kernel.audit import AuditWriter
from nexus_core.kernel.store_factory import get_control_store

router = APIRouter(prefix="/audit", tags=["Audit"])
writer = AuditWriter(get_control_store(NEXUS_DB_PATH))


@router.get("/logs")
async def audit_logs(tenant_id: str, trace_id: str | None = None,
                     run_id: str | None = None,
                     user: dict = Depends(require_admin)):
    ensure_tenant_access(user, tenant_id)
    items = writer.export(tenant_id, trace_id=trace_id, run_id=run_id)
    return {"items": items, "total": len(items)}


@router.get("/verify")
async def verify_audit(user: dict = Depends(require_admin)):
    valid, corrupt_sequence = writer.verify_chain()
    return {"valid": valid, "corrupt_sequence": corrupt_sequence}
