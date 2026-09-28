"""Department package administration."""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from nexus_api.auth.deps import ensure_tenant_access, require_admin
from nexus_api.config import NEXUS_DB_PATH, NEXUS_ROOT
from nexus_core.kernel.packages import PackageManager
from nexus_core.kernel.store_factory import get_control_store

router = APIRouter(prefix="/packages", tags=["Packages"])
manager = PackageManager(get_control_store(NEXUS_DB_PATH), Path(NEXUS_ROOT) / "departments")


class PackageInstall(BaseModel):
    package_path: str
    tenant_id: str


@router.get("")
def list_packages(tenant_id: str, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, tenant_id)
    return {"items": manager.list_installed(tenant_id)}


@router.post("/install", status_code=201)
def install_package(body: PackageInstall, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    try:
        return manager.install(body.package_path, body.tenant_id, str(user["id"]))
    except (OSError, ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/{package_id}/rollback")
def rollback_package(package_id: str, tenant_id: str, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, tenant_id)
    try:
        return manager.rollback(package_id, tenant_id, str(user["id"]))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
