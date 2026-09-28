"""Desktop/edge connector bootstrap API with production mTLS binding."""

import hmac
import os

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field

from nexus_api.auth.deps import ensure_tenant_access, require_admin
from nexus_api.config import NEXUS_DB_PATH
from nexus_core.kernel.connectors import ConnectorRegistry
from nexus_core.kernel.store_factory import get_control_store

router = APIRouter(prefix="/connectors", tags=["Connectors"])
registry = ConnectorRegistry(get_control_store(NEXUS_DB_PATH))


class EnrollmentCreate(BaseModel):
    tenant_id: str
    ttl_minutes: int = Field(default=10, ge=1, le=60)


class EnrollRequest(BaseModel):
    token: str
    name: str = Field(min_length=2, max_length=120)
    device_id: str = Field(min_length=8, max_length=200)
    capabilities: list[str] = []
    allowed_roots: list[str] = []


def verify_mtls_proxy(proxy_secret: str | None, fingerprint: str | None) -> None:
    if os.getenv("NEXUS_ENV", "development").lower() != "production":
        return
    expected = os.getenv("NEXUS_CONNECTOR_PROXY_SECRET", "")
    if (not expected or not proxy_secret
            or not hmac.compare_digest(expected, proxy_secret)
            or not fingerprint):
        raise PermissionError("verified connector mTLS gateway is required")


@router.post("/enrollment-token")
def enrollment_token(body: EnrollmentCreate, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    return {"token": registry.create_enrollment_token(
        body.tenant_id, str(user["id"]), body.ttl_minutes
    )}


@router.post("/enroll", status_code=201)
def enroll(body: EnrollRequest, x_client_cert_sha256: str | None = Header(default=None),
           x_nexus_connector_proxy_secret: str | None = Header(default=None)):
    try:
        verify_mtls_proxy(x_nexus_connector_proxy_secret, x_client_cert_sha256)
        return registry.enroll(
            body.token, name=body.name, device_id=body.device_id,
            capabilities=body.capabilities, allowed_roots=body.allowed_roots,
            certificate_fingerprint=x_client_cert_sha256,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@router.post("/{connector_id}/heartbeat")
def heartbeat(connector_id: str, x_nexus_connector_token: str = Header(),
              x_client_cert_sha256: str | None = Header(default=None),
              x_nexus_connector_proxy_secret: str | None = Header(default=None)):
    try:
        verify_mtls_proxy(x_nexus_connector_proxy_secret, x_client_cert_sha256)
        return registry.heartbeat(connector_id, x_nexus_connector_token, x_client_cert_sha256)
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


@router.delete("/{connector_id}")
def revoke(connector_id: str, user: dict = Depends(require_admin)):
    try:
        registry.revoke(connector_id, user.get("tenant_id", "system"))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"status": "revoked"}


@router.post("/{connector_id}/rotate")
def rotate(connector_id: str, x_nexus_connector_token: str = Header(),
           x_client_cert_sha256: str | None = Header(default=None),
           x_nexus_connector_proxy_secret: str | None = Header(default=None)):
    try:
        verify_mtls_proxy(x_nexus_connector_proxy_secret, x_client_cert_sha256)
        return {"credential": registry.rotate_credential(
            connector_id, x_nexus_connector_token, x_client_cert_sha256
        )}
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
