"""
nexus_api/routes/auth.py — NEXUS PRO v2.0
Auth con email + JSON + JWT — reemplaza OAuth2PasswordRequestForm
"""
from fastapi import APIRouter, HTTPException, status, Depends
import os
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional

# Usar el nuevo servicio de auth
from nexus_api.auth.service import (
    authenticate, create_tokens, refresh_access_token,
    create_user, list_users, get_user_by_id,
    decode_token, init_users_table, revoke_token
)
from nexus_api.auth.deps import get_current_user, require_admin, bearer, ensure_tenant_access

router = APIRouter(prefix="/auth", tags=["Auth"])

# Inicializar tabla + admin por defecto al cargar
init_users_table()

# ── Schemas inline (compatibles con frontend) ─────────────────
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    tenant_id: str = "system"

class RefreshRequest(BaseModel):
    refresh_token: str

class UserCreateRequest(BaseModel):
    email: EmailStr
    name: str
    password: str
    role: str = "viewer"
    tenant_id: str = "system"

# ── Endpoints ─────────────────────────────────────────────────
@router.post("/login")
async def login(body: LoginRequest):
    user = authenticate(body.email, body.password, body.tenant_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas"
        )
    return create_tokens(user)

@router.post("/refresh")
async def refresh(body: RefreshRequest):
    tokens = refresh_access_token(body.refresh_token)
    if not tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token inválido o expirado"
        )
    return tokens

@router.get("/me")
async def me(user: dict = Depends(get_current_user)):
    return {k: v for k, v in user.items() if k != "hashed_pw"}

@router.post("/logout")
async def logout(
    user: dict = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
):
    revoke_token(credentials.credentials)
    return {"message": "ok", "user": user["email"]}

@router.get("/users")
async def get_users(tenant_id: str, admin: dict = Depends(require_admin)):
    ensure_tenant_access(admin, tenant_id)
    users = list_users(tenant_id)
    return {"users": users, "total": len(users)}

@router.post("/users", status_code=201)
async def create_new_user(body: UserCreateRequest, admin: dict = Depends(require_admin)):
    try:
        ensure_tenant_access(admin, body.tenant_id)
        user = create_user(body.email, body.name, body.password, body.role, body.tenant_id)
        return {k: v for k, v in user.items() if k != "hashed_pw"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {e}")

# ── Compatibilidad: register legacy ───────────────────────────
@router.post("/register", status_code=201)
async def register(body: UserCreateRequest):
    if os.getenv("NEXUS_ALLOW_REGISTER") != "true":
        raise HTTPException(
            status_code=403,
            detail="Registration is closed. Contact your administrator.",
        )
    try:
        user = create_user(body.email, body.name, body.password, body.role, body.tenant_id)
        return {k: v for k, v in user.items() if k != "hashed_pw"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error: {e}")
