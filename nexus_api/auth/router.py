from fastapi import APIRouter, HTTPException, Depends, status
from .models import UserLogin, UserCreate, UserOut, Token
from .service import (authenticate, create_tokens, refresh_access_token,
                      create_user, list_users, init_users_table)
from .deps import get_current_user, require_admin
from pydantic import BaseModel

router = APIRouter(prefix="/auth", tags=["auth"])

# Inicializar tabla al importar el router
init_users_table()

class RefreshRequest(BaseModel):
    refresh_token: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

# ── Login ─────────────────────────────────────────────────────
@router.post("/login", response_model=Token)
async def login(body: UserLogin):
    user = authenticate(body.email, body.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas"
        )
    return create_tokens(user)

# ── Refresh ───────────────────────────────────────────────────
@router.post("/refresh", response_model=Token)
async def refresh(body: RefreshRequest):
    tokens = refresh_access_token(body.refresh_token)
    if not tokens:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token inválido o expirado"
        )
    return tokens

# ── Me ────────────────────────────────────────────────────────
@router.get("/me")
async def me(user: dict = Depends(get_current_user)):
    return {k: v for k, v in user.items() if k != "hashed_pw"}

# ── Logout (cliente borra el token — stateless) ───────────────
@router.post("/logout")
async def logout(user: dict = Depends(get_current_user)):
    return {"message": "ok", "user": user["email"]}

# ── Users — solo admin ────────────────────────────────────────
@router.get("/users")
async def get_users(admin: dict = Depends(require_admin)):
    users = list_users()
    return {"users": users, "total": len(users)}

@router.post("/users", status_code=status.HTTP_201_CREATED)
async def create_new_user(body: UserCreate, admin: dict = Depends(require_admin)):
    try:
        user = create_user(body.email, body.name, body.password, body.role)
        return {k: v for k, v in user.items() if k != "hashed_pw"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error creando usuario: {e}")
