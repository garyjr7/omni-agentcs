from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError
from .service import decode_token, get_user_by_id
import os

bearer = HTTPBearer(auto_error=False)

DEV_MODE = os.getenv("NEXUS_ENV", "production") == "development"

async def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer)
) -> dict:
    # En development sin token → usuario admin mock
    if DEV_MODE and not creds:
        return {"id": 0, "email": "dev@local", "name": "Dev", "role": "admin", "active": True}

    if not creds:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token requerido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(creds.credentials)
        uid = int(payload["sub"])
        user = get_user_by_id(uid)
        if not user or not user["active"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario inactivo")
        return user
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token inválido: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Se requiere rol admin")
    return user

async def require_operator(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] not in ("admin", "operator"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Se requiere rol operator o admin")
    return user

# Helper para rutas que funcionan con o sin auth
async def optional_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer)
) -> dict | None:
    if not creds:
        return None
    try:
        payload = decode_token(creds.credentials)
        return get_user_by_id(int(payload["sub"]))
    except Exception:
        return None
