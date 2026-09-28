from fastapi import Depends, HTTPException, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError as JWTError

from .oidc import oidc_verifier
from .service import decode_token, get_user_by_id

bearer = HTTPBearer(auto_error=False)

async def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer)
) -> dict:
    if not creds:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token requerido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(creds.credentials)
        if payload.get("type"):
            raise JWTError("Refresh tokens cannot authorize API requests")
        uid = payload["sub"]
        user = get_user_by_id(uid)
        if not user or not user["active"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuario inactivo")
        return user
    except JWTError as local_error:
        try:
            return await oidc_verifier.verify(creds.credentials)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token inválido: {local_error}",
                headers={"WWW-Authenticate": "Bearer"},
            ) from local_error

async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Se requiere rol admin")
    return user

async def require_operator(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] not in ("admin", "operator"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Se requiere rol operator o admin")
    return user


async def require_system_admin(user: dict = Depends(require_admin)) -> dict:
    if user.get("tenant_id", "system") != "system":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere administrador del tenant system",
        )
    return user


def ensure_tenant_access(user: dict, tenant_id: str) -> None:
    user_tenant = user.get("tenant_id", "system")
    if user_tenant != "system" and user_tenant != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cross-tenant access denied",
        )

# Helper para rutas que funcionan con o sin auth
async def optional_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer)
) -> dict | None:
    if not creds:
        return None
    try:
        payload = decode_token(creds.credentials)
        if payload.get("type"):
            return None
        return get_user_by_id(payload["sub"])
    except Exception:
        return None


async def authenticate_websocket(websocket: WebSocket) -> dict | None:
    """Authenticate a WebSocket before accepting it.

    Browser clients pass the token as the second WebSocket subprotocol value;
    this avoids putting credentials in URLs and access logs.
    """
    authorization = websocket.headers.get("authorization", "")
    token = authorization[7:] if authorization.lower().startswith("bearer ") else None
    protocols = [part.strip() for part in websocket.headers.get(
        "sec-websocket-protocol", ""
    ).split(",") if part.strip()]
    if not token and len(protocols) == 2 and protocols[0] == "nexus-auth":
        token = protocols[1]
    if not token:
        await websocket.close(code=4401)
        return None
    try:
        payload = decode_token(token)
        if payload.get("type"):
            raise ValueError("refresh token is not an access token")
        user = get_user_by_id(payload["sub"])
        if not user or not user["active"]:
            raise ValueError("inactive user")
        return user
    except Exception:
        await websocket.close(code=4401)
        return None
