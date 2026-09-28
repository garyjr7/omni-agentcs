import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import jwt
from jwt import InvalidTokenError as JWTError
from passlib.context import CryptContext

from nexus_core.kernel.store_factory import get_control_store

logger = logging.getLogger("nexus.auth")

ENVIRONMENT  = os.getenv("NEXUS_ENV", "development").lower()
SECRET_KEY   = os.getenv("JWT_SECRET_KEY", "")
if not SECRET_KEY:
    if ENVIRONMENT == "production":
        raise RuntimeError("JWT_SECRET_KEY is required in production")
    SECRET_KEY = secrets.token_urlsafe(48)
    logger.warning("Using an ephemeral JWT key for development; tokens reset on restart")
if len(SECRET_KEY) < 32:
    raise RuntimeError("JWT_SECRET_KEY must contain at least 32 characters")
ALGORITHM    = os.getenv("JWT_ALGORITHM",   "HS256")
if ALGORITHM != "HS256":
    raise RuntimeError("Only JWT_ALGORITHM=HS256 is supported by local identity")
if ENVIRONMENT == "production" and SECRET_KEY.startswith("cambia-esto"):
    raise RuntimeError("JWT_SECRET_KEY still contains the documented placeholder")
JWT_ISSUER = os.getenv("JWT_ISSUER", "nexus")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "nexus-api")
EXPIRE_MIN   = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))
REFRESH_DAYS = int(os.getenv("JWT_REFRESH_DAYS",   "7"))

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

def _get_conn():
    fallback = os.getenv(
        "NEXUS_DB_PATH", str(Path(__file__).parent.parent.parent / "data" / "nexus_pro.db")
    )
    return get_control_store(fallback).connect()

def _prep(plain):
    return hashlib.sha256(plain.encode()).hexdigest()

def init_users_table():
    fallback = os.getenv(
        "NEXUS_DB_PATH", str(Path(__file__).parent.parent.parent / "data" / "nexus_pro.db")
    )
    store = get_control_store(fallback)
    store.initialize()
    migrate = getattr(store, "migrate_legacy_users", None)
    if migrate:
        migrate()
    _ensure_admin()

def _ensure_admin():
    email = os.getenv("NEXUS_ADMIN_EMAIL")
    pw = os.getenv("NEXUS_ADMIN_PASSWORD")
    if not email or not pw:
        logger.info("Admin bootstrap skipped; set NEXUS_ADMIN_EMAIL and NEXUS_ADMIN_PASSWORD explicitly")
        return
    if len(pw) < 12:
        raise RuntimeError("NEXUS_ADMIN_PASSWORD must contain at least 12 characters")
    if ENVIRONMENT == "production" and pw.startswith("cambia-esto"):
        raise RuntimeError("NEXUS_ADMIN_PASSWORD still contains the documented placeholder")
    name  = os.getenv("NEXUS_ADMIN_NAME", "Admin")
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM kernel_users WHERE tenant_id='system' AND email=?", (email,)
        ).fetchone()
        if not row:
            hashed = pwd_ctx.hash(_prep(pw))
            conn.execute(
                """INSERT INTO kernel_users
                (id,tenant_id,email,name,hashed_pw,role,active,created_at)
                VALUES(?,?,?,?,?,?,?,?)""",
                (f"user_{uuid4().hex}", "system", email, name, hashed, "admin", 1,
                 datetime.now(timezone.utc).isoformat()),
            )
            logger.info(f"Admin creado: {email}")

def get_user_by_email(email, tenant_id="system"):
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM kernel_users WHERE tenant_id=? AND email=?", (tenant_id, email)
        ).fetchone()
        return dict(row) if row else None

def get_user_by_id(uid):
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM kernel_users WHERE id=?", (uid,)).fetchone()
        return dict(row) if row else None

def list_users(tenant_id: str):
    with _get_conn() as conn:
        rows = conn.execute(
            """SELECT id,email,name,role,active,tenant_id,created_at FROM kernel_users
            WHERE tenant_id=?""", (tenant_id,)
        ).fetchall()
        return [dict(r) for r in rows]

def create_user(email, name, password, role="viewer", tenant_id="system"):
    if role not in {"admin", "operator", "viewer"}:
        raise ValueError("Invalid role")
    if len(password) < 12:
        raise ValueError("Password must contain at least 12 characters")
    hashed = pwd_ctx.hash(_prep(password))
    user_id = f"user_{uuid4().hex}"
    with _get_conn() as conn:
        conn.execute(
            """INSERT INTO kernel_users
            (id,tenant_id,email,name,hashed_pw,role,active,created_at)
            VALUES(?,?,?,?,?,?,?,?)""",
            (user_id, tenant_id, email, name, hashed, role, 1,
             datetime.now(timezone.utc).isoformat()),
        )
    return get_user_by_id(user_id)

def verify_password(plain, hashed):
    return pwd_ctx.verify(_prep(plain), hashed)

def authenticate(email, password, tenant_id="system"):
    user = get_user_by_email(email, tenant_id)
    if not user or not user["active"]:
        return None
    if not verify_password(password, user["hashed_pw"]):
        return None
    return user

def _make_token(data, expires_delta):
    now = datetime.now(timezone.utc)
    payload = {**data,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "jti": secrets.token_hex(32), "iss": JWT_ISSUER, "aud": JWT_AUDIENCE}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def _register_refresh(token: str, user_id: str) -> None:
    payload = jwt.decode(token, options={"verify_signature": False})
    expires_at = datetime.fromtimestamp(payload["exp"], timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute(
            """INSERT INTO auth_refresh_sessions(jti,user_id,expires_at,created_at)
            VALUES(?,?,?,?)""",
            (payload["jti"], user_id, expires_at, datetime.now(timezone.utc).isoformat()),
        )

def create_tokens(user):
    base = {"sub": str(user["id"]), "email": user["email"], "role": user["role"],
            "tenant_id": user.get("tenant_id", "system")}
    access  = _make_token(base, timedelta(minutes=EXPIRE_MIN))
    refresh = _make_token({**base, "type": "refresh"}, timedelta(days=REFRESH_DAYS))
    _register_refresh(refresh, str(user["id"]))
    return {"access_token": access, "refresh_token": refresh,
            "token_type": "bearer", "expires_in": EXPIRE_MIN * 60,
            "user": {"id": user["id"], "email": user["email"], "name": user["name"],
                     "role": user["role"], "active": bool(user["active"]),
                     "tenant_id": user.get("tenant_id", "system"),
                     "created_at": user["created_at"]}}

def decode_token(token):
    payload = jwt.decode(
        token, SECRET_KEY, algorithms=[ALGORITHM], issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
    )
    with _get_conn() as conn:
        revoked = conn.execute(
            "SELECT jti FROM auth_revoked_tokens WHERE jti=?", (payload.get("jti", ""),)
        ).fetchone()
    if revoked:
        raise JWTError("Token revoked")
    return payload


def revoke_token(token: str) -> None:
    payload = jwt.decode(
        token, SECRET_KEY, algorithms=[ALGORITHM], issuer=JWT_ISSUER,
        audience=JWT_AUDIENCE,
    )
    expires_at = datetime.fromtimestamp(payload["exp"], timezone.utc).isoformat()
    now = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute(
            """INSERT INTO auth_revoked_tokens(jti,expires_at,revoked_at)
            VALUES(?,?,?) ON CONFLICT(jti) DO NOTHING""",
            (payload["jti"], expires_at, now),
        )
        if payload.get("type") == "refresh":
            conn.execute(
                "UPDATE auth_refresh_sessions SET revoked_at=? WHERE jti=?",
                (now, payload["jti"]),
            )

def refresh_access_token(refresh_token):
    try:
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            return None
        with _get_conn() as conn:
            session = conn.execute(
                """SELECT jti FROM auth_refresh_sessions
                WHERE jti=? AND user_id=? AND revoked_at IS NULL AND expires_at>?""",
                (payload["jti"], payload["sub"], datetime.now(timezone.utc).isoformat()),
            ).fetchone()
        if not session:
            return None
        user = get_user_by_id(payload["sub"])
        if not user or not user["active"]:
            return None
        revoke_token(refresh_token)
        return create_tokens(user)
    except JWTError:
        return None
