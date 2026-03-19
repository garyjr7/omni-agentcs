import os, sqlite3, hashlib, secrets, logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from pathlib import Path
from jose import jwt, JWTError
from passlib.context import CryptContext

logger = logging.getLogger("nexus.auth")

SECRET_KEY   = os.getenv("JWT_SECRET_KEY",  "dev-secret-nexuspro-2024-change-me")
ALGORITHM    = os.getenv("JWT_ALGORITHM",   "HS256")
EXPIRE_MIN   = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))
REFRESH_DAYS = int(os.getenv("JWT_REFRESH_DAYS",   "7"))

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

def _db_path():
    return os.getenv("NEXUS_DB_PATH",
        str(Path(__file__).parent.parent.parent / "data" / "nexus_pro.db"))

def _get_conn():
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    return conn

def _prep(plain):
    return hashlib.sha256(plain.encode()).hexdigest()

def init_users_table():
    with _get_conn() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS nexus_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            hashed_pw TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')))""")
        conn.commit()
    _ensure_admin()

def _ensure_admin():
    email = os.getenv("NEXUS_ADMIN_EMAIL",    "admin@nexuspro.io")
    name  = os.getenv("NEXUS_ADMIN_NAME",     "Admin")
    pw    = os.getenv("NEXUS_ADMIN_PASSWORD", "synthetic-password")
    with _get_conn() as conn:
        row = conn.execute("SELECT id FROM nexus_users WHERE email=?", (email,)).fetchone()
        if not row:
            hashed = pwd_ctx.hash(_prep(pw))
            conn.execute("INSERT INTO nexus_users(email,name,hashed_pw,role) VALUES(?,?,?,?)",
                         (email, name, hashed, "admin"))
            conn.commit()
            logger.info(f"Admin creado: {email}")

def get_user_by_email(email):
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM nexus_users WHERE email=?", (email,)).fetchone()
        return dict(row) if row else None

def get_user_by_id(uid):
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM nexus_users WHERE id=?", (uid,)).fetchone()
        return dict(row) if row else None

def list_users():
    with _get_conn() as conn:
        rows = conn.execute("SELECT id,email,name,role,active,created_at FROM nexus_users").fetchall()
        return [dict(r) for r in rows]

def create_user(email, name, password, role="viewer"):
    hashed = pwd_ctx.hash(_prep(password))
    with _get_conn() as conn:
        cur = conn.execute("INSERT INTO nexus_users(email,name,hashed_pw,role) VALUES(?,?,?,?)",
                           (email, name, hashed, role))
        conn.commit()
        return get_user_by_id(cur.lastrowid)

def verify_password(plain, hashed):
    return pwd_ctx.verify(_prep(plain), hashed)

def authenticate(email, password):
    user = get_user_by_email(email)
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
        "jti": secrets.token_hex(8)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_tokens(user):
    base = {"sub": str(user["id"]), "email": user["email"], "role": user["role"]}
    access  = _make_token(base, timedelta(minutes=EXPIRE_MIN))
    refresh = _make_token({**base, "type": "refresh"}, timedelta(days=REFRESH_DAYS))
    return {"access_token": access, "refresh_token": refresh,
            "token_type": "bearer", "expires_in": EXPIRE_MIN * 60,
            "user": {"id": user["id"], "email": user["email"], "name": user["name"],
                     "role": user["role"], "active": bool(user["active"]),
                     "created_at": user["created_at"]}}

def decode_token(token):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

def refresh_access_token(refresh_token):
    try:
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            return None
        user = get_user_by_id(int(payload["sub"]))
        if not user or not user["active"]:
            return None
        return create_tokens(user)
    except JWTError:
        return None
