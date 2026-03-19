#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Punto 7: JWT Auth Real                        ║
# ║  7A · auth/models  7B · auth/router  7C · middleware       ║
# ║  7D · Login page   7E · axios interceptor  7F · TopBar     ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

ROOT="/home/operator/NEXUS-PRO"
API="$ROOT/nexus_api"
FRONT="$ROOT/nexus_frontend/src"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

# ══════════════════════════════════════════════════════════════
head "1/8 · nexus_api/auth/models.py — User + Token schemas"
# ══════════════════════════════════════════════════════════════
mkdir -p "$API/auth"
touch "$API/auth/__init__.py"

cat > "$API/auth/models.py" << 'EOF'
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str
    role: str = "viewer"   # admin | operator | viewer

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: int
    email: str
    name: str
    role: str
    active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut

class TokenPayload(BaseModel):
    sub: str          # user id
    email: str
    role: str
    exp: int
    iat: int
    jti: Optional[str] = None   # para blacklist futura
EOF
log "auth/models.py"

# ══════════════════════════════════════════════════════════════
head "2/8 · nexus_api/auth/service.py — hash + JWT + DB users"
# ══════════════════════════════════════════════════════════════
cat > "$API/auth/service.py" << 'EOF'
import os, sqlite3, hashlib, secrets, logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from pathlib import Path
from jose import jwt, JWTError
from passlib.context import CryptContext

logger = logging.getLogger("nexus.auth")

# ── Config ────────────────────────────────────────────────────
SECRET_KEY  = os.getenv("JWT_SECRET_KEY",  "dev-secret-change-in-production-32chars")
ALGORITHM   = os.getenv("JWT_ALGORITHM",   "HS256")
EXPIRE_MIN  = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))   # 8h
REFRESH_DAYS= int(os.getenv("JWT_REFRESH_DAYS",   "7"))

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ── DB path ───────────────────────────────────────────────────
def _db_path() -> str:
    p = os.getenv("NEXUS_DB_PATH", str(Path(__file__).parent.parent.parent / "data" / "nexus_pro.db"))
    return p

def _get_conn():
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    return conn

# ── Init tabla users ──────────────────────────────────────────
def init_users_table():
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nexus_users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                email      TEXT UNIQUE NOT NULL,
                name       TEXT NOT NULL,
                hashed_pw  TEXT NOT NULL,
                role       TEXT NOT NULL DEFAULT 'viewer',
                active     INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT (datetime('now'))
            )
        """)
        conn.commit()
    _ensure_admin()

def _ensure_admin():
    """Crea el admin por defecto si no existe."""
    email = os.getenv("NEXUS_ADMIN_EMAIL",    "admin@nexuspro.io")
    name  = os.getenv("NEXUS_ADMIN_NAME",     "Admin")
    pw    = os.getenv("NEXUS_ADMIN_PASSWORD", "synthetic-password")
    with _get_conn() as conn:
        row = conn.execute("SELECT id FROM nexus_users WHERE email=?", (email,)).fetchone()
        if not row:
            hashed = pwd_ctx.hash(pw)
            conn.execute(
                "INSERT INTO nexus_users(email,name,hashed_pw,role) VALUES(?,?,?,?)",
                (email, name, hashed, "admin")
            )
            conn.commit()
            logger.info(f"Admin creado: {email}")

# ── CRUD ──────────────────────────────────────────────────────
def get_user_by_email(email: str) -> Optional[dict]:
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM nexus_users WHERE email=?", (email,)).fetchone()
        return dict(row) if row else None

def get_user_by_id(uid: int) -> Optional[dict]:
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM nexus_users WHERE id=?", (uid,)).fetchone()
        return dict(row) if row else None

def list_users() -> list:
    with _get_conn() as conn:
        rows = conn.execute("SELECT id,email,name,role,active,created_at FROM nexus_users").fetchall()
        return [dict(r) for r in rows]

def create_user(email: str, name: str, password: str, role: str = "viewer") -> dict:
    hashed = pwd_ctx.hash(password)
    with _get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO nexus_users(email,name,hashed_pw,role) VALUES(?,?,?,?)",
            (email, name, hashed, role)
        )
        conn.commit()
        return get_user_by_id(cur.lastrowid)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def authenticate(email: str, password: str) -> Optional[dict]:
    user = get_user_by_email(email)
    if not user or not user["active"]:
        return None
    if not verify_password(password, user["hashed_pw"]):
        return None
    return user

# ── JWT ───────────────────────────────────────────────────────
def _make_token(data: dict, expires_delta: timedelta) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        **data,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_tokens(user: dict) -> dict:
    base = {"sub": str(user["id"]), "email": user["email"], "role": user["role"]}
    access  = _make_token(base, timedelta(minutes=EXPIRE_MIN))
    refresh = _make_token({**base, "type": "refresh"}, timedelta(days=REFRESH_DAYS))
    return {
        "access_token":  access,
        "refresh_token": refresh,
        "token_type":    "bearer",
        "expires_in":    EXPIRE_MIN * 60,
        "user": {
            "id":         user["id"],
            "email":      user["email"],
            "name":       user["name"],
            "role":       user["role"],
            "active":     bool(user["active"]),
            "created_at": user["created_at"],
        }
    }

def decode_token(token: str) -> dict:
    """Lanza JWTError si inválido o expirado."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

def refresh_access_token(refresh_token: str) -> Optional[dict]:
    try:
        payload = decode_token(refresh_token)
        if payload.get("type") != "refresh":
            return None
        uid = int(payload["sub"])
        user = get_user_by_id(uid)
        if not user or not user["active"]:
            return None
        return create_tokens(user)
    except JWTError:
        return None
EOF
log "auth/service.py"

# ══════════════════════════════════════════════════════════════
head "3/8 · nexus_api/auth/deps.py — FastAPI dependencies"
# ══════════════════════════════════════════════════════════════
cat > "$API/auth/deps.py" << 'EOF'
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
EOF
log "auth/deps.py"

# ══════════════════════════════════════════════════════════════
head "4/8 · nexus_api/auth/router.py — endpoints /auth/*"
# ══════════════════════════════════════════════════════════════
cat > "$API/auth/router.py" << 'EOF'
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
EOF
log "auth/router.py"

# ══════════════════════════════════════════════════════════════
head "5/8 · Inyectar router en nexus_api/main.py"
# ══════════════════════════════════════════════════════════════
# Solo añadir si no está ya
if ! grep -q "auth.router" "$API/main.py"; then
    # Buscar la línea donde se incluyen otros routers
    # Añadir import y include_router al final de los imports de routers
    python3 << 'PYEOF'
import re

path = "/home/operator/NEXUS-PRO/nexus_api/main.py"
with open(path, "r") as f:
    content = f.read()

# Añadir import si no existe
if "from nexus_api.auth.router import router as auth_router" not in content:
    # Insertar después del último 'from ... import'
    content = content.replace(
        'from fastapi.middleware.cors import CORSMiddleware',
        'from fastapi.middleware.cors import CORSMiddleware\nfrom nexus_api.auth.router import router as auth_router'
    )

# Añadir include_router si no existe
if "auth_router" not in content or "include_router(auth_router" not in content:
    # Buscar donde se añaden otros routers (app.include_router)
    # Insertar al inicio de los include_router
    if "app.include_router" in content:
        content = content.replace(
            "app.include_router",
            "app.include_router(auth_router)\napp.include_router",
            1  # solo la primera ocurrencia
        )
    else:
        # Si no hay routers, añadir antes del healthcheck o al final
        content += "\napp.include_router(auth_router)\n"

with open(path, "w") as f:
    f.write(content)

print("main.py actualizado")
PYEOF
    log "auth router inyectado en main.py"
else
    log "auth router ya presente en main.py"
fi

# ══════════════════════════════════════════════════════════════
head "6/8 · Frontend — store/authStore.js"
# ══════════════════════════════════════════════════════════════
cat > "$FRONT/store/authStore.js" << 'EOF'
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export const useAuthStore = create(
  persist(
    (set, get) => ({
      user:          null,
      accessToken:   null,
      refreshToken:  null,
      isAuthenticated: false,

      setTokens: (tokens) => set({
        accessToken:     tokens.access_token,
        refreshToken:    tokens.refresh_token,
        user:            tokens.user,
        isAuthenticated: true,
      }),

      logout: () => {
        set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false })
        // Limpiar cualquier cache de react-query
        window.dispatchEvent(new Event('nexus:logout'))
      },

      updateUser: (user) => set({ user }),
    }),
    {
      name: 'nexus-auth',
      partialize: (s) => ({
        user:         s.user,
        accessToken:  s.accessToken,
        refreshToken: s.refreshToken,
        isAuthenticated: s.isAuthenticated,
      }),
    }
  )
)
EOF
log "store/authStore.js"

# ══════════════════════════════════════════════════════════════
head "7/8 · Frontend — api/client.js con interceptor JWT"
# ══════════════════════════════════════════════════════════════
cat > "$FRONT/api/client.js" << 'EOF'
import axios from 'axios'

export const API_URL = import.meta.env.VITE_API_URL || 'http://192.168.220.134:8000'
export const WS_URL  = import.meta.env.VITE_WS_URL  || 'ws://192.168.220.134:8000'

export const api = axios.create({
  baseURL: API_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

// ── Interceptor request — inyecta el token ────────────────────
api.interceptors.request.use((config) => {
  try {
    const raw = localStorage.getItem('nexus-auth')
    if (raw) {
      const state = JSON.parse(raw)
      const token = state?.state?.accessToken
      if (token) config.headers['Authorization'] = `Bearer ${token}`
    }
  } catch { /* sin token → petición sin auth */ }
  return config
})

// ── Interceptor response — auto-refresh en 401 ───────────────
let _refreshing = false
let _queue = []

api.interceptors.response.use(
  r => r,
  async err => {
    const original = err.config
    if (err.response?.status === 401 && !original._retry) {
      if (_refreshing) {
        // Encolar mientras se refresca
        return new Promise((res, rej) => {
          _queue.push({ res, rej })
        }).then(token => {
          original.headers['Authorization'] = `Bearer ${token}`
          return api(original)
        })
      }
      original._retry = true
      _refreshing = true
      try {
        const raw = localStorage.getItem('nexus-auth')
        const state = raw ? JSON.parse(raw) : null
        const refreshToken = state?.state?.refreshToken
        if (!refreshToken) throw new Error('No refresh token')

        const { data } = await axios.post(`${API_URL}/auth/refresh`, { refresh_token: refreshToken })
        // Actualizar store
        const nexusState = JSON.parse(localStorage.getItem('nexus-auth') || '{}')
        nexusState.state = { ...nexusState.state, accessToken: data.access_token, refreshToken: data.refresh_token }
        localStorage.setItem('nexus-auth', JSON.stringify(nexusState))

        _queue.forEach(p => p.res(data.access_token))
        _queue = []
        original.headers['Authorization'] = `Bearer ${data.access_token}`
        return api(original)
      } catch(e) {
        _queue.forEach(p => p.rej(e))
        _queue = []
        // Token expirado → logout
        window.dispatchEvent(new Event('nexus:logout'))
        return Promise.reject(err)
      } finally {
        _refreshing = false
      }
    }
    console.warn('API Error:', err.response?.status, err.config?.url)
    return Promise.reject(err)
  }
)

export const nexusApi = {
  // Auth
  login:    (email, password) => api.post('/auth/login',   { email, password }),
  refresh:  (rt) => api.post('/auth/refresh', { refresh_token: rt }),
  me:       () => api.get('/auth/me'),
  logout:   () => api.post('/auth/logout'),
  getUsers: () => api.get('/auth/users'),
  createUser:(d) => api.post('/auth/users', d),

  // Health
  health: () => api.get('/health'),

  // Tools
  tools: () => api.get('/tools'),

  // Agents
  agents:        () => api.get('/agents'),
  agentRegistry: () => api.get('/agents/registry'),
  agent:         (id) => api.get(`/agents/${id}`),
  createAgent:   (d) => api.post('/agents', d),
  updateAgent:   (id, d) => api.put(`/agents/${id}`, d),
  assignTools:   (id, tools) => api.post(`/agents/${id}/tools`, { tools }),
  deleteAgent:   (id) => api.delete(`/agents/${id}`),
  chatAgent:     (id, msg, sys) => api.post(`/agents/${id}/chat`, { message: msg, system_override: sys }),

  // Teams
  teams:              () => api.get('/teams-v2/teams-v2'),
  createTeam:         (d) => api.post('/teams-v2/teams-v2', d),
  updateTeam:         (id, d) => api.put(`/teams-v2/teams-v2/${id}`, d),
  addAgentToTeam:     (tid, aid) => api.post(`/teams-v2/teams-v2/${tid}/agents`, { agent_id: aid }),
  removeAgentFromTeam:(tid, aid) => api.delete(`/teams-v2/teams-v2/${tid}/agents/${aid}`),
  deleteTeam:         (id) => api.delete(`/teams-v2/teams-v2/${id}`),

  // Tasks
  tasks:      (status) => api.get('/tasks', { params: status ? { status } : {} }),
  task:        (id) => api.get(`/tasks/${id}`),
  createTask:  (d) => api.post('/tasks', d),
  runTask:     (id) => api.post(`/tasks/${id}/run`),
  cancelTask:  (id) => api.post(`/tasks/${id}/cancel`),

  // Models & API Keys
  apiKeys:        () => api.get('/models/keys'),
  addApiKey:      (d) => api.post('/models/keys', d),
  deleteApiKey:   (id) => api.delete(`/models/keys/${id}`),
  redetect:       (id) => api.post(`/models/keys/${id}/detect`),
  availableModels:() => api.get('/models/available'),

  // HITL
  hitlPending:   () => api.get('/hitl/pending'),
  hitlHistory:   () => api.get('/hitl/history'),
  hitlCount:     () => api.get('/hitl/count'),
  approveHITL:   (id, by, reason) => api.post(`/hitl/${id}/approve`, { approved_by: by||'admin', reason: reason||'' }),
  denyHITL:      (id, by, reason) => api.post(`/hitl/${id}/deny`, { denied_by: by||'admin', reason: reason||'' }),
  approveAllHITL:() => api.post('/hitl/approve-all', { approved_by: 'admin' }),
  denyAllHITL:   () => api.post('/hitl/deny-all', { denied_by: 'admin' }),

  // Junior
  juniorRun:     (objective, maxSteps) => api.post('/junior/run', { objective, max_steps: maxSteps || 6 }),
  juniorStatus:  (id) => api.get(`/junior/status/${id}`),
  juniorChat:    (msg, sessionId) => api.post('/junior/chat', { message: msg, session_id: sessionId }),
  juniorSessions:() => api.get('/junior/sessions'),

  // Pentest
  pentestRun:    (d) => api.post('/pentest/run', d),
  pentestStatus: (id) => api.get(`/pentest/status/${id}`),
  pentestReports:() => api.get('/pentest/reports'),
  pentestReport: (f) => api.get(`/pentest/reports/${f}`),
  quickScan:     () => api.post('/pentest/quick-scan'),

  // Guardian
  guardianScan:    () => api.post('/guardian/scan/full'),
  guardianSecrets: () => api.post('/guardian/scan/secrets'),
  guardianBandit:  () => api.post('/guardian/scan/bandit'),
  guardianIncidents:() => api.get('/guardian/incidents'),
}
EOF
log "api/client.js con interceptor JWT"

# ══════════════════════════════════════════════════════════════
head "8/8 · Frontend — pages/Login.jsx + App.jsx con guard"
# ══════════════════════════════════════════════════════════════
cat > "$FRONT/pages/Login.jsx" << 'EOF'
import { useState, useEffect } from 'react'
import { useAuthStore } from '../store/authStore'
import { nexusApi } from '../api/client'

export default function Login() {
  const { setTokens } = useAuthStore()
  const [email,    setEmail]    = useState('admin@nexuspro.io')
  const [password, setPassword] = useState('')
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)

  const submit = async (e) => {
    e?.preventDefault()
    if (!email || !password) { setError('Completa los campos'); return }
    setLoading(true); setError('')
    try {
      const { data } = await nexusApi.login(email, password)
      setTokens(data)
    } catch (err) {
      setError(err.response?.data?.detail || 'Credenciales inválidas')
    } finally {
      setLoading(false)
    }
  }

  // Enter para submit
  useEffect(() => {
    const handler = (e) => { if (e.key === 'Enter') submit() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [email, password])

  return (
    <div style={{ minHeight:'100vh', background:'var(--bg-base)',
      display:'flex', alignItems:'center', justifyContent:'center',
      fontFamily:'var(--ui)' }}>

      {/* Fondo animado */}
      <div style={{ position:'fixed', inset:0, overflow:'hidden', zIndex:0, opacity:.04 }}>
        {Array.from({length:20},(_,i)=>(
          <div key={i} style={{ position:'absolute', fontFamily:'var(--mono)', fontSize:11,
            color:'var(--green)', whiteSpace:'nowrap',
            left:`${(i*7.3)%100}%`, top:`${(i*13.7)%100}%`,
            animation:`float ${8+i%4}s linear infinite`, opacity:.6 }}>
            {['01001110','11001000','00110101','10110001','NEXUS_PRO'][i%5]}
          </div>
        ))}
      </div>

      <div style={{ position:'relative', zIndex:1, width:'100%', maxWidth:420, padding:24 }}>
        {/* Logo */}
        <div style={{ textAlign:'center', marginBottom:40 }}>
          <div style={{ display:'inline-flex', alignItems:'center', justifyContent:'center',
            width:64, height:64, border:'1px solid var(--green)',
            background:'linear-gradient(135deg,#001a0d,#002a1a)',
            borderRadius:8, marginBottom:16,
            boxShadow:'0 0 30px #00ff9d25, inset 0 0 20px #00ff9d08' }}>
            <span style={{ fontFamily:'var(--display)', fontSize:22,
              color:'var(--green)', fontWeight:700, letterSpacing:2 }}>N</span>
          </div>
          <div style={{ fontFamily:'var(--display)', fontSize:24, fontWeight:700,
            color:'var(--text-bright)', letterSpacing:3 }}>NEXUS PRO</div>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
            marginTop:6, letterSpacing:2 }}>AI OPERATIONS PLATFORM</div>
        </div>

        {/* Card */}
        <div style={{ background:'var(--bg-panel)', border:'1px solid var(--border)',
          borderRadius:6, padding:32,
          boxShadow:'0 20px 60px rgba(0,0,0,.5), 0 0 40px #00ff9d08' }}>

          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
            letterSpacing:2, textTransform:'uppercase', marginBottom:24 }}>
            Acceso al Sistema
          </div>

          {/* Email */}
          <div style={{ marginBottom:16 }}>
            <label style={{ display:'block', fontFamily:'var(--mono)', fontSize:10,
              color:'var(--text-dim)', letterSpacing:1, textTransform:'uppercase', marginBottom:6 }}>
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              autoComplete="email"
              style={{ width:'100%', background:'var(--bg-base)', border:'1px solid var(--border)',
                borderRadius:3, padding:'10px 14px', color:'var(--text)',
                fontFamily:'var(--mono)', fontSize:13, outline:'none',
                transition:'border-color .2s',
                borderColor: error ? 'var(--red)' : undefined }}
              onFocus={e => e.target.style.borderColor = 'var(--green)'}
              onBlur={e => e.target.style.borderColor = 'var(--border)'}
            />
          </div>

          {/* Password */}
          <div style={{ marginBottom:24 }}>
            <label style={{ display:'block', fontFamily:'var(--mono)', fontSize:10,
              color:'var(--text-dim)', letterSpacing:1, textTransform:'uppercase', marginBottom:6 }}>
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              autoComplete="current-password"
              placeholder="••••••••"
              style={{ width:'100%', background:'var(--bg-base)', border:'1px solid var(--border)',
                borderRadius:3, padding:'10px 14px', color:'var(--text)',
                fontFamily:'var(--mono)', fontSize:13, outline:'none',
                transition:'border-color .2s' }}
              onFocus={e => e.target.style.borderColor = 'var(--green)'}
              onBlur={e => e.target.style.borderColor = 'var(--border)'}
            />
          </div>

          {/* Error */}
          {error && (
            <div style={{ padding:'8px 12px', background:'#ff386015', border:'1px solid var(--red)',
              borderRadius:3, fontFamily:'var(--mono)', fontSize:11, color:'var(--red)',
              marginBottom:16 }}>
              ✗ {error}
            </div>
          )}

          {/* Submit */}
          <button
            onClick={submit}
            disabled={loading}
            style={{ width:'100%', padding:'12px', borderRadius:3, cursor: loading ? 'wait' : 'pointer',
              background: loading ? 'transparent' : 'var(--green)',
              border:`1px solid var(--green)`,
              color: loading ? 'var(--green)' : 'var(--bg-base)',
              fontFamily:'var(--mono)', fontSize:13, fontWeight:700, letterSpacing:2,
              transition:'all .2s',
              boxShadow: loading ? 'none' : '0 0 20px #00ff9d30' }}>
            {loading ? '⟳ AUTENTICANDO...' : '▶ ACCEDER'}
          </button>

          <div style={{ marginTop:20, padding:'10px 12px', background:'var(--bg-base)',
            border:'1px solid var(--border)', borderRadius:3,
            fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', lineHeight:1.8 }}>
            Default: admin@nexuspro.io / synthetic-password
          </div>
        </div>

        <div style={{ textAlign:'center', marginTop:20,
          fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)', letterSpacing:1 }}>
          NEXUS PRO · ZERO TRUST · JWT HS256
        </div>
      </div>

      <style>{`
        @keyframes float {
          0% { transform: translateY(0) translateX(0); }
          50% { transform: translateY(-20px) translateX(10px); }
          100% { transform: translateY(0) translateX(0); }
        }
        @keyframes blink { 50% { opacity: 0; } }
      `}</style>
    </div>
  )
}
EOF
log "pages/Login.jsx"

# ── App.jsx con auth guard ────────────────────────────────────
cat > "$FRONT/App.jsx" << 'EOF'
import { useEffect } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useNexusStore } from './store/nexusStore'
import { useAuthStore }  from './store/authStore'
import { useNexusWebSocket, useHITLWebSocket } from './hooks/useWebSocket'
import TopBar    from './components/layout/TopBar'
import Sidebar   from './components/layout/Sidebar'
import Login     from './pages/Login'
import Overview  from './pages/Overview'
import Agents    from './pages/Agents'
import Tasks     from './pages/Tasks'
import Teams     from './pages/Teams'
import Models    from './pages/Models'
import HITL      from './pages/HITL'
import Vault     from './pages/Vault'
import Guardian  from './pages/Guardian'
import RBAC      from './pages/RBAC'
import Audit     from './pages/Audit'
import Terminal  from './pages/Terminal'
import Settings  from './pages/Settings'
import Junior    from './pages/Junior'
import Pentest   from './pages/Pentest'

const qc = new QueryClient({ defaultOptions:{ queries:{ retry:1, staleTime:3000 } } })

const PAGES = {
  overview: Overview, agents: Agents, tasks: Tasks, teams: Teams,
  models: Models, hitl: HITL, vault: Vault, guardian: Guardian,
  rbac: RBAC, audit: Audit, terminal: Terminal, settings: Settings,
  junior: Junior, pentest: Pentest,
}

function NexusApp() {
  useNexusWebSocket()
  useHITLWebSocket()
  const activePage = useNexusStore(s => s.activePage)
  const Page = PAGES[activePage] || Overview

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100vh', overflow:'hidden' }}>
      <TopBar />
      <div style={{ display:'flex', flex:1, overflow:'hidden' }}>
        <Sidebar />
        <main style={{ flex:1, overflowY:'auto', overflowX:'hidden', background:'var(--bg-base)' }}>
          <Page />
        </main>
      </div>
    </div>
  )
}

function AuthGuard({ children }) {
  const { isAuthenticated, logout } = useAuthStore()

  // Escuchar evento de logout forzado (token expirado)
  useEffect(() => {
    const handler = () => logout()
    window.addEventListener('nexus:logout', handler)
    return () => window.removeEventListener('nexus:logout', handler)
  }, [logout])

  if (!isAuthenticated) return <Login />
  return children
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <AuthGuard>
        <NexusApp />
      </AuthGuard>
    </QueryClientProvider>
  )
}
EOF
log "App.jsx con AuthGuard"

# ── TopBar — mostrar usuario logueado + logout ────────────────
# Actualizar TopBar solo si existe
TOPBAR="$FRONT/components/layout/TopBar.jsx"
if [ -f "$TOPBAR" ]; then
cat > "$TOPBAR" << 'EOF'
import { useNexusStore } from '../../store/nexusStore'
import { useAuthStore }  from '../../store/authStore'
import { nexusApi } from '../../api/client'
import { Dot } from '../ui'

export default function TopBar() {
  const { systemStatus, hitlCount, wsConnected, notifications } = useNexusStore()
  const { user, logout } = useAuthStore()

  const handleLogout = async () => {
    try { await nexusApi.logout() } catch {}
    logout()
  }

  const STATUS_COLOR = {
    ok: 'var(--green)', healthy: 'var(--green)',
    degraded: 'var(--yellow)', error: 'var(--red)',
    connecting: 'var(--cyan)',
  }
  const sc = STATUS_COLOR[systemStatus] || 'var(--cyan)'

  return (
    <header style={{ height:48, background:'var(--bg-panel)', borderBottom:'1px solid var(--border)',
      display:'flex', alignItems:'center', padding:'0 20px', gap:16, flexShrink:0, zIndex:100 }}>

      {/* Logo */}
      <div style={{ display:'flex', alignItems:'center', gap:10, marginRight:8 }}>
        <div style={{ width:28, height:28, border:'1px solid var(--green)', borderRadius:4,
          background:'linear-gradient(135deg,#001a0d,#002a1a)',
          display:'flex', alignItems:'center', justifyContent:'center',
          fontFamily:'var(--display)', fontSize:11, color:'var(--green)', fontWeight:700,
          boxShadow:'0 0 10px #00ff9d20' }}>N</div>
        <span style={{ fontFamily:'var(--display)', fontSize:13, fontWeight:700,
          color:'var(--text-bright)', letterSpacing:2 }}>NEXUS PRO</span>
      </div>

      {/* Status */}
      <div style={{ display:'flex', alignItems:'center', gap:6, padding:'3px 10px',
        border:`1px solid ${sc}30`, borderRadius:10, background:`${sc}08` }}>
        <Dot color={sc} size={6} />
        <span style={{ fontFamily:'var(--mono)', fontSize:10, color:sc }}>
          {systemStatus?.toUpperCase() || 'CONECTANDO'}
        </span>
      </div>

      {/* WS */}
      <div style={{ display:'flex', alignItems:'center', gap:5 }}>
        <Dot color={wsConnected ? 'var(--green)' : 'var(--red)'} size={5} />
        <span style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)' }}>
          {wsConnected ? 'WS' : 'WS OFF'}
        </span>
      </div>

      {/* HITL badge */}
      {hitlCount > 0 && (
        <div style={{ padding:'3px 10px', borderRadius:10,
          border:'1px solid var(--yellow)', background:'#ffc10715',
          fontFamily:'var(--mono)', fontSize:10, color:'var(--yellow)',
          animation:'pulse 2s infinite' }}>
          ⚠ {hitlCount} HITL
        </div>
      )}

      <div style={{ flex:1 }} />

      {/* Role badge */}
      {user && (
        <div style={{ padding:'3px 10px', borderRadius:10,
          border:'1px solid var(--border)', background:'var(--bg-card)',
          fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)' }}>
          {user.role?.toUpperCase()}
        </div>
      )}

      {/* User + logout */}
      {user && (
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <div style={{ textAlign:'right' }}>
            <div style={{ fontSize:12, fontWeight:600, color:'var(--text-bright)' }}>{user.name}</div>
            <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)' }}>{user.email}</div>
          </div>
          <button onClick={handleLogout}
            style={{ padding:'5px 12px', borderRadius:3, cursor:'pointer',
              border:'1px solid var(--border)', background:'transparent',
              color:'var(--text-dim)', fontFamily:'var(--mono)', fontSize:10,
              transition:'all .15s' }}
            onMouseEnter={e => { e.target.style.borderColor='var(--red)'; e.target.style.color='var(--red)' }}
            onMouseLeave={e => { e.target.style.borderColor='var(--border)'; e.target.style.color='var(--text-dim)' }}>
            ⏏ SALIR
          </button>
        </div>
      )}
    </header>
  )
}
EOF
log "TopBar.jsx con user + logout"
fi

# ── Instalar zustand/middleware persist si falta ──────────────
cd "$ROOT/nexus_frontend"
if ! npm list zustand --depth=0 2>/dev/null | grep -q zustand; then
    npm install zustand --silent
fi
log "zustand OK"

# Build
head "Build final"
npm run build --silent 2>&1 | tail -5

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO — Punto 7: JWT Auth ✓                  ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Backend:${NC}"
echo -e "  POST /auth/login          → JWT access + refresh tokens"
echo -e "  POST /auth/refresh        → renovar token sin re-login"
echo -e "  GET  /auth/me             → usuario actual"
echo -e "  GET  /auth/users          → listar usuarios (admin)"
echo -e "  POST /auth/users          → crear usuario (admin)"
echo ""
echo -e "  ${CYAN}Frontend:${NC}"
echo -e "  Login page con guard      → redirige si no autenticado"
echo -e "  axios interceptor         → token automático en cada request"
echo -e "  auto-refresh en 401       → renueva token transparente"
echo -e "  TopBar user + logout      → nombre, rol, botón salir"
echo ""
echo -e "  ${BOLD}Credenciales por defecto:${NC}"
echo -e "  Email:    admin@nexuspro.io"
echo -e "  Password: synthetic-password"
echo ""
echo -e "  ${BOLD}Siguiente — Punto 8: Multi-tenant + install.sh final${NC}"
echo ""
