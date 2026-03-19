#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Punto 13: Security Headers + BAJIOWARE        ║
# ║  13A · HTTP security headers middleware                     ║
# ║  13B · JARVIS notifications en dashboard                   ║
# ║  13C · Landing page BAJIOWARE                              ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

ROOT="/home/operator/NEXUS-PRO"
FRONT="$ROOT/nexus_frontend/src"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

# ══════════════════════════════════════════════════════════════
head "1/5 · Security headers middleware en FastAPI"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
path = "/home/operator/NEXUS-PRO/nexus_api/main.py"
with open(path) as f:
    content = f.read()

if "SecurityHeadersMiddleware" not in content:
    middleware_code = '''
# ── Security Headers Middleware ────────────────────────────────
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"]           = "DENY"
        response.headers["X-Content-Type-Options"]    = "nosniff"
        response.headers["X-XSS-Protection"]          = "1; mode=block"
        response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
        response.headers["Content-Security-Policy"]   = (
            "default-src \'self\'; "
            "connect-src \'self\' ws: wss: http://192.168.220.134:8000 ws://192.168.220.134:8000; "
            "script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'; "
            "style-src \'self\' \'unsafe-inline\';"
        )
        # Solo HSTS en producción con HTTPS
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

'''
    # Insertar después de los imports de middleware existentes
    content = content.replace(
        "from fastapi.middleware.cors import CORSMiddleware",
        "from fastapi.middleware.cors import CORSMiddleware" + middleware_code
    )
    # Añadir al app después del CORSMiddleware
    content = content.replace(
        "app.add_middleware(CORSMiddleware",
        "app.add_middleware(SecurityHeadersMiddleware)\napp.add_middleware(CORSMiddleware"
    )
    with open(path, "w") as f:
        f.write(content)
    print("Security headers middleware añadido")
else:
    print("ya estaba")
PYEOF
log "Security headers middleware"

# ══════════════════════════════════════════════════════════════
head "2/5 · JARVIS notifications widget en TopBar"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
content = r"""import { useAuthStore }  from '../../store/authStore'
import { useNexusStore } from '../../store/nexusStore'
import { nexusApi } from '../../api/client'
import { api } from '../../api/client'
import { Dot } from '../ui'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

export default function TopBar() {
  const { systemStatus, hitlCount, wsConnected } = useNexusStore()
  const { user, logout } = useAuthStore()
  const [showNotif, setShowNotif] = useState(false)
  const qc = useQueryClient()

  const { data: jarvisData } = useQuery({
    queryKey: ['jarvis-notifications'],
    queryFn: () => api.get('/jarvis/notifications?limit=10').then(r => r.data),
    refetchInterval: 30000,
  })

  const readAllMutation = useMutation({
    mutationFn: () => api.post('/jarvis/notifications/read-all'),
    onSuccess: () => qc.invalidateQueries(['jarvis-notifications']),
  })

  const handleLogout = async () => {
    try { await nexusApi.logout() } catch {}
    logout()
  }

  const STATUS_COLOR = {
    ok:'var(--green)', healthy:'var(--green)',
    degraded:'var(--yellow)', error:'var(--red)', connecting:'var(--cyan)',
  }
  const sc = STATUS_COLOR[systemStatus] || 'var(--cyan)'

  const unread = jarvisData?.unread || 0
  const notifications = jarvisData?.notifications || []

  const NOTIF_COLOR = {
    proposal:'var(--cyan)', security:'var(--orange)',
    warning:'var(--yellow)', error:'var(--red)', info:'var(--text-dim)'
  }

  return (
    <header style={{ height:48, background:'var(--bg-panel)', borderBottom:'1px solid var(--border)',
      display:'flex', alignItems:'center', padding:'0 20px', gap:16, flexShrink:0, zIndex:100,
      position:'relative' }}>

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

      {/* JARVIS notifications bell */}
      <div style={{ position:'relative' }}>
        <button onClick={() => setShowNotif(s => !s)}
          style={{ padding:'5px 10px', borderRadius:3, cursor:'pointer',
            border:`1px solid ${unread > 0 ? 'var(--cyan)' : 'var(--border)'}`,
            background: unread > 0 ? '#00d4ff10' : 'transparent',
            color: unread > 0 ? 'var(--cyan)' : 'var(--text-dim)',
            fontFamily:'var(--mono)', fontSize:11, display:'flex', alignItems:'center', gap:6,
            transition:'all .15s' }}>
          🤖 JARVIS
          {unread > 0 && (
            <span style={{ background:'var(--cyan)', color:'var(--bg-base)',
              borderRadius:'50%', width:16, height:16, display:'flex',
              alignItems:'center', justifyContent:'center',
              fontFamily:'var(--mono)', fontSize:9, fontWeight:700 }}>
              {unread > 9 ? '9+' : unread}
            </span>
          )}
        </button>

        {/* Dropdown notificaciones */}
        {showNotif && (
          <div style={{ position:'absolute', right:0, top:'100%', marginTop:4,
            width:360, background:'var(--bg-panel)', border:'1px solid var(--border)',
            borderRadius:4, boxShadow:'0 10px 40px rgba(0,0,0,.5)', zIndex:1000 }}>
            <div style={{ padding:'10px 14px', borderBottom:'1px solid var(--border)',
              display:'flex', alignItems:'center', justifyContent:'space-between' }}>
              <span style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
                letterSpacing:2 }}>JARVIS ALERTS</span>
              {unread > 0 && (
                <button onClick={() => readAllMutation.mutate()}
                  style={{ background:'none', border:'none', cursor:'pointer',
                    fontFamily:'var(--mono)', fontSize:9, color:'var(--cyan)' }}>
                  MARCAR LEÍDAS
                </button>
              )}
            </div>
            <div style={{ maxHeight:300, overflowY:'auto' }}>
              {notifications.length === 0 ? (
                <div style={{ padding:'20px', textAlign:'center',
                  fontFamily:'var(--mono)', fontSize:11, color:'var(--text-dim)' }}>
                  Sin notificaciones
                </div>
              ) : notifications.map(n => (
                <div key={n.id} style={{ padding:'10px 14px',
                  borderBottom:'1px solid var(--border)',
                  background: n.read ? 'transparent' : '#00d4ff05',
                  borderLeft:`2px solid ${NOTIF_COLOR[n.tipo] || 'var(--border)'}` }}>
                  <div style={{ fontSize:12, color:'var(--text)', lineHeight:1.4,
                    marginBottom:4 }}>{n.message}</div>
                  <div style={{ fontFamily:'var(--mono)', fontSize:9,
                    color:'var(--text-dim)' }}>
                    {new Date(n.created_at).toLocaleString()} · {n.tipo}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

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
"""

with open("/home/operator/NEXUS-PRO/nexus_frontend/src/components/layout/TopBar.jsx", "w") as f:
    f.write(content)
print("TopBar.jsx con JARVIS notifications —", len(content), "bytes")
PYEOF
log "TopBar.jsx con JARVIS bell"

# ══════════════════════════════════════════════════════════════
head "3/5 · Landing page BAJIOWARE (HTML standalone)"
# ══════════════════════════════════════════════════════════════
mkdir -p "$ROOT/bajioware_landing"

python3 - << 'PYEOF'
content = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BAJIOWARE — Software & Ciberseguridad con IA</title>
<style>
  :root {
    --green: #00ff9d; --cyan: #00d4ff; --red: #ff3860;
    --orange: #ff6b35; --purple: #8b5cf6; --yellow: #ffc107;
    --bg: #030609; --bg2: #070d12; --panel: #0a1520;
    --border: #0d2035; --text: #8ab4c8; --bright: #e8f4f8;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif; overflow-x:hidden; }

  /* Nav */
  nav { position:fixed; top:0; width:100%; background:rgba(3,6,9,.9);
    backdrop-filter:blur(10px); border-bottom:1px solid var(--border);
    padding:0 40px; height:60px; display:flex; align-items:center;
    justify-content:space-between; z-index:100; }
  .logo { display:flex; align-items:center; gap:12; }
  .logo-icon { width:36px; height:36px; border:1px solid var(--green);
    border-radius:6px; background:linear-gradient(135deg,#001a0d,#002a1a);
    display:flex; align-items:center; justify-content:center;
    font-size:16px; font-weight:900; color:var(--green);
    box-shadow:0 0 15px #00ff9d30; font-family:monospace; }
  .logo-text { font-size:18px; font-weight:700; color:var(--bright); letter-spacing:3px; }
  .logo-sub { font-size:10px; color:var(--text); letter-spacing:2px; font-family:monospace; }
  nav ul { list-style:none; display:flex; gap:30px; }
  nav a { color:var(--text); text-decoration:none; font-size:13px;
    transition:color .2s; letter-spacing:.5px; }
  nav a:hover { color:var(--green); }
  .cta-nav { padding:8px 20px; border:1px solid var(--green); border-radius:3px;
    color:var(--green) !important; font-family:monospace; font-size:12px;
    transition:all .2s !important; }
  .cta-nav:hover { background:#00ff9d15 !important; }

  /* Hero */
  .hero { min-height:100vh; display:flex; align-items:center;
    justify-content:center; text-align:center; padding:100px 40px 60px;
    position:relative; overflow:hidden; }
  .hero::before { content:''; position:absolute; inset:0;
    background:radial-gradient(ellipse 80% 60% at 50% 40%, #00ff9d08 0%, transparent 70%); }
  .hero-badge { display:inline-block; padding:6px 16px;
    border:1px solid var(--green); border-radius:20px;
    font-family:monospace; font-size:11px; color:var(--green);
    background:#00ff9d08; margin-bottom:24px; letter-spacing:2px; }
  h1 { font-size:clamp(36px,6vw,72px); font-weight:800;
    color:var(--bright); line-height:1.1; margin-bottom:16px; letter-spacing:-1px; }
  h1 span { color:var(--green); }
  .hero-sub { font-size:clamp(16px,2vw,20px); color:var(--text);
    max-width:600px; margin:0 auto 40px; line-height:1.6; }
  .hero-btns { display:flex; gap:16px; justify-content:center; flex-wrap:wrap; }
  .btn-primary { padding:14px 32px; background:var(--green); color:#030609;
    border:none; border-radius:4px; font-size:14px; font-weight:700;
    cursor:pointer; letter-spacing:1px; font-family:monospace;
    transition:all .2s; box-shadow:0 0 30px #00ff9d30; }
  .btn-primary:hover { box-shadow:0 0 50px #00ff9d50; transform:translateY(-1px); }
  .btn-ghost { padding:14px 32px; background:transparent;
    border:1px solid var(--border); color:var(--text); border-radius:4px;
    font-size:14px; cursor:pointer; letter-spacing:1px; font-family:monospace;
    transition:all .2s; }
  .btn-ghost:hover { border-color:var(--cyan); color:var(--cyan); }

  /* Stats */
  .stats { display:flex; gap:40px; justify-content:center;
    margin-top:60px; flex-wrap:wrap; }
  .stat { text-align:center; }
  .stat-num { font-size:36px; font-weight:800; color:var(--green);
    font-family:monospace; display:block; }
  .stat-label { font-size:12px; color:var(--text); letter-spacing:1px;
    text-transform:uppercase; margin-top:4px; }

  /* Sections */
  section { padding:80px 40px; max-width:1100px; margin:0 auto; }
  .section-label { font-family:monospace; font-size:11px; color:var(--green);
    letter-spacing:3px; text-transform:uppercase; margin-bottom:12px; }
  h2 { font-size:clamp(28px,4vw,42px); font-weight:700; color:var(--bright);
    margin-bottom:16px; }
  .section-sub { font-size:16px; color:var(--text); max-width:500px;
    line-height:1.6; margin-bottom:48px; }

  /* Products */
  .products { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:20px; }
  .product-card { background:var(--panel); border:1px solid var(--border);
    border-radius:8px; padding:28px; transition:all .3s; position:relative;
    overflow:hidden; }
  .product-card::before { content:''; position:absolute; inset:0; opacity:0;
    transition:opacity .3s; }
  .product-card.nexus::before { background:radial-gradient(ellipse at top right, #00ff9d08, transparent); }
  .product-card.junior::before { background:radial-gradient(ellipse at top right, #00d4ff08, transparent); }
  .product-card.bajioware::before { background:radial-gradient(ellipse at top right, #8b5cf608, transparent); }
  .product-card:hover { transform:translateY(-4px); }
  .product-card.nexus:hover { border-color:#00ff9d40; box-shadow:0 10px 40px #00ff9d15; }
  .product-card.junior:hover { border-color:#00d4ff40; box-shadow:0 10px 40px #00d4ff15; }
  .product-card.bajioware:hover { border-color:#8b5cf640; box-shadow:0 10px 40px #8b5cf615; }
  .product-card:hover::before { opacity:1; }
  .product-icon { font-size:32px; margin-bottom:16px; }
  .product-name { font-size:20px; font-weight:700; color:var(--bright);
    margin-bottom:4px; letter-spacing:1px; }
  .product-tag { font-family:monospace; font-size:10px; padding:2px 8px;
    border-radius:10px; display:inline-block; margin-bottom:12px; }
  .tag-green { border:1px solid var(--green); color:var(--green); background:#00ff9d10; }
  .tag-cyan  { border:1px solid var(--cyan);  color:var(--cyan);  background:#00d4ff10; }
  .tag-purple{ border:1px solid var(--purple);color:var(--purple);background:#8b5cf610; }
  .product-desc { font-size:14px; color:var(--text); line-height:1.6; margin-bottom:20px; }
  .feature-list { list-style:none; display:flex; flex-direction:column; gap:6px; }
  .feature-list li { font-size:13px; color:var(--text); display:flex; gap:8px; }
  .feature-list li::before { content:'✓'; color:var(--green); flex-shrink:0; font-family:monospace; }

  /* Services */
  .services { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:16px; }
  .service-card { background:var(--panel); border:1px solid var(--border);
    border-radius:6px; padding:20px; }
  .service-icon { font-size:24px; margin-bottom:10px; }
  .service-name { font-size:15px; font-weight:600; color:var(--bright); margin-bottom:6px; }
  .service-desc { font-size:13px; color:var(--text); line-height:1.5; margin-bottom:10px; }
  .service-price { font-family:monospace; font-size:12px; color:var(--green); }

  /* How it works */
  .steps { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:20px; }
  .step { text-align:center; padding:20px; }
  .step-num { width:48px; height:48px; border-radius:50%;
    border:1px solid var(--green); background:#00ff9d10;
    display:flex; align-items:center; justify-content:center;
    font-family:monospace; font-size:18px; font-weight:700;
    color:var(--green); margin:0 auto 16px; }
  .step-title { font-size:15px; font-weight:600; color:var(--bright); margin-bottom:8px; }
  .step-desc { font-size:13px; color:var(--text); line-height:1.5; }

  /* Pricing */
  .pricing { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:20px; }
  .price-card { background:var(--panel); border:1px solid var(--border);
    border-radius:8px; padding:28px; text-align:center; }
  .price-card.featured { border-color:var(--green); position:relative;
    box-shadow:0 0 40px #00ff9d15; }
  .featured-badge { position:absolute; top:-12px; left:50%; transform:translateX(-50%);
    background:var(--green); color:#030609; padding:2px 16px; border-radius:10px;
    font-family:monospace; font-size:10px; font-weight:700; letter-spacing:1px; }
  .price-plan { font-size:13px; font-weight:600; color:var(--text);
    letter-spacing:2px; text-transform:uppercase; margin-bottom:8px; }
  .price-amount { font-size:42px; font-weight:800; color:var(--bright);
    font-family:monospace; }
  .price-period { font-size:14px; color:var(--text); margin-bottom:20px; }
  .price-features { list-style:none; text-align:left; display:flex;
    flex-direction:column; gap:8px; margin-bottom:24px; }
  .price-features li { font-size:13px; color:var(--text);
    display:flex; gap:8px; align-items:flex-start; }
  .price-features li::before { content:'·'; color:var(--green); font-family:monospace; flex-shrink:0; }

  /* CTA */
  .cta-section { text-align:center; padding:80px 40px;
    background:linear-gradient(180deg, transparent, #00ff9d05, transparent); }
  .cta-section h2 { margin-bottom:16px; }
  .cta-section p { font-size:16px; color:var(--text); margin-bottom:40px; }

  /* Footer */
  footer { background:var(--panel); border-top:1px solid var(--border);
    padding:40px; text-align:center; }
  .footer-logo { font-size:20px; font-weight:700; color:var(--bright);
    letter-spacing:3px; margin-bottom:8px; font-family:monospace; }
  .footer-sub { font-size:12px; color:var(--text); margin-bottom:20px; }
  .footer-links { display:flex; gap:24px; justify-content:center;
    flex-wrap:wrap; margin-bottom:20px; }
  .footer-links a { font-size:13px; color:var(--text); text-decoration:none; }
  .footer-links a:hover { color:var(--green); }
  .footer-copy { font-size:11px; color:#2a5060; font-family:monospace; }

  /* Animations */
  @keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-8px)} }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.6} }
  .float { animation:float 4s ease-in-out infinite; }
</style>
</head>
<body>

<nav>
  <div class="logo">
    <div class="logo-icon">BW</div>
    <div>
      <div class="logo-text">BAJIOWARE</div>
      <div class="logo-sub">SOFTWARE · CIBERSEGURIDAD · IA</div>
    </div>
  </div>
  <ul>
    <li><a href="#productos">Productos</a></li>
    <li><a href="#servicios">Servicios</a></li>
    <li><a href="#como">¿Cómo funciona?</a></li>
    <li><a href="#precios">Precios</a></li>
    <li><a href="#contacto" class="cta-nav">CONTACTO</a></li>
  </ul>
</nav>

<!-- Hero -->
<div class="hero">
  <div>
    <div class="hero-badge">🚀 POWERED BY IA MILITAR · NEXUS PRO v2.0</div>
    <h1>Software & Seguridad<br><span>con IA de nivel enterprise</span></h1>
    <p class="hero-sub">
      Desarrollamos software a velocidad IA. Auditamos tu seguridad en horas, no semanas.
      Un equipo de agentes autónomos trabajando por ti, 24/7.
    </p>
    <div class="hero-btns">
      <button class="btn-primary" onclick="document.getElementById('servicios').scrollIntoView({behavior:'smooth'})">
        VER SERVICIOS →
      </button>
      <button class="btn-ghost" onclick="document.getElementById('como').scrollIntoView({behavior:'smooth'})">
        ¿CÓMO FUNCIONA?
      </button>
    </div>
    <div class="stats">
      <div class="stat"><span class="stat-num float">4h</span><span class="stat-label">Pentest completo</span></div>
      <div class="stat"><span class="stat-num float" style="animation-delay:.5s">87%</span><span class="stat-label">Menos tiempo de dev</span></div>
      <div class="stat"><span class="stat-num float" style="animation-delay:1s">24/7</span><span class="stat-label">Monitoreo autónomo</span></div>
      <div class="stat"><span class="stat-num float" style="animation-delay:1.5s">10x</span><span class="stat-label">ROI para el cliente</span></div>
    </div>
  </div>
</div>

<!-- Productos -->
<section id="productos">
  <div class="section-label">Nuestros productos</div>
  <h2>Tecnología que trabaja<br>mientras tú duermes</h2>
  <p class="section-sub">Tres productos, un ecosistema. Úsalos juntos o por separado.</p>
  <div class="products">
    <div class="product-card nexus">
      <div class="product-icon">⬡</div>
      <div class="product-name">NEXUS PRO</div>
      <div class="product-tag tag-green">ORQUESTADOR ENTERPRISE</div>
      <div class="product-desc">Plataforma completa de operaciones con IA. Gestiona equipos de agentes, supervisa tareas críticas con aprobación humana y genera reportes ejecutivos automáticos.</div>
      <ul class="feature-list">
        <li>Dashboard militar con 15+ módulos</li>
        <li>HITL — aprobación humana en tiempo real</li>
        <li>Pentest automatizado OWASP + STRIDE</li>
        <li>Software Factory con Plan Maestro</li>
        <li>JWT Auth + RBAC multi-usuario</li>
        <li>Docker ready — instala en 3 minutos</li>
      </ul>
    </div>
    <div class="product-card junior">
      <div class="product-icon">🤖</div>
      <div class="product-name">JUNIOR JARVIS</div>
      <div class="product-tag tag-cyan">AGENTE AUTÓNOMO 24/7</div>
      <div class="product-desc">Tu asistente de IA que nunca duerme. Monitorea tu infraestructura, detecta amenazas, propone mejoras y ejecuta tareas complejas con un objetivo en lenguaje natural.</div>
      <ul class="feature-list">
        <li>Daemon autónomo 24/7 con auto-monitoreo</li>
        <li>Detección de vulnerabilidades en tiempo real</li>
        <li>Propuestas de mejora automáticas</li>
        <li>Ejecuta objetivos en lenguaje natural</li>
        <li>Memoria persistente entre sesiones</li>
        <li>Alertas proactivas al operador</li>
      </ul>
    </div>
    <div class="product-card bajioware">
      <div class="product-icon">🏭</div>
      <div class="product-name">SOFTWARE FACTORY</div>
      <div class="product-tag tag-purple">DESARROLLO ACELERADO</div>
      <div class="product-desc">Llena un formulario de requerimientos, la IA genera el Plan Maestro, tú apruebas y la fábrica construye tu proyecto fase por fase. Con DevSecOps incluido.</div>
      <ul class="feature-list">
        <li>Plan Maestro generado por GPT-4o</li>
        <li>Ejecución por fases — sin errores de contexto</li>
        <li>DevSecOps incluido en cada entrega</li>
        <li>Dockerfile + docker-compose automático</li>
        <li>Tests y documentación generados</li>
        <li>Reporte de seguridad con cada proyecto</li>
      </ul>
    </div>
  </div>
</section>

<!-- Servicios -->
<section id="servicios">
  <div class="section-label">Lo que hacemos</div>
  <h2>Servicios para empresas<br>que quieren moverse rápido</h2>
  <p class="section-sub">Combinamos IA de nivel militar con experiencia real en desarrollo y ciberseguridad.</p>
  <div class="services">
    <div class="service-card">
      <div class="service-icon">🔴</div>
      <div class="service-name">Pentest Web & API</div>
      <div class="service-desc">Auditoría completa OWASP Top 10, STRIDE, reconocimiento, SAST y reporte ejecutivo en 4 horas.</div>
      <div class="service-price">desde $800 USD</div>
    </div>
    <div class="service-card">
      <div class="service-icon">⚡</div>
      <div class="service-name">Desarrollo FastAPI / React</div>
      <div class="service-desc">Tu API o webapp completa en días, no semanas. Con auth, tests, Docker y documentación incluidos.</div>
      <div class="service-price">desde $1,500 USD</div>
    </div>
    <div class="service-card">
      <div class="service-icon">🛡️</div>
      <div class="service-name">Arquitectura Zero Trust</div>
      <div class="service-desc">Diseño e implementación de arquitectura Zero Trust para tu infraestructura. Threat modeling STRIDE incluido.</div>
      <div class="service-price">desde $2,500 USD</div>
    </div>
    <div class="service-card">
      <div class="service-icon">🔧</div>
      <div class="service-name">DevSecOps Pipeline</div>
      <div class="service-desc">CI/CD con seguridad integrada, scanning automático, SAST/DAST y reportes de compliance.</div>
      <div class="service-price">desde $1,800 USD</div>
    </div>
    <div class="service-card">
      <div class="service-icon">🤖</div>
      <div class="service-name">Agentes IA a medida</div>
      <div class="service-desc">Implementamos NEXUS PRO o JUNIOR JARVIS en tu infraestructura, configurados para tus procesos.</div>
      <div class="service-price">desde $500 setup + $300/mes</div>
    </div>
    <div class="service-card">
      <div class="service-icon">📊</div>
      <div class="service-name">Consultoría de Seguridad</div>
      <div class="service-desc">Revisión de código, políticas de seguridad, capacitación de equipos y roadmap de mejoras.</div>
      <div class="service-price">desde $200/hora</div>
    </div>
  </div>
</section>

<!-- Cómo funciona -->
<section id="como">
  <div class="section-label">El proceso</div>
  <h2>De requerimiento a entrega<br>en tiempo récord</h2>
  <p class="section-sub">Sin reuniones interminables. Sin sorpresas. Con IA haciendo el 80% del trabajo pesado.</p>
  <div class="steps">
    <div class="step">
      <div class="step-num">1</div>
      <div class="step-title">Llenas el formulario</div>
      <div class="step-desc">Describes lo que necesitas en lenguaje natural. Sin tecnicismos, sin formatos complicados.</div>
    </div>
    <div class="step">
      <div class="step-num">2</div>
      <div class="step-title">IA genera el plan</div>
      <div class="step-desc">GPT-4o analiza tus requerimientos y genera un Plan Maestro detallado por fases.</div>
    </div>
    <div class="step">
      <div class="step-num">3</div>
      <div class="step-title">Tú apruebas</div>
      <div class="step-desc">Revisas el plan, haces ajustes si es necesario y das el visto bueno con un click.</div>
    </div>
    <div class="step">
      <div class="step-num">4</div>
      <div class="step-title">La fábrica construye</div>
      <div class="step-desc">Equipo de agentes IA ejecuta fase por fase. Tú puedes supervisar en tiempo real.</div>
    </div>
    <div class="step">
      <div class="step-num">5</div>
      <div class="step-title">Entrega + seguridad</div>
      <div class="step-desc">Recibes código funcional, Docker-ready, con reporte de seguridad y documentación incluida.</div>
    </div>
  </div>
</section>

<!-- Precios -->
<section id="precios">
  <div class="section-label">Precios</div>
  <h2>Simple y transparente</h2>
  <p class="section-sub">Sin contratos complicados. Cancela cuando quieras.</p>
  <div class="pricing">
    <div class="price-card">
      <div class="price-plan">Starter</div>
      <div class="price-amount">$199</div>
      <div class="price-period">/mes · NEXUS PRO básico</div>
      <ul class="price-features">
        <li>5 agentes IA</li>
        <li>3 usuarios</li>
        <li>Junior Agent incluido</li>
        <li>Pentest básico</li>
        <li>Soporte por email</li>
      </ul>
      <button class="btn-ghost" style="width:100%;padding:10px">EMPEZAR</button>
    </div>
    <div class="price-card featured">
      <div class="featured-badge">MÁS POPULAR</div>
      <div class="price-plan">Professional</div>
      <div class="price-amount">$499</div>
      <div class="price-period">/mes · NEXUS PRO completo</div>
      <ul class="price-features">
        <li>20 agentes IA</li>
        <li>10 usuarios + RBAC</li>
        <li>Junior JARVIS 24/7</li>
        <li>Software Factory</li>
        <li>Pentest completo OWASP</li>
        <li>Soporte prioritario</li>
      </ul>
      <button class="btn-primary" style="width:100%;padding:10px">CONTRATAR</button>
    </div>
    <div class="price-card">
      <div class="price-plan">Enterprise</div>
      <div class="price-amount">$1,200+</div>
      <div class="price-period">/mes · Instalación dedicada</div>
      <ul class="price-features">
        <li>Agentes ilimitados</li>
        <li>Usuarios ilimitados</li>
        <li>Instalación en tu servidor</li>
        <li>Integración a medida</li>
        <li>SLA garantizado</li>
        <li>Soporte dedicado</li>
      </ul>
      <button class="btn-ghost" style="width:100%;padding:10px">CONTACTAR</button>
    </div>
  </div>
</section>

<!-- CTA -->
<div class="cta-section" id="contacto">
  <div class="section-label">¿Listo para empezar?</div>
  <h2>Tu primer proyecto en 48 horas</h2>
  <p>Agenda una llamada gratuita de 30 minutos. Te mostramos NEXUS en acción con tu caso de uso real.</p>
  <div class="hero-btns">
    <button class="btn-primary">📅 AGENDAR DEMO GRATUITA</button>
    <button class="btn-ghost">✉️ ENVIAR MENSAJE</button>
  </div>
</div>

<footer>
  <div class="footer-logo">BAJIOWARE</div>
  <div class="footer-sub">Software · Ciberseguridad · Inteligencia Artificial</div>
  <div class="footer-links">
    <a href="#productos">Productos</a>
    <a href="#servicios">Servicios</a>
    <a href="#precios">Precios</a>
    <a href="#">Blog técnico</a>
    <a href="#">GitHub</a>
  </div>
  <div class="footer-copy">© 2026 BAJIOWARE · Powered by NEXUS PRO v2.0 · Zero Trust · Military Grade AI</div>
</footer>

</body>
</html>
"""

with open("/home/operator/NEXUS-PRO/bajioware_landing/index.html", "w") as f:
    f.write(content)
print("Landing BAJIOWARE —", len(content), "bytes")
PYEOF
log "bajioware_landing/index.html"

# ══════════════════════════════════════════════════════════════
head "4/5 · nexusApi + App.jsx — añadir Jarvis page"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
# Añadir endpoints jarvis al client.js
path = "/home/operator/NEXUS-PRO/nexus_frontend/src/api/client.js"
with open(path) as f:
    content = f.read()

if "jarvis/notifications" not in content:
    content = content.replace(
        "  // Factory",
        """  // JARVIS
  jarvisNotifications: (unread) => api.get('/jarvis/notifications', { params: unread ? { unread_only: true } : {} }),
  jarvisReadAll:       ()       => api.post('/jarvis/notifications/read-all'),
  jarvisStatus:        ()       => api.get('/jarvis/status'),
  jarvisReport:        ()       => api.get('/jarvis/report'),

  // Factory"""
    )
    with open(path, "w") as f:
        f.write(content)
    print("jarvis endpoints añadidos a client.js")
else:
    print("ya estaban")
PYEOF
log "nexusApi jarvis endpoints"

# ══════════════════════════════════════════════════════════════
head "5/5 · Build + reiniciar + healthcheck"
# ══════════════════════════════════════════════════════════════
cd "$ROOT/nexus_frontend"
npm run build --silent 2>&1 | tail -3

# Reiniciar stack completo
"$ROOT/nexus_start.sh" stop 2>/dev/null || true
sleep 2
"$ROOT/nexus_start.sh" start

sleep 6

TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@nexuspro.io","password":"synthetic-password"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

echo ""
echo "Test security headers:"
curl -s -I http://localhost:8000/health | grep -E "X-Frame|X-Content|X-XSS|Content-Security" | head -5

echo ""
echo "Test endpoints:"
for ep in "/jarvis/status" "/jarvis/notifications" "/factory/templates"; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" "http://localhost:8000$ep")
  [ "$CODE" = "200" ] && echo "  ✓ $ep" || echo "  ✗ $ep ($CODE)"
done

echo ""
echo "Landing BAJIOWARE:"
ls -lh "$ROOT/bajioware_landing/index.html"
echo "  Abrir en browser: file://$ROOT/bajioware_landing/index.html"

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO — Punto 13: Security + BAJIOWARE ✓     ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Security headers activos:${NC}"
echo -e "  ✓ X-Frame-Options: DENY"
echo -e "  ✓ X-Content-Type-Options: nosniff"
echo -e "  ✓ X-XSS-Protection: 1; mode=block"
echo -e "  ✓ Content-Security-Policy"
echo -e "  ✓ Referrer-Policy"
echo ""
echo -e "  ${CYAN}BAJIOWARE Landing:${NC}"
echo -e "  ✓ Hero con stats animados"
echo -e "  ✓ 3 productos (NEXUS + JUNIOR + Factory)"
echo -e "  ✓ 6 servicios con precios"
echo -e "  ✓ Proceso en 5 pasos"
echo -e "  ✓ Pricing 3 tiers"
echo -e "  ✓ CTA y footer"
echo ""
echo -e "  ${CYAN}JARVIS en TopBar:${NC}"
echo -e "  ✓ Bell con contador de notificaciones"
echo -e "  ✓ Dropdown con alertas en tiempo real"
echo -e "  ✓ Marcar como leídas"
echo ""
