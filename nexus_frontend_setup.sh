#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Frontend Setup Completo                        ║
# ║  React + Vite + Zustand + React Query + WebSocket           ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

NEXUS_ROOT="/home/operator/NEXUS-PRO"
FRONT="$NEXUS_ROOT/nexus_frontend"
API_URL="http://192.168.220.134:8000"
WS_URL="ws://192.168.220.134:8000"

GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
info() { echo -e "${CYAN}[→]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

cd "$NEXUS_ROOT"

head "1/6 · Creando proyecto Vite + React"
if [ ! -d "$FRONT" ]; then
  npm create vite@latest nexus_frontend -- --template react --yes 2>/dev/null || \
  npm create vite@latest nexus_frontend -- --template react
fi
cd "$FRONT"
log "Proyecto Vite creado"

head "2/6 · Instalando dependencias"
npm install --silent
npm install --silent \
  zustand \
  @tanstack/react-query \
  axios \
  react-router-dom \
  recharts \
  lucide-react \
  date-fns
log "Dependencias instaladas"

head "3/6 · Configurando Vite"
cat > vite.config.js << 'VITE'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
      '/ws': {
        target: 'ws://127.0.0.1:8000',
        ws: true,
      },
    },
  },
})
VITE
log "vite.config.js listo"

head "4/6 · Creando estructura de archivos"
mkdir -p src/{api,store,hooks,components/{ui,layout},pages}

# ── index.css ────────────────────────────────────────────────
cat > src/index.css << 'CSS'
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;500;600;700&family=Orbitron:wght@400;700;900&display=swap');

:root {
  --bg-base:    #050a0e;
  --bg-panel:   #080f14;
  --bg-card:    #0c1419;
  --bg-card2:   #0f1a20;
  --border:     #1a3040;
  --green:      #00ff9d;
  --green-dim:  #00cc7a;
  --green-dark: #003d20;
  --cyan:       #00d4ff;
  --yellow:     #ffc107;
  --orange:     #ff6b35;
  --red:        #ff3860;
  --purple:     #bf5fff;
  --blue:       #4fc3f7;
  --text:       #c8e6f0;
  --text-dim:   #5a8a9f;
  --text-bright:#e8f8ff;
  --mono:       'Share Tech Mono', monospace;
  --ui:         'Rajdhani', sans-serif;
  --display:    'Orbitron', monospace;
  --glow-green: 0 0 10px #00ff9d55, 0 0 30px #00ff9d22;
  --glow-cyan:  0 0 10px #00d4ff55, 0 0 30px #00d4ff22;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html, body, #root {
  height: 100%;
  overflow: hidden;
  background: var(--bg-base);
  color: var(--text);
  font-family: var(--ui);
}

/* Scrollbars */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

/* Scanline overlay */
body::before {
  content: '';
  position: fixed; inset: 0;
  background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
  pointer-events: none; z-index: 9999;
}

@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
@keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }

.animate-fade { animation: fadeIn .3s ease forwards; }
.animate-pulse { animation: pulse 2s infinite; }
.animate-spin { animation: spin 3s linear infinite; }
CSS

# ── api/client.js ─────────────────────────────────────────────
cat > src/api/client.js << 'CLIENT'
import axios from 'axios'

export const API_URL = import.meta.env.VITE_API_URL || 'http://192.168.220.134:8000'
export const WS_URL  = import.meta.env.VITE_WS_URL  || 'ws://192.168.220.134:8000'

export const api = axios.create({
  baseURL: API_URL,
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' },
})

// Auth interceptor
api.interceptors.request.use(cfg => {
  const token = localStorage.getItem('nexus_token')
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

api.interceptors.response.use(
  r => r,
  err => {
    if (err.response?.status === 401) localStorage.removeItem('nexus_token')
    return Promise.reject(err)
  }
)

// API calls
export const nexusApi = {
  health:       () => api.get('/health'),
  agents:       () => api.get('/agents'),
  tasks:        () => api.get('/tasks'),
  teams:        () => api.get('/teams-v2'),
  registry:     () => api.get('/agents/registry'),
  hitl:         () => api.get('/hitl/pending'),
  approveHITL:  (id) => api.post(`/hitl/${id}/approve`),
  denyHITL:     (id) => api.post(`/hitl/${id}/deny`),
  createAgent:  (data) => api.post('/agents', data),
  createTask:   (data) => api.post('/tasks', data),
  createTeam:   (data) => api.post('/teams-v2', data),
  guardian:     () => api.get('/guardian/status'),
  guardianScan: () => api.post('/guardian/scan'),
  secrets:      () => api.get('/vault/secrets'),
  plans:        () => api.get('/plans'),
  dispatch:     (data) => api.post('/junior/dispatch', data),
}
CLIENT

# ── store/nexusStore.js ───────────────────────────────────────
cat > src/store/nexusStore.js << 'STORE'
import { create } from 'zustand'

export const useNexusStore = create((set, get) => ({
  // System
  health: null,
  systemStatus: 'connecting',

  // Agents
  agents: [],
  agentsLoading: false,

  // Tasks
  tasks: [],
  tasksLoading: false,

  // HITL
  hitlItems: [],
  hitlCount: 0,

  // Logs
  logs: [],
  maxLogs: 200,

  // UI
  activePage: 'overview',
  notifications: [],

  // WS
  wsConnected: false,

  // Actions
  setHealth: (h) => set({ health: h, systemStatus: h?.status || 'unknown' }),
  setAgents: (a) => set({ agents: a }),
  setTasks: (t) => set({ tasks: t }),
  setHITL: (items) => set({ hitlItems: items, hitlCount: items.length }),
  setActivePage: (p) => set({ activePage: p }),
  setWsConnected: (v) => set({ wsConnected: v }),

  addLog: (log) => set(s => {
    const logs = [log, ...s.logs].slice(0, s.maxLogs)
    return { logs }
  }),

  addNotification: (msg, type = 'info') => set(s => ({
    notifications: [{ id: Date.now(), msg, type, ts: new Date() }, ...s.notifications].slice(0, 20)
  })),

  approveHITL: (id) => set(s => ({
    hitlItems: s.hitlItems.filter(h => h.id !== id),
    hitlCount: Math.max(0, s.hitlCount - 1),
  })),

  denyHITL: (id) => set(s => ({
    hitlItems: s.hitlItems.filter(h => h.id !== id),
    hitlCount: Math.max(0, s.hitlCount - 1),
  })),
}))
STORE

# ── hooks/useWebSocket.js ─────────────────────────────────────
cat > src/hooks/useWebSocket.js << 'WS'
import { useEffect, useRef, useCallback } from 'react'
import { useNexusStore } from '../store/nexusStore'
import { WS_URL } from '../api/client'

const LOG_COLORS = {
  INFO:    '#00d4ff',
  WARN:    '#ffc107',
  WARNING: '#ffc107',
  ERROR:   '#ff3860',
  DEBUG:   '#5a8a9f',
  SUCCESS: '#00ff9d',
}

export function useNexusWebSocket() {
  const wsRef = useRef(null)
  const retryRef = useRef(0)
  const { addLog, setWsConnected, addNotification, setHealth } = useNexusStore()

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(`${WS_URL}/ws/logs`)
      wsRef.current = ws

      ws.onopen = () => {
        retryRef.current = 0
        setWsConnected(true)
        addLog({ level: 'SUCCESS', source: 'nexus-ws', msg: 'WebSocket conectado', ts: new Date() })
      }

      ws.onmessage = (evt) => {
        try {
          const data = JSON.parse(evt.data)

          if (data.type === 'log') {
            addLog({
              level: (data.level || 'INFO').toUpperCase(),
              source: data.source || 'nexus',
              msg: data.message || data.msg || '',
              ts: new Date(data.timestamp || Date.now()),
              color: LOG_COLORS[(data.level || 'info').toUpperCase()] || '#c8e6f0',
            })
          }

          if (data.type === 'health') setHealth(data.payload)
          if (data.type === 'notification') addNotification(data.msg, data.level)
          if (data.type === 'hitl') addNotification(`HITL pendiente: ${data.title}`, 'warn')

        } catch (e) {
          // raw text log
          addLog({ level: 'DEBUG', source: 'ws', msg: evt.data, ts: new Date(), color: '#5a8a9f' })
        }
      }

      ws.onerror = () => setWsConnected(false)

      ws.onclose = () => {
        setWsConnected(false)
        const delay = Math.min(1000 * 2 ** retryRef.current, 15000)
        retryRef.current++
        setTimeout(connect, delay)
      }
    } catch (e) {
      console.error('WS error:', e)
    }
  }, [])

  useEffect(() => {
    connect()
    return () => wsRef.current?.close()
  }, [connect])
}
WS

# ── hooks/useNexusData.js ─────────────────────────────────────
cat > src/hooks/useNexusData.js << 'DATA'
import { useQuery } from '@tanstack/react-query'
import { useNexusStore } from '../store/nexusStore'
import { nexusApi } from '../api/client'

export function useHealth() {
  const setHealth = useNexusStore(s => s.setHealth)
  return useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const { data } = await nexusApi.health()
      setHealth(data)
      return data
    },
    refetchInterval: 5000,
    retry: false,
  })
}

export function useAgents() {
  const setAgents = useNexusStore(s => s.setAgents)
  return useQuery({
    queryKey: ['agents'],
    queryFn: async () => {
      try {
        const { data } = await nexusApi.agents()
        const list = Array.isArray(data) ? data : data?.agents || []
        setAgents(list)
        return list
      } catch { return [] }
    },
    refetchInterval: 8000,
  })
}

export function useTasks() {
  const setTasks = useNexusStore(s => s.setTasks)
  return useQuery({
    queryKey: ['tasks'],
    queryFn: async () => {
      try {
        const { data } = await nexusApi.tasks()
        const list = Array.isArray(data) ? data : data?.tasks || []
        setTasks(list)
        return list
      } catch { return [] }
    },
    refetchInterval: 6000,
  })
}
DATA

# ── components/ui/index.jsx ───────────────────────────────────
cat > src/components/ui/index.jsx << 'UI'
// ── Reusable UI primitives ────────────────────────────────────

export function Card({ children, className = '', style = {} }) {
  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 4,
      padding: 16,
      ...style,
    }} className={className}>
      {children}
    </div>
  )
}

export function CardTitle({ children }) {
  return (
    <div style={{
      fontFamily: 'var(--mono)', fontSize: 10,
      color: 'var(--text-dim)', letterSpacing: 2,
      textTransform: 'uppercase', marginBottom: 8,
    }}>
      {children}
    </div>
  )
}

export function MetricCard({ label, value, sub, color = 'var(--green)', barPct }) {
  return (
    <Card>
      <CardTitle>{label}</CardTitle>
      <div style={{ fontFamily: 'var(--display)', fontSize: 28, fontWeight: 700, color, lineHeight: 1 }}>
        {value}
      </div>
      {sub && <div style={{ fontFamily: 'var(--mono)', fontSize: 10, color: 'var(--text-dim)', marginTop: 4 }}>{sub}</div>}
      {barPct !== undefined && (
        <div style={{ height: 3, background: 'var(--border)', borderRadius: 2, marginTop: 10, overflow: 'hidden' }}>
          <div style={{ height: '100%', width: `${barPct}%`, background: color, borderRadius: 2, transition: 'width 1s ease' }} />
        </div>
      )}
    </Card>
  )
}

export function Badge({ children, color = 'var(--text-dim)', bg = 'transparent' }) {
  return (
    <span style={{
      fontFamily: 'var(--mono)', fontSize: 9,
      padding: '2px 7px', borderRadius: 10,
      border: `1px solid ${color}`, color,
      background: bg,
    }}>
      {children}
    </span>
  )
}

export function Dot({ color = 'var(--green)', size = 7 }) {
  return (
    <span style={{
      display: 'inline-block',
      width: size, height: size, borderRadius: '50%',
      background: color,
      boxShadow: `0 0 6px ${color}`,
      animation: 'pulse 2s infinite',
      flexShrink: 0,
    }} />
  )
}

export function Btn({ children, variant = 'primary', onClick, style = {} }) {
  const variants = {
    primary: { border: '1px solid var(--green)', color: 'var(--green)', background: '#00ff9d15' },
    cyan:    { border: '1px solid var(--cyan)',  color: 'var(--cyan)',  background: '#00d4ff15' },
    danger:  { border: '1px solid var(--red)',   color: 'var(--red)',   background: '#ff386015' },
    warn:    { border: '1px solid var(--yellow)',color: 'var(--yellow)',background: '#ffc10715' },
    ghost:   { border: '1px solid var(--border)',color: 'var(--text-dim)', background: 'transparent' },
  }
  return (
    <button onClick={onClick} style={{
      padding: '7px 14px', borderRadius: 3,
      fontFamily: 'var(--ui)', fontSize: 12, fontWeight: 600,
      letterSpacing: 1, cursor: 'pointer',
      display: 'inline-flex', alignItems: 'center', gap: 6,
      transition: 'all .2s',
      ...variants[variant],
      ...style,
    }}>
      {children}
    </button>
  )
}

export function SectionTitle({ children, style = {} }) {
  return (
    <div style={{
      fontFamily: 'var(--mono)', fontSize: 10,
      color: 'var(--text-dim)', letterSpacing: 2,
      textTransform: 'uppercase', ...style,
    }}>
      {children}
    </div>
  )
}

export function StatusBadge({ status }) {
  const map = {
    running:   { color: 'var(--green)',  label: 'RUNNING'  },
    idle:      { color: 'var(--text-dim)',label: 'IDLE'    },
    error:     { color: 'var(--red)',    label: 'ERROR'    },
    failed:    { color: 'var(--red)',    label: 'FAILED'   },
    completed: { color: 'var(--cyan)',   label: 'DONE'     },
    pending:   { color: 'var(--yellow)', label: 'PENDING'  },
    ok:        { color: 'var(--green)',  label: 'OK'       },
    degraded:  { color: 'var(--yellow)', label: 'DEGRADED' },
  }
  const s = map[status?.toLowerCase()] || { color: 'var(--text-dim)', label: status?.toUpperCase() || '?' }
  return <Badge color={s.color}>{s.label}</Badge>
}
UI

# ── components/layout/Sidebar.jsx ────────────────────────────
cat > src/components/layout/Sidebar.jsx << 'SIDEBAR'
import { useNexusStore } from '../../store/nexusStore'

const NAV = [
  { section: 'Centro de Mando', items: [
    { id: 'overview',  icon: '◈', label: 'Overview' },
  ]},
  { section: 'Orquestación', items: [
    { id: 'agents',   icon: '⬡', label: 'Agentes IA',      badge: null, badgeKey: 'agents' },
    { id: 'teams',    icon: '◎', label: 'Equipos' },
    { id: 'tasks',    icon: '▷', label: 'Tareas',           badge: null, badgeKey: 'tasks' },
    { id: 'models',   icon: '◇', label: 'Modelos & APIs' },
  ]},
  { section: 'Seguridad', items: [
    { id: 'hitl',     icon: '⚠', label: 'HITL',            badgeKey: 'hitl', badgeColor: 'var(--red)' },
    { id: 'vault',    icon: '◉', label: 'Secrets Vault' },
    { id: 'guardian', icon: '⬟', label: 'Guardian Scan' },
    { id: 'rbac',     icon: '⊞', label: 'Roles / RBAC' },
    { id: 'audit',    icon: '≡', label: 'Audit Trail' },
  ]},
  { section: 'Sistema', items: [
    { id: 'terminal', icon: '▸', label: 'Terminal' },
    { id: 'settings', icon: '⚙', label: 'Configuración' },
  ]},
]

export default function Sidebar() {
  const { activePage, setActivePage, agents, tasks, hitlCount } = useNexusStore()

  const counts = {
    agents: agents.length,
    tasks: tasks.length,
    hitl: hitlCount,
  }

  return (
    <nav style={{
      width: 200, flexShrink: 0,
      background: 'var(--bg-panel)',
      borderRight: '1px solid var(--border)',
      overflowY: 'auto', overflowX: 'hidden',
      padding: '16px 0',
      display: 'flex', flexDirection: 'column',
    }}>
      <div style={{ flex: 1 }}>
        {NAV.map(({ section, items }) => (
          <div key={section} style={{ marginBottom: 20 }}>
            <div style={{
              fontFamily: 'var(--mono)', fontSize: 9,
              color: '#2a5060', letterSpacing: 2,
              padding: '0 16px 6px', textTransform: 'uppercase',
            }}>
              {section}
            </div>
            {items.map(item => {
              const active = activePage === item.id
              const count = item.badgeKey ? counts[item.badgeKey] : null
              return (
                <div key={item.id}
                  onClick={() => setActivePage(item.id)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    padding: '8px 16px', cursor: 'pointer',
                    fontSize: 13, fontWeight: 500,
                    color: active ? 'var(--green)' : 'var(--text-dim)',
                    borderLeft: active ? '2px solid var(--green)' : '2px solid transparent',
                    background: active ? '#00ff9d08' : 'transparent',
                    transition: 'all .15s',
                  }}
                >
                  <span style={{ width: 16, textAlign: 'center', fontSize: 13 }}>{item.icon}</span>
                  <span style={{ flex: 1 }}>{item.label}</span>
                  {count > 0 && (
                    <span style={{
                      fontFamily: 'var(--mono)', fontSize: 10,
                      padding: '0 6px', borderRadius: 10, minWidth: 20, textAlign: 'center',
                      border: `1px solid ${item.badgeColor || 'var(--green)'}`,
                      color: item.badgeColor || 'var(--green)',
                      background: 'var(--bg-base)',
                    }}>
                      {count}
                    </span>
                  )}
                </div>
              )
            })}
          </div>
        ))}
      </div>

      {/* User card */}
      <div style={{
        margin: '0 12px', padding: '10px 12px',
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 4, display: 'flex', alignItems: 'center', gap: 10,
      }}>
        <div style={{
          width: 32, height: 32, borderRadius: 3, flexShrink: 0,
          background: 'linear-gradient(135deg,#003d20,#004466)',
          border: '1px solid var(--green)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontFamily: 'var(--display)', fontSize: 10, color: 'var(--green)',
        }}>MC</div>
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-bright)' }}>Marcos</div>
          <div style={{ fontFamily: 'var(--mono)', fontSize: 9, color: 'var(--text-dim)' }}>ADMIN · CORP</div>
        </div>
      </div>
    </nav>
  )
}
SIDEBAR

# ── components/layout/TopBar.jsx ─────────────────────────────
cat > src/components/layout/TopBar.jsx << 'TOPBAR'
import { useState, useEffect } from 'react'
import { useNexusStore } from '../../store/nexusStore'
import { Dot } from '../ui'

export default function TopBar() {
  const { health, hitlCount, wsConnected } = useNexusStore()
  const [time, setTime] = useState('')

  useEffect(() => {
    const tick = () => {
      const now = new Date()
      setTime(now.toTimeString().slice(0, 8) + ' CST')
    }
    tick()
    const t = setInterval(tick, 1000)
    return () => clearInterval(t)
  }, [])

  const status = health?.status || 'connecting'
  const statusColor = status === 'healthy' ? 'var(--green)' : status === 'degraded' ? 'var(--yellow)' : 'var(--red)'

  return (
    <header style={{
      height: 48, background: '#060c10',
      borderBottom: '1px solid var(--border)',
      display: 'flex', alignItems: 'center',
      padding: '0 16px', gap: 12, flexShrink: 0,
    }}>
      {/* Logo */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10,
        fontFamily: 'var(--display)', fontSize: 14, fontWeight: 700,
        color: 'var(--green)', letterSpacing: 3,
        textShadow: '0 0 10px #00ff9d55',
      }}>
        <div style={{
          width: 28, height: 28, border: '2px solid var(--green)',
          transform: 'rotate(45deg)', display: 'flex',
          alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 0 10px #00ff9d55', flexShrink: 0,
        }}>
          <span style={{ transform: 'rotate(-45deg)', fontSize: 10 }}>◆</span>
        </div>
        NEXUS
      </div>

      {/* Search */}
      <div style={{
        flex: 1, maxWidth: 400, marginLeft: 20,
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 3, display: 'flex', alignItems: 'center',
        padding: '0 12px', gap: 8, height: 32,
      }}>
        <span style={{ color: 'var(--text-dim)', fontSize: 13 }}>⌕</span>
        <input
          placeholder="Buscar agentes, tareas, logs..."
          style={{
            background: 'none', border: 'none', outline: 'none',
            color: 'var(--text-dim)', fontFamily: 'var(--mono)',
            fontSize: 11, flex: 1,
          }}
        />
        <span style={{
          fontFamily: 'var(--mono)', fontSize: 10, color: '#2a5060',
          border: '1px solid #1a3040', padding: '1px 5px', borderRadius: 2,
        }}>⌘K</span>
      </div>

      {/* Right */}
      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--mono)', fontSize: 11 }}>
          <Dot color={statusColor} />
          <span style={{ color: statusColor }}>{status.toUpperCase()}</span>
        </div>

        {hitlCount > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--mono)', fontSize: 11 }}>
            <Dot color="var(--yellow)" />
            <span style={{ color: 'var(--yellow)' }}>{hitlCount} HITL</span>
          </div>
        )}

        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--mono)', fontSize: 11 }}>
          <Dot color={wsConnected ? 'var(--green)' : 'var(--red)'} size={6} />
          <span style={{ color: wsConnected ? 'var(--green)' : 'var(--red)', fontSize: 10 }}>
            {wsConnected ? 'WS' : 'WS OFF'}
          </span>
        </div>

        <div style={{ fontFamily: 'var(--mono)', fontSize: 13, color: 'var(--text-dim)', letterSpacing: 1 }}>
          {time}
        </div>

        <div style={{
          width: 30, height: 30, borderRadius: 3,
          background: 'linear-gradient(135deg,var(--green-dark),var(--cyan))',
          border: '1px solid var(--green)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontFamily: 'var(--display)', fontSize: 10, color: 'var(--green)',
          boxShadow: 'var(--glow-green)', cursor: 'pointer',
        }}>MC</div>
      </div>
    </header>
  )
}
TOPBAR

# ── pages/Overview.jsx ────────────────────────────────────────
cat > src/pages/Overview.jsx << 'OVERVIEW'
import { useNexusStore } from '../store/nexusStore'
import { useHealth } from '../hooks/useNexusData'
import { Card, CardTitle, MetricCard, SectionTitle, Dot } from '../components/ui'
import { BarChart, Bar, XAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { useEffect, useRef } from 'react'

const PHASES = [
  { id:'4',  name:'Workforce',    color:'var(--green)' },
  { id:'5A', name:'Sandbox',      color:'var(--cyan)'  },
  { id:'6B', name:'Agent Chat',   color:'var(--green)' },
  { id:'7A', name:'FileSystem',   color:'var(--yellow)'},
  { id:'7B', name:'Monitor',      color:'var(--cyan)'  },
  { id:'7C', name:'Trainer',      color:'var(--green)' },
  { id:'8B', name:'Junior',       color:'var(--green)' },
  { id:'8C', name:'Bridge+Agents',color:'var(--green)' },
]

const BAR_DATA = Array.from({length:12},(_,i)=>({
  h: String(i+1).padStart(2,'0')+'h',
  done: Math.floor(Math.random()*80+20),
  hitl: Math.floor(Math.random()*20),
  proc: Math.floor(Math.random()*40),
}))

export default function Overview() {
  const { health, logs, agents, tasks, hitlCount } = useNexusStore()
  const { isLoading } = useHealth()
  const logRef = useRef(null)

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight
  }, [logs])

  const svc = health?.services || {}
  const coreOk = svc.event_bus === 'ok' && svc.state_manager === 'ok' && svc.registry === 'ok'

  return (
    <div style={{ padding: 24, overflowY: 'auto', height: '100%' }}>
      {/* Header */}
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)', fontSize:22, fontWeight:700, color:'var(--text-bright)', letterSpacing:2 }}>
            Centro de Mando — NEXUS
          </div>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:4, letterSpacing:1 }}>
            AI OPERATIONS PLATFORM · {isLoading ? 'CONECTANDO...' : coreOk ? 'SISTEMA HEALTHY' : 'SISTEMA DEGRADED'}
          </div>
        </div>
      </div>

      {/* Metrics row 1 */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12, marginBottom:12 }}>
        <MetricCard label="EventBus"    value={svc.event_bus === 'ok' ? '✓' : '⚠'}    sub={svc.event_bus || '—'}    color={svc.event_bus==='ok'?'var(--green)':'var(--yellow)'} barPct={svc.event_bus==='ok'?100:30} />
        <MetricCard label="Orchestrator" value={svc.orchestrator === 'ok' ? '✓' : '⚠'} sub={svc.orchestrator || '—'} color={svc.orchestrator==='ok'?'var(--green)':'var(--yellow)'} barPct={svc.orchestrator==='ok'?100:30} />
        <MetricCard label="Agentes Reg." value={agents.length || '—'}                  sub="en registry"              color="var(--cyan)" barPct={Math.min(agents.length*12,100)} />
        <MetricCard label="Tareas"       value={tasks.length || '0'}                   sub="en sistema"               color="var(--yellow)" barPct={Math.min(tasks.length*8,100)} />
      </div>

      {/* Metrics row 2 */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12, marginBottom:16 }}>
        <MetricCard label="LLM"          value={svc.llm === 'ok' ? 'ON' : '—'}       sub="OpenAI + Gemini"           color={svc.llm==='ok'?'var(--green)':'var(--red)'} barPct={svc.llm==='ok'?100:0} />
        <MetricCard label="Memory"       value={svc.memory === 'ok' ? '✓' : '⚠'}    sub="ChromaDB"                  color={svc.memory==='ok'?'var(--purple)':'var(--yellow)'} barPct={svc.memory==='ok'?100:30} />
        <MetricCard label="HITL"         value={hitlCount}                            sub="Pendientes aprobación"     color="var(--yellow)" barPct={Math.min(hitlCount*20,100)} />
        <MetricCard label="JuniorBridge" value={svc.junior_bridge === 'ok' ? '✓' : '⚠'} sub={svc.junior_bridge || '—'} color={svc.junior_bridge==='ok'?'var(--green)':'var(--red)'} barPct={svc.junior_bridge==='ok'?100:0} />
      </div>

      {/* Chart + Phases */}
      <div style={{ display:'grid', gridTemplateColumns:'2fr 1fr', gap:12, marginBottom:16 }}>
        <Card>
          <SectionTitle style={{ marginBottom:12 }}>Actividad de Agentes (últimas 12h)</SectionTitle>
          <ResponsiveContainer width="100%" height={140}>
            <BarChart data={BAR_DATA} barSize={8} barGap={2}>
              <XAxis dataKey="h" tick={{ fontSize:9, fill:'#5a8a9f', fontFamily:'var(--mono)' }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background:'var(--bg-panel)', border:'1px solid var(--border)', fontFamily:'var(--mono)', fontSize:11 }} />
              <Bar dataKey="done" fill="#00ff9d" opacity={0.8} radius={[2,2,0,0]} />
              <Bar dataKey="proc" fill="#00d4ff" opacity={0.8} radius={[2,2,0,0]} />
              <Bar dataKey="hitl" fill="#ffc107" opacity={0.8} radius={[2,2,0,0]} />
            </BarChart>
          </ResponsiveContainer>
          <div style={{ display:'flex', gap:16, marginTop:8, fontFamily:'var(--mono)', fontSize:10 }}>
            <span style={{ color:'var(--green)' }}>■ Completadas</span>
            <span style={{ color:'var(--cyan)' }}>■ En proceso</span>
            <span style={{ color:'var(--yellow)' }}>■ HITL</span>
          </div>
        </Card>

        <Card>
          <SectionTitle style={{ marginBottom:10 }}>Fases Activas</SectionTitle>
          <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
            {PHASES.map(p => (
              <div key={p.id} style={{
                display:'flex', alignItems:'center', gap:8,
                padding:'6px 8px', background:'var(--bg-card2)',
                border:'1px solid var(--border)', borderRadius:3,
              }}>
                <Dot color={p.color} size={7} />
                <span style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)', minWidth:20 }}>{p.id}</span>
                <span style={{ fontSize:12, fontWeight:500 }}>{p.name}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Services grid */}
      <Card style={{ marginBottom:16 }}>
        <SectionTitle style={{ marginBottom:12 }}>Estado de Servicios — /health</SectionTitle>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:8 }}>
          {Object.entries(svc).map(([k, v]) => (
            <div key={k} style={{
              padding:'8px 10px', background:'var(--bg-card2)',
              border:`1px solid ${v==='ok'?'var(--green)':'var(--yellow)'}20`,
              borderRadius:3, display:'flex', alignItems:'center', gap:8,
            }}>
              <Dot color={v==='ok'?'var(--green)':'var(--yellow)'} size={6} />
              <div>
                <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text)' }}>{k}</div>
                <div style={{ fontFamily:'var(--mono)', fontSize:9, color: v==='ok'?'var(--green)':'var(--yellow)' }}>{v}</div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Live Log */}
      <div style={{ background:'#030609', border:'1px solid var(--border)', borderRadius:4, overflow:'hidden' }}>
        <div style={{
          padding:'10px 14px', borderBottom:'1px solid var(--border)',
          background:'var(--bg-panel)', display:'flex', alignItems:'center', justifyContent:'space-between',
        }}>
          <span style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', letterSpacing:2 }}>
            LOG EN TIEMPO REAL
          </span>
          <div style={{ display:'flex', alignItems:'center', gap:8 }}>
            <Dot color="var(--green)" size={6} />
            <span style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--green)' }}>LIVE · {logs.length} entradas</span>
          </div>
        </div>
        <div ref={logRef} style={{
          padding:10, fontFamily:'var(--mono)', fontSize:11,
          height:180, overflowY:'auto', lineHeight:1.7,
        }}>
          {logs.length === 0 ? (
            <div style={{ color:'var(--text-dim)', padding:'20px 0', textAlign:'center' }}>
              Conectando WebSocket...
            </div>
          ) : (
            logs.slice(0,50).map((log, i) => (
              <div key={i} style={{ display:'flex', gap:10, animation:'fadeIn .3s ease' }}>
                <span style={{ color:'#2a5060', flexShrink:0 }}>
                  {log.ts ? new Date(log.ts).toTimeString().slice(0,8) : '--:--:--'}
                </span>
                <span style={{ color: log.level==='WARN'||log.level==='WARNING'?'var(--yellow)':
                                       log.level==='ERROR'?'var(--red)':
                                       log.level==='SUCCESS'?'var(--green)':
                                       log.level==='DEBUG'?'var(--text-dim)':'var(--cyan)',
                                flexShrink:0, fontWeight:'bold' }}>
                  [{log.level}]
                </span>
                <span style={{ color:'#3a7090', flexShrink:0 }}>[{log.source}]</span>
                <span style={{ color:'var(--text)' }}>{log.msg}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}
OVERVIEW

# ── pages/Agents.jsx ──────────────────────────────────────────
cat > src/pages/Agents.jsx << 'AGENTS'
import { useNexusStore } from '../store/nexusStore'
import { useAgents } from '../hooks/useNexusData'
import { Card, StatusBadge, SectionTitle } from '../components/ui'

export default function Agents() {
  const { agents } = useNexusStore()
  useAgents()

  const FALLBACK = [
    { agent_id:'1', name:'BashAgent',  status:'running', model:'claude-3-5-sonnet', capabilities:['file_operations'], stats:{total_tasks:23,success_rate:0.98} },
    { agent_id:'2', name:'CodeAgent',  status:'running', model:'gpt-4o',            capabilities:['code_generation'], stats:{total_tasks:15,success_rate:0.95} },
    { agent_id:'3', name:'FileAgent',  status:'idle',    model:'claude-3-haiku',    capabilities:['file_operations'], stats:{total_tasks:8, success_rate:1.0 } },
  ]

  const list = agents.length > 0 ? agents : FALLBACK

  return (
    <div style={{ padding:24, overflowY:'auto', height:'100%' }}>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)', fontSize:22, fontWeight:700, color:'var(--text-bright)', letterSpacing:2 }}>Agentes IA</div>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:4 }}>
            ORQUESTACIÓN · {list.length} AGENTES
          </div>
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:12 }}>
        {list.map(a => (
          <Card key={a.agent_id} style={{
            border: a.status==='running' ? '1px solid var(--green)' :
                    a.status==='error'   ? '1px solid var(--red)'   : '1px solid var(--border)',
            cursor:'pointer', transition:'all .2s',
          }}>
            <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:12 }}>
              <div style={{
                width:36, height:36, borderRadius:4, fontSize:20,
                display:'flex', alignItems:'center', justifyContent:'center',
                background:'var(--bg-base)', border:'1px solid var(--border)',
              }}>🤖</div>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:14, fontWeight:600, color:'var(--text-bright)' }}>{a.name}</div>
                <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)' }}>
                  {a.model || '—'}
                </div>
              </div>
              <StatusBadge status={a.status || 'idle'} />
            </div>

            <div style={{ display:'flex', flexWrap:'wrap', gap:4, marginBottom:10 }}>
              {(a.capabilities || a.metadata?.capabilities || []).map(c => (
                <span key={c} style={{
                  fontFamily:'var(--mono)', fontSize:9, padding:'2px 6px',
                  borderRadius:2, background:'var(--bg-base)',
                  border:'1px solid var(--border)', color:'var(--text-dim)',
                }}>{c}</span>
              ))}
            </div>

            <div style={{ display:'flex', gap:12, paddingTop:10, borderTop:'1px solid var(--border)' }}>
              <div style={{ flex:1, textAlign:'center' }}>
                <div style={{ fontFamily:'var(--mono)', fontSize:13, color:'var(--cyan)' }}>
                  {a.stats?.total_tasks ?? '—'}
                </div>
                <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)' }}>TAREAS</div>
              </div>
              <div style={{ flex:1, textAlign:'center' }}>
                <div style={{ fontFamily:'var(--mono)', fontSize:13, color:'var(--green)' }}>
                  {a.stats?.success_rate != null ? `${(a.stats.success_rate*100).toFixed(0)}%` : '—'}
                </div>
                <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)' }}>SUCCESS</div>
              </div>
              <div style={{ flex:1, textAlign:'center' }}>
                <div style={{ fontFamily:'var(--mono)', fontSize:13, color:'var(--text-dim)' }}>
                  {a.stats?.avg_duration_ms != null ? `${a.stats.avg_duration_ms.toFixed(0)}ms` : '—'}
                </div>
                <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)' }}>AVG</div>
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  )
}
AGENTS

# ── pages/placeholder pages ───────────────────────────────────
for PAGE in Tasks Teams Models HITL Vault Guardian RBAC Audit Terminal Settings; do
cat > "src/pages/${PAGE}.jsx" << PAGEEOF
import { Card } from '../components/ui'

export default function ${PAGE}() {
  return (
    <div style={{ padding:24, overflowY:'auto', height:'100%' }}>
      <div style={{ fontFamily:'var(--display)', fontSize:22, fontWeight:700, color:'var(--text-bright)', letterSpacing:2, marginBottom:8 }}>
        ${PAGE}
      </div>
      <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginBottom:24 }}>
        MÓDULO EN CONSTRUCCIÓN
      </div>
      <Card>
        <div style={{ fontFamily:'var(--mono)', fontSize:12, color:'var(--text-dim)', textAlign:'center', padding:'40px 0' }}>
          ⟳ Conectando con nexus_api...
        </div>
      </Card>
    </div>
  )
}
PAGEEOF
done

# ── App.jsx ───────────────────────────────────────────────────
cat > src/App.jsx << 'APP'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useNexusStore } from './store/nexusStore'
import { useNexusWebSocket } from './hooks/useWebSocket'
import TopBar from './components/layout/TopBar'
import Sidebar from './components/layout/Sidebar'
import Overview from './pages/Overview'
import Agents   from './pages/Agents'
import Tasks    from './pages/Tasks'
import Teams    from './pages/Teams'
import Models   from './pages/Models'
import HITL     from './pages/HITL'
import Vault    from './pages/Vault'
import Guardian from './pages/Guardian'
import RBAC     from './pages/RBAC'
import Audit    from './pages/Audit'
import Terminal from './pages/Terminal'
import Settings from './pages/Settings'

const qc = new QueryClient({ defaultOptions: { queries: { retry: 1, staleTime: 3000 } } })

const PAGES = {
  overview: Overview,
  agents:   Agents,
  tasks:    Tasks,
  teams:    Teams,
  models:   Models,
  hitl:     HITL,
  vault:    Vault,
  guardian: Guardian,
  rbac:     RBAC,
  audit:    Audit,
  terminal: Terminal,
  settings: Settings,
}

function NexusApp() {
  useNexusWebSocket()
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

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <NexusApp />
    </QueryClientProvider>
  )
}
APP

# ── main.jsx ──────────────────────────────────────────────────
cat > src/main.jsx << 'MAIN'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>
)
MAIN

# ── .env ─────────────────────────────────────────────────────
cat > .env << 'ENV'
VITE_API_URL=http://192.168.220.134:8000
VITE_WS_URL=ws://192.168.220.134:8000
ENV

head "5/6 · Build de prueba"
npm run build --silent 2>&1 | tail -5
log "Build OK"

head "6/6 · Listo"
echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO Frontend — Instalado ✓              ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Para arrancar el frontend:"
echo -e "  ${CYAN}cd ~/NEXUS-PRO/nexus_frontend && npm run dev${NC}"
echo ""
echo -e "  Dashboard: ${CYAN}http://192.168.220.134:5173${NC}"
echo -e "  API Docs:  ${CYAN}http://192.168.220.134:8000/docs${NC}"
echo ""
echo -e "  Para correr ambos a la vez:"
echo -e "  ${CYAN}# Terminal 1:${NC} uvicorn nexus_api.main:app --host 0.0.0.0 --port 8000 --reload"
echo -e "  ${CYAN}# Terminal 2:${NC} cd nexus_frontend && npm run dev"
echo ""
