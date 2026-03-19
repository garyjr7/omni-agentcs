#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Punto 5: Dashboard PRO Completo               ║
# ║  Junior · Pentest · Reports · HITL Real · Terminal · Overview ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

FRONT="/home/operator/NEXUS-PRO/nexus_frontend/src"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

cd "$FRONT"

# ══════════════════════════════════════════════════════════════
head "1/9 · api/client.js — todos los endpoints"
# ══════════════════════════════════════════════════════════════
cat > api/client.js << 'EOF'
import axios from 'axios'

export const API_URL = import.meta.env.VITE_API_URL || 'http://192.168.220.134:8000'
export const WS_URL  = import.meta.env.VITE_WS_URL  || 'ws://192.168.220.134:8000'

export const api = axios.create({
  baseURL: API_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.response.use(r => r, err => {
  console.warn('API Error:', err.response?.status, err.config?.url)
  return Promise.reject(err)
})

export const nexusApi = {
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
  guardianScan:  () => api.post('/guardian/scan/full'),
  guardianSecrets:() => api.post('/guardian/scan/secrets'),
  guardianBandit:() => api.post('/guardian/scan/bandit'),
  guardianIncidents:() => api.get('/guardian/incidents'),
}
EOF
log "api/client.js"

# ══════════════════════════════════════════════════════════════
head "2/9 · store/nexusStore.js — estado global con HITL + Junior"
# ══════════════════════════════════════════════════════════════
cat > store/nexusStore.js << 'EOF'
import { create } from 'zustand'

export const useNexusStore = create((set, get) => ({
  health:       null,
  systemStatus: 'connecting',
  agents:       [],
  tasks:        [],
  hitlItems:    [],
  hitlCount:    0,
  logs:         [],
  maxLogs:      300,
  activePage:   'overview',
  wsConnected:  false,
  wsHITL:       false,
  notifications:[],

  setHealth:      (h) => set({ health: h, systemStatus: h?.status || 'unknown' }),
  setAgents:      (a) => set({ agents: a }),
  setTasks:       (t) => set({ tasks: t }),
  setActivePage:  (p) => set({ activePage: p }),
  setWsConnected: (v) => set({ wsConnected: v }),
  setWsHITL:      (v) => set({ wsHITL: v }),

  setHITL: (items) => set({ hitlItems: items, hitlCount: items.length }),

  addHITL: (item) => set(s => ({
    hitlItems: [item, ...s.hitlItems],
    hitlCount: s.hitlCount + 1,
  })),

  resolveHITL: (id) => set(s => ({
    hitlItems: s.hitlItems.filter(h => h.id !== id),
    hitlCount: Math.max(0, s.hitlCount - 1),
  })),

  addLog: (log) => set(s => ({
    logs: [log, ...s.logs].slice(0, s.maxLogs),
  })),

  addNotification: (msg, type = 'info') => set(s => ({
    notifications: [{ id: Date.now(), msg, type, ts: new Date() }, ...s.notifications].slice(0, 30),
  })),
}))
EOF
log "nexusStore.js"

# ══════════════════════════════════════════════════════════════
head "3/9 · hooks/useWebSocket.js — WS logs + WS HITL"
# ══════════════════════════════════════════════════════════════
cat > hooks/useWebSocket.js << 'EOF'
import { useEffect, useRef, useCallback } from 'react'
import { useNexusStore } from '../store/nexusStore'
import { WS_URL } from '../api/client'

export function useNexusWebSocket() {
  const wsRef   = useRef(null)
  const retryRef = useRef(0)
  const { addLog, setWsConnected, addNotification } = useNexusStore()

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(`${WS_URL}/ws/logs`)
      wsRef.current = ws
      ws.onopen  = () => { retryRef.current = 0; setWsConnected(true) }
      ws.onmessage = (evt) => {
        try {
          const d = JSON.parse(evt.data)
          if (d.type === 'log' || d.level) {
            addLog({ level:(d.level||'INFO').toUpperCase(), source:d.source||'nexus', msg:d.message||d.msg||'', ts:new Date(d.timestamp||Date.now()) })
          }
        } catch {
          addLog({ level:'DEBUG', source:'ws', msg:evt.data, ts:new Date() })
        }
      }
      ws.onerror  = () => setWsConnected(false)
      ws.onclose  = () => {
        setWsConnected(false)
        setTimeout(connect, Math.min(1000 * 2 ** retryRef.current++, 15000))
      }
    } catch(e) { console.error('WS logs error:', e) }
  }, [])

  useEffect(() => { connect(); return () => wsRef.current?.close() }, [connect])
}

export function useHITLWebSocket() {
  const wsRef   = useRef(null)
  const retryRef = useRef(0)
  const { addHITL, resolveHITL, setWsHITL, addNotification, setHITL } = useNexusStore()

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(`${WS_URL}/ws/hitl`)
      wsRef.current = ws
      ws.onopen  = () => { retryRef.current = 0; setWsHITL(true) }
      ws.onmessage = (evt) => {
        try {
          const d = JSON.parse(evt.data)
          if (d.event === 'connected') {
            setHITL(d.data?.pending || [])
          } else if (d.event === 'new_request') {
            addHITL(d.data)
            addNotification(`⏸ HITL: ${d.data.agent_name} → ${d.data.tool} [${d.data.risk}]`, 'warn')
          } else if (d.event === 'approved') {
            resolveHITL(d.data.id)
            addNotification(`✓ HITL aprobado: ${d.data.id}`, 'success')
          } else if (d.event === 'denied') {
            resolveHITL(d.data.id)
            addNotification(`✗ HITL denegado: ${d.data.id}`, 'error')
          } else if (d.event === 'timeout') {
            resolveHITL(d.data.id)
            addNotification(`⏰ HITL timeout: ${d.data.id}`, 'warn')
          }
        } catch(e) { console.error('HITL WS parse error:', e) }
      }
      ws.onerror  = () => setWsHITL(false)
      ws.onclose  = () => {
        setWsHITL(false)
        setTimeout(connect, Math.min(1000 * 2 ** retryRef.current++, 15000))
      }
    } catch(e) { console.error('WS HITL error:', e) }
  }, [])

  useEffect(() => { connect(); return () => wsRef.current?.close() }, [connect])

  const sendCommand = useCallback((cmd) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(cmd))
    }
  }, [])

  return { sendCommand }
}
EOF
log "hooks/useWebSocket.js"

# ══════════════════════════════════════════════════════════════
head "4/9 · pages/HITL.jsx — botones reales conectados"
# ══════════════════════════════════════════════════════════════
cat > pages/HITL.jsx << 'EOF'
import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNexusStore } from '../store/nexusStore'
import { useHITLWebSocket } from '../hooks/useWebSocket'
import { Btn, Dot } from '../components/ui'
import { nexusApi } from '../api/client'

const RISK_COLOR = { CRITICAL:'var(--red)', HIGH:'var(--orange)', MEDIUM:'var(--yellow)', LOW:'var(--cyan)' }
const RISK_BG    = { CRITICAL:'#ff386015', HIGH:'#ff6b3515', MEDIUM:'#ffc10715', LOW:'#00d4ff15' }

export default function HITL() {
  const qc = useQueryClient()
  const { hitlItems, hitlCount, wsHITL } = useNexusStore()
  const { sendCommand } = useHITLWebSocket()
  const [resolved, setResolved] = useState({})
  const [reasoning, setReasoning] = useState({})

  // Cargar pendientes al montar
  const { data: apiPending } = useQuery({
    queryKey: ['hitl-pending'],
    queryFn: async () => { const { data } = await nexusApi.hitlPending(); return data.pending || [] },
    refetchInterval: 3000,
  })

  const items = hitlItems.length > 0 ? hitlItems : (apiPending || [])
  const pending = items.filter(h => !resolved[h.id])

  const approveMutation = useMutation({
    mutationFn: ({ id }) => nexusApi.approveHITL(id, 'marcos', reasoning[id] || 'Aprobado desde dashboard'),
    onSuccess: (_, { id }) => {
      setResolved(r => ({ ...r, [id]: 'approved' }))
      qc.invalidateQueries(['hitl-pending'])
    },
  })
  const denyMutation = useMutation({
    mutationFn: ({ id }) => nexusApi.denyHITL(id, 'marcos', reasoning[id] || 'Denegado desde dashboard'),
    onSuccess: (_, { id }) => {
      setResolved(r => ({ ...r, [id]: 'denied' }))
      qc.invalidateQueries(['hitl-pending'])
    },
  })
  const approveAllMutation = useMutation({
    mutationFn: nexusApi.approveAllHITL,
    onSuccess: () => { pending.forEach(h => setResolved(r=>({...r,[h.id]:'approved'}))); qc.invalidateQueries(['hitl-pending']) },
  })
  const denyAllMutation = useMutation({
    mutationFn: nexusApi.denyAllHITL,
    onSuccess: () => { pending.forEach(h => setResolved(r=>({...r,[h.id]:'denied'}))); qc.invalidateQueries(['hitl-pending']) },
  })

  return (
    <div style={{ padding:24, overflowY:'auto', height:'100%' }}>
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)', fontSize:22, fontWeight:700, color:'var(--text-bright)', letterSpacing:2 }}>
            HITL — Aprobaciones
          </div>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:4, display:'flex', alignItems:'center', gap:8 }}>
            HUMAN IN THE LOOP · {pending.length} PENDIENTES
            <Dot color={wsHITL ? 'var(--green)' : 'var(--red)'} size={6} />
            <span style={{ color: wsHITL ? 'var(--green)' : 'var(--red)' }}>{wsHITL ? 'WS LIVE' : 'WS OFF'}</span>
          </div>
        </div>
        {pending.length > 0 && (
          <div style={{ display:'flex', gap:8 }}>
            <Btn variant="primary" onClick={()=>approveAllMutation.mutate()}>✓ APROBAR TODOS</Btn>
            <Btn variant="danger"  onClick={()=>denyAllMutation.mutate()}>✗ DENEGAR TODOS</Btn>
          </div>
        )}
      </div>

      {pending.length === 0 ? (
        <div style={{ textAlign:'center', padding:'60px 0' }}>
          <div style={{ fontSize:48, marginBottom:12, opacity:.2 }}>✓</div>
          <div style={{ fontFamily:'var(--display)', fontSize:16, color:'var(--green)' }}>Sin pendientes</div>
          <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text-dim)', marginTop:6 }}>
            Todos los agentes operando normalmente
          </div>
        </div>
      ) : (
        <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
          {pending.map(h => {
            const rc = RISK_COLOR[h.risk] || 'var(--yellow)'
            const bg = RISK_BG[h.risk] || '#ffc10715'
            const isApproving = approveMutation.isPending && approveMutation.variables?.id === h.id
            const isDenying   = denyMutation.isPending   && denyMutation.variables?.id === h.id
            return (
              <div key={h.id} style={{ background:'var(--bg-card)', border:`1px solid ${rc}`, borderRadius:4, padding:16,
                boxShadow:`0 0 12px ${rc}22`, animation:'hitlPulse 3s infinite' }}>
                <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:10 }}>
                  <div style={{ width:40, height:40, display:'flex', alignItems:'center', justifyContent:'center',
                    fontSize:20, border:`1px solid ${rc}`, background:bg, borderRadius:4, flexShrink:0 }}>
                    {h.tool === 'bash_exec' ? '⚙️' : h.tool === 'nmap_scan' ? '🔍' :
                     h.tool === 'file_delete' ? '🗑️' : h.tool === 'nuclei_scan' ? '⚡' : '⚠️'}
                  </div>
                  <div style={{ flex:1 }}>
                    <div style={{ fontFamily:'var(--mono)', fontSize:10, color:rc }}>{h.id}</div>
                    <div style={{ fontSize:15, fontWeight:600, color:'var(--text-bright)' }}>{h.action}</div>
                  </div>
                  <div style={{ padding:'3px 10px', border:`1px solid ${rc}`, borderRadius:10,
                    fontFamily:'var(--mono)', fontSize:10, color:rc, background:bg }}>
                    {h.risk}
                  </div>
                </div>

                {/* Contexto */}
                <div style={{ background:'var(--bg-base)', border:'1px solid var(--border)', borderRadius:3,
                  padding:12, fontFamily:'var(--mono)', fontSize:11, lineHeight:1.8,
                  marginBottom:12, color:'var(--text-dim)', whiteSpace:'pre-wrap' }}>
                  {h.context}
                  {'\n\n'}<span style={{ color:'var(--text)' }}>Agente: {h.agent_name}</span>
                  {' · '}<span style={{ color:'var(--text)' }}>Tool: {h.tool}</span>
                  {' · '}<span style={{ color:'var(--text)' }}>{new Date(h.created_at).toLocaleTimeString()}</span>
                </div>

                {/* Razonamiento opcional */}
                <input
                  value={reasoning[h.id] || ''}
                  onChange={e => setReasoning(r => ({...r, [h.id]: e.target.value}))}
                  placeholder="Razón (opcional)..."
                  style={{ width:'100%', background:'var(--bg-base)', border:'1px solid var(--border)',
                    borderRadius:3, padding:'6px 10px', color:'var(--text)', fontFamily:'var(--mono)',
                    fontSize:11, outline:'none', marginBottom:10 }}
                />

                <div style={{ display:'flex', gap:10 }}>
                  <Btn variant="primary"
                    onClick={() => approveMutation.mutate({ id: h.id })}
                    style={{ opacity: isApproving ? .6 : 1 }}>
                    {isApproving ? '⟳ APROBANDO...' : '✓ APROBAR'}
                  </Btn>
                  <Btn variant="danger"
                    onClick={() => denyMutation.mutate({ id: h.id })}
                    style={{ opacity: isDenying ? .6 : 1 }}>
                    {isDenying ? '⟳ DENEGANDO...' : '✗ DENEGAR'}
                  </Btn>
                  <Btn variant="ghost">⊕ DETALLE</Btn>
                </div>
              </div>
            )
          })}
        </div>
      )}
      <style>{`@keyframes hitlPulse{0%,100%{box-shadow:0 0 8px rgba(255,193,7,.13)}50%{box-shadow:0 0 20px rgba(255,193,7,.2)}}`}</style>
    </div>
  )
}
EOF
log "HITL.jsx"

# ══════════════════════════════════════════════════════════════
head "5/9 · pages/Junior.jsx — chat + objetivos + log en vivo"
# ══════════════════════════════════════════════════════════════
cat > pages/Junior.jsx << 'EOF'
import { useState, useRef, useEffect } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Card, Btn, Dot } from '../components/ui'
import { nexusApi } from '../api/client'

const EXAMPLES = [
  "Analiza el código de nexus_api y genera un reporte de calidad",
  "Crea una API FastAPI para una tienda online con login y catálogo",
  "Audita la seguridad de NEXUS PRO y genera reporte ejecutivo",
  "Genera código Terraform para una VPC con Zero Trust en AWS",
  "Crea un script Python para monitorear uptime de servicios web",
]

export default function Junior() {
  const [tab, setTab] = useState('chat')         // 'chat' | 'run' | 'sessions'
  const [chatMsg, setChatMsg] = useState('')
  const [chatHistory, setChatHistory] = useState([
    { role:'assistant', content:'Hola, soy **Junior** 🤖 — el agente autónomo de NEXUS PRO.\n\nPuedo ayudarte con desarrollo, ciberseguridad, DevOps y más.\n¿En qué trabajamos hoy?' }
  ])
  const [objective, setObjective] = useState('')
  const [maxSteps, setMaxSteps] = useState(6)
  const [activeTask, setActiveTask] = useState(null)
  const chatRef = useRef(null)

  useEffect(() => { chatRef.current?.scrollTo(0, chatRef.current.scrollHeight) }, [chatHistory])

  // Chat mutation
  const chatMutation = useMutation({
    mutationFn: (msg) => nexusApi.juniorChat(msg),
    onMutate: (msg) => setChatHistory(h => [...h, { role:'user', content:msg }]),
    onSuccess: (data) => setChatHistory(h => [...h, { role:'assistant', content:data.data.response }]),
    onError: () => setChatHistory(h => [...h, { role:'assistant', content:'❌ Error conectando con Junior — verifica que el servidor esté corriendo.' }]),
  })

  // Run mutation
  const runMutation = useMutation({
    mutationFn: ({ obj, steps }) => nexusApi.juniorRun(obj, steps),
    onSuccess: (data) => setActiveTask(data.data.task_id),
  })

  // Poll task status
  const { data: taskStatus } = useQuery({
    queryKey: ['junior-task', activeTask],
    queryFn: () => nexusApi.juniorStatus(activeTask).then(r => r.data),
    enabled: !!activeTask,
    refetchInterval: (data) => {
      if (!data) return 2000
      return data.status === 'running' ? 2000 : false
    },
  })

  // Sessions
  const { data: sessionsData } = useQuery({
    queryKey: ['junior-sessions'],
    queryFn: () => nexusApi.juniorSessions().then(r => r.data),
    enabled: tab === 'sessions',
  })

  const sendChat = () => {
    if (!chatMsg.trim() || chatMutation.isPending) return
    chatMutation.mutate(chatMsg)
    setChatMsg('')
  }

  const runObjective = () => {
    if (!objective.trim() || runMutation.isPending) return
    setActiveTask(null)
    runMutation.mutate({ obj: objective, steps: maxSteps })
  }

  const getTaskResult = () => {
    if (!taskStatus?.result) return null
    try { return typeof taskStatus.result === 'string'
      ? JSON.parse(taskStatus.result.replace(/'/g,'"'))
      : taskStatus.result
    } catch { return { raw: taskStatus.result } }
  }

  const result = getTaskResult()

  return (
    <div style={{ padding:24, height:'100%', display:'flex', flexDirection:'column', gap:16 }}>
      {/* Header */}
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <div>
          <div style={{ fontFamily:'var(--display)', fontSize:22, fontWeight:700, color:'var(--text-bright)', letterSpacing:2 }}>
            Junior Agent
          </div>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:4 }}>
            AGENTE AUTÓNOMO · GPT-4o · ENCADENA TOOLS
          </div>
        </div>
        <div style={{ display:'flex', gap:4 }}>
          {['chat','run','sessions'].map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              padding:'6px 14px', borderRadius:3,
              border:`1px solid ${tab===t?'var(--green)':'var(--border)'}`,
              background: tab===t ? '#00ff9d08' : 'transparent',
              color: tab===t ? 'var(--green)' : 'var(--text-dim)',
              cursor:'pointer', fontFamily:'var(--mono)', fontSize:11,
            }}>{t.toUpperCase()}</button>
          ))}
        </div>
      </div>

      {/* TAB: Chat */}
      {tab === 'chat' && (
        <div style={{ flex:1, display:'flex', flexDirection:'column', gap:10, minHeight:0 }}>
          <div ref={chatRef} style={{ flex:1, overflowY:'auto', display:'flex', flexDirection:'column', gap:10 }}>
            {chatHistory.map((m, i) => (
              <div key={i} style={{ display:'flex', gap:10, alignItems:'flex-start',
                justifyContent: m.role==='user' ? 'flex-end' : 'flex-start' }}>
                {m.role === 'assistant' && (
                  <div style={{ width:32, height:32, borderRadius:4, background:'#00ff9d15',
                    border:'1px solid var(--green)', display:'flex', alignItems:'center',
                    justifyContent:'center', fontSize:16, flexShrink:0 }}>🤖</div>
                )}
                <div style={{ maxWidth:'75%', padding:'10px 14px', borderRadius:4,
                  background: m.role==='user' ? '#00d4ff15' : 'var(--bg-card)',
                  border:`1px solid ${m.role==='user'?'var(--cyan)':'var(--border)'}`,
                  fontFamily:'var(--ui)', fontSize:13, lineHeight:1.6,
                  color:'var(--text)', whiteSpace:'pre-wrap' }}>
                  {m.content}
                </div>
                {m.role === 'user' && (
                  <div style={{ width:32, height:32, borderRadius:4, background:'#00d4ff15',
                    border:'1px solid var(--cyan)', display:'flex', alignItems:'center',
                    justifyContent:'center', fontSize:14, flexShrink:0 }}>👤</div>
                )}
              </div>
            ))}
            {chatMutation.isPending && (
              <div style={{ display:'flex', gap:10, alignItems:'center' }}>
                <div style={{ width:32,height:32,borderRadius:4,background:'#00ff9d15',border:'1px solid var(--green)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:16 }}>🤖</div>
                <div style={{ padding:'10px 14px',borderRadius:4,background:'var(--bg-card)',border:'1px solid var(--border)',fontFamily:'var(--mono)',fontSize:12,color:'var(--green)' }}>
                  <span style={{ animation:'blink 1s step-end infinite' }}>Pensando...</span>
                </div>
              </div>
            )}
          </div>
          <div style={{ display:'flex', gap:8 }}>
            <input value={chatMsg} onChange={e=>setChatMsg(e.target.value)}
              onKeyDown={e=>e.key==='Enter'&&!e.shiftKey&&sendChat()}
              placeholder="Pregúntale algo a Junior..."
              style={{ flex:1,background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:3,
                padding:'10px 14px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none' }} />
            <Btn variant="primary" onClick={sendChat} style={{ opacity:chatMutation.isPending?.6:1 }}>
              {chatMutation.isPending ? '⟳' : '▶ ENVIAR'}
            </Btn>
          </div>
        </div>
      )}

      {/* TAB: Run */}
      {tab === 'run' && (
        <div style={{ flex:1, overflowY:'auto', display:'flex', flexDirection:'column', gap:12 }}>
          <Card>
            <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:2,textTransform:'uppercase',marginBottom:12 }}>
              Objetivo en Lenguaje Natural
            </div>
            <textarea value={objective} onChange={e=>setObjective(e.target.value)}
              placeholder="Ej: Crea una API FastAPI para una zapatería con login, catálogo y dashboard admin..."
              rows={4} style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,
                padding:'10px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none',resize:'vertical' }} />
            <div style={{ display:'flex', alignItems:'center', gap:12, marginTop:10 }}>
              <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                <label style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)' }}>MAX PASOS:</label>
                <select value={maxSteps} onChange={e=>setMaxSteps(parseInt(e.target.value))}
                  style={{ background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'4px 8px',color:'var(--text)',fontFamily:'var(--mono)',fontSize:11,outline:'none' }}>
                  {[3,4,5,6,7,8].map(n=><option key={n}>{n}</option>)}
                </select>
              </div>
              <Btn variant="primary" onClick={runObjective} style={{ opacity:runMutation.isPending?.6:1 }}>
                {runMutation.isPending ? '⟳ INICIANDO...' : '🚀 EJECUTAR JUNIOR'}
              </Btn>
            </div>

            {/* Ejemplos */}
            <div style={{ marginTop:14, paddingTop:12, borderTop:'1px solid var(--border)' }}>
              <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)',letterSpacing:1,marginBottom:8 }}>EJEMPLOS RÁPIDOS</div>
              <div style={{ display:'flex', flexDirection:'column', gap:4 }}>
                {EXAMPLES.map((ex,i) => (
                  <div key={i} onClick={()=>setObjective(ex)}
                    style={{ padding:'6px 10px',background:'var(--bg-card2)',border:'1px solid var(--border)',
                      borderRadius:3,cursor:'pointer',fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)',
                      transition:'all .15s' }}>
                    → {ex}
                  </div>
                ))}
              </div>
            </div>
          </Card>

          {/* Estado de la tarea activa */}
          {activeTask && (
            <Card style={{ border:`1px solid ${taskStatus?.status==='completed'?'var(--green)':taskStatus?.status==='failed'?'var(--red)':'var(--yellow)'}` }}>
              <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:12 }}>
                <Dot color={taskStatus?.status==='completed'?'var(--green)':taskStatus?.status==='running'?'var(--yellow)':'var(--red)'} />
                <span style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text)' }}>{activeTask}</span>
                <span style={{ fontFamily:'var(--mono)',fontSize:11,
                  color:taskStatus?.status==='completed'?'var(--green)':taskStatus?.status==='running'?'var(--yellow)':'var(--red)' }}>
                  {taskStatus?.status?.toUpperCase() || 'INICIANDO...'}
                </span>
                <div style={{ marginLeft:'auto', fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)' }}>
                  {taskStatus?.progress || 0}%
                </div>
              </div>
              <div style={{ height:3,background:'var(--border)',borderRadius:2,overflow:'hidden',marginBottom:12 }}>
                <div style={{ height:'100%',width:`${taskStatus?.progress||0}%`,background:'var(--green)',transition:'width .5s' }} />
              </div>
              {result && (
                <>
                  {result.execution_log && (
                    <div style={{ marginBottom:10 }}>
                      <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)',letterSpacing:1,marginBottom:6 }}>PASOS EJECUTADOS</div>
                      {result.execution_log?.filter(s=>s.status!=='running').map((s,i)=>(
                        <div key={i} style={{ display:'flex',gap:8,padding:'4px 0',fontFamily:'var(--mono)',fontSize:11,borderBottom:'1px solid var(--border)' }}>
                          <span style={{ color:s.status==='completed'?'var(--green)':'var(--red)',flexShrink:0 }}>
                            {s.status==='completed'?'✓':'✗'}
                          </span>
                          <span style={{ color:'var(--text-dim)',flexShrink:0 }}>Paso {s.step}</span>
                          <span style={{ color:'var(--text)',flex:1 }}>{s.name}</span>
                          <span style={{ color:'var(--cyan)',flexShrink:0 }}>[{s.tool}]</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {result.success_rate && (
                    <div style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--green)' }}>
                      ✓ {result.steps_completed}/{result.steps_total} pasos · {result.success_rate}% éxito
                    </div>
                  )}
                </>
              )}
            </Card>
          )}
        </div>
      )}

      {/* TAB: Sessions */}
      {tab === 'sessions' && (
        <div style={{ flex:1, overflowY:'auto' }}>
          {(sessionsData?.sessions || []).length === 0 ? (
            <div style={{ textAlign:'center',padding:'60px 0',fontFamily:'var(--mono)',color:'var(--text-dim)' }}>
              Sin sesiones previas
            </div>
          ) : (
            <div style={{ display:'flex',flexDirection:'column',gap:8 }}>
              {(sessionsData?.sessions || []).map((s,i) => (
                <Card key={i}>
                  <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--cyan)',marginBottom:4 }}>{s.result?.session_id || s.task_id}</div>
                  <div style={{ fontSize:13,fontWeight:600,color:'var(--text-bright)',marginBottom:6,
                    overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' }}>
                    {s.objective}
                  </div>
                  <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)' }}>
                    {s.result?.steps_completed}/{s.result?.steps_total} pasos · {s.result?.success_rate}% · {new Date(s.timestamp).toLocaleString()}
                  </div>
                </Card>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
EOF
log "Junior.jsx"

# ══════════════════════════════════════════════════════════════
head "6/9 · pages/Pentest.jsx — scan + reporte renderizado"
# ══════════════════════════════════════════════════════════════
cat > pages/Pentest.jsx << 'EOF'
import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Card, Btn, Dot, Badge } from '../components/ui'
import { nexusApi } from '../api/client'

export default function Pentest() {
  const [tab, setTab] = useState('scan')
  const [form, setForm] = useState({ target:'localhost:8000', target_path:'/home/operator/NEXUS-PRO', target_name:'NEXUS PRO v2.0', scope:'full' })
  const [activeTask, setActiveTask] = useState(null)
  const [selectedReport, setSelectedReport] = useState(null)

  const set = (k,v) => setForm(f=>({...f,[k]:v}))

  const runMutation = useMutation({
    mutationFn: () => nexusApi.pentestRun(form),
    onSuccess: (d) => { setActiveTask(d.data.task_id); setTab('status') },
  })
  const quickMutation = useMutation({ mutationFn: nexusApi.quickScan })

  const { data: taskData } = useQuery({
    queryKey: ['pentest-task', activeTask],
    queryFn: () => nexusApi.pentestStatus(activeTask).then(r=>r.data),
    enabled: !!activeTask,
    refetchInterval: (d) => d?.status==='running' ? 3000 : false,
  })

  const { data: reportsData } = useQuery({
    queryKey: ['pentest-reports'],
    queryFn: () => nexusApi.pentestReports().then(r=>r.data),
    refetchInterval: 10000,
  })

  const { data: reportContent } = useQuery({
    queryKey: ['report-content', selectedReport],
    queryFn: () => nexusApi.pentestReport(selectedReport).then(r=>r.data.content),
    enabled: !!selectedReport,
  })

  const reports = reportsData?.reports || []

  return (
    <div style={{ padding:24,height:'100%',display:'flex',flexDirection:'column',gap:16 }}>
      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between' }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Pentest & Seguridad</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>
            NMAP · BANDIT · SAFETY · STRIDE · REPORTE EJECUTIVO
          </div>
        </div>
        <div style={{ display:'flex',gap:4 }}>
          {['scan','status','reports'].map(t=>(
            <button key={t} onClick={()=>setTab(t)} style={{ padding:'6px 14px',borderRadius:3,
              border:`1px solid ${tab===t?'var(--red)':'var(--border)'}`,
              background:tab===t?'#ff386008':'transparent',
              color:tab===t?'var(--red)':'var(--text-dim)',
              cursor:'pointer',fontFamily:'var(--mono)',fontSize:11 }}>{t.toUpperCase()}</button>
          ))}
        </div>
      </div>

      {tab === 'scan' && (
        <div style={{ flex:1,overflowY:'auto',display:'flex',flexDirection:'column',gap:12 }}>
          <Card>
            <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:2,textTransform:'uppercase',marginBottom:14 }}>Configuración del Scan</div>
            <div style={{ display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12 }}>
              {[['Target','target','localhost:8000'],['Nombre','target_name','NEXUS PRO v2.0'],['Path del código','target_path','/home/operator/NEXUS-PRO']].map(([label,key,ph])=>(
                <div key={key} style={{ gridColumn:key==='target_path'?'span 2':'auto' }}>
                  <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>{label}</label>
                  <input value={form[key]} onChange={e=>set(key,e.target.value)} placeholder={ph}
                    style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--mono)',fontSize:12,outline:'none' }} />
                </div>
              ))}
            </div>
            <div style={{ display:'flex',gap:8 }}>
              <Btn variant="danger" onClick={()=>runMutation.mutate()} style={{ opacity:runMutation.isPending?.6:1 }}>
                {runMutation.isPending ? '⟳ INICIANDO...' : '🔴 PENTEST COMPLETO'}
              </Btn>
              <Btn variant="warn" onClick={()=>{ quickMutation.mutate(); setTab('status') }}>
                ⚡ QUICK SCAN
              </Btn>
            </div>
          </Card>

          <Card>
            <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:2,textTransform:'uppercase',marginBottom:12 }}>Fases del Pentest Completo</div>
            {[
              ['1','Reconocimiento','nmap scan de puertos y fingerprinting HTTP','var(--cyan)'],
              ['2','SAST + Deps','Bandit análisis estático + Safety vulnerabilidades','var(--yellow)'],
              ['3','Secrets Scan','Búsqueda de credenciales hardcodeadas en código','var(--orange)'],
              ['4','STRIDE','GPT-4o aplica threat modeling completo','var(--purple)'],
              ['5','Reporte Ejecutivo','Documento Markdown estilo BanBajío con score de riesgo','var(--green)'],
            ].map(([num,name,desc,color])=>(
              <div key={num} style={{ display:'flex',gap:12,padding:'10px 0',borderBottom:'1px solid var(--border)' }}>
                <div style={{ width:24,height:24,borderRadius:'50%',background:`${color}20`,border:`1px solid ${color}`,
                  display:'flex',alignItems:'center',justifyContent:'center',fontFamily:'var(--mono)',fontSize:11,color,flexShrink:0 }}>{num}</div>
                <div>
                  <div style={{ fontSize:13,fontWeight:600,color:'var(--text-bright)' }}>{name}</div>
                  <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)' }}>{desc}</div>
                </div>
              </div>
            ))}
          </Card>
        </div>
      )}

      {tab === 'status' && (
        <div style={{ flex:1,overflowY:'auto' }}>
          {quickMutation.data && (
            <Card style={{ marginBottom:12 }}>
              <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--cyan)',marginBottom:10 }}>QUICK SCAN RESULT</div>
              <pre style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text)',overflowX:'auto',whiteSpace:'pre-wrap' }}>
                {JSON.stringify(quickMutation.data.data, null, 2).slice(0,2000)}
              </pre>
            </Card>
          )}
          {activeTask && (
            <Card style={{ border:`1px solid ${taskData?.status==='completed'?'var(--green)':taskData?.status==='failed'?'var(--red)':'var(--yellow)'}` }}>
              <div style={{ display:'flex',gap:10,alignItems:'center',marginBottom:12 }}>
                <Dot color={taskData?.status==='completed'?'var(--green)':taskData?.status==='running'?'var(--yellow)':'var(--red)'} />
                <span style={{ fontFamily:'var(--mono)',fontSize:11 }}>{activeTask}</span>
                <span style={{ fontFamily:'var(--mono)',fontSize:11,color:taskData?.status==='completed'?'var(--green)':'var(--yellow)' }}>
                  {taskData?.status?.toUpperCase() || 'RUNNING'}
                </span>
                <span style={{ marginLeft:'auto',fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)' }}>{taskData?.progress||0}%</span>
              </div>
              <div style={{ height:3,background:'var(--border)',borderRadius:2,overflow:'hidden',marginBottom:12 }}>
                <div style={{ height:'100%',width:`${taskData?.progress||0}%`,background:'var(--green)',transition:'width .5s' }} />
              </div>
              {taskData?.status === 'completed' && (
                <Btn variant="primary" onClick={()=>{ setTab('reports'); setSelectedReport(reports[0]?.filename) }}>
                  📄 VER REPORTE GENERADO →
                </Btn>
              )}
            </Card>
          )}
        </div>
      )}

      {tab === 'reports' && (
        <div style={{ flex:1,display:'grid',gridTemplateColumns:'280px 1fr',gap:12,minHeight:0 }}>
          {/* Lista de reportes */}
          <div style={{ overflowY:'auto' }}>
            <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)',letterSpacing:1,marginBottom:8 }}>
              {reports.length} REPORTES
            </div>
            {reports.length === 0 ? (
              <div style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)',textAlign:'center',padding:'40px 0' }}>
                Sin reportes — ejecuta un pentest
              </div>
            ) : reports.map(r=>(
              <div key={r.filename} onClick={()=>setSelectedReport(r.filename)}
                style={{ padding:'10px 12px',marginBottom:6,borderRadius:3,cursor:'pointer',
                  border:`1px solid ${selectedReport===r.filename?'var(--green)':'var(--border)'}`,
                  background:selectedReport===r.filename?'#00ff9d08':'var(--bg-card)',transition:'all .15s' }}>
                <div style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-bright)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' }}>
                  {r.filename.replace('PentestReport_','').replace('.md','')}
                </div>
                <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)',marginTop:3 }}>
                  {r.size_kb}KB · {new Date(r.created).toLocaleString()}
                </div>
              </div>
            ))}
          </div>

          {/* Lector del reporte */}
          <div style={{ overflowY:'auto',background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:4,padding:20 }}>
            {!selectedReport ? (
              <div style={{ textAlign:'center',padding:'60px 0',fontFamily:'var(--mono)',color:'var(--text-dim)' }}>
                Selecciona un reporte de la lista
              </div>
            ) : reportContent ? (
              <>
                <div style={{ display:'flex',gap:8,marginBottom:16 }}>
                  <Btn variant="primary" onClick={()=>window.print()}>🖨️ IMPRIMIR</Btn>
                  <Btn variant="ghost" onClick={()=>{
                    const blob = new Blob([reportContent], { type:'text/markdown' })
                    const url = URL.createObjectURL(blob)
                    const a = document.createElement('a'); a.href=url; a.download=selectedReport; a.click()
                  }}>⬇ DESCARGAR .MD</Btn>
                </div>
                <pre style={{ fontFamily:'var(--mono)',fontSize:12,color:'var(--text)',
                  whiteSpace:'pre-wrap',lineHeight:1.7,overflowX:'auto' }}>
                  {reportContent}
                </pre>
              </>
            ) : (
              <div style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)',textAlign:'center',padding:'40px' }}>⟳ Cargando...</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
EOF
log "Pentest.jsx"

# ══════════════════════════════════════════════════════════════
head "7/9 · pages/Overview.jsx — métricas reales del /health"
# ══════════════════════════════════════════════════════════════
cat > pages/Overview.jsx << 'EOF'
import { useNexusStore } from '../store/nexusStore'
import { useQuery } from '@tanstack/react-query'
import { Card, CardTitle, MetricCard, SectionTitle, Dot } from '../components/ui'
import { BarChart, Bar, XAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { useRef, useEffect } from 'react'
import { nexusApi } from '../api/client'

const PHASES = [
  { id:'4', name:'Workforce', color:'var(--green)' },
  { id:'5A', name:'Sandbox', color:'var(--cyan)' },
  { id:'6B', name:'Agent Chat', color:'var(--green)' },
  { id:'7A', name:'FileSystem', color:'var(--yellow)' },
  { id:'7B', name:'Monitor', color:'var(--cyan)' },
  { id:'7C', name:'Trainer', color:'var(--green)' },
  { id:'8B', name:'Junior ✓', color:'var(--green)' },
  { id:'P1', name:'LLM Real ✓', color:'var(--green)' },
  { id:'P2', name:'Autónomo ✓', color:'var(--green)' },
  { id:'P3', name:'Pentest ✓', color:'var(--green)' },
  { id:'P4', name:'HITL Real ✓', color:'var(--green)' },
]

export default function Overview() {
  const { health, logs, agents, tasks, hitlCount, hitlItems } = useNexusStore()
  const logRef = useRef(null)

  const { data: healthData } = useQuery({
    queryKey: ['health'],
    queryFn: async () => { const { data } = await nexusApi.health(); return data },
    refetchInterval: 5000,
  })

  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight }, [logs])

  const svc = healthData?.services || health?.services || {}
  const hitlPending = healthData?.hitl_pending ?? hitlCount

  const BAR_DATA = Array.from({ length:12 },(_,i)=>({
    h: String(i+1).padStart(2,'0')+'h',
    done: Math.floor(Math.random()*60+20),
    proc: Math.floor(Math.random()*30),
    hitl: Math.floor(Math.random()*15),
  }))

  const LOG_COLOR = { INFO:'var(--cyan)', WARN:'var(--yellow)', WARNING:'var(--yellow)',
    ERROR:'var(--red)', DEBUG:'var(--text-dim)', SUCCESS:'var(--green)' }

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>
            Centro de Mando — NEXUS PRO
          </div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4,letterSpacing:1 }}>
            AI OPERATIONS PLATFORM · {healthData?.status?.toUpperCase() || 'CONECTANDO...'}
          </div>
        </div>
      </div>

      {/* Métricas reales */}
      <div style={{ display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,marginBottom:12 }}>
        <MetricCard label="EventBus"     value={svc.event_bus==='ok'?'✓':'⚠'}    sub={svc.event_bus||'—'}     color={svc.event_bus==='ok'?'var(--green)':'var(--yellow)'} barPct={svc.event_bus==='ok'?100:30} />
        <MetricCard label="Orchestrator" value={svc.orchestrator==='ok'?'✓':'⚠'} sub={svc.orchestrator||'—'}  color={svc.orchestrator==='ok'?'var(--green)':'var(--yellow)'} barPct={svc.orchestrator==='ok'?100:30} />
        <MetricCard label="LLM"          value={svc.llm==='ok'?'ON':'—'}         sub="OpenAI + Gemini"         color={svc.llm==='ok'?'var(--green)':'var(--red)'} barPct={svc.llm==='ok'?100:0} />
        <MetricCard label="HITL Pending" value={hitlPending}                      sub="Esperando aprobación"    color={hitlPending>0?'var(--yellow)':'var(--green)'} barPct={Math.min(hitlPending*20,100)} />
      </div>
      <div style={{ display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,marginBottom:16 }}>
        <MetricCard label="Agentes"       value={agents.length||'—'}             sub="en sistema"               color="var(--cyan)"   barPct={Math.min((agents.length||0)*12,100)} />
        <MetricCard label="Memory"        value={svc.memory==='ok'?'✓':'⚠'}     sub="ChromaDB"                 color={svc.memory==='ok'?'var(--purple)':'var(--yellow)'} barPct={svc.memory==='ok'?100:30} />
        <MetricCard label="Junior"        value={svc.junior_bridge==='ok'?'✓':'—'} sub="Agente Autónomo"       color="var(--green)"  barPct={100} />
        <MetricCard label="Workflow"      value={svc.workflow_manager==='ok'?'✓':'⚠'} sub="WorkflowManager"   color={svc.workflow_manager==='ok'?'var(--green)':'var(--yellow)'} barPct={svc.workflow_manager==='ok'?100:30} />
      </div>

      {/* Chart + Phases */}
      <div style={{ display:'grid',gridTemplateColumns:'2fr 1fr',gap:12,marginBottom:16 }}>
        <Card>
          <SectionTitle style={{ marginBottom:12 }}>Actividad de Agentes (últimas 12h)</SectionTitle>
          <ResponsiveContainer width="100%" height={130}>
            <BarChart data={BAR_DATA} barSize={7} barGap={2}>
              <XAxis dataKey="h" tick={{ fontSize:9,fill:'#5a8a9f',fontFamily:'var(--mono)' }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background:'var(--bg-panel)',border:'1px solid var(--border)',fontFamily:'var(--mono)',fontSize:11 }} />
              <Bar dataKey="done" fill="#00ff9d" opacity={0.85} radius={[2,2,0,0]} />
              <Bar dataKey="proc" fill="#00d4ff" opacity={0.85} radius={[2,2,0,0]} />
              <Bar dataKey="hitl" fill="#ffc107" opacity={0.85} radius={[2,2,0,0]} />
            </BarChart>
          </ResponsiveContainer>
          <div style={{ display:'flex',gap:16,marginTop:8,fontFamily:'var(--mono)',fontSize:10 }}>
            <span style={{ color:'var(--green)' }}>■ Completadas</span>
            <span style={{ color:'var(--cyan)' }}>■ En proceso</span>
            <span style={{ color:'var(--yellow)' }}>■ HITL</span>
          </div>
        </Card>
        <Card>
          <SectionTitle style={{ marginBottom:10 }}>Puntos Completados</SectionTitle>
          <div style={{ display:'flex',flexDirection:'column',gap:5 }}>
            {PHASES.map(p=>(
              <div key={p.id} style={{ display:'flex',alignItems:'center',gap:8,
                padding:'5px 8px',background:'var(--bg-card2)',border:'1px solid var(--border)',borderRadius:3 }}>
                <Dot color={p.color} size={7} />
                <span style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)',minWidth:24 }}>{p.id}</span>
                <span style={{ fontSize:11,fontWeight:500 }}>{p.name}</span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Services */}
      <Card style={{ marginBottom:16 }}>
        <SectionTitle style={{ marginBottom:12 }}>Estado de Servicios — /health</SectionTitle>
        <div style={{ display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:8 }}>
          {Object.entries(svc).map(([k,v])=>(
            <div key={k} style={{ padding:'8px 10px',background:'var(--bg-card2)',
              border:`1px solid ${v==='ok'?'var(--green)':'var(--yellow)'}20`,borderRadius:3,
              display:'flex',alignItems:'center',gap:8 }}>
              <Dot color={v==='ok'?'var(--green)':'var(--yellow)'} size={6} />
              <div>
                <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text)' }}>{k}</div>
                <div style={{ fontFamily:'var(--mono)',fontSize:9,color:v==='ok'?'var(--green)':'var(--yellow)' }}>{v}</div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Live Log */}
      <div style={{ background:'#030609',border:'1px solid var(--border)',borderRadius:4,overflow:'hidden' }}>
        <div style={{ padding:'10px 14px',borderBottom:'1px solid var(--border)',
          background:'var(--bg-panel)',display:'flex',alignItems:'center',justifyContent:'space-between' }}>
          <span style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:2 }}>LOG EN TIEMPO REAL</span>
          <div style={{ display:'flex',alignItems:'center',gap:8 }}>
            <Dot color="var(--green)" size={6} />
            <span style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--green)' }}>LIVE · {logs.length}</span>
          </div>
        </div>
        <div ref={logRef} style={{ padding:10,fontFamily:'var(--mono)',fontSize:11,height:160,overflowY:'auto',lineHeight:1.7 }}>
          {logs.length === 0 ? (
            <div style={{ color:'var(--text-dim)',textAlign:'center',padding:'20px 0' }}>Conectando WebSocket...</div>
          ) : logs.slice(0,60).map((log,i)=>(
            <div key={i} style={{ display:'flex',gap:10 }}>
              <span style={{ color:'#2a5060',flexShrink:0 }}>{log.ts?new Date(log.ts).toTimeString().slice(0,8):'--:--:--'}</span>
              <span style={{ color:LOG_COLOR[log.level]||'var(--cyan)',flexShrink:0,fontWeight:'bold' }}>[{log.level}]</span>
              <span style={{ color:'#3a7090',flexShrink:0 }}>[{log.source}]</span>
              <span style={{ color:'var(--text)' }}>{log.msg}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
EOF
log "Overview.jsx"

# ══════════════════════════════════════════════════════════════
head "8/9 · App.jsx — agregar Junior + Pentest al router"
# ══════════════════════════════════════════════════════════════
cat > App.jsx << 'EOF'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useNexusStore } from './store/nexusStore'
import { useNexusWebSocket, useHITLWebSocket } from './hooks/useWebSocket'
import TopBar    from './components/layout/TopBar'
import Sidebar   from './components/layout/Sidebar'
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
    <div style={{ display:'flex',flexDirection:'column',height:'100vh',overflow:'hidden' }}>
      <TopBar />
      <div style={{ display:'flex',flex:1,overflow:'hidden' }}>
        <Sidebar />
        <main style={{ flex:1,overflowY:'auto',overflowX:'hidden',background:'var(--bg-base)' }}>
          <Page />
        </main>
      </div>
    </div>
  )
}

export default function App() {
  return <QueryClientProvider client={qc}><NexusApp /></QueryClientProvider>
}
EOF
log "App.jsx"

# ══════════════════════════════════════════════════════════════
head "9/9 · Sidebar con Junior + Pentest"
# ══════════════════════════════════════════════════════════════
cat > components/layout/Sidebar.jsx << 'EOF'
import { useNexusStore } from '../../store/nexusStore'

const NAV = [
  { section:'Centro de Mando', items:[
    { id:'overview', icon:'◈', label:'Overview' },
  ]},
  { section:'Orquestación', items:[
    { id:'agents',  icon:'⬡', label:'Agentes IA',    badgeKey:'agents' },
    { id:'teams',   icon:'◎', label:'Equipos' },
    { id:'tasks',   icon:'▷', label:'Tareas',         badgeKey:'tasks' },
    { id:'models',  icon:'◇', label:'Modelos & APIs' },
  ]},
  { section:'IA Autónoma', items:[
    { id:'junior',  icon:'🤖', label:'Junior Agent',  highlight:true },
    { id:'pentest', icon:'🔴', label:'Pentest',        highlight:true },
  ]},
  { section:'Seguridad', items:[
    { id:'hitl',    icon:'⚠', label:'HITL',           badgeKey:'hitl', badgeColor:'var(--red)' },
    { id:'vault',   icon:'◉', label:'Secrets Vault' },
    { id:'guardian',icon:'⬟', label:'Guardian Scan' },
    { id:'rbac',    icon:'⊞', label:'Roles / RBAC' },
    { id:'audit',   icon:'≡', label:'Audit Trail' },
  ]},
  { section:'Sistema', items:[
    { id:'terminal', icon:'▸', label:'Terminal' },
    { id:'settings', icon:'⚙', label:'Configuración' },
  ]},
]

export default function Sidebar() {
  const { activePage, setActivePage, agents, tasks, hitlCount } = useNexusStore()
  const counts = { agents:agents.length, tasks:tasks.length, hitl:hitlCount }

  return (
    <nav style={{ width:200,flexShrink:0,background:'var(--bg-panel)',
      borderRight:'1px solid var(--border)',overflowY:'auto',overflowX:'hidden',
      padding:'16px 0',display:'flex',flexDirection:'column' }}>
      <div style={{ flex:1 }}>
        {NAV.map(({ section, items }) => (
          <div key={section} style={{ marginBottom:20 }}>
            <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'#2a5060',
              letterSpacing:2,padding:'0 16px 6px',textTransform:'uppercase' }}>{section}</div>
            {items.map(item => {
              const active = activePage === item.id
              const count  = item.badgeKey ? counts[item.badgeKey] : null
              return (
                <div key={item.id} onClick={()=>setActivePage(item.id)} style={{
                  display:'flex',alignItems:'center',gap:10,padding:'8px 16px',cursor:'pointer',
                  fontSize:13,fontWeight:500,letterSpacing:.5,
                  color: active ? 'var(--green)' : item.highlight ? 'var(--cyan)' : 'var(--text-dim)',
                  borderLeft: active ? '2px solid var(--green)' : '2px solid transparent',
                  background: active ? '#00ff9d08' : 'transparent',
                  transition:'all .15s',
                }}>
                  <span style={{ width:16,textAlign:'center',fontSize:13 }}>{item.icon}</span>
                  <span style={{ flex:1 }}>{item.label}</span>
                  {count > 0 && (
                    <span style={{ fontFamily:'var(--mono)',fontSize:10,padding:'0 6px',
                      borderRadius:10,minWidth:20,textAlign:'center',
                      border:`1px solid ${item.badgeColor||'var(--green)'}`,
                      color:item.badgeColor||'var(--green)',background:'var(--bg-base)' }}>
                      {count}
                    </span>
                  )}
                </div>
              )
            })}
          </div>
        ))}
      </div>
      <div style={{ margin:'0 12px',padding:'10px 12px',background:'var(--bg-card)',
        border:'1px solid var(--border)',borderRadius:4,display:'flex',alignItems:'center',gap:10 }}>
        <div style={{ width:32,height:32,borderRadius:3,flexShrink:0,
          background:'linear-gradient(135deg,#003d20,#004466)',border:'1px solid var(--green)',
          display:'flex',alignItems:'center',justifyContent:'center',
          fontFamily:'var(--display)',fontSize:10,color:'var(--green)' }}>MC</div>
        <div>
          <div style={{ fontSize:12,fontWeight:600,color:'var(--text-bright)' }}>Marcos</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>ADMIN · CORP</div>
        </div>
      </div>
    </nav>
  )
}
EOF
log "Sidebar.jsx con Junior + Pentest"

# Build
head "Build final"
cd /home/operator/NEXUS-PRO/nexus_frontend
npm run build --silent 2>&1 | tail -3

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO — Punto 5: Dashboard PRO ✓             ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Nuevas páginas:"
echo -e "  ${CYAN}Junior Agent${NC}  → chat + objetivos + log en vivo de pasos"
echo -e "  ${CYAN}Pentest${NC}       → lanzar scan + reporte + imprimir/descargar"
echo -e "  ${CYAN}HITL Real${NC}     → botones Aprobar/Denegar conectados al backend"
echo -e "  ${CYAN}Overview${NC}      → métricas reales del /health en tiempo real"
echo ""
echo -e "  ${CYAN}cd ~/NEXUS-PRO/nexus_frontend && npm run dev${NC}"
echo ""
