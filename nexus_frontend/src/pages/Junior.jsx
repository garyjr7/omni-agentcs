import { useState, useRef, useEffect, useCallback, useMemo } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../api/client'
import { Btn, Dot } from '../components/ui'
import { useAuthStore } from '../store/authStore'

// ── API helpers ───────────────────────────────────────────────
const jApi = {
  chats:       (tenantId) => api.get('/api/v1/sovereign/conversations', { params:{ tenant_id:tenantId } }).then(r => {
    r.data.chats = (r.data.conversations || []).map(c => ({ ...c, session_id:c.id }))
    return r
  }),
  newChat:     (title, tenantId) => api.post('/api/v1/sovereign/conversations', {
    tenant_id:tenantId, title, classification:'internal'
  }).then(r => { r.data.session_id = r.data.id; return r }),
  deleteChat:  (sid, tenantId) => api.delete(`/api/v1/sovereign/conversations/${sid}`, { params:{ tenant_id:tenantId } }),
  messages:    (sid, tenantId) => api.get(`/api/v1/sovereign/conversations/${sid}/messages`, { params:{ tenant_id:tenantId } }),
  send:        async (sid, msg, tenantId) => {
    const queued = await api.post(`/api/v1/sovereign/conversations/${sid}/messages`, { content:msg })
    const runId = queued.data.run.id
    for (let attempt=0; attempt<120; attempt += 1) {
      const current = await api.get(`/api/v1/sovereign/runs/${runId}`, { params:{ tenant_id:tenantId } })
      if (['completed','failed','dead_letter','cancelled'].includes(current.data.status)) return current
      await new Promise(resolve => setTimeout(resolve, 750))
    }
    throw new Error('La ejecución durable excedió el tiempo de espera de la interfaz')
  },
  updates:     () => Promise.resolve({ data:{ total:0, updates:[] } }),
  approveUpd:  (id) => api.post(`/jarvis/updates/${id}/approve`, { approved_by: 'marcos' }),
  denyUpd:     (id) => api.post(`/jarvis/updates/${id}/deny`, { reason: 'Descartado' }),
  deleteUpd:   (id) => api.delete(`/jarvis/updates/${id}`),
  notifs:      () => api.get('/jarvis/notifications?limit=20'),
  readAllNotifs:() => api.post('/jarvis/notifications/read-all'),
  status:      () => api.get('/api/v1/sovereign/capabilities'),
  start:       () => Promise.resolve({ data:{ status:'managed-by-worker' } }),
  stop:        () => Promise.resolve({ data:{ status:'managed-by-worker' } }),
  runObjective:(obj, _steps, tenantId) => api.post('/api/v1/sovereign/runs', { tenant_id:tenantId, objective:obj, mode:'brain' }),
  taskStatus:  (id, tenantId) => api.get(`/api/v1/sovereign/runs/${id}`, { params:{ tenant_id:tenantId } }).then(r => {
    r.data.progress = r.data.status === 'completed' ? 100 : r.data.status === 'running' ? 50 : r.data.status === 'queued' ? 10 : 0
    return r
  }),
}

const PRIO_COLOR = { crítica:'var(--red)', alta:'var(--orange)', media:'var(--yellow)', baja:'var(--green)' }
const CAT_ICON   = { seguridad:'🛡️', rendimiento:'⚡', mantenimiento:'🔧', operaciones:'📋', mejora:'💡' }
const EXAMPLES   = [
  "Analiza todo el proyecto NEXUS PRO y dime qué archivos son basura",
  "¿Cuál es el estado actual del sistema?",
  "Crea una API FastAPI para una zapatería con login y catálogo",
  "Audita la seguridad de NEXUS y genera reporte ejecutivo",
  "¿Qué mejoras recomiendas para optimizar NEXUS?",
  "Genera Terraform para arquitectura Zero Trust en AWS",
]

// ── Componente de mensaje ─────────────────────────────────────
function Message({ msg }) {
  const isUser = msg.role === 'user'
  return (
    <div style={{ display:'flex', gap:12, alignItems:'flex-start',
      justifyContent: isUser ? 'flex-end' : 'flex-start',
      padding:'4px 0' }}>
      {!isUser && (
        <div style={{ width:32, height:32, borderRadius:8, flexShrink:0,
          background:'linear-gradient(135deg,#003d20,#001a40)',
          border:'1px solid var(--green)', display:'flex',
          alignItems:'center', justifyContent:'center', fontSize:16 }}>🤖</div>
      )}
      <div style={{ maxWidth:'80%', padding:'10px 14px', borderRadius:12,
        background: isUser ? 'var(--cyan)' : 'var(--bg-card)',
        border: isUser ? 'none' : '1px solid var(--border)',
        color: isUser ? 'var(--bg-base)' : 'var(--text)',
        fontFamily:'var(--ui)', fontSize:13, lineHeight:1.65,
        whiteSpace:'pre-wrap', wordBreak:'break-word' }}>
        {msg.content}
        <div style={{ fontFamily:'var(--mono)', fontSize:9,
          color: isUser ? 'rgba(0,0,0,.4)' : 'var(--text-dim)',
          marginTop:4 }}>
          {msg.created_at ? new Date(msg.created_at).toLocaleTimeString() : ''}
        </div>
      </div>
      {isUser && (
        <div style={{ width:32, height:32, borderRadius:8, flexShrink:0,
          background:'var(--cyan)', display:'flex', alignItems:'center',
          justifyContent:'center', fontSize:14, fontWeight:700,
          color:'var(--bg-base)' }}>M</div>
      )}
    </div>
  )
}

// ── Panel de actualizaciones ──────────────────────────────────
function UpdatesPanel({ onClose }) {
  const qc = useQueryClient()
  const { data } = useQuery({
    queryKey: ['junior-updates'],
    queryFn: () => jApi.updates('pending').then(r => r.data.updates || []),
    refetchInterval: 10000,
  })
  const updates = data || []

  const approveMut = useMutation({
    mutationFn: (id) => jApi.approveUpd(id),
    onSuccess: () => qc.invalidateQueries(['junior-updates']),
  })
  const denyMut = useMutation({
    mutationFn: (id) => jApi.denyUpd(id),
    onSuccess: () => qc.invalidateQueries(['junior-updates']),
  })

  return (
    <div style={{ position:'fixed', right:0, top:0, bottom:0, width:420,
      background:'var(--bg-panel)', borderLeft:'1px solid var(--border)',
      zIndex:200, display:'flex', flexDirection:'column',
      boxShadow:'-4px 0 20px rgba(0,0,0,.4)' }}>
      <div style={{ padding:'16px 20px', borderBottom:'1px solid var(--border)',
        display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <div>
          <div style={{ fontFamily:'var(--display)', fontSize:15, color:'var(--text-bright)', letterSpacing:1 }}>
            Actualizaciones Pendientes
          </div>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:2 }}>
            Junior propone · Tú autorizas · Agentes ejecutan
          </div>
        </div>
        <div style={{ display:'flex', gap:8 }}>
          <span style={{ fontFamily:'var(--mono)', fontSize:11,
            padding:'2px 8px', borderRadius:10,
            border:'1px solid var(--yellow)', color:'var(--yellow)' }}>
            {updates.length}
          </span>
          <button onClick={onClose} style={{ background:'none', border:'none',
            color:'var(--text-dim)', cursor:'pointer', fontSize:18 }}>✕</button>
        </div>
      </div>

      <div style={{ flex:1, overflowY:'auto', padding:16 }}>
        {updates.length === 0 ? (
          <div style={{ textAlign:'center', padding:'40px 0',
            fontFamily:'var(--mono)', fontSize:11, color:'var(--text-dim)' }}>
            <div style={{ fontSize:32, marginBottom:8 }}>💡</div>
            Sin propuestas pendientes<br/>Junior está analizando el sistema...
          </div>
        ) : updates.map(u => (
          <div key={u.id} style={{ background:'var(--bg-card)',
            border:'1px solid var(--border)', borderRadius:8,
            padding:14, marginBottom:10 }}>
            <div style={{ display:'flex', alignItems:'flex-start',
              gap:8, marginBottom:8 }}>
              <span style={{ fontSize:18 }}>{CAT_ICON[u.category] || '💡'}</span>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:13, fontWeight:600,
                  color:'var(--text-bright)', marginBottom:2 }}>{u.title}</div>
                <div style={{ display:'flex', gap:6 }}>
                  <span style={{ fontFamily:'var(--mono)', fontSize:9,
                    padding:'1px 6px', borderRadius:3,
                    border:`1px solid ${PRIO_COLOR[u.priority]||'var(--border)'}`,
                    color:PRIO_COLOR[u.priority]||'var(--text-dim)' }}>
                    {u.priority}
                  </span>
                  <span style={{ fontFamily:'var(--mono)', fontSize:9,
                    color:'var(--text-dim)' }}>{u.category}</span>
                </div>
              </div>
            </div>
            <div style={{ fontFamily:'var(--mono)', fontSize:11,
              color:'var(--text-dim)', marginBottom:8, lineHeight:1.6 }}>
              {u.description}
            </div>
            {u.impact && (
              <div style={{ fontFamily:'var(--mono)', fontSize:10,
                color:'var(--green)', marginBottom:8 }}>
                💥 Impacto: {u.impact}
              </div>
            )}
            {u.implementation && (
              <div style={{ background:'var(--bg-base)', border:'1px solid var(--border)',
                borderRadius:4, padding:'6px 10px', marginBottom:10,
                fontFamily:'var(--mono)', fontSize:10, color:'var(--cyan)',
                overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                $ {u.implementation}
              </div>
            )}
            <div style={{ display:'flex', gap:8 }}>
              <button onClick={() => approveMut.mutate(u.id)}
                style={{ flex:1, padding:'6px', borderRadius:4,
                  background:'#00ff9d15', border:'1px solid var(--green)',
                  color:'var(--green)', cursor:'pointer',
                  fontFamily:'var(--mono)', fontSize:11 }}>
                {approveMut.isPending && approveMut.variables === u.id ? '⟳' : '✓ APROBAR'}
              </button>
              <button onClick={() => denyMut.mutate(u.id)}
                style={{ flex:1, padding:'6px', borderRadius:4,
                  background:'#ff386015', border:'1px solid var(--red)',
                  color:'var(--red)', cursor:'pointer',
                  fontFamily:'var(--mono)', fontSize:11 }}>
                ✗ DESCARTAR
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Sidebar de Junior ─────────────────────────────────────────
function JuniorSidebar({ chats, activeChat, onSelect, onCreate, onDelete,
                         sidebarOpen, setSidebarOpen, updCount, onShowUpdates }) {
  return (
    <div style={{ width: sidebarOpen ? 260 : 0, flexShrink:0,
      overflow:'hidden', transition:'width .25s ease',
      background:'var(--bg-panel)', borderRight:'1px solid var(--border)',
      display:'flex', flexDirection:'column' }}>
      <div style={{ padding:'14px 12px', borderBottom:'1px solid var(--border)',
        display:'flex', gap:8 }}>
        <button onClick={onCreate}
          style={{ flex:1, padding:'8px 12px', borderRadius:6,
            background:'var(--bg-card)', border:'1px solid var(--border)',
            color:'var(--text)', cursor:'pointer', fontFamily:'var(--ui)',
            fontSize:12, display:'flex', alignItems:'center', gap:8,
            transition:'all .15s' }}>
          <span style={{ fontSize:14 }}>✎</span> Nueva conversación
        </button>
        <button onClick={() => setSidebarOpen(false)}
          style={{ padding:'8px', borderRadius:6, background:'var(--bg-card)',
            border:'1px solid var(--border)', color:'var(--text-dim)',
            cursor:'pointer', fontSize:14 }}>✕</button>
      </div>

      {/* Actualizaciones */}
      <button onClick={onShowUpdates}
        style={{ margin:'10px 12px', padding:'10px 12px', borderRadius:6,
          background: updCount > 0 ? '#ffc10710' : 'var(--bg-card)',
          border:`1px solid ${updCount > 0 ? 'var(--yellow)' : 'var(--border)'}`,
          color: updCount > 0 ? 'var(--yellow)' : 'var(--text-dim)',
          cursor:'pointer', display:'flex', alignItems:'center', gap:8,
          fontFamily:'var(--ui)', fontSize:12 }}>
        <span>💡</span>
        <span style={{ flex:1, textAlign:'left' }}>Actualizaciones</span>
        {updCount > 0 && (
          <span style={{ background:'var(--yellow)', color:'var(--bg-base)',
            borderRadius:10, padding:'1px 7px',
            fontFamily:'var(--mono)', fontSize:10, fontWeight:700 }}>
            {updCount}
          </span>
        )}
      </button>

      {/* Historial */}
      <div style={{ padding:'0 12px 6px',
        fontFamily:'var(--mono)', fontSize:9,
        color:'var(--text-dim)', letterSpacing:1, textTransform:'uppercase' }}>
        Conversaciones
      </div>
      <div style={{ flex:1, overflowY:'auto', padding:'0 8px' }}>
        {chats.length === 0 ? (
          <div style={{ padding:'20px 12px', fontFamily:'var(--mono)',
            fontSize:10, color:'var(--text-dim)', textAlign:'center' }}>
            Sin conversaciones
          </div>
        ) : chats.map(c => (
          <div key={c.session_id}
            onClick={() => onSelect(c.session_id)}
            style={{ padding:'8px 10px', borderRadius:6, cursor:'pointer',
              marginBottom:2, display:'flex', alignItems:'center', gap:8,
              background: activeChat === c.session_id ? 'var(--bg-card)' : 'transparent',
              border: activeChat === c.session_id ? '1px solid var(--border)' : '1px solid transparent',
              transition:'all .15s' }}>
            <span style={{ fontSize:12 }}>💬</span>
            <span style={{ flex:1, fontSize:12, overflow:'hidden',
              textOverflow:'ellipsis', whiteSpace:'nowrap',
              color: activeChat === c.session_id ? 'var(--text-bright)' : 'var(--text-dim)' }}>
              {c.title || 'Nueva conversación'}
            </span>
            <button onClick={e => { e.stopPropagation(); onDelete(c.session_id) }}
              style={{ background:'none', border:'none', color:'var(--text-dim)',
                cursor:'pointer', fontSize:11, opacity:.5,
                ':hover': { opacity:1 } }}>✕</button>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── COMPONENTE PRINCIPAL ──────────────────────────────────────
export default function Junior() {
  const qc = useQueryClient()
  const tenantId = useAuthStore(s => s.user?.tenant_id || 'system')
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [activeChat, setActiveChat]   = useState(null)
  const [input, setInput]             = useState('')
  const [tab, setTab]                 = useState('chat') // chat | run
  const [showUpdates, setShowUpdates] = useState(false)
  const [activeTask, setActiveTask]   = useState(null)
  const [runObj, setRunObj]           = useState('')
  const [runSteps, setRunSteps]       = useState(6)
  const messagesEndRef = useRef(null)
  const inputRef = useRef(null)

  // Queries
  const { data: chatsData } = useQuery({
    queryKey: ['junior-chats'],
    queryFn: () => jApi.chats(tenantId).then(r => r.data.chats || []),
    refetchInterval: 15000,
  })
  const chats = chatsData || []

  const { data: messagesData, refetch: refetchMessages } = useQuery({
    queryKey: ['junior-messages', activeChat],
    queryFn: () => activeChat ? jApi.messages(activeChat, tenantId).then(r => r.data.messages || []) : Promise.resolve([]),
    enabled: !!activeChat,
  })
  const messages = useMemo(() => messagesData || [], [messagesData])

  const { data: statusData } = useQuery({
    queryKey: ['junior-status'],
    queryFn: () => jApi.status().then(r => r.data),
    refetchInterval: 30000,
  })

  const { data: updData } = useQuery({
    queryKey: ['junior-updates'],
    queryFn: () => jApi.updates('pending').then(r => r.data),
    refetchInterval: 10000,
  })
  const updCount = updData?.total || 0

  const { data: taskData } = useQuery({
    queryKey: ['junior-task-status', activeTask],
    queryFn: () => activeTask ? jApi.taskStatus(activeTask, tenantId).then(r => r.data) : Promise.resolve(null),
    enabled: !!activeTask,
    refetchInterval: query => ['queued','running'].includes(query.state.data?.status) ? 2000 : false,
  })

  // Scroll al fondo
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior:'smooth' })
  }, [messages])

  // Mutations
  const sendMut = useMutation({
    mutationFn: ({ sid, msg }) => jApi.send(sid, msg, tenantId),
    onSuccess: () => {
      refetchMessages()
      qc.invalidateQueries(['junior-chats'])
    },
  })

  const newChatMut = useMutation({
    mutationFn: (title) => jApi.newChat(title, tenantId),
    onSuccess: (data) => {
      setActiveChat(data.data.session_id)
      qc.invalidateQueries(['junior-chats'])
    },
  })

  const deleteChatMut = useMutation({
    mutationFn: (sid) => jApi.deleteChat(sid, tenantId),
    onSuccess: (_, sid) => {
      if (activeChat === sid) setActiveChat(null)
      qc.invalidateQueries(['junior-chats'])
    },
  })

  const runMut = useMutation({
    mutationFn: ({ obj, steps }) => jApi.runObjective(obj, steps, tenantId),
    onSuccess: (data) => setActiveTask(data.data.id),
  })

  const startMut = useMutation({ mutationFn: jApi.start })
  const stopMut  = useMutation({ mutationFn: jApi.stop })

  const handleSend = useCallback(async () => {
    if (!input.trim() || sendMut.isPending) return
    const msg = input.trim()
    setInput('')

    let sid = activeChat
    if (!sid) {
      const result = await newChatMut.mutateAsync(msg.slice(0, 60))
      sid = result.data.session_id
      setActiveChat(sid)
    }
    sendMut.mutate({ sid, msg })
    inputRef.current?.focus()
  }, [input, activeChat, sendMut, newChatMut])

  const handleExample = (ex) => {
    setInput(ex)
    inputRef.current?.focus()
  }

  return (
    <div style={{ display:'flex', height:'100%', overflow:'hidden', position:'relative' }}>
      {/* Sidebar */}
      <JuniorSidebar
        chats={chats}
        activeChat={activeChat}
        onSelect={setActiveChat}
        onCreate={() => newChatMut.mutate('Nueva conversación')}
        onDelete={(sid) => deleteChatMut.mutate(sid)}
        sidebarOpen={sidebarOpen}
        setSidebarOpen={setSidebarOpen}
        updCount={updCount}
        onShowUpdates={() => setShowUpdates(true)}
      />

      {/* Main */}
      <div style={{ flex:1, display:'flex', flexDirection:'column', minWidth:0 }}>
        {/* Header */}
        <div style={{ padding:'12px 20px', borderBottom:'1px solid var(--border)',
          display:'flex', alignItems:'center', gap:12, flexShrink:0 }}>
          {!sidebarOpen && (
            <button onClick={() => setSidebarOpen(true)}
              style={{ background:'none', border:'none',
                color:'var(--text-dim)', cursor:'pointer', fontSize:18 }}>☰</button>
          )}
          <div style={{ width:36, height:36, borderRadius:8,
            background:'linear-gradient(135deg,#003d20,#001a40)',
            border:'1px solid var(--green)', display:'flex',
            alignItems:'center', justifyContent:'center', fontSize:20 }}>🤖</div>
          <div>
            <div style={{ fontSize:15, fontWeight:700, color:'var(--text-bright)' }}>Junior</div>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
              display:'flex', alignItems:'center', gap:6 }}>
              <Dot color={statusData?.running ? 'var(--green)' : 'var(--red)'} size={6} />
              {statusData?.running ? 'DAEMON ACTIVO · 24/7' : 'DAEMON INACTIVO'}
              {statusData?.pending_updates > 0 && (
                <span style={{ color:'var(--yellow)' }}>· {statusData.pending_updates} actualizaciones</span>
              )}
            </div>
          </div>
          <div style={{ marginLeft:'auto', display:'flex', gap:8 }}>
            {/* Tabs */}
            {['chat','run'].map(t => (
              <button key={t} onClick={() => setTab(t)}
                style={{ padding:'5px 14px', borderRadius:6,
                  border:`1px solid ${tab===t?'var(--green)':'var(--border)'}`,
                  background: tab===t ? '#00ff9d08' : 'transparent',
                  color: tab===t ? 'var(--green)' : 'var(--text-dim)',
                  cursor:'pointer', fontFamily:'var(--mono)', fontSize:11 }}>
                {t === 'chat' ? '💬 CHAT' : '🚀 EJECUTAR'}
              </button>
            ))}
            {/* Daemon control */}
            {statusData?.running ? (
              <button onClick={() => stopMut.mutate()}
                style={{ padding:'5px 12px', borderRadius:6,
                  border:'1px solid var(--red)', background:'#ff386008',
                  color:'var(--red)', cursor:'pointer',
                  fontFamily:'var(--mono)', fontSize:11 }}>
                ■ DETENER
              </button>
            ) : (
              <button onClick={() => startMut.mutate()}
                style={{ padding:'5px 12px', borderRadius:6,
                  border:'1px solid var(--green)', background:'#00ff9d08',
                  color:'var(--green)', cursor:'pointer',
                  fontFamily:'var(--mono)', fontSize:11 }}>
                ▶ INICIAR DAEMON
              </button>
            )}
          </div>
        </div>

        {/* TAB: CHAT */}
        {tab === 'chat' && (
          <>
            <div style={{ flex:1, overflowY:'auto', padding:'20px 24px',
              display:'flex', flexDirection:'column', gap:12 }}>
              {!activeChat ? (
                /* Pantalla de bienvenida */
                <div style={{ flex:1, display:'flex', flexDirection:'column',
                  alignItems:'center', justifyContent:'center', textAlign:'center', padding:'40px 20px' }}>
                  <div style={{ width:72, height:72, borderRadius:16, marginBottom:20,
                    background:'linear-gradient(135deg,#003d20,#001a40)',
                    border:'2px solid var(--green)', display:'flex',
                    alignItems:'center', justifyContent:'center', fontSize:36 }}>🤖</div>
                  <div style={{ fontFamily:'var(--display)', fontSize:24,
                    color:'var(--text-bright)', marginBottom:8, letterSpacing:1 }}>
                    Hola, soy Junior
                  </div>
                  <div style={{ fontFamily:'var(--ui)', fontSize:14,
                    color:'var(--text-dim)', marginBottom:32, maxWidth:400, lineHeight:1.6 }}>
                    Tu agente autónomo de NEXUS PRO. Puedo ayudarte con desarrollo,
                    ciberseguridad, DevOps y análisis del sistema.
                  </div>
                  <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr',
                    gap:8, maxWidth:520, width:'100%' }}>
                    {EXAMPLES.map((ex, i) => (
                      <button key={i} onClick={() => handleExample(ex)}
                        style={{ padding:'10px 14px', borderRadius:8, cursor:'pointer',
                          background:'var(--bg-card)', border:'1px solid var(--border)',
                          color:'var(--text-dim)', fontFamily:'var(--ui)', fontSize:12,
                          textAlign:'left', lineHeight:1.4, transition:'all .15s' }}
                        onMouseEnter={e => { e.target.style.borderColor='var(--green)'; e.target.style.color='var(--text)' }}
                        onMouseLeave={e => { e.target.style.borderColor='var(--border)'; e.target.style.color='var(--text-dim)' }}>
                        {ex}
                      </button>
                    ))}
                  </div>
                </div>
              ) : (
                <>
                  {messages.map((m, i) => <Message key={i} msg={m} />)}
                  {sendMut.isPending && (
                    <div style={{ display:'flex', gap:12, alignItems:'flex-start' }}>
                      <div style={{ width:32, height:32, borderRadius:8,
                        background:'linear-gradient(135deg,#003d20,#001a40)',
                        border:'1px solid var(--green)', display:'flex',
                        alignItems:'center', justifyContent:'center', fontSize:16 }}>🤖</div>
                      <div style={{ padding:'10px 14px', borderRadius:12,
                        background:'var(--bg-card)', border:'1px solid var(--border)',
                        fontFamily:'var(--mono)', fontSize:12, color:'var(--green)' }}>
                        Pensando...
                      </div>
                    </div>
                  )}
                  <div ref={messagesEndRef} />
                </>
              )}
            </div>

            {/* Input */}
            <div style={{ padding:'16px 24px', borderTop:'1px solid var(--border)',
              display:'flex', gap:10, alignItems:'flex-end' }}>
              <textarea
                ref={inputRef}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend() } }}
                placeholder="Escríbele algo a Junior... (Enter para enviar, Shift+Enter para nueva línea)"
                rows={input.split('\n').length > 1 ? Math.min(input.split('\n').length, 4) : 1}
                style={{ flex:1, background:'var(--bg-card)',
                  border:'1px solid var(--border)', borderRadius:10,
                  padding:'10px 14px', color:'var(--text)',
                  fontFamily:'var(--ui)', fontSize:13, outline:'none',
                  resize:'none', lineHeight:1.6, transition:'border-color .2s' }}
                onFocus={e => e.target.style.borderColor = 'var(--green)'}
                onBlur={e => e.target.style.borderColor = 'var(--border)'}
              />
              <button onClick={handleSend}
                disabled={!input.trim() || sendMut.isPending}
                style={{ padding:'10px 18px', borderRadius:10,
                  background: input.trim() ? 'var(--green)' : 'var(--bg-card)',
                  border:`1px solid ${input.trim() ? 'var(--green)' : 'var(--border)'}`,
                  color: input.trim() ? 'var(--bg-base)' : 'var(--text-dim)',
                  cursor: input.trim() ? 'pointer' : 'default',
                  fontFamily:'var(--mono)', fontSize:12, fontWeight:700,
                  transition:'all .2s' }}>
                {sendMut.isPending ? '⟳' : '▶'}
              </button>
            </div>
          </>
        )}

        {/* TAB: RUN */}
        {tab === 'run' && (
          <div style={{ flex:1, overflowY:'auto', padding:'24px' }}>
            <div style={{ maxWidth:640, margin:'0 auto' }}>
              <div style={{ background:'var(--bg-card)', border:'1px solid var(--border)',
                borderRadius:12, padding:20, marginBottom:16 }}>
                <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
                  letterSpacing:2, textTransform:'uppercase', marginBottom:12 }}>
                  Objetivo Autónomo — Junior ejecuta N pasos solo
                </div>
                <textarea value={runObj} onChange={e => setRunObj(e.target.value)}
                  placeholder="Ej: Analiza todo el proyecto NEXUS PRO, identifica archivos innecesarios y genera reporte con recomendaciones..."
                  rows={4}
                  style={{ width:'100%', background:'var(--bg-base)',
                    border:'1px solid var(--border)', borderRadius:8,
                    padding:'10px 14px', color:'var(--text)',
                    fontFamily:'var(--ui)', fontSize:13, outline:'none',
                    resize:'vertical', lineHeight:1.6 }}
                />
                <div style={{ display:'flex', alignItems:'center', gap:12, marginTop:12 }}>
                  <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                    <span style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)' }}>PASOS:</span>
                    <select value={runSteps} onChange={e => setRunSteps(parseInt(e.target.value))}
                      style={{ background:'var(--bg-base)', border:'1px solid var(--border)',
                        borderRadius:4, padding:'4px 8px', color:'var(--text)',
                        fontFamily:'var(--mono)', fontSize:11 }}>
                      {[3,4,5,6,7,8].map(n => <option key={n}>{n}</option>)}
                    </select>
                  </div>
                  <button onClick={() => runMut.mutate({ obj: runObj, steps: runSteps })}
                    disabled={!runObj.trim() || runMut.isPending}
                    style={{ flex:1, padding:'10px', borderRadius:8,
                      background: runObj.trim() ? '#00ff9d15' : 'var(--bg-base)',
                      border:`1px solid ${runObj.trim() ? 'var(--green)' : 'var(--border)'}`,
                      color: runObj.trim() ? 'var(--green)' : 'var(--text-dim)',
                      cursor: runObj.trim() ? 'pointer' : 'default',
                      fontFamily:'var(--mono)', fontSize:12, fontWeight:700 }}>
                    {runMut.isPending ? '⟳ INICIANDO...' : '🚀 EJECUTAR JUNIOR'}
                  </button>
                </div>
              </div>

              {/* Estado de tarea activa */}
              {activeTask && taskData && (
                <div style={{ background:'var(--bg-card)',
                  border:`1px solid ${taskData.status==='completed'?'var(--green)':taskData.status==='failed'?'var(--red)':'var(--yellow)'}`,
                  borderRadius:12, padding:16, marginBottom:16 }}>
                  <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:10 }}>
                    <Dot color={taskData.status==='completed'?'var(--green)':taskData.status==='running'?'var(--yellow)':'var(--red)'} />
                    <span style={{ fontFamily:'var(--mono)', fontSize:11 }}>{activeTask}</span>
                    <span style={{ marginLeft:'auto', fontFamily:'var(--mono)', fontSize:11,
                      color:taskData.status==='completed'?'var(--green)':'var(--yellow)' }}>
                      {taskData.status?.toUpperCase()} · {taskData.progress}%
                    </span>
                  </div>
                  <div style={{ height:4, background:'var(--border)', borderRadius:2, overflow:'hidden' }}>
                    <div style={{ height:'100%', width:`${taskData.progress||0}%`,
                      background:'var(--green)', transition:'width .5s' }} />
                  </div>
                </div>
              )}

              {/* Ejemplos */}
              <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)',
                letterSpacing:1, textTransform:'uppercase', marginBottom:8 }}>
                Ejemplos rápidos
              </div>
              {EXAMPLES.map((ex, i) => (
                <div key={i} onClick={() => setRunObj(ex)}
                  style={{ padding:'10px 14px', marginBottom:6,
                    background:'var(--bg-card)', border:'1px solid var(--border)',
                    borderRadius:8, cursor:'pointer', fontFamily:'var(--mono)',
                    fontSize:11, color:'var(--text-dim)', transition:'all .15s' }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor='var(--green)'; e.currentTarget.style.color='var(--text)' }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor='var(--border)'; e.currentTarget.style.color='var(--text-dim)' }}>
                  → {ex}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Panel de actualizaciones */}
      {showUpdates && <UpdatesPanel onClose={() => setShowUpdates(false)} />}
    </div>
  )
}
