#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Frontend Conectado a API Real v2.0             ║
# ║  Agents + Teams + Tasks + Models con datos reales           ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

FRONT="/home/operator/NEXUS-PRO/nexus_frontend/src"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

cd "$FRONT"

# ══════════════════════════════════════════════════════════════
head "1/6 · api/client.js — endpoints completos"
# ══════════════════════════════════════════════════════════════
cat > api/client.js << 'EOF'
import axios from 'axios'

export const API_URL = import.meta.env.VITE_API_URL || 'http://192.168.220.134:8000'
export const WS_URL  = import.meta.env.VITE_WS_URL  || 'ws://192.168.220.134:8000'

export const api = axios.create({
  baseURL: API_URL,
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.response.use(r => r, err => {
  console.error('API Error:', err.response?.status, err.config?.url)
  return Promise.reject(err)
})

export const nexusApi = {
  // Health
  health: () => api.get('/health'),

  // Tools
  tools:       () => api.get('/tools'),
  toolsByCategory: () => api.get('/tools/categories'),
  createTool:  (d) => api.post('/tools', d),
  deleteTool:  (id) => api.delete(`/tools/${id}`),

  // Agents
  agents:       () => api.get('/agents'),
  agentsRegistry: () => api.get('/agents/registry'),
  agent:        (id) => api.get(`/agents/${id}`),
  createAgent:  (d) => api.post('/agents', d),
  updateAgent:  (id, d) => api.put(`/agents/${id}`, d),
  assignTools:  (id, tools) => api.post(`/agents/${id}/tools`, { tools }),
  deleteAgent:  (id) => api.delete(`/agents/${id}`),

  // Teams
  teams:        () => api.get('/teams-v2/teams-v2'),
  team:         (id) => api.get(`/teams-v2/teams-v2/${id}`),
  createTeam:   (d) => api.post('/teams-v2/teams-v2', d),
  updateTeam:   (id, d) => api.put(`/teams-v2/teams-v2/${id}`, d),
  addAgentToTeam: (tid, aid) => api.post(`/teams-v2/teams-v2/${tid}/agents`, { agent_id: aid }),
  removeAgentFromTeam: (tid, aid) => api.delete(`/teams-v2/teams-v2/${tid}/agents/${aid}`),
  deleteTeam:   (id) => api.delete(`/teams-v2/teams-v2/${id}`),

  // Tasks
  tasks:        (status) => api.get('/tasks', { params: status ? { status } : {} }),
  task:         (id) => api.get(`/tasks/${id}`),
  createTask:   (d) => api.post('/tasks', d),
  runTask:      (id) => api.post(`/tasks/${id}/run`),
  cancelTask:   (id) => api.post(`/tasks/${id}/cancel`),

  // Models & API Keys
  apiKeys:      () => api.get('/models/keys'),
  addApiKey:    (d) => api.post('/models/keys', d),
  deleteApiKey: (id) => api.delete(`/models/keys/${id}`),
  redetect:     (id) => api.post(`/models/keys/${id}/detect`),
  availableModels: () => api.get('/models/available'),
  modelCatalog: () => api.get('/models/catalog'),

  // Guardian
  guardianScan: () => api.post('/guardian/scan/full'),
  guardianStatus: () => api.get('/guardian/incidents'),
}
EOF
log "api/client.js"

# ══════════════════════════════════════════════════════════════
head "2/6 · components/ui/Modal.jsx — modal reutilizable"
# ══════════════════════════════════════════════════════════════
mkdir -p components/ui
cat > components/ui/Modal.jsx << 'EOF'
export default function Modal({ title, subtitle, onClose, children, width = 540 }) {
  return (
    <div onClick={e => e.target === e.currentTarget && onClose()}
      style={{ position:'fixed',inset:0,background:'rgba(2,5,8,.88)',backdropFilter:'blur(4px)',
        display:'flex',alignItems:'center',justifyContent:'center',zIndex:1000,padding:20 }}>
      <div style={{ background:'var(--bg-panel)',border:'1px solid var(--border)',borderRadius:6,
        padding:24,width,maxWidth:'95vw',maxHeight:'90vh',overflowY:'auto',
        animation:'fadeIn .2s ease' }}>
        <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:16 }}>
          <div>
            <div style={{ fontFamily:'var(--display)',fontSize:16,color:'var(--text-bright)',letterSpacing:1 }}>{title}</div>
            {subtitle && <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:3 }}>{subtitle}</div>}
          </div>
          <button onClick={onClose} style={{ background:'none',border:'none',color:'var(--text-dim)',cursor:'pointer',fontSize:18,lineHeight:1,padding:'0 4px' }}>✕</button>
        </div>
        {children}
      </div>
    </div>
  )
}
EOF

# ── Form primitives ───────────────────────────────────────────
cat > components/ui/Form.jsx << 'EOF'
export function FormGroup({ label, children, half }) {
  return (
    <div style={{ marginBottom:14,flex:half?'1':'unset' }}>
      <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',
        letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>{label}</label>
      {children}
    </div>
  )
}

export function Input({ value, onChange, placeholder, type='text', style={} }) {
  return (
    <input value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder} type={type}
      style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,
        padding:'8px 12px',color:'var(--text)',fontFamily:type==='password'?'var(--mono)':'var(--ui)',
        fontSize:13,outline:'none',transition:'border-color .2s',...style }}
      onFocus={e=>e.target.style.borderColor='var(--cyan)'}
      onBlur={e=>e.target.style.borderColor='var(--border)'} />
  )
}

export function Select({ value, onChange, options, style={} }) {
  return (
    <select value={value} onChange={e=>onChange(e.target.value)}
      style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,
        padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none',...style }}>
      {options.map(o => typeof o === 'string'
        ? <option key={o} value={o}>{o}</option>
        : <option key={o.value} value={o.value}>{o.label}</option>
      )}
    </select>
  )
}

export function Textarea({ value, onChange, placeholder, rows=3 }) {
  return (
    <textarea value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder} rows={rows}
      style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,
        padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none',
        resize:'vertical' }}
      onFocus={e=>e.target.style.borderColor='var(--cyan)'}
      onBlur={e=>e.target.style.borderColor='var(--border)'} />
  )
}

export function FormRow({ children }) {
  return <div style={{ display:'flex',gap:12 }}>{children}</div>
}

export function ModalFooter({ onClose, onSave, saveLabel='GUARDAR', loading=false }) {
  return (
    <div style={{ display:'flex',gap:10,justifyContent:'flex-end',paddingTop:16,
      borderTop:'1px solid var(--border)',marginTop:16 }}>
      <button onClick={onClose} style={{ padding:'7px 14px',borderRadius:3,border:'1px solid var(--border)',
        background:'transparent',color:'var(--text-dim)',cursor:'pointer',fontFamily:'var(--ui)',fontSize:12,fontWeight:600 }}>
        CANCELAR
      </button>
      <button onClick={onSave} disabled={loading}
        style={{ padding:'7px 14px',borderRadius:3,border:'1px solid var(--green)',
          background:'#00ff9d15',color:'var(--green)',cursor:'pointer',fontFamily:'var(--ui)',fontSize:12,fontWeight:600,
          opacity:loading?.6:1 }}>
        {loading ? '⟳ GUARDANDO...' : saveLabel}
      </button>
    </div>
  )
}
EOF

# ── Update ui/index.jsx to export Modal and Form ─────────────
cat >> components/ui/index.jsx << 'EOF'
export { default as Modal } from './Modal'
export { FormGroup, Input, Select, Textarea, FormRow, ModalFooter } from './Form'
EOF

log "Modal.jsx + Form.jsx"

# ══════════════════════════════════════════════════════════════
head "3/6 · pages/Agents.jsx — CRUD real con selector de modelo"
# ══════════════════════════════════════════════════════════════
cat > pages/Agents.jsx << 'EOF'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, StatusBadge, Btn, Badge, Dot } from '../components/ui'
import Modal from '../components/ui/Modal'
import { FormGroup, Input, Select, Textarea, FormRow, ModalFooter } from '../components/ui/Form'
import { nexusApi } from '../api/client'

const ROLES = ['security','devops','data','cloud','compliance','red_team','general']
const HITL_MODES = [
  { value:'always', label:'Siempre (toda acción)' },
  { value:'destructive', label:'Solo acciones destructivas' },
  { value:'never', label:'Nunca (autónomo)' },
]
const ROLE_ICON = { security:'🛡️', devops:'⚙️', data:'📊', cloud:'☁️', compliance:'📋', red_team:'🔴', general:'🤖' }
const ROLE_COLOR = { security:'var(--red)', devops:'var(--cyan)', data:'var(--purple)', cloud:'var(--blue)', compliance:'var(--yellow)', red_team:'var(--orange)', general:'var(--green)' }

function AgentModal({ agent, onClose, tools, models }) {
  const qc = useQueryClient()
  const isEdit = !!agent
  const [form, setForm] = useState({
    name: agent?.name || '',
    role: agent?.role || 'general',
    description: agent?.description || '',
    model: agent?.model || (models[0]?.model || 'gpt-4o'),
    provider: agent?.provider || (models[0]?.provider || 'openai'),
    temperature: agent?.temperature || 0.7,
    max_tokens: agent?.max_tokens || 4096,
    system_prompt: agent?.system_prompt || '',
    tools: agent?.tools || [],
    hitl_mode: agent?.hitl_mode || 'destructive',
  })
  const [loading, setLoading] = useState(false)
  const set = (k,v) => setForm(f => ({...f,[k]:v}))

  const toggleTool = (t) => set('tools', form.tools.includes(t)
    ? form.tools.filter(x=>x!==t)
    : [...form.tools, t])

  const handleModelChange = (modelStr) => {
    const found = models.find(m => m.model === modelStr)
    set('model', modelStr)
    if (found) set('provider', found.provider)
  }

  const save = async () => {
    if (!form.name.trim()) return alert('El nombre es requerido')
    setLoading(true)
    try {
      if (isEdit) {
        await nexusApi.updateAgent(agent.id, form)
      } else {
        await nexusApi.createAgent(form)
      }
      await qc.invalidateQueries(['agents'])
      onClose()
    } catch(e) {
      alert(`Error: ${e.response?.data?.detail || e.message}`)
    } finally {
      setLoading(false)
    }
  }

  // Agrupar tools por categoría
  const toolsBycat = {}
  tools.forEach(t => {
    toolsBycat[t.category] = toolsBycat[t.category] || []
    toolsBycat[t.category].push(t)
  })

  const modelOptions = models.length > 0
    ? models.map(m => ({ value: m.model, label: `${m.model} (${m.provider})` }))
    : [{ value:'gpt-4o', label:'gpt-4o (openai)' }]

  return (
    <Modal title={isEdit ? `EDITAR — ${agent.name}` : 'NUEVO AGENTE'} subtitle="Configura el agente con modelo y herramientas" onClose={onClose} width={600}>
      <FormRow>
        <FormGroup label="Nombre" half>
          <Input value={form.name} onChange={v=>set('name',v)} placeholder="PentestBot" />
        </FormGroup>
        <FormGroup label="Rol" half>
          <Select value={form.role} onChange={v=>set('role',v)} options={ROLES} />
        </FormGroup>
      </FormRow>

      <FormGroup label="Descripción">
        <Input value={form.description} onChange={v=>set('description',v)} placeholder="Agente especializado en..." />
      </FormGroup>

      <FormRow>
        <FormGroup label="Modelo LLM" half>
          <Select value={form.model} onChange={handleModelChange} options={modelOptions} />
        </FormGroup>
        <FormGroup label="HITL Mode" half>
          <Select value={form.hitl_mode} onChange={v=>set('hitl_mode',v)} options={HITL_MODES} />
        </FormGroup>
      </FormRow>

      <FormRow>
        <FormGroup label="Temperatura" half>
          <Input value={form.temperature} onChange={v=>set('temperature',parseFloat(v)||0.7)} type="number" />
        </FormGroup>
        <FormGroup label="Max Tokens" half>
          <Input value={form.max_tokens} onChange={v=>set('max_tokens',parseInt(v)||4096)} type="number" />
        </FormGroup>
      </FormRow>

      <FormGroup label="System Prompt">
        <Textarea value={form.system_prompt} onChange={v=>set('system_prompt',v)}
          placeholder="Eres un agente especializado en..." rows={3} />
      </FormGroup>

      <FormGroup label={`Herramientas (${form.tools.length} seleccionadas)`}>
        <div style={{ background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:12,maxHeight:200,overflowY:'auto' }}>
          {Object.entries(toolsBycat).map(([cat, catTools]) => (
            <div key={cat} style={{ marginBottom:10 }}>
              <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)',letterSpacing:2,textTransform:'uppercase',marginBottom:6 }}>{cat}</div>
              <div style={{ display:'flex',flexWrap:'wrap',gap:6 }}>
                {catTools.map(t => {
                  const sel = form.tools.includes(t.name)
                  return (
                    <div key={t.name} onClick={()=>toggleTool(t.name)}
                      title={t.description}
                      style={{ padding:'4px 10px',borderRadius:3,cursor:'pointer',
                        border:`1px solid ${sel?'var(--green)':'var(--border)'}`,
                        background:sel?'#00ff9d15':'transparent',
                        color:sel?'var(--green)':'var(--text-dim)',
                        fontFamily:'var(--mono)',fontSize:10,transition:'all .15s',
                        userSelect:'none' }}>
                      {sel ? '✓ ' : ''}{t.name}
                    </div>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </FormGroup>

      <ModalFooter onClose={onClose} onSave={save} saveLabel={isEdit?'ACTUALIZAR':'CREAR AGENTE'} loading={loading} />
    </Modal>
  )
}

export default function Agents() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [editAgent, setEditAgent] = useState(null)
  const [filter, setFilter] = useState('all')

  const { data: agents = [], isLoading } = useQuery({ queryKey:['agents'], queryFn: async()=>{ const {data}=await nexusApi.agents(); return data }, refetchInterval:8000 })
  const { data: toolsData } = useQuery({ queryKey:['tools'], queryFn: async()=>{ const {data}=await nexusApi.tools(); return data?.tools||[] } })
  const { data: modelsData } = useQuery({ queryKey:['models-available'], queryFn: async()=>{ const {data}=await nexusApi.availableModels(); return data?.models||[] } })

  const tools = toolsData || []
  const models = modelsData || []

  const deleteMutation = useMutation({
    mutationFn: (id) => nexusApi.deleteAgent(id),
    onSuccess: () => qc.invalidateQueries(['agents']),
  })

  const filters = ['all', ...new Set(agents.map(a=>a.role))]
  const filtered = filter === 'all' ? agents : agents.filter(a=>a.role===filter)

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      {(showModal || editAgent) && (
        <AgentModal
          agent={editAgent}
          tools={tools}
          models={models}
          onClose={()=>{ setShowModal(false); setEditAgent(null) }}
        />
      )}

      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Agentes IA</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>
            ORQUESTACIÓN · {agents.length} AGENTES · {models.length} MODELOS DISPONIBLES
          </div>
        </div>
        <Btn variant="primary" onClick={()=>setShowModal(true)}>+ NUEVO AGENTE</Btn>
      </div>

      {/* Filtros */}
      <div style={{ display:'flex',gap:8,marginBottom:16,flexWrap:'wrap' }}>
        {filters.map(f=>(
          <span key={f} onClick={()=>setFilter(f)} style={{
            padding:'4px 12px',borderRadius:20,cursor:'pointer',
            fontFamily:'var(--mono)',fontSize:11,
            border:`1px solid ${filter===f?'var(--green)':'var(--border)'}`,
            color:filter===f?'var(--green)':'var(--text-dim)',
            background:filter===f?'#00ff9d08':'transparent',
          }}>{f.toUpperCase()}</span>
        ))}
      </div>

      {isLoading ? (
        <div style={{ textAlign:'center',padding:'60px 0',color:'var(--text-dim)',fontFamily:'var(--mono)' }}>
          ⟳ Cargando agentes...
        </div>
      ) : filtered.length === 0 ? (
        <div style={{ textAlign:'center',padding:'60px 0' }}>
          <div style={{ fontSize:48,marginBottom:12,opacity:.2 }}>⬡</div>
          <div style={{ fontFamily:'var(--display)',fontSize:16,color:'var(--text-dim)' }}>Sin agentes</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)',marginTop:6 }}>Crea tu primer agente con el botón + NUEVO AGENTE</div>
        </div>
      ) : (
        <div style={{ display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(320px,1fr))',gap:12 }}>
          {filtered.map(a => {
            const rc = ROLE_COLOR[a.role] || 'var(--green)'
            const icon = ROLE_ICON[a.role] || '🤖'
            return (
              <Card key={a.id} style={{ border:`1px solid ${a.status==='running'?rc:'var(--border)'}`,cursor:'pointer',transition:'all .2s' }}
                onClick={()=>setEditAgent(a)}>
                <div style={{ display:'flex',alignItems:'center',gap:10,marginBottom:12 }}>
                  <div style={{ width:38,height:38,borderRadius:4,display:'flex',alignItems:'center',justifyContent:'center',
                    fontSize:20,border:`1px solid ${rc}`,background:`${rc}15`,flexShrink:0 }}>{icon}</div>
                  <div style={{ flex:1,minWidth:0 }}>
                    <div style={{ fontSize:14,fontWeight:600,color:'var(--text-bright)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' }}>{a.name}</div>
                    <div style={{ fontFamily:'var(--mono)',fontSize:10,color:rc }}>{a.role}</div>
                  </div>
                  <StatusBadge status={a.status||'idle'} />
                </div>

                {a.description && (
                  <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginBottom:10,
                    overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' }}>{a.description}</div>
                )}

                <div style={{ display:'flex',alignItems:'center',gap:8,marginBottom:10,
                  padding:'6px 8px',background:'var(--bg-base)',borderRadius:3,border:'1px solid var(--border)' }}>
                  <span style={{ fontSize:12 }}>{a.provider==='openai'?'🟡':a.provider==='anthropic'?'🟢':'🔵'}</span>
                  <span style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--cyan)',flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' }}>{a.model}</span>
                  <Badge color="var(--text-dim)">{a.hitl_mode}</Badge>
                </div>

                <div style={{ display:'flex',flexWrap:'wrap',gap:4,marginBottom:10,maxHeight:48,overflow:'hidden' }}>
                  {(a.tools||[]).slice(0,6).map(t=>(
                    <span key={t} style={{ fontFamily:'var(--mono)',fontSize:9,padding:'2px 6px',
                      borderRadius:2,background:'var(--bg-base)',border:'1px solid var(--border)',color:'var(--text-dim)' }}>{t}</span>
                  ))}
                  {(a.tools||[]).length > 6 && (
                    <span style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>+{a.tools.length-6}</span>
                  )}
                </div>

                <div style={{ display:'flex',gap:0,paddingTop:10,borderTop:'1px solid var(--border)' }}>
                  {[['TAREAS',a.tasks_count||0,'var(--cyan)'],['SUCCESS',`${((a.success_rate||0)*100).toFixed(0)}%`,'var(--green)'],['TEMP',a.temperature,'var(--yellow)']].map(([l,v,c])=>(
                    <div key={l} style={{ flex:1,textAlign:'center' }}>
                      <div style={{ fontFamily:'var(--mono)',fontSize:13,color:c }}>{v}</div>
                      <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>{l}</div>
                    </div>
                  ))}
                </div>

                <div style={{ display:'flex',gap:6,marginTop:10 }} onClick={e=>e.stopPropagation()}>
                  <button onClick={()=>setEditAgent(a)}
                    style={{ flex:1,padding:'5px',background:'var(--bg-base)',border:'1px solid var(--border)',
                      borderRadius:3,color:'var(--text-dim)',cursor:'pointer',fontFamily:'var(--mono)',fontSize:10 }}>
                    ✎ EDITAR
                  </button>
                  <button onClick={()=>{ if(confirm(`¿Eliminar ${a.name}?`)) deleteMutation.mutate(a.id) }}
                    style={{ flex:1,padding:'5px',background:'var(--bg-base)',border:'1px solid var(--red)',
                      borderRadius:3,color:'var(--red)',cursor:'pointer',fontFamily:'var(--mono)',fontSize:10 }}>
                    🗑 ELIMINAR
                  </button>
                </div>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
EOF
log "Agents.jsx"

# ══════════════════════════════════════════════════════════════
head "4/6 · pages/Teams.jsx — agentes arrastrables / asignables"
# ══════════════════════════════════════════════════════════════
cat > pages/Teams.jsx << 'EOF'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, Btn, Badge, Dot } from '../components/ui'
import Modal from '../components/ui/Modal'
import { FormGroup, Input, Select, Textarea, FormRow, ModalFooter } from '../components/ui/Form'
import { nexusApi } from '../api/client'

const STRATEGIES = [
  { value:'sequential',   label:'Secuencial — uno a uno en orden' },
  { value:'parallel',     label:'Paralela — todos simultáneo' },
  { value:'hierarchical', label:'Jerárquica — líder + equipo' },
  { value:'consensus',    label:'Consenso — votación entre agentes' },
]
const HITL_OPTS = [
  { value:'enabled',      label:'Habilitado (toda acción)' },
  { value:'critical_only',label:'Solo crítico' },
  { value:'disabled',     label:'Deshabilitado' },
]
const SPECS = ['Ciberseguridad','DevOps','Data Engineering','Cloud Architecture','Compliance','Red Team','General']
const STRAT_COLOR = { sequential:'var(--cyan)', parallel:'var(--green)', hierarchical:'var(--yellow)', consensus:'var(--purple)' }

function TeamModal({ team, agents, onClose }) {
  const qc = useQueryClient()
  const isEdit = !!team
  const [form, setForm] = useState({
    name: team?.name || '',
    description: team?.description || '',
    specialization: team?.specialization || 'General',
    strategy: team?.strategy || 'sequential',
    hitl: team?.hitl || 'enabled',
    agents: team?.agents || [],
  })
  const [loading, setLoading] = useState(false)
  const set = (k,v) => setForm(f=>({...f,[k]:v}))

  const toggleAgent = (id) => set('agents', form.agents.includes(id)
    ? form.agents.filter(x=>x!==id)
    : [...form.agents, id])

  const save = async () => {
    if (!form.name.trim()) return alert('El nombre es requerido')
    setLoading(true)
    try {
      if (isEdit) {
        await nexusApi.updateTeam(team.id, form)
      } else {
        await nexusApi.createTeam(form)
      }
      await qc.invalidateQueries(['teams'])
      onClose()
    } catch(e) {
      alert(`Error: ${e.response?.data?.detail || e.message}`)
    } finally {
      setLoading(false)
    }
  }

  const ROLE_ICON = { security:'🛡️', devops:'⚙️', data:'📊', cloud:'☁️', compliance:'📋', red_team:'🔴', general:'🤖' }

  return (
    <Modal title={isEdit?`EDITAR — ${team.name}`:'NUEVO EQUIPO'} subtitle="Configura el equipo y asigna agentes" onClose={onClose} width={560}>
      <FormRow>
        <FormGroup label="Nombre del equipo" half>
          <Input value={form.name} onChange={v=>set('name',v)} placeholder="Red Team Alpha" />
        </FormGroup>
        <FormGroup label="Especialización" half>
          <Select value={form.specialization} onChange={v=>set('specialization',v)} options={SPECS} />
        </FormGroup>
      </FormRow>

      <FormGroup label="Misión / Descripción">
        <Input value={form.description} onChange={v=>set('description',v)} placeholder="Objetivo del equipo..." />
      </FormGroup>

      <FormRow>
        <FormGroup label="Estrategia de orquestación" half>
          <Select value={form.strategy} onChange={v=>set('strategy',v)} options={STRATEGIES} />
        </FormGroup>
        <FormGroup label="HITL del equipo" half>
          <Select value={form.hitl} onChange={v=>set('hitl',v)} options={HITL_OPTS} />
        </FormGroup>
      </FormRow>

      <FormGroup label={`Agentes miembros (${form.agents.length} seleccionados)`}>
        {agents.length === 0 ? (
          <div style={{ padding:'20px',textAlign:'center',fontFamily:'var(--mono)',fontSize:11,
            color:'var(--text-dim)',border:'1px solid var(--border)',borderRadius:3,background:'var(--bg-base)' }}>
            No hay agentes creados. Crea agentes primero.
          </div>
        ) : (
          <div style={{ background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:10 }}>
            {agents.map(a => {
              const sel = form.agents.includes(a.id)
              return (
                <div key={a.id} onClick={()=>toggleAgent(a.id)}
                  style={{ display:'flex',alignItems:'center',gap:10,padding:'8px 10px',
                    borderRadius:3,cursor:'pointer',marginBottom:4,
                    border:`1px solid ${sel?'var(--green)':'transparent'}`,
                    background:sel?'#00ff9d08':'transparent',transition:'all .15s' }}>
                  <div style={{ width:28,height:28,borderRadius:3,display:'flex',alignItems:'center',
                    justifyContent:'center',fontSize:16,border:`1px solid ${sel?'var(--green)':'var(--border)'}`,
                    background:sel?'#00ff9d15':'var(--bg-card)',flexShrink:0 }}>
                    {ROLE_ICON[a.role]||'🤖'}
                  </div>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:13,fontWeight:600,color:sel?'var(--text-bright)':'var(--text)' }}>{a.name}</div>
                    <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)' }}>
                      {a.role} · {a.model}
                    </div>
                  </div>
                  <div style={{ width:18,height:18,borderRadius:'50%',
                    border:`2px solid ${sel?'var(--green)':'var(--border)'}`,
                    background:sel?'var(--green)':'transparent',
                    display:'flex',alignItems:'center',justifyContent:'center',
                    fontSize:10,color:sel?'var(--bg-base)':'transparent',flexShrink:0 }}>
                    {sel?'✓':''}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </FormGroup>

      <ModalFooter onClose={onClose} onSave={save} saveLabel={isEdit?'ACTUALIZAR':'CREAR EQUIPO'} loading={loading} />
    </Modal>
  )
}

export default function Teams() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [editTeam, setEditTeam] = useState(null)

  const { data: teams=[], isLoading } = useQuery({
    queryKey:['teams'],
    queryFn: async()=>{ const {data}=await nexusApi.teams(); return data },
    refetchInterval:10000,
  })
  const { data: agents=[] } = useQuery({
    queryKey:['agents'],
    queryFn: async()=>{ const {data}=await nexusApi.agents(); return data },
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => nexusApi.deleteTeam(id),
    onSuccess: () => qc.invalidateQueries(['teams']),
  })

  const ROLE_ICON = { security:'🛡️', devops:'⚙️', data:'📊', cloud:'☁️', compliance:'📋', red_team:'🔴', general:'🤖' }

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      {(showModal || editTeam) && (
        <TeamModal
          team={editTeam}
          agents={agents}
          onClose={()=>{ setShowModal(false); setEditTeam(null) }}
        />
      )}

      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Equipos</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>ORQUESTACIÓN COLABORATIVA · {teams.length} EQUIPOS</div>
        </div>
        <Btn variant="primary" onClick={()=>setShowModal(true)}>+ NUEVO EQUIPO</Btn>
      </div>

      {isLoading ? (
        <div style={{ textAlign:'center',padding:'60px 0',color:'var(--text-dim)',fontFamily:'var(--mono)' }}>⟳ Cargando...</div>
      ) : teams.length === 0 ? (
        <div style={{ textAlign:'center',padding:'60px 0' }}>
          <div style={{ fontSize:48,marginBottom:12,opacity:.2 }}>◎</div>
          <div style={{ fontFamily:'var(--display)',fontSize:16,color:'var(--text-dim)' }}>Sin equipos</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)',marginTop:6 }}>Crea tu primer equipo asignando agentes</div>
        </div>
      ) : (
        <div style={{ display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(340px,1fr))',gap:12 }}>
          {teams.map(t => {
            const sc = STRAT_COLOR[t.strategy] || 'var(--green)'
            const memberAgents = agents.filter(a => (t.agents||[]).includes(a.id))
            return (
              <Card key={t.id} style={{ cursor:'pointer',transition:'all .2s' }} onClick={()=>setEditTeam(t)}>
                <div style={{ display:'flex',alignItems:'flex-start',gap:12,marginBottom:12 }}>
                  <div style={{ width:42,height:42,borderRadius:4,display:'flex',alignItems:'center',
                    justifyContent:'center',fontSize:22,border:`1px solid ${sc}`,background:`${sc}15`,flexShrink:0 }}>
                    👥
                  </div>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:15,fontWeight:600,color:'var(--text-bright)' }}>{t.name}</div>
                    <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:2 }}>{t.description}</div>
                  </div>
                </div>

                <div style={{ display:'flex',gap:6,marginBottom:12,flexWrap:'wrap' }}>
                  <Badge color={sc}>{t.strategy}</Badge>
                  <Badge color="var(--text-dim)">{t.specialization}</Badge>
                  <Badge color={t.hitl==='enabled'?'var(--yellow)':t.hitl==='disabled'?'var(--green)':'var(--orange)'}>
                    HITL: {t.hitl}
                  </Badge>
                </div>

                {/* Agentes miembros */}
                <div style={{ marginBottom:12 }}>
                  <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)',letterSpacing:1,marginBottom:6 }}>AGENTES</div>
                  {memberAgents.length === 0 ? (
                    <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)' }}>Sin agentes asignados</div>
                  ) : (
                    <div style={{ display:'flex',flexDirection:'column',gap:4 }}>
                      {memberAgents.map(a => (
                        <div key={a.id} style={{ display:'flex',alignItems:'center',gap:8,
                          padding:'5px 8px',background:'var(--bg-card2)',borderRadius:3,
                          border:'1px solid var(--border)' }}>
                          <span style={{ fontSize:14 }}>{ROLE_ICON[a.role]||'🤖'}</span>
                          <span style={{ fontSize:12,fontWeight:500,flex:1 }}>{a.name}</span>
                          <Badge color="var(--cyan)">{a.model}</Badge>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div style={{ display:'flex',gap:0,paddingTop:10,borderTop:'1px solid var(--border)' }}>
                  {[['AGENTES',(t.agents||[]).length,'var(--green)'],['TAREAS',t.tasks_count||0,'var(--cyan)'],['ESTADO',t.status||'active','var(--yellow)']].map(([l,v,c])=>(
                    <div key={l} style={{ flex:1,textAlign:'center' }}>
                      <div style={{ fontFamily:'var(--mono)',fontSize:13,color:c }}>{v}</div>
                      <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>{l}</div>
                    </div>
                  ))}
                </div>

                <div style={{ display:'flex',gap:6,marginTop:10 }} onClick={e=>e.stopPropagation()}>
                  <button onClick={()=>setEditTeam(t)}
                    style={{ flex:1,padding:'5px',background:'var(--bg-base)',border:'1px solid var(--border)',
                      borderRadius:3,color:'var(--text-dim)',cursor:'pointer',fontFamily:'var(--mono)',fontSize:10 }}>
                    ✎ EDITAR
                  </button>
                  <button onClick={()=>{ if(confirm(`¿Eliminar ${t.name}?`)) deleteMutation.mutate(t.id) }}
                    style={{ flex:1,padding:'5px',background:'var(--bg-base)',border:'1px solid var(--red)',
                      borderRadius:3,color:'var(--red)',cursor:'pointer',fontFamily:'var(--mono)',fontSize:10 }}>
                    🗑 ELIMINAR
                  </button>
                </div>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
EOF
log "Teams.jsx"

# ══════════════════════════════════════════════════════════════
head "5/6 · pages/Tasks.jsx — con selector de agente/equipo real"
# ══════════════════════════════════════════════════════════════
cat > pages/Tasks.jsx << 'EOF'
import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, Btn, Badge, StatusBadge, Dot } from '../components/ui'
import Modal from '../components/ui/Modal'
import { FormGroup, Input, Select, Textarea, FormRow, ModalFooter } from '../components/ui/Form'
import { nexusApi } from '../api/client'

const TYPES = ['unique','monitor','cron','pipeline','event']
const PRIORITIES = ['crítica','alta','media','baja']
const TYPE_COLOR = { monitor:'var(--cyan)', cron:'var(--purple)', pipeline:'var(--yellow)', unique:'var(--text-dim)', event:'var(--orange)' }
const PRIO_COLOR = { 'crítica':'var(--red)', alta:'var(--orange)', media:'var(--yellow)', baja:'var(--green)' }
const TYPE_ICON = { monitor:'👁️', cron:'⏱️', pipeline:'⚡', unique:'▷', event:'🔔' }

function TaskModal({ onClose, agents, teams }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({
    name:'', description:'', task_type:'unique', priority:'media',
    agent_id:'', team_id:'', cron_expr:'', payload:{},
  })
  const [assignTo, setAssignTo] = useState('agent') // 'agent' | 'team'
  const [loading, setLoading] = useState(false)
  const set = (k,v) => setForm(f=>({...f,[k]:v}))

  const agentOpts = [{ value:'', label:'— Seleccionar agente —' }, ...agents.map(a=>({ value:a.id, label:`${a.name} (${a.role})` }))]
  const teamOpts  = [{ value:'', label:'— Seleccionar equipo —' }, ...teams.map(t=>({ value:t.id, label:`${t.name} (${t.strategy})` }))]

  const save = async () => {
    if (!form.name.trim()) return alert('El nombre es requerido')
    if (assignTo==='agent' && !form.agent_id) return alert('Selecciona un agente')
    if (assignTo==='team' && !form.team_id) return alert('Selecciona un equipo')
    setLoading(true)
    try {
      const data = {
        ...form,
        agent_id: assignTo==='agent' ? form.agent_id : null,
        team_id: assignTo==='team' ? form.team_id : null,
      }
      await nexusApi.createTask(data)
      await qc.invalidateQueries(['tasks'])
      onClose()
    } catch(e) {
      alert(`Error: ${e.response?.data?.detail || e.message}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal title="NUEVA TAREA" subtitle="Programa una tarea para agentes o equipos" onClose={onClose} width={540}>
      <FormGroup label="Nombre de la tarea">
        <Input value={form.name} onChange={v=>set('name',v)} placeholder="Scan de vulnerabilidades API" />
      </FormGroup>
      <FormGroup label="Descripción">
        <Input value={form.description} onChange={v=>set('description',v)} placeholder="Descripción detallada..." />
      </FormGroup>

      <FormRow>
        <FormGroup label="Tipo" half>
          <Select value={form.task_type} onChange={v=>set('task_type',v)} options={TYPES} />
        </FormGroup>
        <FormGroup label="Prioridad" half>
          <Select value={form.priority} onChange={v=>set('priority',v)} options={PRIORITIES} />
        </FormGroup>
      </FormRow>

      {form.task_type === 'cron' && (
        <FormGroup label="Expresión Cron">
          <Input value={form.cron_expr} onChange={v=>set('cron_expr',v)} placeholder="0 */6 * * *" />
        </FormGroup>
      )}

      {/* Asignar a agente o equipo */}
      <FormGroup label="Asignar a">
        <div style={{ display:'flex',gap:8,marginBottom:10 }}>
          {['agent','team'].map(opt=>(
            <div key={opt} onClick={()=>setAssignTo(opt)}
              style={{ flex:1,padding:'8px',textAlign:'center',borderRadius:3,cursor:'pointer',
                border:`1px solid ${assignTo===opt?'var(--green)':'var(--border)'}`,
                background:assignTo===opt?'#00ff9d08':'transparent',
                color:assignTo===opt?'var(--green)':'var(--text-dim)',
                fontFamily:'var(--mono)',fontSize:11,transition:'all .15s' }}>
              {opt==='agent' ? '⬡ AGENTE' : '◎ EQUIPO'}
            </div>
          ))}
        </div>
        {assignTo === 'agent' ? (
          <Select value={form.agent_id} onChange={v=>set('agent_id',v)} options={agentOpts} />
        ) : (
          <Select value={form.team_id} onChange={v=>set('team_id',v)} options={teamOpts} />
        )}
      </FormGroup>

      <ModalFooter onClose={onClose} onSave={save} saveLabel="CREAR TAREA" loading={loading} />
    </Modal>
  )
}

export default function Tasks() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)
  const [filter, setFilter] = useState('all')

  const { data: tasks=[], isLoading } = useQuery({
    queryKey:['tasks'],
    queryFn: async()=>{ const {data}=await nexusApi.tasks(); return data },
    refetchInterval:4000,
  })
  const { data: agents=[] } = useQuery({ queryKey:['agents'], queryFn: async()=>{ const {data}=await nexusApi.agents(); return data } })
  const { data: teams=[]  } = useQuery({ queryKey:['teams'],  queryFn: async()=>{ const {data}=await nexusApi.teams(); return data } })

  const runMutation = useMutation({
    mutationFn: (id) => nexusApi.runTask(id),
    onSuccess: () => qc.invalidateQueries(['tasks']),
  })
  const cancelMutation = useMutation({
    mutationFn: (id) => nexusApi.cancelTask(id),
    onSuccess: () => qc.invalidateQueries(['tasks']),
  })

  const agentName = (id) => agents.find(a=>a.id===id)?.name || id
  const teamName  = (id) => teams.find(t=>t.id===id)?.name || id

  const filters = ['all','running','completed','failed','queue']
  const filtered = filter==='all' ? tasks : tasks.filter(t=>t.status===filter)

  const running = tasks.filter(t=>t.status==='running').length
  const completed = tasks.filter(t=>t.status==='completed').length
  const failed = tasks.filter(t=>t.status==='failed').length

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      {showModal && <TaskModal onClose={()=>setShowModal(false)} agents={agents} teams={teams} />}

      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:16 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Tareas</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>
            PIPELINE · {running} RUNNING · {completed} DONE · {failed} FAILED
          </div>
        </div>
        <Btn variant="primary" onClick={()=>setShowModal(true)}>+ NUEVA TAREA</Btn>
      </div>

      {/* Stats rápidas */}
      <div style={{ display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:8,marginBottom:16 }}>
        {[['Total',tasks.length,'var(--text-dim)'],['Running',running,'var(--green)'],['Done',completed,'var(--cyan)'],['Failed',failed,'var(--red)']].map(([l,v,c])=>(
          <div key={l} style={{ background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:3,padding:'10px 14px',display:'flex',alignItems:'center',gap:10 }}>
            <Dot color={c} size={6} />
            <div>
              <div style={{ fontFamily:'var(--display)',fontSize:20,color:c }}>{v}</div>
              <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>{l}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Filtros */}
      <div style={{ display:'flex',gap:8,marginBottom:14,flexWrap:'wrap' }}>
        {filters.map(f=>(
          <span key={f} onClick={()=>setFilter(f)} style={{
            padding:'4px 12px',borderRadius:20,cursor:'pointer',
            fontFamily:'var(--mono)',fontSize:11,
            border:`1px solid ${filter===f?'var(--green)':'var(--border)'}`,
            color:filter===f?'var(--green)':'var(--text-dim)',
            background:filter===f?'#00ff9d08':'transparent',
          }}>{f.toUpperCase()}</span>
        ))}
      </div>

      {isLoading ? (
        <div style={{ textAlign:'center',padding:'40px',fontFamily:'var(--mono)',color:'var(--text-dim)' }}>⟳ Cargando...</div>
      ) : filtered.length === 0 ? (
        <div style={{ textAlign:'center',padding:'60px 0' }}>
          <div style={{ fontSize:48,marginBottom:12,opacity:.2 }}>▷</div>
          <div style={{ fontFamily:'var(--display)',fontSize:16,color:'var(--text-dim)' }}>Sin tareas</div>
        </div>
      ) : (
        <div style={{ display:'flex',flexDirection:'column',gap:8 }}>
          {filtered.map(t => {
            const sc = t.status==='running'?'var(--green)':t.status==='failed'?'var(--red)':t.status==='completed'?'var(--cyan)':t.status==='queue'?'var(--yellow)':'var(--text-dim)'
            const tc = TYPE_COLOR[t.task_type] || 'var(--text-dim)'
            const pc = PRIO_COLOR[t.priority] || 'var(--text-dim)'
            const executor = t.agent_id ? `⬡ ${agentName(t.agent_id)}` : t.team_id ? `◎ ${teamName(t.team_id)}` : '—'
            return (
              <div key={t.id} style={{ background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:4,padding:'14px 16px',
                display:'flex',alignItems:'center',gap:14,transition:'all .2s' }}>
                <div style={{ fontSize:20,width:36,height:36,display:'flex',alignItems:'center',justifyContent:'center',
                  background:'var(--bg-base)',borderRadius:4,border:'1px solid var(--border)',flexShrink:0 }}>
                  {TYPE_ICON[t.task_type]||'▷'}
                </div>
                <div style={{ flex:1,minWidth:0 }}>
                  <div style={{ fontSize:14,fontWeight:600,color:'var(--text-bright)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' }}>{t.name}</div>
                  <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:2 }}>
                    {t.description} · {executor}
                  </div>
                  <div style={{ display:'flex',gap:6,marginTop:6,alignItems:'center',flexWrap:'wrap' }}>
                    <StatusBadge status={t.status} />
                    <Badge color={tc}>{t.task_type}</Badge>
                    <Badge color={pc}>{t.priority}</Badge>
                    {t.cron_expr && <Badge color="var(--purple)">{t.cron_expr}</Badge>}
                    <span style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>{t.id}</span>
                  </div>
                </div>
                <div style={{ width:120,flexShrink:0 }}>
                  <div style={{ fontFamily:'var(--mono)',fontSize:10,color:sc,textAlign:'right',marginBottom:4 }}>{t.progress}%</div>
                  <div style={{ height:3,background:'var(--border)',borderRadius:2,overflow:'hidden' }}>
                    <div style={{ height:'100%',width:`${t.progress}%`,background:sc,transition:'width .5s ease' }}/>
                  </div>
                  <div style={{ display:'flex',gap:4,marginTop:8,justifyContent:'flex-end' }}>
                    {t.status === 'queue' && (
                      <button onClick={()=>runMutation.mutate(t.id)}
                        style={{ padding:'3px 8px',background:'#00ff9d15',border:'1px solid var(--green)',borderRadius:2,
                          color:'var(--green)',cursor:'pointer',fontFamily:'var(--mono)',fontSize:9 }}>▶ RUN</button>
                    )}
                    {t.status === 'running' && (
                      <button onClick={()=>cancelMutation.mutate(t.id)}
                        style={{ padding:'3px 8px',background:'#ff386015',border:'1px solid var(--red)',borderRadius:2,
                          color:'var(--red)',cursor:'pointer',fontFamily:'var(--mono)',fontSize:9 }}>■ STOP</button>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
EOF
log "Tasks.jsx"

# ══════════════════════════════════════════════════════════════
head "6/6 · pages/Models.jsx — API Keys reales + detección"
# ══════════════════════════════════════════════════════════════
cat > pages/Models.jsx << 'EOF'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, Btn, Badge } from '../components/ui'
import Modal from '../components/ui/Modal'
import { FormGroup, Input, Select, ModalFooter } from '../components/ui/Form'
import { nexusApi } from '../api/client'

const PROVIDERS = ['openai','anthropic','google','groq','together','ollama']
const PROVIDER_ICON = { openai:'🟡', anthropic:'🟢', google:'🔵', groq:'🟠', together:'🟣', ollama:'⚪' }
const PROVIDER_COLOR = { openai:'var(--yellow)', anthropic:'var(--green)', google:'var(--blue)', groq:'var(--orange)', together:'var(--purple)', ollama:'var(--text-dim)' }

function AddKeyModal({ onClose }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ alias:'', provider:'openai', api_key:'' })
  const [loading, setLoading] = useState(false)
  const set = (k,v) => setForm(f=>({...f,[k]:v}))

  const save = async () => {
    if (!form.alias.trim()) return alert('El alias es requerido')
    if (!form.api_key.trim()) return alert('La API key es requerida')
    setLoading(true)
    try {
      await nexusApi.addApiKey(form)
      await qc.invalidateQueries(['api-keys'])
      await qc.invalidateQueries(['models-available'])
      onClose()
    } catch(e) {
      alert(`Error: ${e.response?.data?.detail || e.message}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal title="AGREGAR API KEY" subtitle="Detecta modelos disponibles automáticamente" onClose={onClose} width={460}>
      <FormGroup label="Provider">
        <Select value={form.provider} onChange={v=>set('provider',v)} options={PROVIDERS} />
      </FormGroup>
      <FormGroup label="Alias">
        <Input value={form.alias} onChange={v=>set('alias',v)} placeholder="OpenAI Principal" />
      </FormGroup>
      <FormGroup label="API Key">
        <Input value={form.api_key} onChange={v=>set('api_key',v)} type="password"
          placeholder={form.provider==='openai'?'sk-...':form.provider==='anthropic'?'sk-ant-...':form.provider==='ollama'?'http://localhost:11434':'...'} />
      </FormGroup>
      <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',padding:'8px 10px',
        background:'var(--bg-base)',borderRadius:3,border:'1px solid var(--border)',marginBottom:4 }}>
        ⚡ Al guardar, NEXUS detectará automáticamente los modelos disponibles llamando a la API del provider
      </div>
      <ModalFooter onClose={onClose} onSave={save} saveLabel="DETECTAR MODELOS" loading={loading} />
    </Modal>
  )
}

export default function Models() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)

  const { data: keys=[], isLoading: keysLoading } = useQuery({
    queryKey:['api-keys'],
    queryFn: async()=>{ const {data}=await nexusApi.apiKeys(); return data },
    refetchInterval:5000,
  })
  const { data: availData } = useQuery({
    queryKey:['models-available'],
    queryFn: async()=>{ const {data}=await nexusApi.availableModels(); return data },
    refetchInterval:10000,
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => nexusApi.deleteApiKey(id),
    onSuccess: () => { qc.invalidateQueries(['api-keys']); qc.invalidateQueries(['models-available']) },
  })
  const redetectMutation = useMutation({
    mutationFn: (id) => nexusApi.redetect(id),
    onSuccess: () => qc.invalidateQueries(['api-keys']),
  })

  const availableModels = availData?.models || []
  const totalModels = availData?.total || 0

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      {showModal && <AddKeyModal onClose={()=>setShowModal(false)} />}

      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Modelos & APIs</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>
            {keys.length} PROVIDERS · {totalModels} MODELOS DISPONIBLES
          </div>
        </div>
        <Btn variant="cyan" onClick={()=>setShowModal(true)}>+ API KEY</Btn>
      </div>

      {/* API Keys */}
      <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--cyan)',letterSpacing:2,
        textTransform:'uppercase',marginBottom:12 }}>API Keys Configuradas</div>

      {keysLoading ? (
        <div style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)',padding:20 }}>⟳ Cargando...</div>
      ) : keys.length === 0 ? (
        <Card style={{ textAlign:'center',padding:'40px 0',marginBottom:20 }}>
          <div style={{ fontSize:40,marginBottom:10,opacity:.2 }}>🔑</div>
          <div style={{ fontFamily:'var(--display)',fontSize:14,color:'var(--text-dim)' }}>Sin API keys</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:6,marginBottom:16 }}>
            Agrega tu primera API key para activar los modelos
          </div>
          <Btn variant="primary" onClick={()=>setShowModal(true)}>+ AGREGAR API KEY</Btn>
        </Card>
      ) : (
        <div style={{ marginBottom:24 }}>
          {keys.map(k => {
            const pc = PROVIDER_COLOR[k.provider] || 'var(--text-dim)'
            const isOk = k.status === 'ok'
            return (
              <div key={k.id} style={{ background:'var(--bg-card)',border:`1px solid ${isOk?pc+'44':'var(--border)'}`,
                borderRadius:4,padding:'14px 16px',marginBottom:8,display:'flex',alignItems:'flex-start',gap:12 }}>
                <div style={{ width:40,height:40,borderRadius:4,display:'flex',alignItems:'center',justifyContent:'center',
                  fontSize:22,background:'var(--bg-base)',border:`1px solid ${isOk?pc:'var(--border)'}`,flexShrink:0 }}>
                  {PROVIDER_ICON[k.provider]||'🔑'}
                </div>
                <div style={{ flex:1,minWidth:0 }}>
                  <div style={{ display:'flex',alignItems:'center',gap:8,marginBottom:4 }}>
                    <div style={{ fontSize:14,fontWeight:600,color:'var(--text-bright)' }}>{k.alias}</div>
                    <Badge color={pc}>{k.provider.toUpperCase()}</Badge>
                    <Badge color={isOk?'var(--green)':'var(--yellow)'}>
                      {isOk ? '✓ ACTIVA' : k.status === 'detecting' ? '⟳ DETECTANDO' : '⚠ '+k.status}
                    </Badge>
                  </div>
                  <div style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)',marginBottom:6 }}>{k.key_masked}</div>
                  {(k.models||[]).length > 0 && (
                    <div style={{ display:'flex',flexWrap:'wrap',gap:4 }}>
                      {k.models.slice(0,8).map(m=>(
                        <span key={m} style={{ fontFamily:'var(--mono)',fontSize:9,padding:'2px 7px',
                          borderRadius:2,background:'var(--bg-base)',border:`1px solid ${pc}44`,color:pc }}>
                          {m}
                        </span>
                      ))}
                      {k.models.length > 8 && (
                        <span style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>
                          +{k.models.length-8} más
                        </span>
                      )}
                    </div>
                  )}
                </div>
                <div style={{ display:'flex',flexDirection:'column',gap:6,flexShrink:0 }}>
                  <button onClick={()=>redetectMutation.mutate(k.id)}
                    style={{ padding:'4px 10px',background:'var(--bg-base)',border:'1px solid var(--cyan)',
                      borderRadius:3,color:'var(--cyan)',cursor:'pointer',fontFamily:'var(--mono)',fontSize:10 }}>
                    ⟳ RE-DETECTAR
                  </button>
                  <button onClick={()=>{ if(confirm(`¿Eliminar ${k.alias}?`)) deleteMutation.mutate(k.id) }}
                    style={{ padding:'4px 10px',background:'var(--bg-base)',border:'1px solid var(--red)',
                      borderRadius:3,color:'var(--red)',cursor:'pointer',fontFamily:'var(--mono)',fontSize:10 }}>
                    🗑 ELIMINAR
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Modelos disponibles agrupados por provider */}
      {availableModels.length > 0 && (
        <>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--cyan)',letterSpacing:2,
            textTransform:'uppercase',marginBottom:12 }}>
            Modelos Disponibles para Agentes — {totalModels} total
          </div>
          {Object.entries(
            availableModels.reduce((acc, m) => {
              acc[m.provider] = acc[m.provider] || []
              acc[m.provider].push(m)
              return acc
            }, {})
          ).map(([provider, pModels]) => (
            <Card key={provider} style={{ marginBottom:12 }}>
              <div style={{ display:'flex',alignItems:'center',gap:8,marginBottom:12 }}>
                <span style={{ fontSize:18 }}>{PROVIDER_ICON[provider]||'🔵'}</span>
                <span style={{ fontFamily:'var(--display)',fontSize:14,color:PROVIDER_COLOR[provider]||'var(--text-bright)' }}>
                  {provider.toUpperCase()}
                </span>
                <Badge color={PROVIDER_COLOR[provider]||'var(--text-dim)'}>{pModels.length} modelos</Badge>
              </div>
              <div style={{ display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))',gap:6 }}>
                {pModels.map(m=>(
                  <div key={m.model} style={{ padding:'8px 10px',background:'var(--bg-card2)',
                    border:'1px solid var(--border)',borderRadius:3,
                    fontFamily:'var(--mono)',fontSize:11,color:'var(--text)',
                    overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' }}
                    title={`${m.model} — ${m.key_alias}`}>
                    {m.model}
                  </div>
                ))}
              </div>
            </Card>
          ))}
        </>
      )}
    </div>
  )
}
EOF
log "Models.jsx"

# ── Rebuild ───────────────────────────────────────────────────
head "Build final"
cd /home/operator/NEXUS-PRO/nexus_frontend
npm run build --silent 2>&1 | tail -3

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO Frontend Real v2.0 ✓                    ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Páginas conectadas a API real:"
echo -e "  ${CYAN}Agents${NC}  → crear/editar/eliminar + selector modelo real + checkboxes tools"
echo -e "  ${CYAN}Teams${NC}   → crear/editar/eliminar + asignar agentes con checkboxes"
echo -e "  ${CYAN}Tasks${NC}   → crear/ejecutar/cancelar + asignar a agente o equipo real"
echo -e "  ${CYAN}Models${NC}  → agregar API keys + detección automática de modelos"
echo ""
echo -e "  ${CYAN}cd ~/NEXUS-PRO/nexus_frontend && npm run dev${NC}"
echo ""
