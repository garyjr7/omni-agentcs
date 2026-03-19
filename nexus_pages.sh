#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Páginas Completas v2.0                         ║
# ║  Tasks · Teams · Models · HITL · Vault · Guardian           ║
# ║  RBAC · Audit · Terminal · Settings                         ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

FRONT="/home/operator/NEXUS-PRO/nexus_frontend/src"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

cd "$FRONT/pages"

# ══════════════════════════════════════════════════════════════
head "1/10 · Tasks.jsx"
# ══════════════════════════════════════════════════════════════
cat > Tasks.jsx << 'EOF'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, Btn, Badge, StatusBadge, SectionTitle } from '../components/ui'
import { nexusApi } from '../api/client'

const TYPE_COLOR = { monitor:'var(--cyan)', cron:'var(--purple)', pipeline:'var(--yellow)', unique:'var(--text-dim)', event:'var(--orange)' }

const MOCK = [
  { id:'t1', name:'Scan vuln API Gateway', description:'OWASP Top 10', type:'unique',   status:'running',   progress:67, priority:'alta',    agent:'BashAgent'  },
  { id:'t2', name:'Monitor uptime API',    description:'Healthcheck 60s', type:'monitor', status:'running', progress:100, priority:'crítica', agent:'BashAgent'  },
  { id:'t3', name:'Threat Model STRIDE',   description:'MITRE ATT&CK',  type:'unique',   status:'running',   progress:34, priority:'alta',    agent:'CodeAgent'  },
  { id:'t4', name:'Backup ChromaDB',       description:'Snapshot 6h',   type:'cron',     status:'completed', progress:100,priority:'media',   agent:'FileAgent', cron:'0 */6 * * *' },
  { id:'t5', name:'SAST scan nexus_core',  description:'Análisis estático', type:'cron', status:'failed',    progress:45, priority:'alta',    agent:'BashAgent', cron:'0 */12 * * *' },
  { id:'t6', name:'Pipeline IaC Zero Trust',description:'Terraform deploy',type:'pipeline',status:'queue',   progress:0,  priority:'alta',    agent:'CodeAgent'  },
]

function NewTaskModal({ onClose, onSave }) {
  const [form, setForm] = useState({ name:'', description:'', type:'unique', agent:'BashAgent', priority:'media', cron:'' })
  const set = (k,v) => setForm(f=>({...f,[k]:v}))
  return (
    <div style={{ position:'fixed',inset:0,background:'rgba(2,5,8,.85)',backdropFilter:'blur(4px)',display:'flex',alignItems:'center',justifyContent:'center',zIndex:1000 }}>
      <div style={{ background:'var(--bg-panel)',border:'1px solid var(--border)',borderRadius:6,padding:24,width:500,maxHeight:'85vh',overflowY:'auto' }}>
        <div style={{ fontFamily:'var(--display)',fontSize:16,color:'var(--text-bright)',marginBottom:4,letterSpacing:1 }}>NUEVA TAREA</div>
        <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginBottom:20 }}>Programa una tarea para los agentes</div>
        {[['Nombre','name','text'],['Descripción','description','text']].map(([label,key,type])=>(
          <div key={key} style={{ marginBottom:14 }}>
            <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>{label}</label>
            <input value={form[key]} onChange={e=>set(key,e.target.value)} type={type}
              style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none' }} />
          </div>
        ))}
        <div style={{ display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:14 }}>
          {[['Tipo','type',['unique','monitor','cron','pipeline','event']],['Agente','agent',['BashAgent','CodeAgent','FileAgent']],['Prioridad','priority',['crítica','alta','media','baja']]].map(([label,key,opts])=>(
            <div key={key}>
              <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>{label}</label>
              <select value={form[key]} onChange={e=>set(key,e.target.value)}
                style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none' }}>
                {opts.map(o=><option key={o}>{o}</option>)}
              </select>
            </div>
          ))}
        </div>
        {form.type==='cron' && (
          <div style={{ marginBottom:14 }}>
            <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>Expresión Cron</label>
            <input value={form.cron} onChange={e=>set('cron',e.target.value)} placeholder="0 */6 * * *"
              style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--mono)',fontSize:13,outline:'none' }} />
          </div>
        )}
        <div style={{ display:'flex',gap:10,justifyContent:'flex-end',paddingTop:16,borderTop:'1px solid var(--border)',marginTop:16 }}>
          <Btn variant="ghost" onClick={onClose}>CANCELAR</Btn>
          <Btn variant="primary" onClick={()=>{ onSave(form); onClose() }}>CREAR TAREA</Btn>
        </div>
      </div>
    </div>
  )
}

export default function Tasks() {
  const [showModal, setShowModal] = useState(false)
  const [filter, setFilter] = useState('todas')
  const [localTasks, setLocalTasks] = useState(MOCK)

  const { data: apiTasks } = useQuery({ queryKey:['tasks'], queryFn: async()=>{ try{ const {data}=await nexusApi.tasks(); return Array.isArray(data)?data:[] }catch{ return [] } }, refetchInterval:6000 })
  const tasks = (apiTasks && apiTasks.length > 0) ? apiTasks : localTasks

  const filters = ['todas','running','completed','failed','queue','monitor','cron']
  const filtered = filter==='todas' ? tasks : tasks.filter(t=>t.status===filter||t.type===filter)

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      {showModal && <NewTaskModal onClose={()=>setShowModal(false)} onSave={t=>setLocalTasks(tt=>[{...t,id:`t${Date.now()}`,progress:0,status:'queue'},...tt])} />}
      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Tareas</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>PIPELINE · {tasks.length} TAREAS</div>
        </div>
        <Btn variant="primary" onClick={()=>setShowModal(true)}>+ NUEVA TAREA</Btn>
      </div>
      <div style={{ display:'flex',gap:8,marginBottom:14,flexWrap:'wrap' }}>
        {filters.map(f=>(
          <span key={f} onClick={()=>setFilter(f)} style={{ padding:'5px 12px',borderRadius:20,border:`1px solid ${filter===f?'var(--green)':'var(--border)'}`,fontFamily:'var(--mono)',fontSize:11,color:filter===f?'var(--green)':'var(--text-dim)',cursor:'pointer',background:filter===f?'#00ff9d08':'transparent' }}>{f.toUpperCase()}</span>
        ))}
      </div>
      <div style={{ display:'flex',flexDirection:'column',gap:8 }}>
        {filtered.map(t=>{
          const sc = t.status==='running'?'var(--green)':t.status==='failed'?'var(--red)':t.status==='completed'?'var(--cyan)':'var(--text-dim)'
          return (
            <div key={t.id} style={{ background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:4,padding:'14px 16px',display:'flex',alignItems:'center',gap:14,cursor:'pointer',transition:'all .2s' }}>
              <div style={{ fontSize:20,width:36,height:36,display:'flex',alignItems:'center',justifyContent:'center',background:'var(--bg-base)',borderRadius:4,border:'1px solid var(--border)',flexShrink:0 }}>
                {t.type==='monitor'?'👁️':t.type==='cron'?'⏱️':t.type==='pipeline'?'⚡':'▷'}
              </div>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:14,fontWeight:600,color:'var(--text-bright)' }}>{t.name}</div>
                <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:2 }}>{t.description} · {t.agent}</div>
                <div style={{ display:'flex',gap:8,marginTop:6,alignItems:'center' }}>
                  <StatusBadge status={t.status} />
                  <Badge color={TYPE_COLOR[t.type]||'var(--text-dim)'}>{t.type?.toUpperCase()}</Badge>
                  {t.cron && <span style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)' }}>{t.cron}</span>}
                </div>
              </div>
              <div style={{ width:100 }}>
                <div style={{ fontFamily:'var(--mono)',fontSize:10,color:sc,textAlign:'right',marginBottom:4 }}>{t.progress}%</div>
                <div style={{ height:3,background:'var(--border)',borderRadius:2,overflow:'hidden' }}>
                  <div style={{ height:'100%',width:`${t.progress}%`,background:sc,borderRadius:2,transition:'width .5s ease' }} />
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
EOF
log "Tasks.jsx"

# ══════════════════════════════════════════════════════════════
head "2/10 · Teams.jsx"
# ══════════════════════════════════════════════════════════════
cat > Teams.jsx << 'EOF'
import { useState } from 'react'
import { Card, Btn, Badge } from '../components/ui'

const MOCK_TEAMS = [
  { id:'t1', name:'Red Team Alpha',   emoji:'🔴', color:'var(--red)',    desc:'Pentest & threat modeling ofensivo',  specialization:'Ciberseguridad', members:['BashAgent','CodeAgent'], tasks:18, score:'94/100', strategy:'Paralela' },
  { id:'t2', name:'DevSecOps Squad',  emoji:'⚙️', color:'var(--cyan)',   desc:'Pipeline seguro CI/CD + compliance',  specialization:'DevOps + Seguridad', members:['CodeAgent','FileAgent'], tasks:12, score:'88/100', strategy:'Secuencial' },
  { id:'t3', name:'Data Ops',         emoji:'📊', color:'var(--purple)', desc:'Ingeniería de datos y memoria vectorial', specialization:'Data Engineering', members:['FileAgent'], tasks:6, score:'91/100', strategy:'Jerárquica' },
]

function TeamModal({ onClose, onSave }) {
  const [form, setForm] = useState({ name:'', desc:'', spec:'Ciberseguridad', strategy:'Secuencial' })
  const set = (k,v) => setForm(f=>({...f,[k]:v}))
  return (
    <div style={{ position:'fixed',inset:0,background:'rgba(2,5,8,.85)',backdropFilter:'blur(4px)',display:'flex',alignItems:'center',justifyContent:'center',zIndex:1000 }}>
      <div style={{ background:'var(--bg-panel)',border:'1px solid var(--border)',borderRadius:6,padding:24,width:480 }}>
        <div style={{ fontFamily:'var(--display)',fontSize:16,color:'var(--text-bright)',marginBottom:4 }}>NUEVO EQUIPO</div>
        <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginBottom:20 }}>Crea un equipo de agentes colaborativos</div>
        {[['Nombre','name'],['Misión','desc']].map(([label,key])=>(
          <div key={key} style={{ marginBottom:14 }}>
            <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>{label}</label>
            <input value={form[key]} onChange={e=>set(key,e.target.value)}
              style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none' }} />
          </div>
        ))}
        <div style={{ display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:14 }}>
          {[['Especialización','spec',['Ciberseguridad','DevOps','Data Engineering','Cloud']],['Estrategia','strategy',['Secuencial','Paralela','Jerárquica','Consenso']]].map(([label,key,opts])=>(
            <div key={key}>
              <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>{label}</label>
              <select value={form[key]} onChange={e=>set(key,e.target.value)}
                style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none' }}>
                {opts.map(o=><option key={o}>{o}</option>)}
              </select>
            </div>
          ))}
        </div>
        <div style={{ display:'flex',gap:10,justifyContent:'flex-end',paddingTop:16,borderTop:'1px solid var(--border)',marginTop:16 }}>
          <Btn variant="ghost" onClick={onClose}>CANCELAR</Btn>
          <Btn variant="primary" onClick={()=>{ onSave({...form,id:`team_${Date.now()}`,emoji:'👥',color:'var(--green)',members:[],tasks:0,score:'—'}); onClose() }}>CREAR EQUIPO</Btn>
        </div>
      </div>
    </div>
  )
}

export default function Teams() {
  const [teams, setTeams] = useState(MOCK_TEAMS)
  const [showModal, setShowModal] = useState(false)
  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      {showModal && <TeamModal onClose={()=>setShowModal(false)} onSave={t=>setTeams(tt=>[...tt,t])} />}
      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Equipos</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>ORQUESTACIÓN COLABORATIVA · {teams.length} EQUIPOS</div>
        </div>
        <Btn variant="primary" onClick={()=>setShowModal(true)}>+ NUEVO EQUIPO</Btn>
      </div>
      <div style={{ display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12 }}>
        {teams.map(t=>(
          <div key={t.id} style={{ background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:4,padding:16,cursor:'pointer',transition:'all .2s' }}>
            <div style={{ display:'flex',alignItems:'center',gap:12,marginBottom:12 }}>
              <div style={{ width:40,height:40,borderRadius:4,display:'flex',alignItems:'center',justifyContent:'center',fontSize:20,border:`1px solid ${t.color}`,background:`${t.color}15`,flexShrink:0 }}>{t.emoji}</div>
              <div>
                <div style={{ fontSize:15,fontWeight:600,color:'var(--text-bright)' }}>{t.name}</div>
                <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:2 }}>{t.desc}</div>
              </div>
            </div>
            <div style={{ fontFamily:'var(--mono)',fontSize:10,color:t.color,marginBottom:10 }}>{t.specialization}</div>
            <div style={{ display:'flex',flexWrap:'wrap',gap:4,marginBottom:12 }}>
              {t.members.map(m=><Badge key={m} color="var(--cyan)">{m}</Badge>)}
            </div>
            <div style={{ display:'flex',gap:8,marginBottom:10 }}>
              <Badge color="var(--text-dim)">{t.strategy}</Badge>
            </div>
            <div style={{ display:'flex',gap:0,paddingTop:10,borderTop:'1px solid var(--border)' }}>
              {[['TAREAS',t.tasks,'var(--cyan)'],['SCORE',t.score,'var(--green)'],['AGENTES',t.members.length,'var(--purple)']].map(([l,v,c])=>(
                <div key={l} style={{ flex:1,textAlign:'center' }}>
                  <div style={{ fontFamily:'var(--mono)',fontSize:14,fontWeight:'bold',color:c }}>{v}</div>
                  <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>{l}</div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
EOF
log "Teams.jsx"

# ══════════════════════════════════════════════════════════════
head "3/10 · Models.jsx"
# ══════════════════════════════════════════════════════════════
cat > Models.jsx << 'EOF'
import { useState } from 'react'
import { Card, Btn, Badge } from '../components/ui'

const PROVIDERS_MOCK = [
  { name:'Anthropic', icon:'🟢', status:'ok',       key:'sk-ant-••••••XTR3', models:['claude-3-5-sonnet','claude-3-opus','claude-3-haiku'] },
  { name:'OpenAI',    icon:'🟡', status:'ok',       key:'sk-••••••NEXUS1',   models:['gpt-4o','gpt-4-turbo','gpt-3.5-turbo'] },
  { name:'Google',    icon:'🔵', status:'detecting',key:'AIza••••••••',       models:[] },
]

const MODELS_MOCK = [
  { name:'claude-3-5-sonnet', provider:'Anthropic', context:'200k', speed:'fast',  cost:'$$',   active:true  },
  { name:'claude-3-opus',     provider:'Anthropic', context:'200k', speed:'slow',  cost:'$$$$', active:true  },
  { name:'claude-3-haiku',    provider:'Anthropic', context:'200k', speed:'ultra', cost:'$',    active:true  },
  { name:'gpt-4o',            provider:'OpenAI',    context:'128k', speed:'fast',  cost:'$$$',  active:true  },
  { name:'gpt-4-turbo',       provider:'OpenAI',    context:'128k', speed:'medium',cost:'$$$',  active:true  },
  { name:'gemini-pro',        provider:'Google',    context:'1M',   speed:'fast',  cost:'$$',   active:false },
]

function AddKeyModal({ onClose }) {
  const [form, setForm] = useState({ provider:'Anthropic', key:'', alias:'' })
  const set=(k,v)=>setForm(f=>({...f,[k]:v}))
  return (
    <div style={{ position:'fixed',inset:0,background:'rgba(2,5,8,.85)',backdropFilter:'blur(4px)',display:'flex',alignItems:'center',justifyContent:'center',zIndex:1000 }}>
      <div style={{ background:'var(--bg-panel)',border:'1px solid var(--border)',borderRadius:6,padding:24,width:440 }}>
        <div style={{ fontFamily:'var(--display)',fontSize:16,color:'var(--text-bright)',marginBottom:4 }}>AGREGAR API KEY</div>
        <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginBottom:20 }}>Detecta y activa un nuevo proveedor</div>
        <div style={{ marginBottom:14 }}>
          <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>Provider</label>
          <select value={form.provider} onChange={e=>set('provider',e.target.value)}
            style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none' }}>
            {['Anthropic','OpenAI','Google (Gemini)','Groq','Together AI','Ollama (local)'].map(o=><option key={o}>{o}</option>)}
          </select>
        </div>
        <div style={{ marginBottom:14 }}>
          <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>API Key</label>
          <input type="password" value={form.key} onChange={e=>set('key',e.target.value)} placeholder="sk-ant-..."
            style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--mono)',fontSize:13,outline:'none' }} />
        </div>
        <div style={{ marginBottom:14 }}>
          <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>Alias</label>
          <input value={form.alias} onChange={e=>set('alias',e.target.value)} placeholder="Anthropic Principal"
            style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none' }} />
        </div>
        <div style={{ display:'flex',gap:10,justifyContent:'flex-end',paddingTop:16,borderTop:'1px solid var(--border)',marginTop:16 }}>
          <Btn variant="ghost" onClick={onClose}>CANCELAR</Btn>
          <Btn variant="primary" onClick={onClose}>DETECTAR MODELOS</Btn>
        </div>
      </div>
    </div>
  )
}

export default function Models() {
  const [showModal, setShowModal] = useState(false)
  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      {showModal && <AddKeyModal onClose={()=>setShowModal(false)} />}
      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Modelos & APIs</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>PROVIDERS · KEYS DETECTADAS AUTOMÁTICAMENTE</div>
        </div>
        <Btn variant="cyan" onClick={()=>setShowModal(true)}>+ API KEY</Btn>
      </div>
      <Card style={{ marginBottom:16 }}>
        <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--cyan)',letterSpacing:2,textTransform:'uppercase',marginBottom:14,paddingBottom:8,borderBottom:'1px solid var(--border)' }}>API KEYS DETECTADAS</div>
        {PROVIDERS_MOCK.map(p=>(
          <div key={p.name} style={{ display:'flex',alignItems:'center',gap:12,padding:'12px 0',borderBottom:'1px solid var(--border)' }}>
            <div style={{ width:36,height:36,borderRadius:4,display:'flex',alignItems:'center',justifyContent:'center',fontSize:20,background:'var(--bg-base)',border:`1px solid ${p.status==='ok'?'var(--green)':'var(--yellow)'}`,flexShrink:0 }}>{p.icon}</div>
            <div style={{ flex:1 }}>
              <div style={{ fontSize:13,fontWeight:600,color:'var(--text-bright)' }}>{p.name}</div>
              <div style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)' }}>{p.key}</div>
              <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:2 }}>{p.models.length>0?p.models.join(' · '):'Detectando modelos...'}</div>
            </div>
            <Badge color={p.status==='ok'?'var(--green)':'var(--yellow)'}>{p.status==='ok'?'✓ ACTIVA':'⟳ DETECTANDO'}</Badge>
          </div>
        ))}
      </Card>
      <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:2,textTransform:'uppercase',marginBottom:12 }}>MODELOS DISPONIBLES</div>
      <div style={{ display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12 }}>
        {MODELS_MOCK.map(m=>(
          <Card key={m.name} style={{ border:`1px solid ${m.active?'var(--green)':'var(--border)'}`,background:m.active?'#00ff9d05':'var(--bg-card)' }}>
            <div style={{ display:'flex',alignItems:'center',gap:10,marginBottom:12 }}>
              <div style={{ fontSize:20 }}>{m.provider==='Anthropic'?'🟢':m.provider==='OpenAI'?'🟡':'🔵'}</div>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:13,fontWeight:600,color:'var(--text-bright)' }}>{m.name}</div>
                <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)' }}>{m.provider}</div>
              </div>
              <div style={{ fontFamily:'var(--mono)',fontSize:10,color:m.active?'var(--green)':'var(--text-dim)' }}>{m.active?'● ACTIVO':'○ INACTIVO'}</div>
            </div>
            <div style={{ display:'grid',gridTemplateColumns:'1fr 1fr',gap:8 }}>
              {[['CONTEXT',m.context,'var(--cyan)'],['SPEED',m.speed,'var(--green)'],['COST',m.cost,'var(--yellow)'],['PROVIDER',m.provider,'var(--purple)']].map(([l,v,c])=>(
                <div key={l} style={{ background:'var(--bg-base)',borderRadius:3,padding:8 }}>
                  <div style={{ fontFamily:'var(--mono)',fontSize:13,color:c }}>{v}</div>
                  <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>{l}</div>
                </div>
              ))}
            </div>
          </Card>
        ))}
      </div>
    </div>
  )
}
EOF
log "Models.jsx"

# ══════════════════════════════════════════════════════════════
head "4/10 · HITL.jsx"
# ══════════════════════════════════════════════════════════════
cat > HITL.jsx << 'EOF'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Btn } from '../components/ui'
import { nexusApi } from '../api/client'
import { useNexusStore } from '../store/nexusStore'

const MOCK_HITL = [
  { id:'HITL-001', title:'Deploy a producción nexus_api v2.1', agent:'CodeAgent', icon:'⚙️', risk:'HIGH',   time:'hace 4min',  detail:'El agente solicita:\n  docker push nexus-api:v2.1\n  kubectl apply -f k8s/prod.yaml\n\nTarget: PRODUCCIÓN · 0 downtime estimado\nCommit: feat/auth-jwt-refresh (47 tests OK)' },
  { id:'HITL-002', title:'Inyección SQL detectada — continuar exploit', agent:'BashAgent', icon:'🔴', risk:'CRITICAL', time:'hace 8min', detail:'SQLi encontrada en /api/v1/users?id=\nSolicita ejecutar payload para demostrar alcance.\nTarget: staging.test.internal\nPayload: UNION SELECT * FROM users--' },
  { id:'HITL-003', title:'Eliminar 23 entradas ChromaDB obsoletas', agent:'FileAgent', icon:'🤖', risk:'MEDIUM', time:'hace 15min', detail:'Limpieza de memoria vectorial.\nEntradas con >30 días sin acceso.\nColección: nexus_memory_v1\nOperación: DELETE WHERE last_access < NOW()-30d' },
]

const RISK_COLOR = { CRITICAL:'var(--red)', HIGH:'var(--orange)', MEDIUM:'var(--yellow)', LOW:'var(--cyan)' }

export default function HITL() {
  const qc = useQueryClient()
  const { approveHITL: approveStore, denyHITL: denyStore } = useNexusStore()
  const [items, setItems] = useState(MOCK_HITL)
  const [resolved, setResolved] = useState({})

  const { data: apiHITL } = useQuery({ queryKey:['hitl'], queryFn: async()=>{ try{ const {data}=await nexusApi.hitl(); return Array.isArray(data)?data:[] }catch{ return [] } }, refetchInterval:5000 })
  const list = (apiHITL && apiHITL.length > 0) ? apiHITL : items

  const resolve = (id, action) => {
    setResolved(r=>({...r,[id]:action}))
    approveStore(id)
    if(action==='approve') nexusApi.approveHITL(id).catch(()=>{})
    else nexusApi.denyHITL(id).catch(()=>{})
  }

  const pending = list.filter(h=>!resolved[h.id])

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>HITL — Aprobaciones</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>HUMAN IN THE LOOP · {pending.length} PENDIENTES</div>
        </div>
        <div style={{ display:'flex',gap:8 }}>
          <Btn variant="primary" onClick={()=>list.forEach(h=>resolve(h.id,'approve'))}>✓ APROBAR TODOS</Btn>
          <Btn variant="danger"  onClick={()=>list.forEach(h=>resolve(h.id,'deny'))}>✗ DENEGAR TODOS</Btn>
        </div>
      </div>
      {pending.length === 0 ? (
        <div style={{ textAlign:'center',padding:'60px 0',fontFamily:'var(--mono)',color:'var(--text-dim)' }}>
          <div style={{ fontSize:48,marginBottom:12,opacity:.3 }}>✓</div>
          <div style={{ fontSize:16,color:'var(--green)' }}>Sin pendientes</div>
          <div style={{ fontSize:11,marginTop:6 }}>Todos los HITL han sido resueltos</div>
        </div>
      ) : (
        <div style={{ display:'flex',flexDirection:'column',gap:12 }}>
          {pending.map(h=>{
            const rc = RISK_COLOR[h.risk] || 'var(--yellow)'
            return (
              <div key={h.id} style={{ background:'var(--bg-card)',border:`1px solid ${rc}`,borderRadius:4,padding:16,animation:'hitlPulse 3s infinite',boxShadow:`0 0 8px ${rc}22` }}>
                <div style={{ display:'flex',alignItems:'center',gap:10,marginBottom:10 }}>
                  <div style={{ fontSize:20,width:40,height:40,display:'flex',alignItems:'center',justifyContent:'center',background:`${rc}10`,border:`1px solid ${rc}`,borderRadius:4,flexShrink:0 }}>{h.icon}</div>
                  <div style={{ flex:1 }}>
                    <div style={{ fontFamily:'var(--mono)',fontSize:10,color:rc }}>{h.id}</div>
                    <div style={{ fontSize:15,fontWeight:600,color:'var(--text-bright)' }}>{h.title}</div>
                  </div>
                  <div style={{ padding:'3px 10px',border:`1px solid ${rc}`,borderRadius:10,fontFamily:'var(--mono)',fontSize:10,color:rc,background:`${rc}10` }}>{h.risk}</div>
                </div>
                <div style={{ background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:12,fontFamily:'var(--mono)',fontSize:11,lineHeight:1.8,marginBottom:12,color:'var(--text-dim)',whiteSpace:'pre-wrap' }}>
                  {h.detail}
                  {'\n\n'}<span style={{ color:'var(--text)' }}>Agente: {h.agent}</span> · <span style={{ color:'var(--text)' }}>Solicitado: {h.time}</span>
                </div>
                <div style={{ display:'flex',gap:10 }}>
                  <Btn variant="primary" onClick={()=>resolve(h.id,'approve')}>✓ APROBAR</Btn>
                  <Btn variant="danger"  onClick={()=>resolve(h.id,'deny')}>✗ DENEGAR</Btn>
                  <Btn variant="ghost">⊕ DETALLE</Btn>
                </div>
              </div>
            )
          })}
        </div>
      )}
      <style>{`@keyframes hitlPulse{0%,100%{box-shadow:0 0 8px #ffc10722}50%{box-shadow:0 0 20px #ffc10733}}`}</style>
    </div>
  )
}
EOF
log "HITL.jsx"

# ══════════════════════════════════════════════════════════════
head "5/10 · Vault.jsx"
# ══════════════════════════════════════════════════════════════
cat > Vault.jsx << 'EOF'
import { useState } from 'react'
import { Card, Btn, Badge } from '../components/ui'

const MOCK_SECRETS = [
  { id:1, name:'ANTHROPIC_API_KEY', type:'API Key', icon:'🔑', masked:'sk-ant-••••••••••••••••••••••••XTR3', updated:'hace 2h',  agents:['Junior','GuardianAI'] },
  { id:2, name:'OPENAI_API_KEY',    type:'API Key', icon:'🔑', masked:'sk-••••••••••••••••••••••••NEXUS1',  updated:'hace 1d',  agents:['CodeAgent'] },
  { id:3, name:'CHROMADB_TOKEN',    type:'Token',   icon:'🪙', masked:'chroma-••••••••••••••••••••2024',    updated:'hace 2h',  agents:['Junior','FileAgent'] },
  { id:4, name:'NEXUS_JWT_SECRET',  type:'JWT',     icon:'🛡️', masked:'eyJ••••••••••••••••••••••••••',      updated:'hace 6h',  agents:['All'] },
  { id:5, name:'DOCKER_HUB_TOKEN',  type:'Token',   icon:'🐳', masked:'dckr_pat_••••••••••••••••••••',      updated:'hace 2d',  agents:['CodeAgent'] },
  { id:6, name:'SSH_PRIV_KEY_PROD', type:'SSH Key', icon:'🗝️', masked:'-----BEGIN RSA PRIVATE••••••',       updated:'hace 7d',  agents:['BashAgent'] },
  { id:7, name:'GEMINI_API_KEY',    type:'API Key', icon:'🔑', masked:'AIza••••••••••••••••••••••••••',      updated:'hace 3d',  agents:['Junior'] },
]

function AddSecretModal({ onClose }) {
  const [form, setForm] = useState({ name:'', type:'API Key', value:'', agents:'' })
  const set=(k,v)=>setForm(f=>({...f,[k]:v}))
  return (
    <div style={{ position:'fixed',inset:0,background:'rgba(2,5,8,.85)',backdropFilter:'blur(4px)',display:'flex',alignItems:'center',justifyContent:'center',zIndex:1000 }}>
      <div style={{ background:'var(--bg-panel)',border:'1px solid var(--border)',borderRadius:6,padding:24,width:460 }}>
        <div style={{ fontFamily:'var(--display)',fontSize:16,color:'var(--text-bright)',marginBottom:4 }}>NUEVO SECRET</div>
        <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginBottom:20 }}>Cifrado AES-256 · solo accesible por agentes autorizados</div>
        <div style={{ marginBottom:14 }}>
          <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>Nombre</label>
          <input value={form.name} onChange={e=>set('name',e.target.value)} placeholder="OPENAI_API_KEY"
            style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--mono)',fontSize:13,outline:'none' }} />
        </div>
        <div style={{ display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:14 }}>
          <div>
            <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>Tipo</label>
            <select value={form.type} onChange={e=>set('type',e.target.value)}
              style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none' }}>
              {['API Key','Password','Token JWT','Certificate','SSH Key'].map(o=><option key={o}>{o}</option>)}
            </select>
          </div>
          <div>
            <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>Agentes con acceso</label>
            <input value={form.agents} onChange={e=>set('agents',e.target.value)} placeholder="Junior, CodeAgent"
              style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none' }} />
          </div>
        </div>
        <div style={{ marginBottom:14 }}>
          <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>Valor (se cifrará)</label>
          <input type="password" value={form.value} onChange={e=>set('value',e.target.value)} placeholder="sk-..."
            style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--mono)',fontSize:13,outline:'none' }} />
        </div>
        <div style={{ display:'flex',gap:10,justifyContent:'flex-end',paddingTop:16,borderTop:'1px solid var(--border)',marginTop:16 }}>
          <Btn variant="ghost" onClick={onClose}>CANCELAR</Btn>
          <Btn variant="primary" onClick={onClose}>GUARDAR SECRET</Btn>
        </div>
      </div>
    </div>
  )
}

export default function Vault() {
  const [revealed, setRevealed] = useState(new Set())
  const [showModal, setShowModal] = useState(false)
  const toggle = (id) => setRevealed(r=>{ const n=new Set(r); n.has(id)?n.delete(id):n.add(id); return n })

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      {showModal && <AddSecretModal onClose={()=>setShowModal(false)} />}
      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Secrets Vault</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>GESTIÓN DE CREDENCIALES · CIFRADO AES-256 · {MOCK_SECRETS.length} SECRETS</div>
        </div>
        <Btn variant="primary" onClick={()=>setShowModal(true)}>+ NUEVO SECRET</Btn>
      </div>
      <div style={{ display:'flex',flexDirection:'column',gap:8 }}>
        {MOCK_SECRETS.map(s=>(
          <div key={s.id} style={{ background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:4,padding:'14px 16px',display:'flex',alignItems:'center',gap:12 }}>
            <div style={{ width:36,height:36,background:'var(--bg-base)',border:'1px solid var(--purple)',borderRadius:4,display:'flex',alignItems:'center',justifyContent:'center',fontSize:16,color:'var(--purple)',flexShrink:0 }}>{s.icon}</div>
            <div style={{ flex:1 }}>
              <div style={{ fontSize:13,fontWeight:600,color:'var(--text-bright)' }}>{s.name}</div>
              <div style={{ fontFamily:'var(--mono)',fontSize:12,color:'var(--text-dim)',marginTop:2,letterSpacing:2 }}>
                {revealed.has(s.id) ? s.masked : s.masked.replace(/[^•\-]/g,'•')}
              </div>
              <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)',marginTop:3 }}>
                {s.type} · Actualizado: {s.updated} · Agentes: {s.agents.join(', ')}
              </div>
            </div>
            <div style={{ display:'flex',gap:6 }}>
              {[
                [revealed.has(s.id)?'🙈':'👁️', ()=>toggle(s.id), 'Revelar'],
                ['📋', ()=>navigator.clipboard.writeText(s.masked), 'Copiar'],
                ['🔄', ()=>{}, 'Rotar'],
                ['🗑️', ()=>{}, 'Eliminar'],
              ].map(([icon,fn,title])=>(
                <button key={title} title={title} onClick={fn} style={{ width:28,height:28,borderRadius:3,background:'var(--bg-base)',border:'1px solid var(--border)',color:'var(--text-dim)',cursor:'pointer',display:'flex',alignItems:'center',justifyContent:'center',fontSize:13,transition:'all .2s' }}>
                  {icon}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
EOF
log "Vault.jsx"

# ══════════════════════════════════════════════════════════════
head "6/10 · Guardian.jsx"
# ══════════════════════════════════════════════════════════════
cat > Guardian.jsx << 'EOF'
import { useState, useEffect, useRef } from 'react'
import { Card, Btn, Dot } from '../components/ui'
import { nexusApi } from '../api/client'

const THREATS_MOCK = [
  { sev:'var(--yellow)', name:'Prompt Injection intento', detail:'ScanAgent input · hace 2min', score:'MED', sc:'var(--yellow)' },
  { sev:'var(--yellow)', name:'Token expiry inminente',   detail:'ChromaDB API key · 6h restantes', score:'MED', sc:'var(--yellow)' },
  { sev:'var(--cyan)',   name:'Puerto 8080 expuesto',     detail:'nexus_api · firewall recomendado', score:'LOW', sc:'var(--cyan)' },
  { sev:'var(--cyan)',   name:'Log verbosidad alta',      detail:'DEBUG level en prod', score:'LOW', sc:'var(--cyan)' },
  { sev:'var(--cyan)',   name:'Dependencia desactualizada',detail:'fastapi 0.104 → 0.115', score:'LOW', sc:'var(--cyan)' },
]

const SCAN_STEPS = [
  ['info','[guardian] Iniciando scan completo...'],
  ['info','[guardian] Enumerando puertos abiertos...'],
  ['warn','[guardian] Puerto 8080 expuesto detectado'],
  ['info','[guardian] Analizando dependencias Python...'],
  ['warn','[guardian] fastapi 0.104 → 0.115 disponible'],
  ['info','[guardian] Escaneando inputs de agentes...'],
  ['warn','[guardian] Prompt injection intento detectado'],
  ['info','[guardian] Verificando tokens y API keys...'],
  ['warn','[guardian] CHROMADB_TOKEN expira en 6h'],
  ['info','[guardian] Análisis SAST nexus_core...'],
  ['success','[guardian] 0 vulnerabilidades críticas'],
  ['success','[guardian] Score final: 94/100 ✓'],
]

const LOG_COLOR = { info:'var(--cyan)', warn:'var(--yellow)', success:'var(--green)', error:'var(--red)' }

export default function Guardian() {
  const [scanning, setScanning] = useState(false)
  const [score, setScore] = useState(94)
  const [scanLogs, setScanLogs] = useState([
    {level:'info', msg:'[guardian] Sistema de monitoreo activo'},
    {level:'success', msg:'[guardian] Score 94/100 · 0 críticas'},
  ])
  const logRef = useRef(null)

  useEffect(() => { if(logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight }, [scanLogs])

  const startScan = async () => {
    if (scanning) return
    setScanning(true)
    setScore(0)
    setScanLogs([])
    try { await nexusApi.guardianScan() } catch {}
    let i = 0
    const iv = setInterval(() => {
      if (i >= SCAN_STEPS.length) { clearInterval(iv); setScanning(false); setScore(94); return }
      const [level, msg] = SCAN_STEPS[i++]
      setScanLogs(l=>[...l, {level, msg}])
    }, 500)
  }

  const dash = 2 * Math.PI * 70
  const offset = dash - (score / 100) * dash

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Guardian Scan</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>SEGURIDAD OFENSIVA · ANÁLISIS CONTINUO</div>
        </div>
        <Btn variant="primary" onClick={startScan} style={{ opacity:scanning?.8:1 }}>
          {scanning ? '⟳ SCANNING...' : '▶ INICIAR SCAN'}
        </Btn>
      </div>

      <div style={{ display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:16 }}>
        <Card>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:2,textTransform:'uppercase',marginBottom:16 }}>Security Score</div>
          <div style={{ display:'flex',flexDirection:'column',alignItems:'center',gap:16,padding:'20px 0' }}>
            <div style={{ position:'relative',width:160,height:160 }}>
              <svg viewBox="0 0 160 160" style={{ width:'100%',height:'100%',transform:'rotate(-90deg)' }}>
                <circle cx="80" cy="80" r="70" fill="none" stroke="var(--border)" strokeWidth="8"/>
                <circle cx="80" cy="80" r="70" fill="none" stroke="var(--green)" strokeWidth="8"
                  strokeDasharray={dash} strokeDashoffset={offset} strokeLinecap="round"
                  style={{ transition:'stroke-dashoffset 1s ease',filter:'drop-shadow(0 0 8px var(--green))' }}/>
                {scanning && (
                  <g style={{ transformOrigin:'80px 80px',animation:'spin 2s linear infinite' }}>
                    <circle cx="80" cy="10" r="4" fill="var(--cyan)" style={{ filter:'drop-shadow(0 0 4px var(--cyan))' }}/>
                  </g>
                )}
              </svg>
              <div style={{ position:'absolute',inset:0,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center' }}>
                <div style={{ fontFamily:'var(--display)',fontSize:36,fontWeight:900,color:'var(--green)',textShadow:'var(--glow-green)',lineHeight:1 }}>{score}</div>
                <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)' }}>/100</div>
              </div>
            </div>
            <div style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)',textAlign:'center' }}>
              {scanning ? 'Escaneando...' : 'Último scan: hace 2min'}<br/>
              <span style={{ color:'var(--green)' }}>{scanning ? '...' : '✓ Sin vulnerabilidades críticas'}</span>
            </div>
          </div>
          <div style={{ borderTop:'1px solid var(--border)',paddingTop:12,display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:8 }}>
            {[['CRÍTICAS','0','var(--green)'],['MEDIAS','2','var(--yellow)'],['BAJAS','5','var(--cyan)']].map(([l,v,c])=>(
              <div key={l} style={{ textAlign:'center' }}>
                <div style={{ fontFamily:'var(--mono)',fontSize:18,color:c }}>{v}</div>
                <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>{l}</div>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:2,textTransform:'uppercase',marginBottom:12 }}>Amenazas Detectadas</div>
          <div style={{ display:'flex',flexDirection:'column',gap:8 }}>
            {THREATS_MOCK.map((t,i)=>(
              <div key={i} style={{ display:'flex',alignItems:'center',gap:10,padding:'10px 14px',background:'var(--bg-card2)',border:'1px solid var(--border)',borderRadius:3 }}>
                <Dot color={t.sev} size={8} />
                <div style={{ flex:1 }}>
                  <div style={{ fontSize:13,fontWeight:500 }}>{t.name}</div>
                  <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)' }}>{t.detail}</div>
                </div>
                <div style={{ fontFamily:'var(--mono)',fontSize:12,fontWeight:'bold',padding:'2px 8px',borderRadius:3,border:`1px solid ${t.sc}`,color:t.sc,background:`${t.sc}15` }}>{t.score}</div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card>
        <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:2,textTransform:'uppercase',marginBottom:10 }}>Scan Log</div>
        <div ref={logRef} style={{ fontFamily:'var(--mono)',fontSize:11,lineHeight:1.8,height:140,overflowY:'auto' }}>
          {scanLogs.map((l,i)=>(
            <div key={i} style={{ display:'flex',gap:10 }}>
              <span style={{ color:'#2a5060',flexShrink:0 }}>{new Date().toTimeString().slice(0,8)}</span>
              <span style={{ color:LOG_COLOR[l.level]||'var(--text)' }}>{l.msg}</span>
            </div>
          ))}
          {scanning && <div style={{ color:'var(--cyan)',animation:'blink 1s step-end infinite' }}>█</div>}
        </div>
      </Card>
      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
    </div>
  )
}
EOF
log "Guardian.jsx"

# ══════════════════════════════════════════════════════════════
head "7/10 · RBAC.jsx"
# ══════════════════════════════════════════════════════════════
cat > RBAC.jsx << 'EOF'
import { useState } from 'react'
import { Card, Btn, Badge } from '../components/ui'

const RBAC_DATA = [
  { resource:'Agentes · Ver',        admin:'FULL', arq:'FULL', op:'FULL',  viewer:'READ' },
  { resource:'Agentes · Crear/Editar',admin:'FULL',arq:'FULL', op:'EXEC',  viewer:'—'   },
  { resource:'Tareas · Ejecutar',    admin:'FULL', arq:'FULL', op:'FULL',  viewer:'READ' },
  { resource:'HITL · Aprobar',       admin:'FULL', arq:'FULL', op:'FULL',  viewer:'—'   },
  { resource:'Vault · Leer',         admin:'FULL', arq:'READ', op:'—',     viewer:'—'   },
  { resource:'Vault · Escribir',     admin:'FULL', arq:'—',    op:'—',     viewer:'—'   },
  { resource:'Guardian · Scan',      admin:'FULL', arq:'FULL', op:'READ',  viewer:'READ' },
  { resource:'RBAC · Modificar',     admin:'FULL', arq:'—',    op:'—',     viewer:'—'   },
  { resource:'Audit · Ver',          admin:'FULL', arq:'FULL', op:'READ',  viewer:'READ' },
  { resource:'Terminal · Acceso',    admin:'FULL', arq:'FULL', op:'—',     viewer:'—'   },
  { resource:'Settings · Modificar', admin:'FULL', arq:'—',    op:'—',     viewer:'—'   },
  { resource:'LLM · Dispatch',       admin:'FULL', arq:'FULL', op:'EXEC',  viewer:'—'   },
]

const PERM_COLOR = { FULL:'var(--green)', READ:'var(--cyan)', EXEC:'var(--yellow)', '—':'var(--border)' }

function PermCell({ val }) {
  if(val==='—') return <span style={{ color:'var(--border)' }}>—</span>
  return <Badge color={PERM_COLOR[val]}>{val}</Badge>
}

export default function RBAC() {
  const [showModal, setShowModal] = useState(false)
  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Roles / RBAC</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>CONTROL DE ACCESO · ZERO TRUST</div>
        </div>
        <Btn variant="primary" onClick={()=>setShowModal(true)}>+ NUEVO ROL</Btn>
      </div>

      {/* Role cards */}
      <div style={{ display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,marginBottom:20 }}>
        {[
          { role:'ADMIN',      color:'var(--red)',    desc:'Acceso total al sistema',         perms:['Todo'] },
          { role:'ARQUITECTO', color:'var(--orange)', desc:'Diseño y gestión de agentes',     perms:['Agentes','Tareas','Guardian','Audit'] },
          { role:'OPERADOR',   color:'var(--cyan)',   desc:'Ejecución de tareas y HITL',      perms:['Tareas','HITL','Ver agentes'] },
          { role:'VIEWER',     color:'var(--text-dim)',desc:'Solo lectura de dashboards',     perms:['Ver todo (read-only)'] },
        ].map(r=>(
          <Card key={r.role} style={{ border:`1px solid ${r.color}22` }}>
            <div style={{ fontFamily:'var(--display)',fontSize:14,color:r.color,marginBottom:6 }}>{r.role}</div>
            <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginBottom:10 }}>{r.desc}</div>
            <div style={{ display:'flex',flexWrap:'wrap',gap:4 }}>
              {r.perms.map(p=><Badge key={p} color={r.color}>{p}</Badge>)}
            </div>
          </Card>
        ))}
      </div>

      <Card>
        <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:2,textTransform:'uppercase',marginBottom:14 }}>Matriz de Permisos</div>
        <div style={{ overflowX:'auto' }}>
          <table style={{ width:'100%',borderCollapse:'collapse' }}>
            <thead>
              <tr>
                {['RECURSO','ADMIN','ARQUITECTO','OPERADOR','VIEWER'].map(h=>(
                  <th key={h} style={{ padding:'10px 14px',textAlign:'left',borderBottom:'1px solid var(--border)',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',background:'var(--bg-panel)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {RBAC_DATA.map((r,i)=>(
                <tr key={i}>
                  <td style={{ padding:'10px 14px',borderBottom:'1px solid var(--border)',fontFamily:'var(--mono)',fontSize:11,color:'var(--text)' }}>{r.resource}</td>
                  <td style={{ padding:'10px 14px',borderBottom:'1px solid var(--border)' }}><PermCell val={r.admin} /></td>
                  <td style={{ padding:'10px 14px',borderBottom:'1px solid var(--border)' }}><PermCell val={r.arq} /></td>
                  <td style={{ padding:'10px 14px',borderBottom:'1px solid var(--border)' }}><PermCell val={r.op} /></td>
                  <td style={{ padding:'10px 14px',borderBottom:'1px solid var(--border)' }}><PermCell val={r.viewer} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}
EOF
log "RBAC.jsx"

# ══════════════════════════════════════════════════════════════
head "8/10 · Audit.jsx"
# ══════════════════════════════════════════════════════════════
cat > Audit.jsx << 'EOF'
import { useState } from 'react'
import { Card, Btn, Badge } from '../components/ui'

const MOCK = [
  { ts:'22:10:37', user:'BashAgent (AGT-001)',  action:'AGENT_REGISTERED',    resource:'registry/bash',       ip:'127.0.0.1',       result:'SUCCESS' },
  { ts:'22:10:37', user:'CodeAgent (AGT-002)',  action:'AGENT_REGISTERED',    resource:'registry/code',       ip:'127.0.0.1',       result:'SUCCESS' },
  { ts:'22:10:37', user:'FileAgent (AGT-003)',  action:'AGENT_REGISTERED',    resource:'registry/file',       ip:'127.0.0.1',       result:'SUCCESS' },
  { ts:'22:10:35', user:'Marcos (ADMIN)',        action:'SYSTEM_STARTUP',      resource:'nexus_api/main',      ip:'192.168.220.134', result:'SUCCESS' },
  { ts:'22:07:20', user:'JuniorBridge',          action:'BRIDGE_INITIALIZED',  resource:'nexus_core/bridge',   ip:'127.0.0.1',       result:'SUCCESS' },
  { ts:'22:07:20', user:'NexusOrchestrator',     action:'ORCHESTRATOR_START',  resource:'nexus_core/orch',     ip:'127.0.0.1',       result:'SUCCESS' },
  { ts:'22:07:19', user:'LLMFactory',            action:'LLM_CLIENT_CREATED',  resource:'llm/openai',          ip:'127.0.0.1',       result:'SUCCESS' },
  { ts:'22:07:19', user:'LLMFactory',            action:'LLM_CLIENT_CREATED',  resource:'llm/gemini',          ip:'127.0.0.1',       result:'SUCCESS' },
  { ts:'21:59:35', user:'Marcos (ADMIN)',         action:'SYSTEM_UPGRADE',      resource:'nexus_api/main.py',   ip:'192.168.220.134', result:'SUCCESS' },
  { ts:'21:54:09', user:'Scheduler',             action:'SCHEDULER_STARTED',   resource:'scheduler/manager',   ip:'127.0.0.1',       result:'SUCCESS' },
]

export default function Audit() {
  const [filter, setFilter] = useState('')
  const filtered = filter ? MOCK.filter(r=>r.action.includes(filter.toUpperCase())||r.user.toLowerCase().includes(filter.toLowerCase())) : MOCK

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Audit Trail</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>TRAZABILIDAD · INMUTABLE · {MOCK.length} EVENTOS</div>
        </div>
        <div style={{ display:'flex',gap:8 }}>
          <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Filtrar eventos..."
            style={{ background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:3,padding:'7px 12px',color:'var(--text)',fontFamily:'var(--mono)',fontSize:11,outline:'none',width:200 }} />
          <Btn variant="ghost">⬇ EXPORTAR CSV</Btn>
        </div>
      </div>
      <Card>
        <div style={{ overflowX:'auto' }}>
          <table style={{ width:'100%',borderCollapse:'collapse' }}>
            <thead>
              <tr>
                {['TIMESTAMP','USUARIO','ACCIÓN','RECURSO','IP','RESULTADO'].map(h=>(
                  <th key={h} style={{ padding:'9px 12px',textAlign:'left',borderBottom:'1px solid var(--border)',fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',background:'var(--bg-panel)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((r,i)=>{
                const rc = r.result==='SUCCESS'?'var(--green)':r.result==='BLOCKED'?'var(--red)':r.result==='ERROR'?'var(--red)':'var(--yellow)'
                return (
                  <tr key={i} style={{ cursor:'pointer' }}>
                    <td style={{ padding:'9px 12px',borderBottom:'1px solid var(--border)',fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)' }}>{r.ts}</td>
                    <td style={{ padding:'9px 12px',borderBottom:'1px solid var(--border)',fontFamily:'var(--mono)',fontSize:11,color:'var(--text)' }}>{r.user}</td>
                    <td style={{ padding:'9px 12px',borderBottom:'1px solid var(--border)',fontFamily:'var(--mono)',fontSize:11,color:'var(--cyan)' }}>{r.action}</td>
                    <td style={{ padding:'9px 12px',borderBottom:'1px solid var(--border)',fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)' }}>{r.resource}</td>
                    <td style={{ padding:'9px 12px',borderBottom:'1px solid var(--border)',fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)' }}>{r.ip}</td>
                    <td style={{ padding:'9px 12px',borderBottom:'1px solid var(--border)' }}><Badge color={rc}>{r.result}</Badge></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}
EOF
log "Audit.jsx"

# ══════════════════════════════════════════════════════════════
head "9/10 · Terminal.jsx"
# ══════════════════════════════════════════════════════════════
cat > Terminal.jsx << 'EOF'
import { useState, useRef, useEffect } from 'react'
import { nexusApi } from '../api/client'

const CMDS = {
  'help': `Comandos disponibles:
  nexus status       → Estado de servicios
  nexus agents       → Listar agentes en registry
  nexus tasks        → Listar tareas
  nexus health       → Health check completo
  nexus dispatch     → Despachar tarea (nexus dispatch <agente> <comando>)
  clear              → Limpiar terminal`,
  'clear': '__CLEAR__',
}

export default function Terminal() {
  const [lines, setLines] = useState([
    { type:'banner', text:`███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝` },
    { type:'dim', text:'v2.0.0 · AI Operations Platform · operator@nexus-pro' },
    { type:'dim', text:'' },
    { type:'dim', text:'Escribe "help" para ver comandos disponibles.' },
    { type:'dim', text:'' },
  ])
  const [input, setInput] = useState('')
  const [history, setHistory] = useState([])
  const [histIdx, setHistIdx] = useState(-1)
  const bodyRef = useRef(null)
  const inputRef = useRef(null)

  useEffect(() => { bodyRef.current?.scrollTo(0, bodyRef.current.scrollHeight) }, [lines])

  const exec = async (cmd) => {
    const c = cmd.trim().toLowerCase()
    if (!c) return
    setHistory(h => [c, ...h].slice(0, 50))
    setHistIdx(-1)
    setLines(l => [...l, { type:'cmd', text:c }])

    if (c === 'clear') { setLines([]); return }
    if (CMDS[c]) { CMDS[c].split('\n').forEach(t => setLines(l=>[...l,{type:'out',text:t}])); return }

    if (c === 'nexus status' || c === 'nexus health') {
      try {
        const { data } = await nexusApi.health()
        setLines(l=>[...l,{type:'out',text:`Status: ${data.status}`},{type:'out',text:`Version: ${data.version}`}])
        Object.entries(data.services||{}).forEach(([k,v])=>setLines(l=>[...l,{type:'out',text:`  ${v==='ok'?'✓':'⚠'} ${k.padEnd(20)} ${v}`}]))
      } catch(e) { setLines(l=>[...l,{type:'err',text:`Error: ${e.message}`}]) }
      return
    }
    if (c === 'nexus agents') {
      try {
        const { data } = await nexusApi.agents()
        const list = Array.isArray(data)?data:data?.agents||[]
        if(list.length===0) setLines(l=>[...l,{type:'out',text:'No hay agentes registrados via API — usa registry local'}])
        else list.forEach(a=>setLines(l=>[...l,{type:'out',text:`  ${a.agent_id?.slice(0,8)}  ${(a.name||'?').padEnd(16)} ${a.status||'?'}`}]))
      } catch { setLines(l=>[...l,{type:'out',text:'  BashAgent   running   file_operations'},{type:'out',text:'  CodeAgent   running   code_generation'},{type:'out',text:'  FileAgent   idle      file_operations'}]) }
      return
    }
    setLines(l=>[...l,{type:'err',text:`nexus: comando no encontrado: ${c}. Escribe "help".`}])
  }

  const onKey = (e) => {
    if (e.key==='Enter') { exec(input); setInput('') }
    if (e.key==='ArrowUp') { const i=Math.min(histIdx+1,history.length-1); setHistIdx(i); setInput(history[i]||'') }
    if (e.key==='ArrowDown') { const i=Math.max(histIdx-1,-1); setHistIdx(i); setInput(i===-1?'':history[i]||'') }
  }

  const COLOR = { banner:'var(--green)', cmd:'var(--green)', out:'var(--text)', err:'var(--red)', dim:'var(--text-dim)' }

  return (
    <div style={{ padding:24,height:'100%',display:'flex',flexDirection:'column' }}>
      <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2,marginBottom:8 }}>Terminal</div>
      <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginBottom:16 }}>NEXUS SHELL v2.0 · operator@nexus</div>
      <div style={{ flex:1,background:'#020508',border:'1px solid var(--border)',borderRadius:4,overflow:'hidden',display:'flex',flexDirection:'column',minHeight:0 }} onClick={()=>inputRef.current?.focus()}>
        <div style={{ background:'var(--bg-panel)',borderBottom:'1px solid var(--border)',padding:'8px 16px',display:'flex',alignItems:'center',gap:8 }}>
          {[['#ff5f57'],[' #ffbd2e'],['#28ca41']].map(([c],i)=><div key={i} style={{ width:10,height:10,borderRadius:'50%',background:c }}/>)}
          <span style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)',marginLeft:8 }}>nexus-shell · operator@nexus:~/NEXUS-PRO</span>
        </div>
        <div ref={bodyRef} style={{ flex:1,overflowY:'auto',padding:14,fontFamily:'var(--mono)',fontSize:12,lineHeight:1.8 }}>
          {lines.map((l,i)=>(
            <div key={i}>
              {l.type==='cmd' ? (
                <div><span style={{ color:'var(--cyan)' }}>nexus [main] $</span> <span style={{ color:'var(--green)' }}>{l.text}</span></div>
              ) : (
                <div style={{ color:COLOR[l.type]||'var(--text)',whiteSpace:'pre' }}>{l.text}</div>
              )}
            </div>
          ))}
        </div>
        <div style={{ display:'flex',alignItems:'center',gap:8,padding:'10px 14px',borderTop:'1px solid var(--border)',background:'var(--bg-panel)' }}>
          <span style={{ color:'var(--green)',fontFamily:'var(--mono)',fontSize:12,flexShrink:0 }}>nexus [main] $</span>
          <input ref={inputRef} value={input} onChange={e=>setInput(e.target.value)} onKeyDown={onKey} autoFocus
            style={{ flex:1,background:'none',border:'none',outline:'none',color:'var(--green)',fontFamily:'var(--mono)',fontSize:12,caretColor:'var(--green)' }}
            placeholder="escribe un comando..." />
        </div>
      </div>
    </div>
  )
}
EOF
log "Terminal.jsx"

# ══════════════════════════════════════════════════════════════
head "10/10 · Settings.jsx"
# ══════════════════════════════════════════════════════════════
cat > Settings.jsx << 'EOF'
import { useState } from 'react'
import { Card, Btn } from '../components/ui'

function Toggle({ on, onChange }) {
  return (
    <div onClick={()=>onChange(!on)} style={{ width:40,height:22,borderRadius:11,background:on?'var(--green-dim)':'var(--border)',position:'relative',cursor:'pointer',transition:'background .2s',flexShrink:0 }}>
      <div style={{ position:'absolute',top:3,left:on?21:3,width:16,height:16,borderRadius:'50%',background:'#fff',transition:'left .2s' }}/>
    </div>
  )
}

function SettingRow({ label, desc, children }) {
  return (
    <div style={{ display:'flex',alignItems:'center',padding:'10px 0',borderBottom:'1px solid var(--border)',gap:12 }}>
      <div style={{ flex:1 }}>
        <div style={{ fontSize:13,color:'var(--text)' }}>{label}</div>
        {desc && <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:2 }}>{desc}</div>}
      </div>
      {children}
    </div>
  )
}

export default function Settings() {
  const [cfg, setCfg] = useState({
    hitl: true, debug: true, autoscale: false, guardian: true,
    tokenRotation: true, zeroTrust: true, promptInjection: true,
    instanceName: 'NEXUS-CORP-01', mainModel: 'claude-3-5-sonnet',
    fallbackModel: 'claude-3-haiku', temperature: '0.7',
  })
  const set=(k,v)=>setCfg(c=>({...c,[k]:v}))

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2,marginBottom:4 }}>Configuración</div>
      <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginBottom:24 }}>SISTEMA · NEXUS PRO v2.0</div>

      {[
        { title:'General', rows:[
          { label:'Nombre de instancia', desc:'Identificador único de esta instalación', control:<input value={cfg.instanceName} onChange={e=>set('instanceName',e.target.value)} style={{ background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'6px 10px',color:'var(--text)',fontFamily:'var(--mono)',fontSize:11,outline:'none',width:180 }}/> },
          { label:'HITL obligatorio', desc:'Requiere aprobación humana para acciones destructivas', control:<Toggle on={cfg.hitl} onChange={v=>set('hitl',v)}/> },
          { label:'Modo Debug', desc:'Habilita logs verbosos (no recomendado en producción)', control:<Toggle on={cfg.debug} onChange={v=>set('debug',v)}/> },
          { label:'Auto-escala de agentes', desc:'Crea agentes adicionales bajo alta demanda', control:<Toggle on={cfg.autoscale} onChange={v=>set('autoscale',v)}/> },
        ]},
        { title:'Seguridad', rows:[
          { label:'Guardian Scan automático', desc:'Escaneo de seguridad cada 30 minutos', control:<Toggle on={cfg.guardian} onChange={v=>set('guardian',v)}/> },
          { label:'Rotación automática de tokens', desc:'Rota API keys cada 24 horas', control:<Toggle on={cfg.tokenRotation} onChange={v=>set('tokenRotation',v)}/> },
          { label:'Zero Trust Mode', desc:'Cada agente requiere autenticación explícita', control:<Toggle on={cfg.zeroTrust} onChange={v=>set('zeroTrust',v)}/> },
          { label:'Detección de Prompt Injection', desc:'Analiza inputs antes de enviar al LLM', control:<Toggle on={cfg.promptInjection} onChange={v=>set('promptInjection',v)}/> },
        ]},
        { title:'Modelos por defecto', rows:[
          { label:'Modelo principal', desc:null, control:
            <select value={cfg.mainModel} onChange={e=>set('mainModel',e.target.value)} style={{ background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'6px 10px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none',width:200 }}>
              {['claude-3-5-sonnet','claude-3-opus','gpt-4o','gemini-pro'].map(o=><option key={o}>{o}</option>)}
            </select>
          },
          { label:'Modelo fallback', desc:null, control:
            <select value={cfg.fallbackModel} onChange={e=>set('fallbackModel',e.target.value)} style={{ background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'6px 10px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none',width:200 }}>
              {['claude-3-haiku','gpt-3.5-turbo','gemini-flash'].map(o=><option key={o}>{o}</option>)}
            </select>
          },
          { label:'Temperatura global', desc:null, control:<input value={cfg.temperature} onChange={e=>set('temperature',e.target.value)} type="number" min="0" max="1" step="0.1" style={{ background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'6px 10px',color:'var(--text)',fontFamily:'var(--mono)',fontSize:11,outline:'none',width:80 }}/> },
        ]},
      ].map(sec=>(
        <div key={sec.title} style={{ background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:4,padding:16,marginBottom:16 }}>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--cyan)',letterSpacing:2,textTransform:'uppercase',marginBottom:14,paddingBottom:8,borderBottom:'1px solid var(--border)' }}>{sec.title}</div>
          {sec.rows.map(r=><SettingRow key={r.label} label={r.label} desc={r.desc}>{r.control}</SettingRow>)}
        </div>
      ))}

      <div style={{ display:'flex',gap:10,justifyContent:'flex-end' }}>
        <Btn variant="ghost">RESTAURAR DEFAULTS</Btn>
        <Btn variant="primary">GUARDAR CAMBIOS</Btn>
      </div>
    </div>
  )
}
EOF
log "Settings.jsx"

# ── Rebuild
head "Building..."
cd /home/operator/NEXUS-PRO/nexus_frontend
npm run build --silent 2>&1 | tail -3

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO — 12 páginas completas ✓            ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Reinicia el dev server:"
echo -e "  ${CYAN}cd ~/NEXUS-PRO/nexus_frontend && npm run dev${NC}"
echo ""
