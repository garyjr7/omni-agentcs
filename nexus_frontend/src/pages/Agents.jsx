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
