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
