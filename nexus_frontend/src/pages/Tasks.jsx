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
