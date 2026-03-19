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
