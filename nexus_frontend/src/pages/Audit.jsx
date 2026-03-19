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
