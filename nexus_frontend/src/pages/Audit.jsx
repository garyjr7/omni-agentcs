import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Badge } from '../components/ui'
import { nexusApi } from '../api/client'
import { useAuthStore } from '../store/authStore'

export default function Audit() {
  const [filter, setFilter] = useState('')
  const tenant = useAuthStore(s => s.user?.tenant_id || 'system')
  const events = useQuery({
    queryKey:['audit', tenant],
    queryFn:async() => (await nexusApi.auditLogs(tenant)).data.items || [],
    refetchInterval:5000,
  })
  const verification = useQuery({
    queryKey:['audit-verification'], queryFn:async() => (await nexusApi.auditVerify()).data,
    refetchInterval:30000,
  })
  const rows = (events.data || []).filter(row => !filter ||
    row.action?.toLowerCase().includes(filter.toLowerCase()) ||
    row.actor_id?.toLowerCase().includes(filter.toLowerCase()))

  return <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
    <div style={{ display:'flex',justifyContent:'space-between',marginBottom:20 }}>
      <div>
        <div style={{ fontFamily:'var(--display)',fontSize:22,color:'var(--text-bright)',letterSpacing:2 }}>Audit Trail</div>
        <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>
          CADENA {verification.data?.valid ? 'VERIFICADA' : 'PENDIENTE'} · {rows.length} EVENTOS · {tenant}
        </div>
      </div>
      <input value={filter} onChange={event=>setFilter(event.target.value)} placeholder="Filtrar eventos…"
        style={{ background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:3,
          padding:'7px 12px',color:'var(--text)',fontFamily:'var(--mono)',height:34 }} />
    </div>
    <Card><div style={{ overflowX:'auto' }}><table style={{ width:'100%',borderCollapse:'collapse' }}>
      <thead><tr>{['SECUENCIA','FECHA','ACTOR','ACCIÓN','RECURSO','DECISIÓN'].map(label =>
        <th key={label} style={{ padding:9,textAlign:'left',borderBottom:'1px solid var(--border)',fontSize:9,color:'var(--text-dim)' }}>{label}</th>)}</tr></thead>
      <tbody>{rows.map(row => <tr key={row.event_id}>
        <td style={cell}>{row.sequence}</td><td style={cell}>{new Date(row.created_at).toLocaleString()}</td>
        <td style={cell}>{row.actor_id}</td><td style={{...cell,color:'var(--cyan)'}}>{row.action}</td>
        <td style={cell}>{row.resource_type}/{row.resource_id}</td>
        <td style={cell}><Badge color={row.decision==='allow'?'var(--green)':'var(--red)'}>{row.decision || 'record'}</Badge></td>
      </tr>)}</tbody>
    </table>{!rows.length && <div style={{ padding:20,color:'var(--text-dim)' }}>Sin eventos para este tenant.</div>}</div></Card>
  </div>
}

const cell = { padding:9,borderBottom:'1px solid var(--border)',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)' }
