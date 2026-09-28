import { useQuery } from '@tanstack/react-query'
import { Card, MetricCard, SectionTitle, Dot } from '../components/ui'
import { nexusApi } from '../api/client'
import { useAuthStore } from '../store/authStore'

function total(items, status) {
  return items?.find(item => item.status === status)?.count || 0
}

export default function Overview() {
  const tenant = useAuthStore(s => s.user?.tenant_id || 'system')
  const health = useQuery({ queryKey:['health'], queryFn:async()=>(await nexusApi.health()).data,
    refetchInterval:5000 })
  const operations = useQuery({ queryKey:['operations', tenant],
    queryFn:async()=>(await nexusApi.operationsSummary(tenant)).data, refetchInterval:3000 })
  const runs = operations.data?.runs || []
  const tasks = operations.data?.tasks || []
  const usage = operations.data?.usage || []
  const completed = total(runs, 'completed')
  const failed = total(runs, 'failed') + total(runs, 'dead_letter')
  const active = total(runs, 'queued') + total(runs, 'running')
  const tokens = usage.find(item => item.metric === 'tokens')?.total || 0

  return <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
    <div style={{ marginBottom:24 }}>
      <div style={{ fontFamily:'var(--display)',fontSize:22,color:'var(--text-bright)',letterSpacing:2 }}>NEXUS SOVEREIGN</div>
      <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>
        CONTROL Y EJECUCIÓN PROPIA · {health.data?.status?.toUpperCase() || 'CONECTANDO'} · {tenant}
      </div>
    </div>
    <div style={{ display:'grid',gridTemplateColumns:'repeat(4,minmax(0,1fr))',gap:12,marginBottom:16 }}>
      <MetricCard label="Runs activos" value={active} sub="queued + running" color="var(--cyan)" barPct={Math.min(active*10,100)} />
      <MetricCard label="Completados" value={completed} sub="durables" color="var(--green)" barPct={completed ? 100:0} />
      <MetricCard label="Fallidos" value={failed} sub="incluye DLQ" color={failed?'var(--red)':'var(--green)'} barPct={Math.min(failed*20,100)} />
      <MetricCard label="Tokens" value={tokens} sub="ledger del tenant" color="var(--purple)" barPct={Math.min(tokens/1000,100)} />
    </div>
    <div style={{ display:'grid',gridTemplateColumns:'1fr 1fr',gap:12 }}>
      <Card><SectionTitle style={{ marginBottom:12 }}>Servicios</SectionTitle>
        <div style={{ display:'grid',gridTemplateColumns:'1fr 1fr',gap:8 }}>
          <Status name="Control plane" value={health.data?.durable_control_plane} />
          <Status name="API" value={health.data?.status} />
          <Status name="Versión" value={health.data?.version} neutral />
          <Status name="Plataforma" value="Sovereign" neutral />
        </div>
      </Card>
      <Card><SectionTitle style={{ marginBottom:12 }}>Cola durable</SectionTitle>
        {(tasks.length ? tasks : [{ status:'vacía', count:0 }]).map(item =>
          <div key={item.status} style={{ display:'flex',justifyContent:'space-between',padding:'8px 0',borderBottom:'1px solid var(--border)' }}>
            <span style={{ color:'var(--text-dim)' }}>{item.status}</span><strong>{item.count}</strong>
          </div>)}
      </Card>
    </div>
  </div>
}

function Status({ name, value, neutral=false }) {
  const ok = neutral || value === 'ok' || value === 'healthy'
  return <div style={{ padding:10,background:'var(--bg-card2)',border:'1px solid var(--border)' }}>
    <div style={{ display:'flex',alignItems:'center',gap:7 }}><Dot color={ok?'var(--green)':'var(--yellow)'} size={6} />
      <span style={{ fontSize:11 }}>{name}</span></div>
    <div style={{ marginTop:5,fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>{value || '—'}</div>
  </div>
}
