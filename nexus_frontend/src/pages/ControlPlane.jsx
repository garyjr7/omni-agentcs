import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { nexusApi } from '../api/client'
import { useAuthStore } from '../store/authStore'
import { Badge, Btn, Card, SectionTitle } from '../components/ui'

function List({ items, empty = 'Sin registros', render }) {
  if (!items?.length) return <div style={{ color:'var(--text-dim)',fontSize:12 }}>{empty}</div>
  return <div style={{ display:'flex',flexDirection:'column',gap:7 }}>{items.map(render)}</div>
}

export default function ControlPlane() {
  const user = useAuthStore(s => s.user)
  const tenant = user?.tenant_id || 'system'
  const qc = useQueryClient()
  const agents = useQuery({ queryKey:['directory-agents', tenant], queryFn:async()=>(await nexusApi.directoryAgents(tenant)).data.items })
  const tools = useQuery({ queryKey:['directory-tools', tenant], queryFn:async()=>(await nexusApi.directoryTools(tenant)).data.items })
  const packages = useQuery({ queryKey:['packages', tenant], queryFn:async()=>(await nexusApi.packages(tenant)).data.items })
  const evolution = useQuery({ queryKey:['evolution', tenant], queryFn:async()=>(await nexusApi.evolution(tenant)).data.items })
  const installMarketing = useMutation({
    mutationFn:()=>nexusApi.installPackage({ package_path:'marketing', tenant_id:tenant }),
    onSuccess:()=>{
      qc.invalidateQueries({ queryKey:['packages', tenant] })
      qc.invalidateQueries({ queryKey:['directory-agents', tenant] })
    },
  })

  const row = (item, subtitle) => (
    <div key={item.id || item.agent_id || item.tool_id} style={{ padding:9,background:'var(--bg-card2)',border:'1px solid var(--border)',borderRadius:3 }}>
      <div style={{ display:'flex',justifyContent:'space-between',gap:8 }}>
        <span style={{ color:'var(--text-bright)',fontSize:12 }}>{item.name || item.package_name || item.title}</span>
        <Badge color="var(--cyan)">{item.version || item.status || 'ACTIVE'}</Badge>
      </div>
      <div style={{ color:'var(--text-dim)',fontFamily:'var(--mono)',fontSize:9,marginTop:4 }}>{subtitle || item.id || item.agent_id || item.tool_id}</div>
    </div>
  )

  return (
    <div style={{ padding:24 }}>
      <div style={{ fontFamily:'var(--display)',fontSize:22,color:'var(--text-bright)',letterSpacing:2 }}>NEXUS CONTROL PLANE</div>
      <div style={{ color:'var(--text-dim)',fontFamily:'var(--mono)',fontSize:10,margin:'5px 0 20px' }}>TENANT · {tenant}</div>
      <div style={{ display:'grid',gridTemplateColumns:'repeat(2,minmax(0,1fr))',gap:12 }}>
        <Card>
          <SectionTitle style={{ marginBottom:12 }}>Agentes del Directorio · {agents.data?.length || 0}</SectionTitle>
          <List items={agents.data} render={item=>row(item, (item.capabilities || []).join(' · '))} />
        </Card>
        <Card>
          <SectionTitle style={{ marginBottom:12 }}>Tools gobernadas · {tools.data?.length || 0}</SectionTitle>
          <List items={tools.data} render={item=>row(item, `risk: ${item.risk || 'read_only'}`)} />
        </Card>
        <Card>
          <div style={{ display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12 }}>
            <SectionTitle>Paquetes departamentales</SectionTitle>
            <Btn onClick={()=>installMarketing.mutate()} style={{ opacity:installMarketing.isPending ? .7 : 1 }}>Instalar Marketing</Btn>
          </div>
          {installMarketing.error && <div style={{ color:'var(--red)',fontSize:11,marginBottom:8 }}>{installMarketing.error.response?.data?.detail || installMarketing.error.message}</div>}
          <List items={packages.data} render={item=>row(item, item.package_name)} />
        </Card>
        <Card>
          <SectionTitle style={{ marginBottom:12 }}>Evolution Lab</SectionTitle>
          <List items={evolution.data} render={item=>row(item, item.hypothesis)} empty="Sin propuestas de evolución" />
        </Card>
      </div>
    </div>
  )
}
