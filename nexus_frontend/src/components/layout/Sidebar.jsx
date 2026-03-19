import { useNexusStore } from '../../store/nexusStore'

const NAV = [
  { section:'Centro de Mando', items:[
    { id:'overview', icon:'◈', label:'Overview' },
  ]},
  { section:'Orquestación', items:[
    { id:'agents',  icon:'⬡', label:'Agentes IA',    badgeKey:'agents' },
    { id:'teams',   icon:'◎', label:'Equipos' },
    { id:'tasks',   icon:'▷', label:'Tareas',         badgeKey:'tasks' },
    { id:'models',  icon:'◇', label:'Modelos & APIs' },
  ]},
  { section:'IA Autónoma', items:[
    { id:'factory', icon:'🏭', label:'SW Factory',    highlight:true },
    { id:'junior',  icon:'🤖', label:'Junior Agent',  highlight:true },
    { id:'pentest', icon:'🔴', label:'Pentest',        highlight:true },
  ]},
  { section:'Seguridad', items:[
    { id:'hitl',    icon:'⚠', label:'HITL',           badgeKey:'hitl', badgeColor:'var(--red)' },
    { id:'vault',   icon:'◉', label:'Secrets Vault' },
    { id:'guardian',icon:'⬟', label:'Guardian Scan' },
    { id:'memory',  icon:'🧠', label:'Memoria IA',  highlight:true },
    { id:'users',   icon:'👥', label:'Usuarios',     badgeKey:null },
    { id:'rbac',    icon:'⊞', label:'Roles / RBAC' },
    { id:'audit',   icon:'≡', label:'Audit Trail' },
  ]},
  { section:'Sistema', items:[
    { id:'terminal', icon:'▸', label:'Terminal' },
    { id:'settings', icon:'⚙', label:'Configuración' },
  ]},
]

export default function Sidebar() {
  const { activePage, setActivePage, agents, tasks, hitlCount } = useNexusStore()
  const counts = { agents:agents.length, tasks:tasks.length, hitl:hitlCount }

  return (
    <nav style={{ width:200,flexShrink:0,background:'var(--bg-panel)',
      borderRight:'1px solid var(--border)',overflowY:'auto',overflowX:'hidden',
      padding:'16px 0',display:'flex',flexDirection:'column' }}>
      <div style={{ flex:1 }}>
        {NAV.map(({ section, items }) => (
          <div key={section} style={{ marginBottom:20 }}>
            <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'#2a5060',
              letterSpacing:2,padding:'0 16px 6px',textTransform:'uppercase' }}>{section}</div>
            {items.map(item => {
              const active = activePage === item.id
              const count  = item.badgeKey ? counts[item.badgeKey] : null
              return (
                <div key={item.id} onClick={()=>setActivePage(item.id)} style={{
                  display:'flex',alignItems:'center',gap:10,padding:'8px 16px',cursor:'pointer',
                  fontSize:13,fontWeight:500,letterSpacing:.5,
                  color: active ? 'var(--green)' : item.highlight ? 'var(--cyan)' : 'var(--text-dim)',
                  borderLeft: active ? '2px solid var(--green)' : '2px solid transparent',
                  background: active ? '#00ff9d08' : 'transparent',
                  transition:'all .15s',
                }}>
                  <span style={{ width:16,textAlign:'center',fontSize:13 }}>{item.icon}</span>
                  <span style={{ flex:1 }}>{item.label}</span>
                  {count > 0 && (
                    <span style={{ fontFamily:'var(--mono)',fontSize:10,padding:'0 6px',
                      borderRadius:10,minWidth:20,textAlign:'center',
                      border:`1px solid ${item.badgeColor||'var(--green)'}`,
                      color:item.badgeColor||'var(--green)',background:'var(--bg-base)' }}>
                      {count}
                    </span>
                  )}
                </div>
              )
            })}
          </div>
        ))}
      </div>
      <div style={{ margin:'0 12px',padding:'10px 12px',background:'var(--bg-card)',
        border:'1px solid var(--border)',borderRadius:4,display:'flex',alignItems:'center',gap:10 }}>
        <div style={{ width:32,height:32,borderRadius:3,flexShrink:0,
          background:'linear-gradient(135deg,#003d20,#004466)',border:'1px solid var(--green)',
          display:'flex',alignItems:'center',justifyContent:'center',
          fontFamily:'var(--display)',fontSize:10,color:'var(--green)' }}>MC</div>
        <div>
          <div style={{ fontSize:12,fontWeight:600,color:'var(--text-bright)' }}>Marcos</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>ADMIN · CORP</div>
        </div>
      </div>
    </nav>
  )
}
