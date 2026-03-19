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
