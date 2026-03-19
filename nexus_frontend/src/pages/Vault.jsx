import { useState } from 'react'
import { Card, Btn, Badge } from '../components/ui'

const MOCK_SECRETS = [
  { id:1, name:'ANTHROPIC_API_KEY', type:'API Key', icon:'🔑', masked:'sk-ant-••••••••••••••••••••••••XTR3', updated:'hace 2h',  agents:['Junior','GuardianAI'] },
  { id:2, name:'OPENAI_API_KEY',    type:'API Key', icon:'🔑', masked:'sk-••••••••••••••••••••••••NEXUS1',  updated:'hace 1d',  agents:['CodeAgent'] },
  { id:3, name:'CHROMADB_TOKEN',    type:'Token',   icon:'🪙', masked:'chroma-••••••••••••••••••••2024',    updated:'hace 2h',  agents:['Junior','FileAgent'] },
  { id:4, name:'NEXUS_JWT_SECRET',  type:'JWT',     icon:'🛡️', masked:'eyJ••••••••••••••••••••••••••',      updated:'hace 6h',  agents:['All'] },
  { id:5, name:'DOCKER_HUB_TOKEN',  type:'Token',   icon:'🐳', masked:'dckr_pat_••••••••••••••••••••',      updated:'hace 2d',  agents:['CodeAgent'] },
  { id:6, name:'SSH_PRIV_KEY_PROD', type:'SSH Key', icon:'🗝️', masked:'-----BEGIN RSA PRIVATE••••••',       updated:'hace 7d',  agents:['BashAgent'] },
  { id:7, name:'GEMINI_API_KEY',    type:'API Key', icon:'🔑', masked:'AIza••••••••••••••••••••••••••',      updated:'hace 3d',  agents:['Junior'] },
]

function AddSecretModal({ onClose }) {
  const [form, setForm] = useState({ name:'', type:'API Key', value:'', agents:'' })
  const set=(k,v)=>setForm(f=>({...f,[k]:v}))
  return (
    <div style={{ position:'fixed',inset:0,background:'rgba(2,5,8,.85)',backdropFilter:'blur(4px)',display:'flex',alignItems:'center',justifyContent:'center',zIndex:1000 }}>
      <div style={{ background:'var(--bg-panel)',border:'1px solid var(--border)',borderRadius:6,padding:24,width:460 }}>
        <div style={{ fontFamily:'var(--display)',fontSize:16,color:'var(--text-bright)',marginBottom:4 }}>NUEVO SECRET</div>
        <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginBottom:20 }}>Cifrado AES-256 · solo accesible por agentes autorizados</div>
        <div style={{ marginBottom:14 }}>
          <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>Nombre</label>
          <input value={form.name} onChange={e=>set('name',e.target.value)} placeholder="OPENAI_API_KEY"
            style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--mono)',fontSize:13,outline:'none' }} />
        </div>
        <div style={{ display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:14 }}>
          <div>
            <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>Tipo</label>
            <select value={form.type} onChange={e=>set('type',e.target.value)}
              style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none' }}>
              {['API Key','Password','Token JWT','Certificate','SSH Key'].map(o=><option key={o}>{o}</option>)}
            </select>
          </div>
          <div>
            <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>Agentes con acceso</label>
            <input value={form.agents} onChange={e=>set('agents',e.target.value)} placeholder="Junior, CodeAgent"
              style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--ui)',fontSize:13,outline:'none' }} />
          </div>
        </div>
        <div style={{ marginBottom:14 }}>
          <label style={{ display:'block',fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:1,textTransform:'uppercase',marginBottom:6 }}>Valor (se cifrará)</label>
          <input type="password" value={form.value} onChange={e=>set('value',e.target.value)} placeholder="sk-..."
            style={{ width:'100%',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:3,padding:'8px 12px',color:'var(--text)',fontFamily:'var(--mono)',fontSize:13,outline:'none' }} />
        </div>
        <div style={{ display:'flex',gap:10,justifyContent:'flex-end',paddingTop:16,borderTop:'1px solid var(--border)',marginTop:16 }}>
          <Btn variant="ghost" onClick={onClose}>CANCELAR</Btn>
          <Btn variant="primary" onClick={onClose}>GUARDAR SECRET</Btn>
        </div>
      </div>
    </div>
  )
}

export default function Vault() {
  const [revealed, setRevealed] = useState(new Set())
  const [showModal, setShowModal] = useState(false)
  const toggle = (id) => setRevealed(r=>{ const n=new Set(r); n.has(id)?n.delete(id):n.add(id); return n })

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      {showModal && <AddSecretModal onClose={()=>setShowModal(false)} />}
      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Secrets Vault</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>GESTIÓN DE CREDENCIALES · CIFRADO AES-256 · {MOCK_SECRETS.length} SECRETS</div>
        </div>
        <Btn variant="primary" onClick={()=>setShowModal(true)}>+ NUEVO SECRET</Btn>
      </div>
      <div style={{ display:'flex',flexDirection:'column',gap:8 }}>
        {MOCK_SECRETS.map(s=>(
          <div key={s.id} style={{ background:'var(--bg-card)',border:'1px solid var(--border)',borderRadius:4,padding:'14px 16px',display:'flex',alignItems:'center',gap:12 }}>
            <div style={{ width:36,height:36,background:'var(--bg-base)',border:'1px solid var(--purple)',borderRadius:4,display:'flex',alignItems:'center',justifyContent:'center',fontSize:16,color:'var(--purple)',flexShrink:0 }}>{s.icon}</div>
            <div style={{ flex:1 }}>
              <div style={{ fontSize:13,fontWeight:600,color:'var(--text-bright)' }}>{s.name}</div>
              <div style={{ fontFamily:'var(--mono)',fontSize:12,color:'var(--text-dim)',marginTop:2,letterSpacing:2 }}>
                {revealed.has(s.id) ? s.masked : s.masked.replace(/[^•\-]/g,'•')}
              </div>
              <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)',marginTop:3 }}>
                {s.type} · Actualizado: {s.updated} · Agentes: {s.agents.join(', ')}
              </div>
            </div>
            <div style={{ display:'flex',gap:6 }}>
              {[
                [revealed.has(s.id)?'🙈':'👁️', ()=>toggle(s.id), 'Revelar'],
                ['📋', ()=>navigator.clipboard.writeText(s.masked), 'Copiar'],
                ['🔄', ()=>{}, 'Rotar'],
                ['🗑️', ()=>{}, 'Eliminar'],
              ].map(([icon,fn,title])=>(
                <button key={title} title={title} onClick={fn} style={{ width:28,height:28,borderRadius:3,background:'var(--bg-base)',border:'1px solid var(--border)',color:'var(--text-dim)',cursor:'pointer',display:'flex',alignItems:'center',justifyContent:'center',fontSize:13,transition:'all .2s' }}>
                  {icon}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
