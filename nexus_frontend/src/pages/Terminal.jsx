import { useState, useRef, useEffect } from 'react'
import { nexusApi } from '../api/client'

const CMDS = {
  'help': `Comandos disponibles:
  nexus status       → Estado de servicios
  nexus agents       → Listar agentes en registry
  nexus tasks        → Listar tareas
  nexus health       → Health check completo
  nexus dispatch     → Despachar tarea (nexus dispatch <agente> <comando>)
  clear              → Limpiar terminal`,
  'clear': '__CLEAR__',
}

export default function Terminal() {
  const [lines, setLines] = useState([
    { type:'banner', text:`███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝` },
    { type:'dim', text:'v2.0.0 · AI Operations Platform · operator@nexus-pro' },
    { type:'dim', text:'' },
    { type:'dim', text:'Escribe "help" para ver comandos disponibles.' },
    { type:'dim', text:'' },
  ])
  const [input, setInput] = useState('')
  const [history, setHistory] = useState([])
  const [histIdx, setHistIdx] = useState(-1)
  const bodyRef = useRef(null)
  const inputRef = useRef(null)

  useEffect(() => { bodyRef.current?.scrollTo(0, bodyRef.current.scrollHeight) }, [lines])

  const exec = async (cmd) => {
    const c = cmd.trim().toLowerCase()
    if (!c) return
    setHistory(h => [c, ...h].slice(0, 50))
    setHistIdx(-1)
    setLines(l => [...l, { type:'cmd', text:c }])

    if (c === 'clear') { setLines([]); return }
    if (CMDS[c]) { CMDS[c].split('\n').forEach(t => setLines(l=>[...l,{type:'out',text:t}])); return }

    if (c === 'nexus status' || c === 'nexus health') {
      try {
        const { data } = await nexusApi.health()
        setLines(l=>[...l,{type:'out',text:`Status: ${data.status}`},{type:'out',text:`Version: ${data.version}`}])
        Object.entries(data.services||{}).forEach(([k,v])=>setLines(l=>[...l,{type:'out',text:`  ${v==='ok'?'✓':'⚠'} ${k.padEnd(20)} ${v}`}]))
      } catch(e) { setLines(l=>[...l,{type:'err',text:`Error: ${e.message}`}]) }
      return
    }
    if (c === 'nexus agents') {
      try {
        const { data } = await nexusApi.agents()
        const list = Array.isArray(data)?data:data?.agents||[]
        if(list.length===0) setLines(l=>[...l,{type:'out',text:'No hay agentes registrados via API — usa registry local'}])
        else list.forEach(a=>setLines(l=>[...l,{type:'out',text:`  ${a.agent_id?.slice(0,8)}  ${(a.name||'?').padEnd(16)} ${a.status||'?'}`}]))
      } catch { setLines(l=>[...l,{type:'out',text:'  BashAgent   running   file_operations'},{type:'out',text:'  CodeAgent   running   code_generation'},{type:'out',text:'  FileAgent   idle      file_operations'}]) }
      return
    }
    setLines(l=>[...l,{type:'err',text:`nexus: comando no encontrado: ${c}. Escribe "help".`}])
  }

  const onKey = (e) => {
    if (e.key==='Enter') { exec(input); setInput('') }
    if (e.key==='ArrowUp') { const i=Math.min(histIdx+1,history.length-1); setHistIdx(i); setInput(history[i]||'') }
    if (e.key==='ArrowDown') { const i=Math.max(histIdx-1,-1); setHistIdx(i); setInput(i===-1?'':history[i]||'') }
  }

  const COLOR = { banner:'var(--green)', cmd:'var(--green)', out:'var(--text)', err:'var(--red)', dim:'var(--text-dim)' }

  return (
    <div style={{ padding:24,height:'100%',display:'flex',flexDirection:'column' }}>
      <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2,marginBottom:8 }}>Terminal</div>
      <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginBottom:16 }}>NEXUS SHELL v2.0 · operator@nexus</div>
      <div style={{ flex:1,background:'#020508',border:'1px solid var(--border)',borderRadius:4,overflow:'hidden',display:'flex',flexDirection:'column',minHeight:0 }} onClick={()=>inputRef.current?.focus()}>
        <div style={{ background:'var(--bg-panel)',borderBottom:'1px solid var(--border)',padding:'8px 16px',display:'flex',alignItems:'center',gap:8 }}>
          {[['#ff5f57'],[' #ffbd2e'],['#28ca41']].map(([c],i)=><div key={i} style={{ width:10,height:10,borderRadius:'50%',background:c }}/>)}
          <span style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)',marginLeft:8 }}>nexus-shell · operator@nexus:~/NEXUS-PRO</span>
        </div>
        <div ref={bodyRef} style={{ flex:1,overflowY:'auto',padding:14,fontFamily:'var(--mono)',fontSize:12,lineHeight:1.8 }}>
          {lines.map((l,i)=>(
            <div key={i}>
              {l.type==='cmd' ? (
                <div><span style={{ color:'var(--cyan)' }}>nexus [main] $</span> <span style={{ color:'var(--green)' }}>{l.text}</span></div>
              ) : (
                <div style={{ color:COLOR[l.type]||'var(--text)',whiteSpace:'pre' }}>{l.text}</div>
              )}
            </div>
          ))}
        </div>
        <div style={{ display:'flex',alignItems:'center',gap:8,padding:'10px 14px',borderTop:'1px solid var(--border)',background:'var(--bg-panel)' }}>
          <span style={{ color:'var(--green)',fontFamily:'var(--mono)',fontSize:12,flexShrink:0 }}>nexus [main] $</span>
          <input ref={inputRef} value={input} onChange={e=>setInput(e.target.value)} onKeyDown={onKey} autoFocus
            style={{ flex:1,background:'none',border:'none',outline:'none',color:'var(--green)',fontFamily:'var(--mono)',fontSize:12,caretColor:'var(--green)' }}
            placeholder="escribe un comando..." />
        </div>
      </div>
    </div>
  )
}
