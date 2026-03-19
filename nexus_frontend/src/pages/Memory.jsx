import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, Btn, Dot } from '../components/ui'
import { api } from '../api/client'

const memApi = {
  agents:  ()         => api.get('/memory/agents'),
  context: (id, sid)  => api.get(`/memory/agents/${id}`, { params: sid ? { session_id: sid } : {} }),
  stats:   (id)       => api.get(`/memory/agents/${id}/stats`),
  search:  (id, q)    => api.get(`/memory/agents/${id}/search`, { params: { q } }),
  clear:   (id, sid)  => api.delete(`/memory/agents/${id}`, { params: sid ? { session_id: sid } : {} }),
}

const ROLE_COLOR = { user:'var(--cyan)', assistant:'var(--green)', system:'var(--yellow)' }
const ROLE_ICON  = { user:'👤', assistant:'🤖', system:'⚙️' }

export default function Memory() {
  const qc = useQueryClient()
  const [selected, setSelected]   = useState(null)
  const [session,  setSession]    = useState(null)
  const [search,   setSearch]     = useState('')
  const [searchRes,setSearchRes]  = useState(null)

  const { data: agentsData, isLoading } = useQuery({
    queryKey: ['memory-agents'],
    queryFn: () => memApi.agents().then(r => r.data),
    refetchInterval: 10000,
  })

  const { data: ctxData } = useQuery({
    queryKey: ['memory-ctx', selected, session],
    queryFn: () => memApi.context(selected, session).then(r => r.data),
    enabled: !!selected,
  })

  const clearMutation = useMutation({
    mutationFn: ({ id, sid }) => memApi.clear(id, sid),
    onSuccess: () => {
      qc.invalidateQueries(['memory-agents'])
      qc.invalidateQueries(['memory-ctx', selected, session])
    },
  })

  const doSearch = async () => {
    if (!selected || !search.trim()) return
    const { data } = await memApi.search(selected, search)
    setSearchRes(data.results)
  }

  const agents = agentsData?.agents || []
  const ctx    = ctxData?.context  || []
  const stats  = ctxData?.stats    || {}
  const summary= ctxData?.summary

  return (
    <div style={{ padding:24, height:'100%', display:'flex', flexDirection:'column', gap:16 }}>
      <div>
        <div style={{ fontFamily:'var(--display)', fontSize:22, fontWeight:700,
          color:'var(--text-bright)', letterSpacing:2 }}>Memoria de Agentes</div>
        <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:4 }}>
          LONG-TERM MEMORY · SQLite · CONTEXT PERSISTENCE
        </div>
      </div>

      <div style={{ flex:1, display:'grid', gridTemplateColumns:'240px 1fr', gap:12, minHeight:0 }}>

        {/* Panel izquierdo — lista agentes */}
        <div style={{ overflowY:'auto', display:'flex', flexDirection:'column', gap:6 }}>
          <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)',
            letterSpacing:2, marginBottom:4 }}>
            {agents.length} AGENTES CON MEMORIA
          </div>
          {isLoading ? (
            <div style={{ fontFamily:'var(--mono)', fontSize:11,
              color:'var(--text-dim)', textAlign:'center', padding:'20px 0' }}>⟳</div>
          ) : agents.length === 0 ? (
            <div style={{ fontFamily:'var(--mono)', fontSize:11,
              color:'var(--text-dim)', textAlign:'center', padding:'30px 0',
              border:'1px dashed var(--border)', borderRadius:4 }}>
              Sin memoria aún<br/>
              <span style={{ fontSize:9 }}>Usa Junior o chatea con un agente</span>
            </div>
          ) : agents.map(a => (
            <div key={a.agent_id}
              onClick={() => { setSelected(a.agent_id); setSession(null); setSearchRes(null) }}
              style={{ padding:'10px 12px', borderRadius:3, cursor:'pointer',
                border:`1px solid ${selected === a.agent_id ? 'var(--green)' : 'var(--border)'}`,
                background: selected === a.agent_id ? '#00ff9d08' : 'var(--bg-card)',
                transition:'all .15s' }}>
              <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4 }}>
                <div style={{ width:28, height:28, borderRadius:3,
                  background:'#00ff9d10', border:'1px solid var(--green)',
                  display:'flex', alignItems:'center', justifyContent:'center', fontSize:14 }}>🤖</div>
                <div style={{ flex:1, overflow:'hidden' }}>
                  <div style={{ fontSize:12, fontWeight:600, color:'var(--text-bright)',
                    overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                    {a.agent_name}
                  </div>
                  <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)' }}>
                    {a.agent_id.slice(0,12)}...
                  </div>
                </div>
              </div>
              <div style={{ display:'flex', gap:8, fontFamily:'var(--mono)', fontSize:9 }}>
                <span style={{ color:'var(--cyan)' }}>{a.total_msgs} msgs</span>
                <span style={{ color:'var(--text-dim)' }}>·</span>
                <span style={{ color:'var(--yellow)' }}>~{Math.round((a.total_tokens||0)/1000)}k tokens</span>
              </div>
              <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)', marginTop:3 }}>
                {new Date(a.last_activity).toLocaleString()}
              </div>
            </div>
          ))}
        </div>

        {/* Panel derecho — contexto */}
        <div style={{ overflowY:'auto', display:'flex', flexDirection:'column', gap:10 }}>
          {!selected ? (
            <div style={{ display:'flex', alignItems:'center', justifyContent:'center',
              height:'100%', flexDirection:'column', gap:12 }}>
              <div style={{ fontSize:48, opacity:.1 }}>🧠</div>
              <div style={{ fontFamily:'var(--display)', fontSize:16, color:'var(--text-dim)' }}>
                Selecciona un agente
              </div>
            </div>
          ) : (
            <>
              {/* Stats + acciones */}
              <div style={{ display:'flex', gap:10, alignItems:'center', flexWrap:'wrap' }}>
                <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)' }}>
                  {stats.total_messages || 0} mensajes ·
                  ~{Math.round((stats.total_tokens_est||0)/1000)}k tokens est. ·
                  {(stats.sessions||[]).length} sesiones
                </div>
                <div style={{ flex:1 }} />
                <div style={{ display:'flex', gap:8 }}>
                  <input value={search} onChange={e=>setSearch(e.target.value)}
                    onKeyDown={e=>e.key==='Enter'&&doSearch()}
                    placeholder="Buscar en memoria..."
                    style={{ background:'var(--bg-card)', border:'1px solid var(--border)',
                      borderRadius:3, padding:'5px 10px', color:'var(--text)',
                      fontFamily:'var(--mono)', fontSize:11, outline:'none', width:180 }} />
                  <Btn variant="ghost" onClick={doSearch}>🔍</Btn>
                  <Btn variant="danger"
                    onClick={() => clearMutation.mutate({ id:selected, sid:session })}
                    style={{ opacity: clearMutation.isPending ? .6 : 1 }}>
                    🗑 LIMPIAR
                  </Btn>
                </div>
              </div>

              {/* Sesiones */}
              {(stats.sessions||[]).length > 0 && (
                <div style={{ display:'flex', gap:6, flexWrap:'wrap' }}>
                  <button onClick={()=>setSession(null)}
                    style={{ padding:'3px 10px', borderRadius:10,
                      border:`1px solid ${!session?'var(--green)':'var(--border)'}`,
                      background:!session?'#00ff9d10':'transparent',
                      color:!session?'var(--green)':'var(--text-dim)',
                      cursor:'pointer', fontFamily:'var(--mono)', fontSize:10 }}>
                    TODAS
                  </button>
                  {stats.sessions.map(s => (
                    <button key={s.session_id} onClick={()=>setSession(s.session_id)}
                      style={{ padding:'3px 10px', borderRadius:10,
                        border:`1px solid ${session===s.session_id?'var(--cyan)':'var(--border)'}`,
                        background:session===s.session_id?'#00d4ff10':'transparent',
                        color:session===s.session_id?'var(--cyan)':'var(--text-dim)',
                        cursor:'pointer', fontFamily:'var(--mono)', fontSize:10,
                        maxWidth:140, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                      {s.session_id?.slice(0,16)}… ({s.msgs})
                    </button>
                  ))}
                </div>
              )}

              {/* Resumen */}
              {summary && (
                <Card style={{ border:'1px solid var(--purple)', background:'#8b5cf610' }}>
                  <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--purple)',
                    letterSpacing:2, marginBottom:6 }}>RESUMEN DE CONTEXTO</div>
                  <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text)',
                    lineHeight:1.6, whiteSpace:'pre-wrap' }}>{summary}</div>
                </Card>
              )}

              {/* Resultados de búsqueda */}
              {searchRes && (
                <Card style={{ border:'1px solid var(--yellow)' }}>
                  <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--yellow)',
                    letterSpacing:2, marginBottom:8 }}>
                    {searchRes.length} RESULTADOS — "{search}"
                    <button onClick={()=>setSearchRes(null)}
                      style={{ marginLeft:10, background:'none', border:'none',
                        color:'var(--text-dim)', cursor:'pointer', fontSize:10 }}>✕</button>
                  </div>
                  {searchRes.map((r,i) => (
                    <div key={i} style={{ padding:'6px 0', borderBottom:'1px solid var(--border)',
                      fontFamily:'var(--mono)', fontSize:11, lineHeight:1.5 }}>
                      <span style={{ color:ROLE_COLOR[r.role]||'var(--text-dim)', marginRight:8 }}>
                        [{r.role}]
                      </span>
                      <span style={{ color:'var(--text)' }}>{r.content.slice(0,200)}…</span>
                    </div>
                  ))}
                </Card>
              )}

              {/* Historial de mensajes */}
              <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
                {ctx.length === 0 ? (
                  <div style={{ textAlign:'center', padding:'40px 0',
                    fontFamily:'var(--mono)', fontSize:11, color:'var(--text-dim)' }}>
                    Sin mensajes en esta sesión
                  </div>
                ) : ctx.map((msg, i) => (
                  <div key={i} style={{ display:'flex', gap:10, alignItems:'flex-start',
                    justifyContent: msg.role==='user' ? 'flex-end' : 'flex-start' }}>
                    {msg.role !== 'user' && (
                      <div style={{ width:28, height:28, borderRadius:3, flexShrink:0,
                        background:`${ROLE_COLOR[msg.role]||'var(--green)'}15`,
                        border:`1px solid ${ROLE_COLOR[msg.role]||'var(--green)'}`,
                        display:'flex', alignItems:'center', justifyContent:'center', fontSize:14 }}>
                        {ROLE_ICON[msg.role]||'🤖'}
                      </div>
                    )}
                    <div style={{ maxWidth:'75%', padding:'8px 12px', borderRadius:4,
                      background: msg.role==='user' ? '#00d4ff10' : 'var(--bg-card)',
                      border:`1px solid ${ROLE_COLOR[msg.role]||'var(--border)'}30`,
                      fontFamily:'var(--mono)', fontSize:11, color:'var(--text)',
                      lineHeight:1.6, whiteSpace:'pre-wrap', wordBreak:'break-word' }}>
                      {msg.content.slice(0,500)}{msg.content.length>500?'…':''}
                      <div style={{ marginTop:4, fontSize:9, color:'var(--text-dim)',
                        textAlign: msg.role==='user' ? 'right' : 'left' }}>
                        {new Date(msg.created_at).toLocaleTimeString()}
                      </div>
                    </div>
                    {msg.role === 'user' && (
                      <div style={{ width:28, height:28, borderRadius:3, flexShrink:0,
                        background:'#00d4ff15', border:'1px solid var(--cyan)',
                        display:'flex', alignItems:'center', justifyContent:'center', fontSize:14 }}>👤</div>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
