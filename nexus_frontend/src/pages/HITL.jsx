import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNexusStore } from '../store/nexusStore'
import { useHITLWebSocket } from '../hooks/useWebSocket'
import { Btn, Dot } from '../components/ui'
import { nexusApi } from '../api/client'

const RISK_COLOR = { CRITICAL:'var(--red)', HIGH:'var(--orange)', MEDIUM:'var(--yellow)', LOW:'var(--cyan)' }
const RISK_BG    = { CRITICAL:'#ff386015', HIGH:'#ff6b3515', MEDIUM:'#ffc10715', LOW:'#00d4ff15' }

export default function HITL() {
  const qc = useQueryClient()
  const { hitlItems, hitlCount, wsHITL } = useNexusStore()
  const { sendCommand } = useHITLWebSocket()
  const [resolved, setResolved] = useState({})
  const [reasoning, setReasoning] = useState({})

  // Cargar pendientes al montar
  const { data: apiPending } = useQuery({
    queryKey: ['hitl-pending'],
    queryFn: async () => { const { data } = await nexusApi.hitlPending(); return data.pending || [] },
    refetchInterval: 3000,
  })

  const items = hitlItems.length > 0 ? hitlItems : (apiPending || [])
  const pending = items.filter(h => !resolved[h.id])

  const approveMutation = useMutation({
    mutationFn: ({ id }) => nexusApi.approveHITL(id, 'marcos', reasoning[id] || 'Aprobado desde dashboard'),
    onSuccess: (_, { id }) => {
      setResolved(r => ({ ...r, [id]: 'approved' }))
      qc.invalidateQueries(['hitl-pending'])
    },
  })
  const denyMutation = useMutation({
    mutationFn: ({ id }) => nexusApi.denyHITL(id, 'marcos', reasoning[id] || 'Denegado desde dashboard'),
    onSuccess: (_, { id }) => {
      setResolved(r => ({ ...r, [id]: 'denied' }))
      qc.invalidateQueries(['hitl-pending'])
    },
  })
  const approveAllMutation = useMutation({
    mutationFn: nexusApi.approveAllHITL,
    onSuccess: () => { pending.forEach(h => setResolved(r=>({...r,[h.id]:'approved'}))); qc.invalidateQueries(['hitl-pending']) },
  })
  const denyAllMutation = useMutation({
    mutationFn: nexusApi.denyAllHITL,
    onSuccess: () => { pending.forEach(h => setResolved(r=>({...r,[h.id]:'denied'}))); qc.invalidateQueries(['hitl-pending']) },
  })

  return (
    <div style={{ padding:24, overflowY:'auto', height:'100%' }}>
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)', fontSize:22, fontWeight:700, color:'var(--text-bright)', letterSpacing:2 }}>
            HITL — Aprobaciones
          </div>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:4, display:'flex', alignItems:'center', gap:8 }}>
            HUMAN IN THE LOOP · {pending.length} PENDIENTES
            <Dot color={wsHITL ? 'var(--green)' : 'var(--red)'} size={6} />
            <span style={{ color: wsHITL ? 'var(--green)' : 'var(--red)' }}>{wsHITL ? 'WS LIVE' : 'WS OFF'}</span>
          </div>
        </div>
        {pending.length > 0 && (
          <div style={{ display:'flex', gap:8 }}>
            <Btn variant="primary" onClick={()=>approveAllMutation.mutate()}>✓ APROBAR TODOS</Btn>
            <Btn variant="danger"  onClick={()=>denyAllMutation.mutate()}>✗ DENEGAR TODOS</Btn>
          </div>
        )}
      </div>

      {pending.length === 0 ? (
        <div style={{ textAlign:'center', padding:'60px 0' }}>
          <div style={{ fontSize:48, marginBottom:12, opacity:.2 }}>✓</div>
          <div style={{ fontFamily:'var(--display)', fontSize:16, color:'var(--green)' }}>Sin pendientes</div>
          <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text-dim)', marginTop:6 }}>
            Todos los agentes operando normalmente
          </div>
        </div>
      ) : (
        <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
          {pending.map(h => {
            const rc = RISK_COLOR[h.risk] || 'var(--yellow)'
            const bg = RISK_BG[h.risk] || '#ffc10715'
            const isApproving = approveMutation.isPending && approveMutation.variables?.id === h.id
            const isDenying   = denyMutation.isPending   && denyMutation.variables?.id === h.id
            return (
              <div key={h.id} style={{ background:'var(--bg-card)', border:`1px solid ${rc}`, borderRadius:4, padding:16,
                boxShadow:`0 0 12px ${rc}22`, animation:'hitlPulse 3s infinite' }}>
                <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:10 }}>
                  <div style={{ width:40, height:40, display:'flex', alignItems:'center', justifyContent:'center',
                    fontSize:20, border:`1px solid ${rc}`, background:bg, borderRadius:4, flexShrink:0 }}>
                    {h.tool === 'bash_exec' ? '⚙️' : h.tool === 'nmap_scan' ? '🔍' :
                     h.tool === 'file_delete' ? '🗑️' : h.tool === 'nuclei_scan' ? '⚡' : '⚠️'}
                  </div>
                  <div style={{ flex:1 }}>
                    <div style={{ fontFamily:'var(--mono)', fontSize:10, color:rc }}>{h.id}</div>
                    <div style={{ fontSize:15, fontWeight:600, color:'var(--text-bright)' }}>{h.action}</div>
                  </div>
                  <div style={{ padding:'3px 10px', border:`1px solid ${rc}`, borderRadius:10,
                    fontFamily:'var(--mono)', fontSize:10, color:rc, background:bg }}>
                    {h.risk}
                  </div>
                </div>

                {/* Contexto */}
                <div style={{ background:'var(--bg-base)', border:'1px solid var(--border)', borderRadius:3,
                  padding:12, fontFamily:'var(--mono)', fontSize:11, lineHeight:1.8,
                  marginBottom:12, color:'var(--text-dim)', whiteSpace:'pre-wrap' }}>
                  {h.context}
                  {'\n\n'}<span style={{ color:'var(--text)' }}>Agente: {h.agent_name}</span>
                  {' · '}<span style={{ color:'var(--text)' }}>Tool: {h.tool}</span>
                  {' · '}<span style={{ color:'var(--text)' }}>{new Date(h.created_at).toLocaleTimeString()}</span>
                </div>

                {/* Razonamiento opcional */}
                <input
                  value={reasoning[h.id] || ''}
                  onChange={e => setReasoning(r => ({...r, [h.id]: e.target.value}))}
                  placeholder="Razón (opcional)..."
                  style={{ width:'100%', background:'var(--bg-base)', border:'1px solid var(--border)',
                    borderRadius:3, padding:'6px 10px', color:'var(--text)', fontFamily:'var(--mono)',
                    fontSize:11, outline:'none', marginBottom:10 }}
                />

                <div style={{ display:'flex', gap:10 }}>
                  <Btn variant="primary"
                    onClick={() => approveMutation.mutate({ id: h.id })}
                    style={{ opacity: isApproving ? .6 : 1 }}>
                    {isApproving ? '⟳ APROBANDO...' : '✓ APROBAR'}
                  </Btn>
                  <Btn variant="danger"
                    onClick={() => denyMutation.mutate({ id: h.id })}
                    style={{ opacity: isDenying ? .6 : 1 }}>
                    {isDenying ? '⟳ DENEGANDO...' : '✗ DENEGAR'}
                  </Btn>
                  <Btn variant="ghost">⊕ DETALLE</Btn>
                </div>
              </div>
            )
          })}
        </div>
      )}
      <style>{`@keyframes hitlPulse{0%,100%{box-shadow:0 0 8px rgba(255,193,7,.13)}50%{box-shadow:0 0 20px rgba(255,193,7,.2)}}`}</style>
    </div>
  )
}
