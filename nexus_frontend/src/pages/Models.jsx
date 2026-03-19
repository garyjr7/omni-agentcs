import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, Btn, Badge } from '../components/ui'
import Modal from '../components/ui/Modal'
import { FormGroup, Input, Select, ModalFooter } from '../components/ui/Form'
import { nexusApi } from '../api/client'

const PROVIDERS = ['openai','anthropic','google','groq','together','ollama']
const PROVIDER_ICON = { openai:'🟡', anthropic:'🟢', google:'🔵', groq:'🟠', together:'🟣', ollama:'⚪' }
const PROVIDER_COLOR = { openai:'var(--yellow)', anthropic:'var(--green)', google:'var(--blue)', groq:'var(--orange)', together:'var(--purple)', ollama:'var(--text-dim)' }

function AddKeyModal({ onClose }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ alias:'', provider:'openai', api_key:'' })
  const [loading, setLoading] = useState(false)
  const set = (k,v) => setForm(f=>({...f,[k]:v}))

  const save = async () => {
    if (!form.alias.trim()) return alert('El alias es requerido')
    if (!form.api_key.trim()) return alert('La API key es requerida')
    setLoading(true)
    try {
      await nexusApi.addApiKey(form)
      await qc.invalidateQueries(['api-keys'])
      await qc.invalidateQueries(['models-available'])
      onClose()
    } catch(e) {
      alert(`Error: ${e.response?.data?.detail || e.message}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <Modal title="AGREGAR API KEY" subtitle="Detecta modelos disponibles automáticamente" onClose={onClose} width={460}>
      <FormGroup label="Provider">
        <Select value={form.provider} onChange={v=>set('provider',v)} options={PROVIDERS} />
      </FormGroup>
      <FormGroup label="Alias">
        <Input value={form.alias} onChange={v=>set('alias',v)} placeholder="OpenAI Principal" />
      </FormGroup>
      <FormGroup label="API Key">
        <Input value={form.api_key} onChange={v=>set('api_key',v)} type="password"
          placeholder={form.provider==='openai'?'sk-...':form.provider==='anthropic'?'sk-ant-...':form.provider==='ollama'?'http://localhost:11434':'...'} />
      </FormGroup>
      <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',padding:'8px 10px',
        background:'var(--bg-base)',borderRadius:3,border:'1px solid var(--border)',marginBottom:4 }}>
        ⚡ Al guardar, NEXUS detectará automáticamente los modelos disponibles llamando a la API del provider
      </div>
      <ModalFooter onClose={onClose} onSave={save} saveLabel="DETECTAR MODELOS" loading={loading} />
    </Modal>
  )
}

export default function Models() {
  const qc = useQueryClient()
  const [showModal, setShowModal] = useState(false)

  const { data: keys=[], isLoading: keysLoading } = useQuery({
    queryKey:['api-keys'],
    queryFn: async()=>{ const {data}=await nexusApi.apiKeys(); return data },
    refetchInterval:5000,
  })
  const { data: availData } = useQuery({
    queryKey:['models-available'],
    queryFn: async()=>{ const {data}=await nexusApi.availableModels(); return data },
    refetchInterval:10000,
  })

  const deleteMutation = useMutation({
    mutationFn: (id) => nexusApi.deleteApiKey(id),
    onSuccess: () => { qc.invalidateQueries(['api-keys']); qc.invalidateQueries(['models-available']) },
  })
  const redetectMutation = useMutation({
    mutationFn: (id) => nexusApi.redetect(id),
    onSuccess: () => qc.invalidateQueries(['api-keys']),
  })

  const availableModels = availData?.models || []
  const totalModels = availData?.total || 0

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      {showModal && <AddKeyModal onClose={()=>setShowModal(false)} />}

      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Modelos & APIs</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>
            {keys.length} PROVIDERS · {totalModels} MODELOS DISPONIBLES
          </div>
        </div>
        <Btn variant="cyan" onClick={()=>setShowModal(true)}>+ API KEY</Btn>
      </div>

      {/* API Keys */}
      <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--cyan)',letterSpacing:2,
        textTransform:'uppercase',marginBottom:12 }}>API Keys Configuradas</div>

      {keysLoading ? (
        <div style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)',padding:20 }}>⟳ Cargando...</div>
      ) : keys.length === 0 ? (
        <Card style={{ textAlign:'center',padding:'40px 0',marginBottom:20 }}>
          <div style={{ fontSize:40,marginBottom:10,opacity:.2 }}>🔑</div>
          <div style={{ fontFamily:'var(--display)',fontSize:14,color:'var(--text-dim)' }}>Sin API keys</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:6,marginBottom:16 }}>
            Agrega tu primera API key para activar los modelos
          </div>
          <Btn variant="primary" onClick={()=>setShowModal(true)}>+ AGREGAR API KEY</Btn>
        </Card>
      ) : (
        <div style={{ marginBottom:24 }}>
          {keys.map(k => {
            const pc = PROVIDER_COLOR[k.provider] || 'var(--text-dim)'
            const isOk = k.status === 'ok'
            return (
              <div key={k.id} style={{ background:'var(--bg-card)',border:`1px solid ${isOk?pc+'44':'var(--border)'}`,
                borderRadius:4,padding:'14px 16px',marginBottom:8,display:'flex',alignItems:'flex-start',gap:12 }}>
                <div style={{ width:40,height:40,borderRadius:4,display:'flex',alignItems:'center',justifyContent:'center',
                  fontSize:22,background:'var(--bg-base)',border:`1px solid ${isOk?pc:'var(--border)'}`,flexShrink:0 }}>
                  {PROVIDER_ICON[k.provider]||'🔑'}
                </div>
                <div style={{ flex:1,minWidth:0 }}>
                  <div style={{ display:'flex',alignItems:'center',gap:8,marginBottom:4 }}>
                    <div style={{ fontSize:14,fontWeight:600,color:'var(--text-bright)' }}>{k.alias}</div>
                    <Badge color={pc}>{k.provider.toUpperCase()}</Badge>
                    <Badge color={isOk?'var(--green)':'var(--yellow)'}>
                      {isOk ? '✓ ACTIVA' : k.status === 'detecting' ? '⟳ DETECTANDO' : '⚠ '+k.status}
                    </Badge>
                  </div>
                  <div style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)',marginBottom:6 }}>{k.key_masked}</div>
                  {(k.models||[]).length > 0 && (
                    <div style={{ display:'flex',flexWrap:'wrap',gap:4 }}>
                      {k.models.slice(0,8).map(m=>(
                        <span key={m} style={{ fontFamily:'var(--mono)',fontSize:9,padding:'2px 7px',
                          borderRadius:2,background:'var(--bg-base)',border:`1px solid ${pc}44`,color:pc }}>
                          {m}
                        </span>
                      ))}
                      {k.models.length > 8 && (
                        <span style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>
                          +{k.models.length-8} más
                        </span>
                      )}
                    </div>
                  )}
                </div>
                <div style={{ display:'flex',flexDirection:'column',gap:6,flexShrink:0 }}>
                  <button onClick={()=>redetectMutation.mutate(k.id)}
                    style={{ padding:'4px 10px',background:'var(--bg-base)',border:'1px solid var(--cyan)',
                      borderRadius:3,color:'var(--cyan)',cursor:'pointer',fontFamily:'var(--mono)',fontSize:10 }}>
                    ⟳ RE-DETECTAR
                  </button>
                  <button onClick={()=>{ if(confirm(`¿Eliminar ${k.alias}?`)) deleteMutation.mutate(k.id) }}
                    style={{ padding:'4px 10px',background:'var(--bg-base)',border:'1px solid var(--red)',
                      borderRadius:3,color:'var(--red)',cursor:'pointer',fontFamily:'var(--mono)',fontSize:10 }}>
                    🗑 ELIMINAR
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Modelos disponibles agrupados por provider */}
      {availableModels.length > 0 && (
        <>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--cyan)',letterSpacing:2,
            textTransform:'uppercase',marginBottom:12 }}>
            Modelos Disponibles para Agentes — {totalModels} total
          </div>
          {Object.entries(
            availableModels.reduce((acc, m) => {
              acc[m.provider] = acc[m.provider] || []
              acc[m.provider].push(m)
              return acc
            }, {})
          ).map(([provider, pModels]) => (
            <Card key={provider} style={{ marginBottom:12 }}>
              <div style={{ display:'flex',alignItems:'center',gap:8,marginBottom:12 }}>
                <span style={{ fontSize:18 }}>{PROVIDER_ICON[provider]||'🔵'}</span>
                <span style={{ fontFamily:'var(--display)',fontSize:14,color:PROVIDER_COLOR[provider]||'var(--text-bright)' }}>
                  {provider.toUpperCase()}
                </span>
                <Badge color={PROVIDER_COLOR[provider]||'var(--text-dim)'}>{pModels.length} modelos</Badge>
              </div>
              <div style={{ display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))',gap:6 }}>
                {pModels.map(m=>(
                  <div key={m.model} style={{ padding:'8px 10px',background:'var(--bg-card2)',
                    border:'1px solid var(--border)',borderRadius:3,
                    fontFamily:'var(--mono)',fontSize:11,color:'var(--text)',
                    overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap' }}
                    title={`${m.model} — ${m.key_alias}`}>
                    {m.model}
                  </div>
                ))}
              </div>
            </Card>
          ))}
        </>
      )}
    </div>
  )
}
