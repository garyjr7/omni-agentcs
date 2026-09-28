import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Card, Btn, Dot } from '../components/ui'
import { nexusApi } from '../api/client'
import { useAuthStore } from '../store/authStore'

const STATUS_COLOR = {
  draft:'var(--text-dim)', analyzing:'var(--cyan)', pending_approval:'var(--yellow)',
  approved:'var(--cyan)', executing:'var(--orange)', completed:'var(--green)', failed:'var(--red)'
}
const STATUS_ICON = {
  draft:'○', analyzing:'⟳', pending_approval:'⏸', approved:'✓',
  executing:'▶', completed:'✅', failed:'✗'
}

export default function Factory() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const [tab, setTab]             = useState('projects')
  const [mdContent, setMdContent] = useState('')
  const [plan, setPlan]           = useState(null)
  const [selectedProject, setSelectedProject] = useState(null)
  const [error, setError]         = useState('')

  const { data: templatesData } = useQuery({
    queryKey: ['factory-templates'],
    queryFn: () => nexusApi.factoryTemplates().then(r => r.data),
  })

  const { data: projectsData } = useQuery({
    queryKey: ['factory-projects'],
    queryFn: () => nexusApi.factoryProjects().then(r => r.data),
    refetchInterval: 5000,
  })

  const { data: projectDetail } = useQuery({
    queryKey: ['factory-project', selectedProject],
    queryFn: () => nexusApi.factoryProject(selectedProject).then(r => r.data),
    enabled: !!selectedProject,
    refetchInterval: 3000,
  })

  const analyzeMutation = useMutation({
    mutationFn: () => nexusApi.factoryAnalyze(mdContent),
    onSuccess: (res) => { setPlan(res.data); setTab('plan'); setError('') },
    onError: (e) => setError(e.response?.data?.detail || 'Error analizando'),
  })

  const approveMutation = useMutation({
    mutationFn: (pid) => nexusApi.factoryApprove(pid, user?.name || 'admin'),
    onSuccess: () => { qc.invalidateQueries(['factory-projects']); setTab('projects'); setPlan(null) },
  })

  const loadTemplate = () => {
    setMdContent(templatesData?.software || '')
    setTab('new')
  }

  const projects = projectsData?.projects || []

  return (
    <div style={{ padding:24, height:'100%', display:'flex', flexDirection:'column', gap:16 }}>
      {/* Header */}
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between' }}>
        <div>
          <div style={{ fontFamily:'var(--display)', fontSize:22, fontWeight:700,
            color:'var(--text-bright)', letterSpacing:2 }}>Software Factory</div>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:4 }}>
            BAJIOWARE · PLAN MAESTRO · EJECUCIÓN POR FASES · DEVSECOS
          </div>
        </div>
        <div style={{ display:'flex', gap:4 }}>
          {['projects','new','plan'].map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              padding:'6px 14px', borderRadius:3,
              border:`1px solid ${tab===t?'var(--green)':'var(--border)'}`,
              background:tab===t?'#00ff9d08':'transparent',
              color:tab===t?'var(--green)':'var(--text-dim)',
              cursor:'pointer', fontFamily:'var(--mono)', fontSize:11
            }}>{t==='new'?'+ NUEVO':t==='plan'?'PLAN MAESTRO':t.toUpperCase()}</button>
          ))}
        </div>
      </div>

      {/* TAB: Projects */}
      {tab === 'projects' && (
        <div style={{ flex:1, overflowY:'auto', display:'flex', flexDirection:'column', gap:10 }}>
          <div style={{ display:'flex', gap:10, alignItems:'center' }}>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)' }}>
              {projects.length} PROYECTOS
            </div>
            <Btn variant="primary" onClick={loadTemplate}>+ NUEVO PROYECTO</Btn>
          </div>

          {projects.length === 0 ? (
            <div style={{ textAlign:'center', padding:'60px 0', border:'1px dashed var(--border)', borderRadius:4 }}>
              <div style={{ fontSize:48, opacity:.1, marginBottom:12 }}>🏭</div>
              <div style={{ fontFamily:'var(--display)', fontSize:16, color:'var(--text-dim)' }}>
                Sin proyectos aún
              </div>
              <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text-dim)', marginTop:6 }}>
                Descarga el template, llénalo y súbelo para generar el Plan Maestro
              </div>
            </div>
          ) : (
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:10 }}>
              {projects.map(p => {
                const sc = STATUS_COLOR[p.status] || 'var(--text-dim)'
                return (
                  <div key={p.id} onClick={() => setSelectedProject(p.id)}
                    style={{ padding:16, background:'var(--bg-card)',
                      border:`1px solid ${selectedProject===p.id?sc:'var(--border)'}`,
                      borderRadius:4, cursor:'pointer', transition:'all .15s' }}>
                    <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:8 }}>
                      <div style={{ fontSize:24 }}>🏭</div>
                      <div style={{ flex:1 }}>
                        <div style={{ fontSize:14, fontWeight:600, color:'var(--text-bright)' }}>{p.nombre}</div>
                        <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)' }}>{p.cliente}</div>
                      </div>
                      <div style={{ padding:'2px 8px', borderRadius:8,
                        border:`1px solid ${sc}`, color:sc,
                        fontFamily:'var(--mono)', fontSize:10, background:`${sc}10` }}>
                        {STATUS_ICON[p.status]} {p.status}
                      </div>
                    </div>
                    {p.status === 'pending_approval' && (
                      <Btn variant="primary" onClick={e => { e.stopPropagation(); approveMutation.mutate(p.id) }}
                        style={{ width:'100%', opacity: approveMutation.isPending ? .6 : 1 }}>
                        ✓ APROBAR Y EJECUTAR
                      </Btn>
                    )}
                    {p.status === 'executing' && selectedProject === p.id && projectDetail && (
                      <div style={{ marginTop:8 }}>
                        {(projectDetail.phases||[]).map(ph => (
                          <div key={ph.id} style={{ display:'flex', gap:8, padding:'3px 0',
                            fontFamily:'var(--mono)', fontSize:10 }}>
                            <span style={{ color: ph.status==='completed'?'var(--green)':ph.status==='running'?'var(--yellow)':'var(--text-dim)' }}>
                              {ph.status==='completed'?'✓':ph.status==='running'?'▶':'○'}
                            </span>
                            <span style={{ color:'var(--text-dim)' }}>F{ph.fase_num}</span>
                            <span style={{ color:'var(--text)' }}>{ph.nombre}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB: New project */}
      {tab === 'new' && (
        <div style={{ flex:1, display:'flex', flexDirection:'column', gap:10 }}>
          <div style={{ display:'flex', gap:8, alignItems:'center' }}>
            <Btn variant="ghost" onClick={loadTemplate}>⬇ CARGAR TEMPLATE</Btn>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)' }}>
              Llena el template y analiza con IA
            </div>
          </div>
          <textarea value={mdContent} onChange={e => setMdContent(e.target.value)}
            placeholder="Pega aquí el template de requerimientos llenado..."
            style={{ flex:1, background:'var(--bg-card)', border:'1px solid var(--border)',
              borderRadius:4, padding:16, color:'var(--text)', fontFamily:'var(--mono)',
              fontSize:12, outline:'none', resize:'none', lineHeight:1.6 }} />
          {error && (
            <div style={{ padding:'8px 12px', background:'#ff386015', border:'1px solid var(--red)',
              borderRadius:3, fontFamily:'var(--mono)', fontSize:11, color:'var(--red)' }}>
              ✗ {error}
            </div>
          )}
          <Btn variant="primary" onClick={() => analyzeMutation.mutate()}
            style={{ opacity: analyzeMutation.isPending ? .6 : 1 }}>
            {analyzeMutation.isPending ? '⟳ ANALIZANDO CON IA...' : '🧠 GENERAR PLAN MAESTRO'}
          </Btn>
        </div>
      )}

      {/* TAB: Plan Maestro */}
      {tab === 'plan' && plan && (
        <div style={{ flex:1, overflowY:'auto', display:'flex', flexDirection:'column', gap:12 }}>
          <Card style={{ border:'1px solid var(--green)' }}>
            <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--green)',
              letterSpacing:2, marginBottom:12 }}>PLAN MAESTRO — {plan.nombre || plan.plan_maestro?.proyecto}</div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:10, marginBottom:14 }}>
              {[
                ['Proyecto', plan.plan_maestro?.proyecto || '—'],
                ['Cliente',  plan.plan_maestro?.cliente  || '—'],
                ['Fases',    plan.plan_maestro?.num_fases || '—'],
                ['Estimado', plan.plan_maestro?.estimacion || '—'],
              ].map(([k,v]) => (
                <div key={k} style={{ padding:'8px 12px', background:'var(--bg-base)',
                  border:'1px solid var(--border)', borderRadius:3 }}>
                  <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)',
                    letterSpacing:1, textTransform:'uppercase', marginBottom:4 }}>{k}</div>
                  <div style={{ fontSize:13, fontWeight:600, color:'var(--text-bright)' }}>{v}</div>
                </div>
              ))}
            </div>

            {/* Fases */}
            <div style={{ marginBottom:14 }}>
              <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)',
                letterSpacing:2, marginBottom:8 }}>FASES DE EJECUCIÓN</div>
              {(plan.plan_maestro?.fases || []).map(f => (
                <div key={f.num} style={{ display:'flex', gap:12, padding:'8px 0',
                  borderBottom:'1px solid var(--border)', alignItems:'flex-start' }}>
                  <div style={{ width:28, height:28, borderRadius:'50%',
                    background:'#00ff9d15', border:'1px solid var(--green)',
                    display:'flex', alignItems:'center', justifyContent:'center',
                    fontFamily:'var(--mono)', fontSize:11, color:'var(--green)', flexShrink:0 }}>
                    {f.num}
                  </div>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:13, fontWeight:600, color:'var(--text-bright)' }}>{f.nombre}</div>
                    <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:2 }}>{f.desc}</div>
                    <div style={{ display:'flex', gap:6, marginTop:4, flexWrap:'wrap' }}>
                      {(f.agentes||[]).map(a => (
                        <span key={a} style={{ padding:'1px 6px', borderRadius:8,
                          border:'1px solid var(--cyan)', color:'var(--cyan)',
                          fontFamily:'var(--mono)', fontSize:9 }}>{a}</span>
                      ))}
                      {(f.tools||[]).map(t => (
                        <span key={t} style={{ padding:'1px 6px', borderRadius:8,
                          border:'1px solid var(--border)', color:'var(--text-dim)',
                          fontFamily:'var(--mono)', fontSize:9 }}>{t}</span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Análisis LLM */}
            {plan.llm_analysis && (
              <div style={{ padding:12, background:'#8b5cf610', border:'1px solid var(--purple)',
                borderRadius:3, marginBottom:14 }}>
                <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--purple)',
                  letterSpacing:2, marginBottom:8 }}>ANÁLISIS DE ARQUITECTURA (GPT-4o)</div>
                <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text)',
                  lineHeight:1.7, whiteSpace:'pre-wrap' }}>{plan.llm_analysis}</div>
              </div>
            )}

            <Btn variant="primary"
              onClick={() => approveMutation.mutate(plan.project_id)}
              style={{ width:'100%', opacity: approveMutation.isPending ? .6 : 1 }}>
              {approveMutation.isPending ? '⟳ APROBANDO...' : '🚀 APROBAR PLAN Y EJECUTAR FÁBRICA'}
            </Btn>
          </Card>
        </div>
      )}
    </div>
  )
}
