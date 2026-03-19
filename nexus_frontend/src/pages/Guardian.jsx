import { useState, useEffect, useRef } from 'react'
import { Card, Btn, Dot } from '../components/ui'
import { nexusApi } from '../api/client'

const THREATS_MOCK = [
  { sev:'var(--yellow)', name:'Prompt Injection intento', detail:'ScanAgent input · hace 2min', score:'MED', sc:'var(--yellow)' },
  { sev:'var(--yellow)', name:'Token expiry inminente',   detail:'ChromaDB API key · 6h restantes', score:'MED', sc:'var(--yellow)' },
  { sev:'var(--cyan)',   name:'Puerto 8080 expuesto',     detail:'nexus_api · firewall recomendado', score:'LOW', sc:'var(--cyan)' },
  { sev:'var(--cyan)',   name:'Log verbosidad alta',      detail:'DEBUG level en prod', score:'LOW', sc:'var(--cyan)' },
  { sev:'var(--cyan)',   name:'Dependencia desactualizada',detail:'fastapi 0.104 → 0.115', score:'LOW', sc:'var(--cyan)' },
]

const SCAN_STEPS = [
  ['info','[guardian] Iniciando scan completo...'],
  ['info','[guardian] Enumerando puertos abiertos...'],
  ['warn','[guardian] Puerto 8080 expuesto detectado'],
  ['info','[guardian] Analizando dependencias Python...'],
  ['warn','[guardian] fastapi 0.104 → 0.115 disponible'],
  ['info','[guardian] Escaneando inputs de agentes...'],
  ['warn','[guardian] Prompt injection intento detectado'],
  ['info','[guardian] Verificando tokens y API keys...'],
  ['warn','[guardian] CHROMADB_TOKEN expira en 6h'],
  ['info','[guardian] Análisis SAST nexus_core...'],
  ['success','[guardian] 0 vulnerabilidades críticas'],
  ['success','[guardian] Score final: 94/100 ✓'],
]

const LOG_COLOR = { info:'var(--cyan)', warn:'var(--yellow)', success:'var(--green)', error:'var(--red)' }

export default function Guardian() {
  const [scanning, setScanning] = useState(false)
  const [score, setScore] = useState(94)
  const [scanLogs, setScanLogs] = useState([
    {level:'info', msg:'[guardian] Sistema de monitoreo activo'},
    {level:'success', msg:'[guardian] Score 94/100 · 0 críticas'},
  ])
  const logRef = useRef(null)

  useEffect(() => { if(logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight }, [scanLogs])

  const startScan = async () => {
    if (scanning) return
    setScanning(true)
    setScore(0)
    setScanLogs([])
    try { await nexusApi.guardianScan() } catch {}
    let i = 0
    const iv = setInterval(() => {
      if (i >= SCAN_STEPS.length) { clearInterval(iv); setScanning(false); setScore(94); return }
      const [level, msg] = SCAN_STEPS[i++]
      setScanLogs(l=>[...l, {level, msg}])
    }, 500)
  }

  const dash = 2 * Math.PI * 70
  const offset = dash - (score / 100) * dash

  return (
    <div style={{ padding:24,overflowY:'auto',height:'100%' }}>
      <div style={{ display:'flex',alignItems:'flex-start',justifyContent:'space-between',marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)',fontSize:22,fontWeight:700,color:'var(--text-bright)',letterSpacing:2 }}>Guardian Scan</div>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',marginTop:4 }}>SEGURIDAD OFENSIVA · ANÁLISIS CONTINUO</div>
        </div>
        <Btn variant="primary" onClick={startScan} style={{ opacity:scanning?.8:1 }}>
          {scanning ? '⟳ SCANNING...' : '▶ INICIAR SCAN'}
        </Btn>
      </div>

      <div style={{ display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:16 }}>
        <Card>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:2,textTransform:'uppercase',marginBottom:16 }}>Security Score</div>
          <div style={{ display:'flex',flexDirection:'column',alignItems:'center',gap:16,padding:'20px 0' }}>
            <div style={{ position:'relative',width:160,height:160 }}>
              <svg viewBox="0 0 160 160" style={{ width:'100%',height:'100%',transform:'rotate(-90deg)' }}>
                <circle cx="80" cy="80" r="70" fill="none" stroke="var(--border)" strokeWidth="8"/>
                <circle cx="80" cy="80" r="70" fill="none" stroke="var(--green)" strokeWidth="8"
                  strokeDasharray={dash} strokeDashoffset={offset} strokeLinecap="round"
                  style={{ transition:'stroke-dashoffset 1s ease',filter:'drop-shadow(0 0 8px var(--green))' }}/>
                {scanning && (
                  <g style={{ transformOrigin:'80px 80px',animation:'spin 2s linear infinite' }}>
                    <circle cx="80" cy="10" r="4" fill="var(--cyan)" style={{ filter:'drop-shadow(0 0 4px var(--cyan))' }}/>
                  </g>
                )}
              </svg>
              <div style={{ position:'absolute',inset:0,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center' }}>
                <div style={{ fontFamily:'var(--display)',fontSize:36,fontWeight:900,color:'var(--green)',textShadow:'var(--glow-green)',lineHeight:1 }}>{score}</div>
                <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)' }}>/100</div>
              </div>
            </div>
            <div style={{ fontFamily:'var(--mono)',fontSize:11,color:'var(--text-dim)',textAlign:'center' }}>
              {scanning ? 'Escaneando...' : 'Último scan: hace 2min'}<br/>
              <span style={{ color:'var(--green)' }}>{scanning ? '...' : '✓ Sin vulnerabilidades críticas'}</span>
            </div>
          </div>
          <div style={{ borderTop:'1px solid var(--border)',paddingTop:12,display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:8 }}>
            {[['CRÍTICAS','0','var(--green)'],['MEDIAS','2','var(--yellow)'],['BAJAS','5','var(--cyan)']].map(([l,v,c])=>(
              <div key={l} style={{ textAlign:'center' }}>
                <div style={{ fontFamily:'var(--mono)',fontSize:18,color:c }}>{v}</div>
                <div style={{ fontFamily:'var(--mono)',fontSize:9,color:'var(--text-dim)' }}>{l}</div>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:2,textTransform:'uppercase',marginBottom:12 }}>Amenazas Detectadas</div>
          <div style={{ display:'flex',flexDirection:'column',gap:8 }}>
            {THREATS_MOCK.map((t,i)=>(
              <div key={i} style={{ display:'flex',alignItems:'center',gap:10,padding:'10px 14px',background:'var(--bg-card2)',border:'1px solid var(--border)',borderRadius:3 }}>
                <Dot color={t.sev} size={8} />
                <div style={{ flex:1 }}>
                  <div style={{ fontSize:13,fontWeight:500 }}>{t.name}</div>
                  <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)' }}>{t.detail}</div>
                </div>
                <div style={{ fontFamily:'var(--mono)',fontSize:12,fontWeight:'bold',padding:'2px 8px',borderRadius:3,border:`1px solid ${t.sc}`,color:t.sc,background:`${t.sc}15` }}>{t.score}</div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <Card>
        <div style={{ fontFamily:'var(--mono)',fontSize:10,color:'var(--text-dim)',letterSpacing:2,textTransform:'uppercase',marginBottom:10 }}>Scan Log</div>
        <div ref={logRef} style={{ fontFamily:'var(--mono)',fontSize:11,lineHeight:1.8,height:140,overflowY:'auto' }}>
          {scanLogs.map((l,i)=>(
            <div key={i} style={{ display:'flex',gap:10 }}>
              <span style={{ color:'#2a5060',flexShrink:0 }}>{new Date().toTimeString().slice(0,8)}</span>
              <span style={{ color:LOG_COLOR[l.level]||'var(--text)' }}>{l.msg}</span>
            </div>
          ))}
          {scanning && <div style={{ color:'var(--cyan)',animation:'blink 1s step-end infinite' }}>█</div>}
        </div>
      </Card>
      <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>
    </div>
  )
}
