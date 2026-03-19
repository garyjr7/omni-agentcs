import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useAuthStore } from '../store/authStore'
import { Card, Btn, Dot } from '../components/ui'
import { nexusApi } from '../api/client'

export default function Settings() {
  const { user, logout } = useAuthStore()
  const [saved, setSaved] = useState(false)

  const { data: healthData } = useQuery({
    queryKey: ['health'],
    queryFn: () => nexusApi.health().then(r => r.data),
  })

  const { data: modelsData } = useQuery({
    queryKey: ['models'],
    queryFn: () => nexusApi.availableModels().then(r => r.data),
  })

  const svc = healthData?.services || {}

  const handleSave = () => {
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div style={{ padding:24, height:'100%', overflowY:'auto' }}>
      <div style={{ marginBottom:24 }}>
        <div style={{ fontFamily:'var(--display)', fontSize:22, fontWeight:700,
          color:'var(--text-bright)', letterSpacing:2 }}>Configuración</div>
        <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:4 }}>
          NEXUS PRO v2.0 · SISTEMA · CUENTA
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
        {/* Info del sistema */}
        <Card>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
            letterSpacing:2, textTransform:'uppercase', marginBottom:14 }}>
            Estado del Sistema
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
            {[
              ['Versión', healthData?.version || '2.0.0'],
              ['Plataforma', 'NEXUS PRO — AI Operations'],
              ['Python', '3.12'],
              ['FastAPI', '0.111+'],
              ['Auth', 'JWT HS256 · 8h'],
              ['Base de datos', 'SQLite + aiosqlite'],
            ].map(([k, v]) => (
              <div key={k} style={{ display:'flex', justifyContent:'space-between',
                padding:'6px 0', borderBottom:'1px solid var(--border)' }}>
                <span style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text-dim)' }}>{k}</span>
                <span style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text)' }}>{v}</span>
              </div>
            ))}
          </div>
        </Card>

        {/* Servicios */}
        <Card>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
            letterSpacing:2, textTransform:'uppercase', marginBottom:14 }}>
            Servicios Activos
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
            {Object.entries(svc).map(([k, v]) => (
              <div key={k} style={{ display:'flex', alignItems:'center', gap:8,
                padding:'5px 8px', background:'var(--bg-base)',
                border:`1px solid ${v === 'ok' ? 'var(--green)' : 'var(--yellow)'}20`,
                borderRadius:3 }}>
                <Dot color={v === 'ok' ? 'var(--green)' : 'var(--yellow)'} size={6} />
                <span style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text)', flex:1 }}>{k}</span>
                <span style={{ fontFamily:'var(--mono)', fontSize:9,
                  color:v === 'ok' ? 'var(--green)' : 'var(--yellow)' }}>{v}</span>
              </div>
            ))}
          </div>
        </Card>

        {/* Perfil */}
        <Card>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
            letterSpacing:2, textTransform:'uppercase', marginBottom:14 }}>
            Mi Cuenta
          </div>
          <div style={{ display:'flex', alignItems:'center', gap:14, marginBottom:16,
            padding:12, background:'var(--bg-base)', border:'1px solid var(--border)', borderRadius:4 }}>
            <div style={{ width:48, height:48, borderRadius:6,
              background:'linear-gradient(135deg,#001a0d,#002a1a)',
              border:'1px solid var(--green)', display:'flex', alignItems:'center',
              justifyContent:'center', fontFamily:'var(--display)', fontSize:18,
              color:'var(--green)', fontWeight:700, flexShrink:0 }}>
              {user?.name?.[0]?.toUpperCase() || 'A'}
            </div>
            <div>
              <div style={{ fontSize:15, fontWeight:600, color:'var(--text-bright)' }}>{user?.name}</div>
              <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text-dim)' }}>{user?.email}</div>
              <div style={{ fontFamily:'var(--mono)', fontSize:10, marginTop:3,
                padding:'1px 8px', border:'1px solid var(--red)', borderRadius:8,
                color:'var(--red)', display:'inline-block' }}>
                {user?.role?.toUpperCase()}
              </div>
            </div>
          </div>
          <Btn variant="danger" onClick={logout} style={{ width:'100%' }}>
            ⏏ CERRAR SESIÓN
          </Btn>
        </Card>

        {/* Modelos disponibles */}
        <Card>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
            letterSpacing:2, textTransform:'uppercase', marginBottom:14 }}>
            Modelos Disponibles
          </div>
          {(modelsData?.models || []).length === 0 ? (
            <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text-dim)',
              textAlign:'center', padding:'20px 0' }}>
              Configura API keys en la sección Modelos
            </div>
          ) : (
            <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
              {(modelsData?.models || []).map((m, i) => (
                <div key={i} style={{ display:'flex', alignItems:'center', gap:8,
                  padding:'6px 10px', background:'var(--bg-base)',
                  border:'1px solid var(--border)', borderRadius:3 }}>
                  <Dot color="var(--green)" size={5} />
                  <span style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text)', flex:1 }}>
                    {m.model || m.id || m}
                  </span>
                  <span style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)' }}>
                    {m.provider || ''}
                  </span>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* NEXUS Info footer */}
      <div style={{ marginTop:16, padding:16, background:'var(--bg-panel)',
        border:'1px solid var(--border)', borderRadius:4,
        display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)' }}>
          NEXUS PRO v2.0 · AI Operations Platform · Zero Trust · JWT Auth
        </div>
        <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--green)' }}>
          {healthData?.timestamp ? new Date(healthData.timestamp).toLocaleString() : ''}
        </div>
      </div>
    </div>
  )
}
