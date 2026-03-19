import { useAuthStore }  from '../../store/authStore'
import { useNexusStore } from '../../store/nexusStore'
import { nexusApi } from '../../api/client'
import { api } from '../../api/client'
import { Dot } from '../ui'
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

export default function TopBar() {
  const { systemStatus, hitlCount, wsConnected } = useNexusStore()
  const { user, logout } = useAuthStore()
  const [showNotif, setShowNotif] = useState(false)
  const qc = useQueryClient()

  const { data: jarvisData } = useQuery({
    queryKey: ['jarvis-notifications'],
    queryFn: () => api.get('/jarvis/notifications?limit=10').then(r => r.data),
    refetchInterval: 30000,
  })

  const readAllMutation = useMutation({
    mutationFn: () => api.post('/jarvis/notifications/read-all'),
    onSuccess: () => qc.invalidateQueries(['jarvis-notifications']),
  })

  const handleLogout = async () => {
    try { await nexusApi.logout() } catch {}
    logout()
  }

  const STATUS_COLOR = {
    ok:'var(--green)', healthy:'var(--green)',
    degraded:'var(--yellow)', error:'var(--red)', connecting:'var(--cyan)',
  }
  const sc = STATUS_COLOR[systemStatus] || 'var(--cyan)'

  const unread = jarvisData?.unread || 0
  const notifications = jarvisData?.notifications || []

  const NOTIF_COLOR = {
    proposal:'var(--cyan)', security:'var(--orange)',
    warning:'var(--yellow)', error:'var(--red)', info:'var(--text-dim)'
  }

  return (
    <header style={{ height:48, background:'var(--bg-panel)', borderBottom:'1px solid var(--border)',
      display:'flex', alignItems:'center', padding:'0 20px', gap:16, flexShrink:0, zIndex:100,
      position:'relative' }}>

      {/* Logo */}
      <div style={{ display:'flex', alignItems:'center', gap:10, marginRight:8 }}>
        <div style={{ width:28, height:28, border:'1px solid var(--green)', borderRadius:4,
          background:'linear-gradient(135deg,#001a0d,#002a1a)',
          display:'flex', alignItems:'center', justifyContent:'center',
          fontFamily:'var(--display)', fontSize:11, color:'var(--green)', fontWeight:700,
          boxShadow:'0 0 10px #00ff9d20' }}>N</div>
        <span style={{ fontFamily:'var(--display)', fontSize:13, fontWeight:700,
          color:'var(--text-bright)', letterSpacing:2 }}>NEXUS PRO</span>
      </div>

      {/* Status */}
      <div style={{ display:'flex', alignItems:'center', gap:6, padding:'3px 10px',
        border:`1px solid ${sc}30`, borderRadius:10, background:`${sc}08` }}>
        <Dot color={sc} size={6} />
        <span style={{ fontFamily:'var(--mono)', fontSize:10, color:sc }}>
          {systemStatus?.toUpperCase() || 'CONECTANDO'}
        </span>
      </div>

      {/* WS */}
      <div style={{ display:'flex', alignItems:'center', gap:5 }}>
        <Dot color={wsConnected ? 'var(--green)' : 'var(--red)'} size={5} />
        <span style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)' }}>
          {wsConnected ? 'WS' : 'WS OFF'}
        </span>
      </div>

      {/* HITL badge */}
      {hitlCount > 0 && (
        <div style={{ padding:'3px 10px', borderRadius:10,
          border:'1px solid var(--yellow)', background:'#ffc10715',
          fontFamily:'var(--mono)', fontSize:10, color:'var(--yellow)',
          animation:'pulse 2s infinite' }}>
          ⚠ {hitlCount} HITL
        </div>
      )}

      <div style={{ flex:1 }} />

      {/* JARVIS notifications bell */}
      <div style={{ position:'relative' }}>
        <button onClick={() => setShowNotif(s => !s)}
          style={{ padding:'5px 10px', borderRadius:3, cursor:'pointer',
            border:`1px solid ${unread > 0 ? 'var(--cyan)' : 'var(--border)'}`,
            background: unread > 0 ? '#00d4ff10' : 'transparent',
            color: unread > 0 ? 'var(--cyan)' : 'var(--text-dim)',
            fontFamily:'var(--mono)', fontSize:11, display:'flex', alignItems:'center', gap:6,
            transition:'all .15s' }}>
          🤖 JARVIS
          {unread > 0 && (
            <span style={{ background:'var(--cyan)', color:'var(--bg-base)',
              borderRadius:'50%', width:16, height:16, display:'flex',
              alignItems:'center', justifyContent:'center',
              fontFamily:'var(--mono)', fontSize:9, fontWeight:700 }}>
              {unread > 9 ? '9+' : unread}
            </span>
          )}
        </button>

        {/* Dropdown notificaciones */}
        {showNotif && (
          <div style={{ position:'absolute', right:0, top:'100%', marginTop:4,
            width:360, background:'var(--bg-panel)', border:'1px solid var(--border)',
            borderRadius:4, boxShadow:'0 10px 40px rgba(0,0,0,.5)', zIndex:1000 }}>
            <div style={{ padding:'10px 14px', borderBottom:'1px solid var(--border)',
              display:'flex', alignItems:'center', justifyContent:'space-between' }}>
              <span style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
                letterSpacing:2 }}>JARVIS ALERTS</span>
              {unread > 0 && (
                <button onClick={() => readAllMutation.mutate()}
                  style={{ background:'none', border:'none', cursor:'pointer',
                    fontFamily:'var(--mono)', fontSize:9, color:'var(--cyan)' }}>
                  MARCAR LEÍDAS
                </button>
              )}
            </div>
            <div style={{ maxHeight:300, overflowY:'auto' }}>
              {notifications.length === 0 ? (
                <div style={{ padding:'20px', textAlign:'center',
                  fontFamily:'var(--mono)', fontSize:11, color:'var(--text-dim)' }}>
                  Sin notificaciones
                </div>
              ) : notifications.map(n => (
                <div key={n.id} style={{ padding:'10px 14px',
                  borderBottom:'1px solid var(--border)',
                  background: n.read ? 'transparent' : '#00d4ff05',
                  borderLeft:`2px solid ${NOTIF_COLOR[n.tipo] || 'var(--border)'}` }}>
                  <div style={{ fontSize:12, color:'var(--text)', lineHeight:1.4,
                    marginBottom:4 }}>{n.message}</div>
                  <div style={{ fontFamily:'var(--mono)', fontSize:9,
                    color:'var(--text-dim)' }}>
                    {new Date(n.created_at).toLocaleString()} · {n.tipo}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Role badge */}
      {user && (
        <div style={{ padding:'3px 10px', borderRadius:10,
          border:'1px solid var(--border)', background:'var(--bg-card)',
          fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)' }}>
          {user.role?.toUpperCase()}
        </div>
      )}

      {/* User + logout */}
      {user && (
        <div style={{ display:'flex', alignItems:'center', gap:10 }}>
          <div style={{ textAlign:'right' }}>
            <div style={{ fontSize:12, fontWeight:600, color:'var(--text-bright)' }}>{user.name}</div>
            <div style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)' }}>{user.email}</div>
          </div>
          <button onClick={handleLogout}
            style={{ padding:'5px 12px', borderRadius:3, cursor:'pointer',
              border:'1px solid var(--border)', background:'transparent',
              color:'var(--text-dim)', fontFamily:'var(--mono)', fontSize:10,
              transition:'all .15s' }}
            onMouseEnter={e => { e.target.style.borderColor='var(--red)'; e.target.style.color='var(--red)' }}
            onMouseLeave={e => { e.target.style.borderColor='var(--border)'; e.target.style.color='var(--text-dim)' }}>
            ⏏ SALIR
          </button>
        </div>
      )}
    </header>
  )
}
