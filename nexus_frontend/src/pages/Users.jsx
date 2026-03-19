import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuthStore } from '../store/authStore'
import { Card, Btn, Dot } from '../components/ui'
import { nexusApi } from '../api/client'

const ROLE_COLOR = { admin:'var(--red)', operator:'var(--yellow)', viewer:'var(--cyan)' }

export default function Users() {
  const qc = useQueryClient()
  const { user: me } = useAuthStore()
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ email:'', name:'', password:'', role:'viewer' })
  const [error, setError] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: () => nexusApi.getUsers().then(r => r.data),
  })

  const createMutation = useMutation({
    mutationFn: () => nexusApi.createUser(form),
    onSuccess: () => {
      qc.invalidateQueries(['users'])
      setShowForm(false)
      setForm({ email:'', name:'', password:'', role:'viewer' })
      setError('')
    },
    onError: (err) => setError(err.response?.data?.detail || 'Error creando usuario'),
  })

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const users = data?.users || []

  return (
    <div style={{ padding:24, height:'100%', overflowY:'auto' }}>
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:'var(--display)', fontSize:22, fontWeight:700,
            color:'var(--text-bright)', letterSpacing:2 }}>Gestión de Usuarios</div>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)', marginTop:4 }}>
            {users.length} USUARIOS · RBAC ACTIVO · JWT HS256
          </div>
        </div>
        {me?.role === 'admin' && (
          <Btn variant="primary" onClick={() => setShowForm(s => !s)}>
            {showForm ? '✕ CANCELAR' : '+ NUEVO USUARIO'}
          </Btn>
        )}
      </div>

      {/* Formulario nuevo usuario */}
      {showForm && (
        <Card style={{ marginBottom:16, border:'1px solid var(--green)' }}>
          <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
            letterSpacing:2, textTransform:'uppercase', marginBottom:14 }}>
            Crear Nuevo Usuario
          </div>
          <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12, marginBottom:12 }}>
            {[['Email', 'email', 'user@empresa.com', 'email'],
              ['Nombre', 'name', 'Juan Pérez', 'text'],
              ['Password', 'password', '••••••••', 'password']].map(([label, key, ph, type]) => (
              <div key={key}>
                <label style={{ display:'block', fontFamily:'var(--mono)', fontSize:10,
                  color:'var(--text-dim)', letterSpacing:1, textTransform:'uppercase', marginBottom:6 }}>
                  {label}
                </label>
                <input type={type} value={form[key]} onChange={e => set(key, e.target.value)}
                  placeholder={ph}
                  style={{ width:'100%', background:'var(--bg-base)', border:'1px solid var(--border)',
                    borderRadius:3, padding:'8px 12px', color:'var(--text)',
                    fontFamily:'var(--mono)', fontSize:12, outline:'none' }} />
              </div>
            ))}
            <div>
              <label style={{ display:'block', fontFamily:'var(--mono)', fontSize:10,
                color:'var(--text-dim)', letterSpacing:1, textTransform:'uppercase', marginBottom:6 }}>
                Rol
              </label>
              <select value={form.role} onChange={e => set('role', e.target.value)}
                style={{ width:'100%', background:'var(--bg-base)', border:'1px solid var(--border)',
                  borderRadius:3, padding:'8px 12px', color:'var(--text)',
                  fontFamily:'var(--mono)', fontSize:12, outline:'none' }}>
                <option value="viewer">viewer — Solo lectura</option>
                <option value="operator">operator — Operar agentes</option>
                <option value="admin">admin — Acceso total</option>
              </select>
            </div>
          </div>
          {error && (
            <div style={{ padding:'8px 12px', background:'#ff386015', border:'1px solid var(--red)',
              borderRadius:3, fontFamily:'var(--mono)', fontSize:11, color:'var(--red)', marginBottom:12 }}>
              ✗ {error}
            </div>
          )}
          <Btn variant="primary"
            onClick={() => createMutation.mutate()}
            style={{ opacity: createMutation.isPending ? .6 : 1 }}>
            {createMutation.isPending ? '⟳ CREANDO...' : '✓ CREAR USUARIO'}
          </Btn>
        </Card>
      )}

      {/* Tabla de usuarios */}
      {isLoading ? (
        <div style={{ textAlign:'center', padding:'60px 0', fontFamily:'var(--mono)',
          color:'var(--text-dim)' }}>⟳ Cargando...</div>
      ) : (
        <div style={{ background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:4, overflow:'hidden' }}>
          {/* Header */}
          <div style={{ display:'grid', gridTemplateColumns:'2fr 2fr 1fr 1fr 1fr',
            padding:'10px 16px', borderBottom:'1px solid var(--border)',
            fontFamily:'var(--mono)', fontSize:9, color:'var(--text-dim)',
            letterSpacing:2, textTransform:'uppercase' }}>
            <span>Usuario</span><span>Email</span><span>Rol</span>
            <span>Estado</span><span>Creado</span>
          </div>
          {users.map((u, i) => (
            <div key={u.id} style={{ display:'grid', gridTemplateColumns:'2fr 2fr 1fr 1fr 1fr',
              padding:'12px 16px', alignItems:'center',
              borderBottom: i < users.length-1 ? '1px solid var(--border)' : 'none',
              background: u.email === me?.email ? '#00ff9d05' : 'transparent',
              transition:'background .15s' }}>
              <div style={{ display:'flex', alignItems:'center', gap:10 }}>
                <div style={{ width:32, height:32, borderRadius:4, flexShrink:0,
                  background:`${ROLE_COLOR[u.role] || 'var(--cyan)'}15`,
                  border:`1px solid ${ROLE_COLOR[u.role] || 'var(--cyan)'}`,
                  display:'flex', alignItems:'center', justifyContent:'center',
                  fontFamily:'var(--display)', fontSize:12, color:ROLE_COLOR[u.role] || 'var(--cyan)',
                  fontWeight:700 }}>
                  {u.name?.[0]?.toUpperCase() || '?'}
                </div>
                <div>
                  <div style={{ fontSize:13, fontWeight:600, color:'var(--text-bright)' }}>
                    {u.name}
                    {u.email === me?.email && (
                      <span style={{ fontFamily:'var(--mono)', fontSize:9, color:'var(--green)',
                        marginLeft:8, padding:'1px 6px', border:'1px solid var(--green)',
                        borderRadius:8 }}>TÚ</span>
                    )}
                  </div>
                </div>
              </div>
              <div style={{ fontFamily:'var(--mono)', fontSize:11, color:'var(--text-dim)' }}>
                {u.email}
              </div>
              <div style={{ padding:'2px 8px', borderRadius:8, display:'inline-flex',
                alignItems:'center', gap:4, width:'fit-content',
                border:`1px solid ${ROLE_COLOR[u.role] || 'var(--cyan)'}`,
                background:`${ROLE_COLOR[u.role] || 'var(--cyan)'}10`,
                fontFamily:'var(--mono)', fontSize:10,
                color:ROLE_COLOR[u.role] || 'var(--cyan)' }}>
                {u.role}
              </div>
              <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                <Dot color={u.active ? 'var(--green)' : 'var(--red)'} size={6} />
                <span style={{ fontFamily:'var(--mono)', fontSize:10,
                  color:u.active ? 'var(--green)' : 'var(--red)' }}>
                  {u.active ? 'ACTIVO' : 'INACTIVO'}
                </span>
              </div>
              <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)' }}>
                {new Date(u.created_at).toLocaleDateString()}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Info de roles */}
      <Card style={{ marginTop:16 }}>
        <div style={{ fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)',
          letterSpacing:2, textTransform:'uppercase', marginBottom:12 }}>
          Permisos por Rol
        </div>
        <div style={{ display:'grid', gridTemplateColumns:'repeat(3, 1fr)', gap:10 }}>
          {[
            ['admin', 'var(--red)',    ['Todo el sistema', 'Crear/eliminar usuarios', 'Configurar modelos', 'Aprobar HITL', 'Pentest completo']],
            ['operator', 'var(--yellow)', ['Crear agentes y tareas', 'Ejecutar Junior', 'Ver logs y auditoría', 'Aprobar HITL', 'Quick scan']],
            ['viewer', 'var(--cyan)',  ['Ver dashboard', 'Ver agentes y tareas', 'Ver reportes', 'Sin modificaciones', 'Sin ejecuciones']],
          ].map(([role, color, perms]) => (
            <div key={role} style={{ padding:12, background:'var(--bg-base)',
              border:`1px solid ${color}20`, borderRadius:4 }}>
              <div style={{ fontFamily:'var(--mono)', fontSize:11, color, fontWeight:700,
                textTransform:'uppercase', marginBottom:10, letterSpacing:1 }}>
                {role}
              </div>
              {perms.map((p, i) => (
                <div key={i} style={{ display:'flex', gap:8, padding:'3px 0',
                  fontFamily:'var(--mono)', fontSize:10, color:'var(--text-dim)' }}>
                  <span style={{ color }}>·</span> {p}
                </div>
              ))}
            </div>
          ))}
        </div>
      </Card>
    </div>
  )
}
