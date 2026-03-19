#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  NEXUS PRO — Punto 8: Users Management + Polish            ║
# ║  8A · silenciar bcrypt warning  8B · página Users          ║
# ║  8C · Settings funcional  8D · build final                 ║
# ╚══════════════════════════════════════════════════════════════╝
set -euo pipefail

ROOT="/home/operator/NEXUS-PRO"
FRONT="$ROOT/nexus_frontend/src"
GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $1"; }
head() { echo -e "\n${BOLD}${CYAN}$1${NC}"; echo "────────────────────────────────────────"; }

# ══════════════════════════════════════════════════════════════
head "1/5 · Silenciar bcrypt warning en Python 3.12"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
import os

# Patch: suprimir el warning de passlib/bcrypt en Python 3.12
patch = '''
import warnings
import logging
# Silenciar warning cosmético de passlib con bcrypt 4.x en Python 3.12
logging.getLogger("passlib").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*bcrypt.*", category=UserWarning)
'''

path = "/home/operator/NEXUS-PRO/nexus_api/main.py"
with open(path) as f:
    content = f.read()

if "Silenciar warning" not in content:
    # Insertar después de los primeros imports
    content = content.replace(
        "import logging\nimport sys",
        "import logging\nimport sys\nimport warnings\nlogging.getLogger('passlib').setLevel(logging.ERROR)\nwarnings.filterwarnings('ignore', message='.*bcrypt.*')"
    )
    with open(path, "w") as f:
        f.write(content)
    print("main.py patcheado — warning silenciado")
else:
    print("ya estaba silenciado")
PYEOF
log "bcrypt warning silenciado"

# ══════════════════════════════════════════════════════════════
head "2/5 · pages/Users.jsx — gestión completa de usuarios"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
content = r"""import { useState } from 'react'
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
"""

with open("/home/operator/NEXUS-PRO/nexus_frontend/src/pages/Users.jsx", "w") as f:
    f.write(content)
print("Users.jsx escrito —", len(content), "bytes")
PYEOF
log "pages/Users.jsx"

# ══════════════════════════════════════════════════════════════
head "3/5 · pages/Settings.jsx — configuración real del sistema"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
content = r"""import { useState } from 'react'
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
"""

with open("/home/operator/NEXUS-PRO/nexus_frontend/src/pages/Settings.jsx", "w") as f:
    f.write(content)
print("Settings.jsx escrito —", len(content), "bytes")
PYEOF
log "pages/Settings.jsx"

# ══════════════════════════════════════════════════════════════
head "4/5 · App.jsx + Sidebar — agregar Users al router"
# ══════════════════════════════════════════════════════════════
python3 - << 'PYEOF'
# Actualizar App.jsx para incluir Users
path = "/home/operator/NEXUS-PRO/nexus_frontend/src/App.jsx"
with open(path) as f:
    content = f.read()

if "import Users" not in content:
    content = content.replace(
        "import Pentest   from './pages/Pentest'",
        "import Pentest   from './pages/Pentest'\nimport Users     from './pages/Users'"
    )
    content = content.replace(
        "junior: Junior, pentest: Pentest,",
        "junior: Junior, pentest: Pentest, users: Users,"
    )
    with open(path, "w") as f:
        f.write(content)
    print("App.jsx actualizado con Users")
else:
    print("Users ya estaba en App.jsx")
PYEOF

python3 - << 'PYEOF'
# Actualizar Sidebar para agregar Users en sección Seguridad
path = "/home/operator/NEXUS-PRO/nexus_frontend/src/components/layout/Sidebar.jsx"
with open(path) as f:
    content = f.read()

if "'users'" not in content:
    content = content.replace(
        "{ id:'rbac',    icon:'⊞', label:'Roles / RBAC' },",
        "{ id:'users',   icon:'👥', label:'Usuarios',     badgeKey:null },\n    { id:'rbac',    icon:'⊞', label:'Roles / RBAC' },"
    )
    with open(path, "w") as f:
        f.write(content)
    print("Sidebar actualizado con Users")
else:
    print("Users ya estaba en Sidebar")
PYEOF
log "App.jsx + Sidebar actualizados"

# ══════════════════════════════════════════════════════════════
head "5/5 · Build final"
# ══════════════════════════════════════════════════════════════
cd "$ROOT/nexus_frontend"
npm run build --silent 2>&1 | tail -4

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  NEXUS PRO — Punto 8: Users + Settings ✓          ${NC}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Nuevo:${NC}"
echo -e "  👥 Users page    → tabla de usuarios + crear nuevo"
echo -e "  ⚙  Settings page → estado sistema + perfil + logout"
echo -e "  🔇 bcrypt warning silenciado en logs"
echo ""
echo -e "  ${BOLD}Resumen de lo que tiene NEXUS para vender:${NC}"
echo -e "  ✅ Auth JWT real con roles (admin/operator/viewer)"
echo -e "  ✅ Dashboard militar completo (14 páginas)"
echo -e "  ✅ Junior Agent autónomo con GPT-4o"
echo -e "  ✅ Pentest automatizado con reportes"
echo -e "  ✅ HITL real WebSocket"
echo -e "  ✅ Docker ready (install.sh)"
echo -e "  ✅ Gestión de usuarios multi-rol"
echo ""
echo -e "  ${BOLD}Siguiente — Punto 9: Memoria persistente + onboarding${NC}"
echo ""
