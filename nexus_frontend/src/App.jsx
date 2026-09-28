import { lazy, Suspense, useEffect } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useNexusStore } from './store/nexusStore'
import { useAuthStore }  from './store/authStore'
import { useNexusWebSocket, useHITLWebSocket } from './hooks/useWebSocket'
import TopBar    from './components/layout/TopBar'
import Sidebar   from './components/layout/Sidebar'
import Login     from './pages/Login'
const Overview = lazy(() => import('./pages/Overview'))
const Agents = lazy(() => import('./pages/Agents'))
const Tasks = lazy(() => import('./pages/Tasks'))
const Teams = lazy(() => import('./pages/Teams'))
const Models = lazy(() => import('./pages/Models'))
const HITL = lazy(() => import('./pages/HITL'))
const Vault = lazy(() => import('./pages/Vault'))
const Guardian = lazy(() => import('./pages/Guardian'))
const RBAC = lazy(() => import('./pages/RBAC'))
const Audit = lazy(() => import('./pages/Audit'))
const Terminal = lazy(() => import('./pages/Terminal'))
const Settings = lazy(() => import('./pages/Settings'))
const Junior = lazy(() => import('./pages/Junior'))
const Pentest = lazy(() => import('./pages/Pentest'))
const Users = lazy(() => import('./pages/Users'))
const Memory = lazy(() => import('./pages/Memory'))
const Factory = lazy(() => import('./pages/Factory'))
const ControlPlane = lazy(() => import('./pages/ControlPlane'))

const qc = new QueryClient({ defaultOptions:{ queries:{ retry:1, staleTime:3000 } } })

const PAGES = {
  overview: Overview, agents: Agents, tasks: Tasks, teams: Teams,
  models: Models, hitl: HITL, vault: Vault, guardian: Guardian,
  rbac: RBAC, audit: Audit, terminal: Terminal, settings: Settings,
  junior: Junior, pentest: Pentest, users: Users, memory: Memory, factory: Factory,
  control: ControlPlane,
}

function NexusApp() {
  useNexusWebSocket()
  useHITLWebSocket()
  const activePage = useNexusStore(s => s.activePage)
  const Page = PAGES[activePage] || Overview

  return (
    <div style={{ display:'flex', flexDirection:'column', height:'100vh', overflow:'hidden' }}>
      <TopBar />
      <div style={{ display:'flex', flex:1, overflow:'hidden' }}>
        <Sidebar />
        <main style={{ flex:1, overflowY:'auto', overflowX:'hidden', background:'var(--bg-base)' }}>
          <Suspense fallback={<div style={{ padding:24, color:'var(--text-dim)' }}>Cargando módulo…</div>}>
            <Page />
          </Suspense>
        </main>
      </div>
    </div>
  )
}

function AuthGuard({ children }) {
  const { isAuthenticated, logout } = useAuthStore()

  // Escuchar evento de logout forzado (token expirado)
  useEffect(() => {
    const handler = () => logout()
    window.addEventListener('nexus:logout', handler)
    return () => window.removeEventListener('nexus:logout', handler)
  }, [logout])

  if (!isAuthenticated) return <Login />
  return children
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <AuthGuard>
        <NexusApp />
      </AuthGuard>
    </QueryClientProvider>
  )
}
