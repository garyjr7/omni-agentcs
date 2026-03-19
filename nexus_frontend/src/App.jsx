import { useEffect } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useNexusStore } from './store/nexusStore'
import { useAuthStore }  from './store/authStore'
import { useNexusWebSocket, useHITLWebSocket } from './hooks/useWebSocket'
import TopBar    from './components/layout/TopBar'
import Sidebar   from './components/layout/Sidebar'
import Login     from './pages/Login'
import Overview  from './pages/Overview'
import Agents    from './pages/Agents'
import Tasks     from './pages/Tasks'
import Teams     from './pages/Teams'
import Models    from './pages/Models'
import HITL      from './pages/HITL'
import Vault     from './pages/Vault'
import Guardian  from './pages/Guardian'
import RBAC      from './pages/RBAC'
import Audit     from './pages/Audit'
import Terminal  from './pages/Terminal'
import Settings  from './pages/Settings'
import Junior    from './pages/Junior'
import Pentest   from './pages/Pentest'
import Users     from './pages/Users'
import Memory    from './pages/Memory'
import Factory   from './pages/Factory'

const qc = new QueryClient({ defaultOptions:{ queries:{ retry:1, staleTime:3000 } } })

const PAGES = {
  overview: Overview, agents: Agents, tasks: Tasks, teams: Teams,
  models: Models, hitl: HITL, vault: Vault, guardian: Guardian,
  rbac: RBAC, audit: Audit, terminal: Terminal, settings: Settings,
  junior: Junior, pentest: Pentest, users: Users, memory: Memory, factory: Factory,
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
          <Page />
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
