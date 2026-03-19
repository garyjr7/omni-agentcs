import axios from 'axios'

export const API_URL = import.meta.env.VITE_API_URL || 'http://192.168.220.134:8000'
export const WS_URL  = import.meta.env.VITE_WS_URL  || 'ws://192.168.220.134:8000'

export const api = axios.create({
  baseURL: API_URL,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

// ── Interceptor request — inyecta el token ────────────────────
api.interceptors.request.use((config) => {
  try {
    const raw = localStorage.getItem('nexus-auth')
    if (raw) {
      const state = JSON.parse(raw)
      const token = state?.state?.accessToken
      if (token) config.headers['Authorization'] = `Bearer ${token}`
    }
  } catch { /* sin token → petición sin auth */ }
  return config
})

// ── Interceptor response — auto-refresh en 401 ───────────────
let _refreshing = false
let _queue = []

api.interceptors.response.use(
  r => r,
  async err => {
    const original = err.config
    if (err.response?.status === 401 && !original._retry) {
      if (_refreshing) {
        // Encolar mientras se refresca
        return new Promise((res, rej) => {
          _queue.push({ res, rej })
        }).then(token => {
          original.headers['Authorization'] = `Bearer ${token}`
          return api(original)
        })
      }
      original._retry = true
      _refreshing = true
      try {
        const raw = localStorage.getItem('nexus-auth')
        const state = raw ? JSON.parse(raw) : null
        const refreshToken = state?.state?.refreshToken
        if (!refreshToken) throw new Error('No refresh token')

        const { data } = await axios.post(`${API_URL}/auth/refresh`, { refresh_token: refreshToken })
        // Actualizar store
        const nexusState = JSON.parse(localStorage.getItem('nexus-auth') || '{}')
        nexusState.state = { ...nexusState.state, accessToken: data.access_token, refreshToken: data.refresh_token }
        localStorage.setItem('nexus-auth', JSON.stringify(nexusState))

        _queue.forEach(p => p.res(data.access_token))
        _queue = []
        original.headers['Authorization'] = `Bearer ${data.access_token}`
        return api(original)
      } catch(e) {
        _queue.forEach(p => p.rej(e))
        _queue = []
        // Token expirado → logout
        window.dispatchEvent(new Event('nexus:logout'))
        return Promise.reject(err)
      } finally {
        _refreshing = false
      }
    }
    console.warn('API Error:', err.response?.status, err.config?.url)
    return Promise.reject(err)
  }
)

export const nexusApi = {
  // Auth
  login:    (email, password) => api.post('/auth/login',   { email, password }),
  refresh:  (rt) => api.post('/auth/refresh', { refresh_token: rt }),
  me:       () => api.get('/auth/me'),
  logout:   () => api.post('/auth/logout'),
  getUsers: () => api.get('/auth/users'),
  createUser:(d) => api.post('/auth/users', d),

  // Health
  health: () => api.get('/health'),

  // Tools
  tools: () => api.get('/tools'),

  // Agents
  agents:        () => api.get('/agents'),
  agentRegistry: () => api.get('/agents/registry'),
  agent:         (id) => api.get(`/agents/${id}`),
  createAgent:   (d) => api.post('/agents', d),
  updateAgent:   (id, d) => api.put(`/agents/${id}`, d),
  assignTools:   (id, tools) => api.post(`/agents/${id}/tools`, { tools }),
  deleteAgent:   (id) => api.delete(`/agents/${id}`),
  chatAgent:     (id, msg, sys) => api.post(`/agents/${id}/chat`, { message: msg, system_override: sys }),

  // Teams
  teams:              () => api.get('/teams-v2/teams-v2'),
  createTeam:         (d) => api.post('/teams-v2/teams-v2', d),
  updateTeam:         (id, d) => api.put(`/teams-v2/teams-v2/${id}`, d),
  addAgentToTeam:     (tid, aid) => api.post(`/teams-v2/teams-v2/${tid}/agents`, { agent_id: aid }),
  removeAgentFromTeam:(tid, aid) => api.delete(`/teams-v2/teams-v2/${tid}/agents/${aid}`),
  deleteTeam:         (id) => api.delete(`/teams-v2/teams-v2/${id}`),

  // Tasks
  tasks:      (status) => api.get('/tasks', { params: status ? { status } : {} }),
  task:        (id) => api.get(`/tasks/${id}`),
  createTask:  (d) => api.post('/tasks', d),
  runTask:     (id) => api.post(`/tasks/${id}/run`),
  cancelTask:  (id) => api.post(`/tasks/${id}/cancel`),

  // Models & API Keys
  apiKeys:        () => api.get('/models/keys'),
  addApiKey:      (d) => api.post('/models/keys', d),
  deleteApiKey:   (id) => api.delete(`/models/keys/${id}`),
  redetect:       (id) => api.post(`/models/keys/${id}/detect`),
  availableModels:() => api.get('/models/available'),

  // HITL
  hitlPending:   () => api.get('/hitl/pending'),
  hitlHistory:   () => api.get('/hitl/history'),
  hitlCount:     () => api.get('/hitl/count'),
  approveHITL:   (id, by, reason) => api.post(`/hitl/${id}/approve`, { approved_by: by||'admin', reason: reason||'' }),
  denyHITL:      (id, by, reason) => api.post(`/hitl/${id}/deny`, { denied_by: by||'admin', reason: reason||'' }),
  approveAllHITL:() => api.post('/hitl/approve-all', { approved_by: 'admin' }),
  denyAllHITL:   () => api.post('/hitl/deny-all', { denied_by: 'admin' }),

  // Junior
  juniorRun:     (objective, maxSteps) => api.post('/junior/run', { objective, max_steps: maxSteps || 6 }),
  juniorStatus:  (id) => api.get(`/junior/status/${id}`),
  juniorChat:    (msg, sessionId) => api.post('/junior/chat', { message: msg, session_id: sessionId }),
  juniorSessions:() => api.get('/junior/sessions'),

  // Pentest
  pentestRun:    (d) => api.post('/pentest/run', d),
  pentestStatus: (id) => api.get(`/pentest/status/${id}`),
  pentestReports:() => api.get('/pentest/reports'),
  pentestReport: (f) => api.get(`/pentest/reports/${f}`),
  quickScan:     () => api.post('/pentest/quick-scan'),

  // JARVIS
  jarvisNotifications: (unread) => api.get('/jarvis/notifications', { params: unread ? { unread_only: true } : {} }),
  jarvisReadAll:       ()       => api.post('/jarvis/notifications/read-all'),
  jarvisStatus:        ()       => api.get('/jarvis/status'),
  jarvisReport:        ()       => api.get('/jarvis/report'),

  // Factory — Software Factory + Pentest Flow
  factoryTemplates:      ()       => api.get('/factory/templates'),
  factoryAnalyze:        (md)     => api.post('/factory/analyze', { requirements_md: md, use_llm: true }),
  factoryApprove:        (id, by) => api.post(`/factory/projects/${id}/approve`, { approved_by: by }),
  factoryProjects:       ()       => api.get('/factory/projects'),
  factoryProject:        (id)     => api.get(`/factory/projects/${id}`),
  pentestAnalyze:        (md)     => api.post('/factory/pentest/analyze', { scope_md: md, use_llm: true }),
  pentestApprove:        (id, by) => api.post(`/factory/pentest/${id}/approve`, { approved_by: by }),
  pentestEngagements:    ()       => api.get('/factory/pentest'),
  pentestEngagement:     (id)     => api.get(`/factory/pentest/${id}`),

  // Memory
  memoryAgents:  ()           => api.get('/memory/agents'),
  memoryContext: (id, sid)    => api.get(`/memory/agents/${id}`, { params: sid ? { session_id: sid } : {} }),
  memoryStats:   (id)         => api.get(`/memory/agents/${id}/stats`),
  memorySearch:  (id, q)      => api.get(`/memory/agents/${id}/search`, { params: { q } }),
  memoryClear:   (id, sid)    => api.delete(`/memory/agents/${id}`, { params: sid ? { session_id: sid } : {} }),

  // Guardian
  guardianScan:    () => api.post('/guardian/scan/full'),
  guardianSecrets: () => api.post('/guardian/scan/secrets'),
  guardianBandit:  () => api.post('/guardian/scan/bandit'),
  guardianIncidents:() => api.get('/guardian/incidents'),
}
