import { create } from 'zustand'

export const useNexusStore = create((set, get) => ({
  health:       null,
  systemStatus: 'connecting',
  agents:       [],
  tasks:        [],
  hitlItems:    [],
  hitlCount:    0,
  logs:         [],
  maxLogs:      300,
  activePage:   'overview',
  wsConnected:  false,
  wsHITL:       false,
  notifications:[],

  setHealth:      (h) => set({ health: h, systemStatus: h?.status || 'unknown' }),
  setAgents:      (a) => set({ agents: a }),
  setTasks:       (t) => set({ tasks: t }),
  setActivePage:  (p) => set({ activePage: p }),
  setWsConnected: (v) => set({ wsConnected: v }),
  setWsHITL:      (v) => set({ wsHITL: v }),

  setHITL: (items) => set({ hitlItems: items, hitlCount: items.length }),

  addHITL: (item) => set(s => ({
    hitlItems: [item, ...s.hitlItems],
    hitlCount: s.hitlCount + 1,
  })),

  resolveHITL: (id) => set(s => ({
    hitlItems: s.hitlItems.filter(h => h.id !== id),
    hitlCount: Math.max(0, s.hitlCount - 1),
  })),

  addLog: (log) => set(s => ({
    logs: [log, ...s.logs].slice(0, s.maxLogs),
  })),

  addNotification: (msg, type = 'info') => set(s => ({
    notifications: [{ id: Date.now(), msg, type, ts: new Date() }, ...s.notifications].slice(0, 30),
  })),
}))
