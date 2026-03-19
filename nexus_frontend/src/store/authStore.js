import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export const useAuthStore = create(
  persist(
    (set, get) => ({
      user:          null,
      accessToken:   null,
      refreshToken:  null,
      isAuthenticated: false,

      setTokens: (tokens) => set({
        accessToken:     tokens.access_token,
        refreshToken:    tokens.refresh_token,
        user:            tokens.user,
        isAuthenticated: true,
      }),

      logout: () => {
        set({ user: null, accessToken: null, refreshToken: null, isAuthenticated: false })
        // Limpiar cualquier cache de react-query
        window.dispatchEvent(new Event('nexus:logout'))
      },

      updateUser: (user) => set({ user }),
    }),
    {
      name: 'nexus-auth',
      partialize: (s) => ({
        user:         s.user,
        accessToken:  s.accessToken,
        refreshToken: s.refreshToken,
        isAuthenticated: s.isAuthenticated,
      }),
    }
  )
)
