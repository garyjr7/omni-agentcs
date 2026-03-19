import { useQuery } from '@tanstack/react-query'
import { useNexusStore } from '../store/nexusStore'
import { nexusApi } from '../api/client'

export function useHealth() {
  const setHealth = useNexusStore(s => s.setHealth)
  return useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const { data } = await nexusApi.health()
      setHealth(data)
      return data
    },
    refetchInterval: 5000,
    retry: false,
  })
}

export function useAgents() {
  const setAgents = useNexusStore(s => s.setAgents)
  return useQuery({
    queryKey: ['agents'],
    queryFn: async () => {
      try {
        const { data } = await nexusApi.agents()
        const list = Array.isArray(data) ? data : data?.agents || []
        setAgents(list)
        return list
      } catch { return [] }
    },
    refetchInterval: 8000,
  })
}

export function useTasks() {
  const setTasks = useNexusStore(s => s.setTasks)
  return useQuery({
    queryKey: ['tasks'],
    queryFn: async () => {
      try {
        const { data } = await nexusApi.tasks()
        const list = Array.isArray(data) ? data : data?.tasks || []
        setTasks(list)
        return list
      } catch { return [] }
    },
    refetchInterval: 6000,
  })
}
