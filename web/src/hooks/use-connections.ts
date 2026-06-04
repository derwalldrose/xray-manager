import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'

export function useConnections() {
  return useQuery({
    queryKey: ['connections'],
    queryFn: () => api.get('/connections'),
    refetchInterval: 5000,
  })
}

export function useConnect() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ nodeIds, strategy, transparent }: { nodeIds: string[]; strategy: string; transparent: boolean }) =>
      api.post('/connections/connect', { nodeIds, strategy, transparent }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['connections'] })
      queryClient.invalidateQueries({ queryKey: ['status'] })
    },
  })
}

export function useDisconnect() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => api.post('/connections/disconnect'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['connections'] })
      queryClient.invalidateQueries({ queryKey: ['status'] })
    },
  })
}
