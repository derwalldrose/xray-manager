import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'

export function useNodes() {
  return useQuery({
    queryKey: ['nodes'],
    queryFn: () => api.get('/nodes'),
  })
}

export function useImportNodes() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (links: string[]) => api.post('/nodes/import', { text: links.join('\n') }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

export function useDeleteNode() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (nodeId: string) => api.delete(`/nodes/${nodeId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

export function useUpdateNode() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ nodeId, config }: { nodeId: string; config: any }) =>
      api.put(`/nodes/${nodeId}`, config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['nodes'] })
    },
  })
}

export function useTestNodes() {
  return useMutation({
    mutationFn: ({ nodeIds, mode }: { nodeIds: string[]; mode: 'ping' | 'speed' }) =>
      api.post('/nodes/test', { nodeIds, mode }),
  })
}
