import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'

export function useStatus() {
  return useQuery({
    queryKey: ['status'],
    queryFn: () => api.get('/status'),
    refetchInterval: 3000,
  })
}
