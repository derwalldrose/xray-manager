import { useAuthStore } from '../stores/auth-store'

interface FetchOptions extends RequestInit {
  body?: any
}

export async function apiFetch<T = any>(endpoint: string, options: FetchOptions = {}): Promise<T> {
  const token = useAuthStore.getState().token
  
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(token && { 'X-Token': token }),
    ...options.headers,
  }

  const config: RequestInit = {
    ...options,
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  }

  const response = await fetch(`/api${endpoint}`, config)

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: '请求失败' }))
    throw new Error(error.message || `HTTP ${response.status}`)
  }

  return response.json()
}

export const api = {
  get: <T = any>(endpoint: string) => apiFetch<T>(endpoint, { method: 'GET' }),
  post: <T = any>(endpoint: string, body?: any) => apiFetch<T>(endpoint, { method: 'POST', body }),
  put: <T = any>(endpoint: string, body?: any) => apiFetch<T>(endpoint, { method: 'PUT', body }),
  delete: <T = any>(endpoint: string) => apiFetch<T>(endpoint, { method: 'DELETE' }),
}
