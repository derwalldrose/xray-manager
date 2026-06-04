import { create } from 'zustand'

interface AuthState {
  token: string | null
  setToken: (token: string) => void
  clearToken: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  token: localStorage.getItem('xray-token') || '123456',
  setToken: (token: string) => {
    localStorage.setItem('xray-token', token)
    set({ token })
  },
  clearToken: () => {
    localStorage.removeItem('xray-token')
    set({ token: null })
  },
}))
