import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../stores/auth-store'
import { api } from '../lib/api'

export default function LoginPage() {
  const [token, setToken] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const setAuthToken = useAuthStore((s) => s.setToken)
  const navigate = useNavigate()

  const handleLogin = async () => {
    if (!token.trim()) { setError('请输入 Token'); return }
    setLoading(true)
    setError('')
    try {
      setAuthToken(token.trim())
      await api.get('/status')
      navigate('/')
    } catch {
      setError('Token 错误')
      setAuthToken('')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: 'var(--bg)' }}>
      <div className="w-full max-w-sm p-8 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
        <div className="text-center mb-8">
          <div className="text-4xl mb-3">🛡️</div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--accent)' }}>XRay Manager</h1>
          <p className="text-sm mt-1" style={{ color: 'var(--text)' }}>v3.0</p>
        </div>
        <input
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
          placeholder="输入 Token"
          className="w-full px-4 py-3 rounded-lg border mb-4 outline-none focus:border-blue-500"
          style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}
        />
        {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
        <button
          onClick={handleLogin}
          disabled={loading}
          className="w-full py-3 rounded-lg font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50"
          style={{ background: 'var(--accent)' }}
        >
          {loading ? '验证中...' : '登录'}
        </button>
      </div>
    </div>
  )
}
