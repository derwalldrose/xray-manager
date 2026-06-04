import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'

const defaultProxyBypass = '<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*'

export default function SystemPage() {
  const { showToast } = useToast()
  const queryClient = useQueryClient()
  const [changes, setChanges] = useState<Record<string, string>>({})
  const [proxyBypass, setProxyBypass] = useState(defaultProxyBypass)

  const { data: sysctlData } = useQuery({
    queryKey: ['sysctl'],
    queryFn: () => api.get('/sysctl'),
  })

  const { data: proxyStatus, isLoading: proxyLoading } = useQuery({
    queryKey: ['system-proxy'],
    queryFn: () => api.get('/system-proxy/status'),
    refetchInterval: 5000,
  })

  useEffect(() => {
    if (proxyStatus?.ProxyOverride !== undefined) {
      setProxyBypass(proxyStatus.ProxyOverride || defaultProxyBypass)
    }
  }, [proxyStatus?.ProxyOverride])

  const enableProxy = useMutation({
    mutationFn: () => api.post('/system-proxy/enable', { port: 10818, bypass: proxyBypass || defaultProxyBypass }),
    onSuccess: () => { showToast('系统代理已开启', 'success'); queryClient.invalidateQueries({ queryKey: ['system-proxy'] }) },
    onError: (e: any) => showToast(e.message || '开启失败', 'error'),
  })

  const applyProxyBypass = useMutation({
    mutationFn: () => api.post('/system-proxy/enable', { server: proxyStatus?.ProxyServer || '127.0.0.1:10818', bypass: proxyBypass || defaultProxyBypass }),
    onSuccess: () => { showToast('系统代理绕过列表已应用', 'success'); queryClient.invalidateQueries({ queryKey: ['system-proxy'] }) },
    onError: (e: any) => showToast(e.message || '应用失败', 'error'),
  })

  const disableProxy = useMutation({
    mutationFn: () => api.post('/system-proxy/disable'),
    onSuccess: () => { showToast('系统代理已关闭', 'success'); queryClient.invalidateQueries({ queryKey: ['system-proxy'] }) },
    onError: (e: any) => showToast(e.message || '关闭失败', 'error'),
  })

  const saveSysctl = useMutation({
    mutationFn: (data: any) => api.post('/sysctl', data),
    onSuccess: (result: any) => {
      showToast(`已应用 ${result.applied?.length || 0} 项`, 'success')
      setChanges({})
      queryClient.invalidateQueries({ queryKey: ['sysctl'] })
    },
    onError: (e: any) => showToast(e.message || '保存失败', 'error'),
  })

  const params = sysctlData?.params || []

  const handleChange = (key: string, value: string) => {
    setChanges((prev) => ({ ...prev, [key]: value }))
  }

  const handleSave = () => {
    if (Object.keys(changes).length === 0) { showToast('无修改', 'info'); return }
    saveSysctl.mutate({ changes })
  }

  const handleApplyRecommended = () => {
    const recommended: Record<string, string> = {}
    for (const p of params) {
      if (p.recommended && String(p.value) !== String(p.recommended)) recommended[p.key] = p.recommended
    }
    if (Object.keys(recommended).length === 0) { showToast('全部已是推荐值', 'info'); return }
    saveSysctl.mutate({ changes: recommended })
  }

  const proxySupported = proxyStatus?.supported !== false
  const proxyEnabled = proxyStatus?.enabled === true

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>系统</h1>

      {proxySupported && (
        <div className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
          <div className="flex items-center justify-between p-4 border-b" style={{ borderColor: 'var(--border)', background: 'var(--bg2)' }}>
            <div>
              <h2 className="font-semibold">Windows 系统代理</h2>
              <p className="text-xs mt-1" style={{ color: '#8b949e' }}>
                {proxyEnabled ? `已开启 → ${proxyStatus?.ProxyServer || '127.0.0.1:10818'}` : '未开启 — 浏览器不会走代理'}
              </p>
            </div>
            <div className="flex items-center gap-3">
              <div className={`w-3 h-3 rounded-full ${proxyEnabled ? 'bg-green-500' : 'bg-gray-500'}`} />
              {proxyEnabled ? (
                <button onClick={() => disableProxy.mutate()} disabled={disableProxy.isPending}
                  className="px-4 py-2 rounded-lg text-sm text-white disabled:opacity-50" style={{ background: '#f85149' }}>
                  {disableProxy.isPending ? '关闭中...' : '关闭代理'}
                </button>
              ) : (
                <button onClick={() => enableProxy.mutate()} disabled={enableProxy.isPending}
                  className="px-4 py-2 rounded-lg text-sm text-white disabled:opacity-50" style={{ background: '#3fb950' }}>
                  {enableProxy.isPending ? '开启中...' : '开启代理'}
                </button>
              )}
            </div>
          </div>
          <div className="p-4 space-y-3" style={{ background: 'var(--bg)' }}>
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div>
                <div className="text-sm font-medium" style={{ color: 'var(--text)' }}>绕过列表</div>
                <div className="text-xs mt-1" style={{ color: '#8b949e' }}>Windows ProxyOverride，分号分隔；应用后会重新设置系统代理。</div>
              </div>
              <button onClick={() => applyProxyBypass.mutate()} disabled={applyProxyBypass.isPending}
                className="px-3 py-1.5 rounded text-sm text-white disabled:opacity-50" style={{ background: 'var(--accent)' }}>
                {applyProxyBypass.isPending ? '应用中...' : '应用绕过列表'}
              </button>
            </div>
            <textarea value={proxyBypass} onChange={(e) => setProxyBypass(e.target.value)} rows={4}
              className="w-full px-3 py-2 rounded border text-xs font-mono"
              style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}
              placeholder={defaultProxyBypass}
            />
          </div>
        </div>
      )}

      {!proxySupported && !proxyLoading && (
        <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border)', background: 'var(--bg2)' }}>
          <h2 className="font-semibold mb-1">系统代理</h2>
          <p className="text-sm" style={{ color: '#8b949e' }}>{proxyStatus?.message || '当前平台不支持系统代理 API。Linux 下请使用透明代理模式。'}</p>
        </div>
      )}

      {params.length > 0 && (
        <div className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
          <div className="flex items-center justify-between p-4 border-b" style={{ borderColor: 'var(--border)', background: 'var(--bg2)' }}>
            <h2 className="font-semibold">内核参数调优</h2>
            <div className="flex gap-2">
              <button onClick={handleApplyRecommended} className="px-3 py-1 rounded text-sm border" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>一键应用推荐值</button>
              <button onClick={handleSave} disabled={saveSysctl.isPending || Object.keys(changes).length === 0} className="px-3 py-1 rounded text-sm text-white disabled:opacity-40" style={{ background: 'var(--accent)' }}>{saveSysctl.isPending ? '保存中...' : '保存修改'}</button>
            </div>
          </div>
          <table className="w-full">
            <thead><tr style={{ background: 'var(--bg2)' }}><th className="text-left px-4 py-2 text-xs font-medium" style={{ color: '#8b949e' }}>参数</th><th className="text-left px-4 py-2 text-xs font-medium" style={{ color: '#8b949e' }}>说明</th><th className="text-left px-4 py-2 text-xs font-medium" style={{ color: '#8b949e' }}>当前值</th><th className="text-left px-4 py-2 text-xs font-medium" style={{ color: '#8b949e' }}>推荐值</th></tr></thead>
            <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
              {params.map((p: any) => {
                const mismatch = p.recommended && String(p.value) !== String(p.recommended)
                const currentVal = changes[p.key] ?? p.value
                return <tr key={p.key} className="hover:bg-gray-800/30"><td className="px-4 py-2 font-mono text-xs">{p.key}</td><td className="px-4 py-2 text-xs" style={{ color: '#8b949e' }}>{p.desc}</td><td className="px-4 py-2"><input value={currentVal} onChange={(e) => handleChange(p.key, e.target.value)} className="px-2 py-1 rounded border text-xs font-mono w-28" style={{ background: 'var(--bg)', borderColor: mismatch ? '#d29922' : 'var(--border)', color: mismatch ? '#d29922' : 'var(--text)' }} /></td><td className="px-4 py-2 text-xs font-mono" style={{ color: '#8b949e' }}>{p.recommended || '-'}</td></tr>
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
