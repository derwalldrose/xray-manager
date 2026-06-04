import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'

export default function SettingsPage() {
  const { showToast } = useToast()
  const queryClient = useQueryClient()

  const { data: settings } = useQuery({ queryKey: ['settings'], queryFn: () => api.get('/settings') })
  const { data: geoInfo } = useQuery({ queryKey: ['geo-info'], queryFn: () => api.get('/geo/info') })
  const { data: geoUrls } = useQuery({ queryKey: ['geo-urls'], queryFn: () => api.get('/geo/urls') })

  const [ports, setPorts] = useState({ socks: 10810, http: 10818, transparent: 12345 })
  const [editGeoUrls, setEditGeoUrls] = useState(false)
  const [geoipUrl, setGeoipUrl] = useState('')
  const [geositeUrl, setGeositeUrl] = useState('')
  const [updating, setUpdating] = useState(false)

  useEffect(() => {
    if (settings?.ports) setPorts(settings.ports)
  }, [settings])

  useEffect(() => {
    if (geoUrls) {
      setGeoipUrl(geoUrls.geoip || '')
      setGeositeUrl(geoUrls.geosite || '')
    }
  }, [geoUrls])

  const saveSettings = useMutation({
    mutationFn: (data: any) => api.post('/settings', data),
    onSuccess: () => { showToast('设置已保存', 'success'); queryClient.invalidateQueries({ queryKey: ['settings'] }) },
    onError: (e: any) => showToast(e.message || '保存失败', 'error'),
  })

  const saveGeoUrls = useMutation({
    mutationFn: () => api.post('/geo/urls', { geoip: geoipUrl, geosite: geositeUrl }),
    onSuccess: () => { showToast('GeoURL 已保存', 'success'); setEditGeoUrls(false); queryClient.invalidateQueries({ queryKey: ['geo-urls'] }) },
    onError: (e: any) => showToast(e.message || '保存失败', 'error'),
  })

  const updateGeo = async () => {
    setUpdating(true)
    try {
      const r = await api.post('/geo/update')
      const results = r.results || []
      const msgs = results.map((x: any) => `${x.name}: ${x.ok ? '成功' : x.error}`).join(', ')
      showToast(msgs || '更新完成', results.every((x: any) => x.ok) ? 'success' : 'error')
      queryClient.invalidateQueries({ queryKey: ['geo-info'] })
    } catch (e: any) {
      showToast(e.message || '更新失败', 'error')
    } finally {
      setUpdating(false)
    }
  }

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
  }

  const geoFiles = geoInfo?.files || []

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>设置</h1>

      {/* Ports */}
      <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
        <h2 className="text-lg font-semibold mb-4">端口配置</h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[
            { key: 'socks' as const, label: 'SOCKS5' },
            { key: 'http' as const, label: 'HTTP' },
            { key: 'transparent' as const, label: '透明代理' },
          ].map(p => (
            <div key={p.key}>
              <label className="block text-sm mb-1" style={{ color: '#8b949e' }}>{p.label} 端口</label>
              <input type="number" value={ports[p.key]}
                onChange={e => setPorts({ ...ports, [p.key]: +e.target.value })}
                className="w-full px-3 py-2 rounded border text-sm"
                style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }} />
            </div>
          ))}
        </div>
        <button onClick={() => saveSettings.mutate({ ...settings, ports })}
          disabled={saveSettings.isPending} className="mt-4 px-4 py-2 rounded-lg text-sm text-white disabled:opacity-50"
          style={{ background: 'var(--accent)' }}>
          {saveSettings.isPending ? '保存中...' : '保存'}
        </button>
      </div>

      {/* GeoIP */}
      <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">GeoIP / GeoSite</h2>
          <div className="flex gap-2">
            <button onClick={() => setEditGeoUrls(!editGeoUrls)} className="px-3 py-1.5 rounded text-xs border"
              style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>
              {editGeoUrls ? '取消' : '编辑 URL'}
            </button>
            <button onClick={updateGeo} disabled={updating}
              className="px-3 py-1.5 rounded text-xs text-white disabled:opacity-50" style={{ background: '#d29922' }}>
              {updating ? '更新中...' : '在线更新'}
            </button>
          </div>
        </div>

        {/* File table */}
        <table className="w-full mb-4">
          <thead>
            <tr style={{ color: '#8b949e' }}>
              <th className="text-left text-xs py-2">文件</th>
              <th className="text-right text-xs py-2">大小</th>
              <th className="text-right text-xs py-2">最后更新</th>
            </tr>
          </thead>
          <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
            {geoFiles.map((f: any) => (
              <tr key={f.name}>
                <td className="py-2 text-sm font-mono">{f.name}</td>
                <td className="py-2 text-right text-sm" style={{ color: f.exists ? 'var(--text)' : '#f85149' }}>
                  {f.exists ? formatSize(f.size) : '未找到'}
                </td>
                <td className="py-2 text-right text-xs" style={{ color: '#8b949e' }}>
                  {f.exists ? new Date(f.lastModified).toLocaleString('zh-CN') : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {/* Edit URLs */}
        {editGeoUrls && (
          <div className="space-y-3 pt-3 border-t" style={{ borderColor: 'var(--border)' }}>
            <div>
              <label className="text-sm block mb-1" style={{ color: '#8b949e' }}>GeoIP URL</label>
              <input value={geoipUrl} onChange={e => setGeoipUrl(e.target.value)} className="w-full px-3 py-2 rounded border text-sm font-mono"
                style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }} />
            </div>
            <div>
              <label className="text-sm block mb-1" style={{ color: '#8b949e' }}>GeoSite URL</label>
              <input value={geositeUrl} onChange={e => setGeositeUrl(e.target.value)} className="w-full px-3 py-2 rounded border text-sm font-mono"
                style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }} />
            </div>
            <button onClick={() => saveGeoUrls.mutate()} disabled={saveGeoUrls.isPending}
              className="px-4 py-2 rounded-lg text-sm text-white disabled:opacity-50" style={{ background: 'var(--accent)' }}>
              {saveGeoUrls.isPending ? '保存中...' : '保存 URL'}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
