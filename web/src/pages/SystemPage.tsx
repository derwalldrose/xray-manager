import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'
import { useState } from 'react'

export default function SystemPage() {
  const { showToast } = useToast()
  const queryClient = useQueryClient()
  const [changes, setChanges] = useState<Record<string, string>>({})

  const { data: sysctlData } = useQuery({
    queryKey: ['sysctl'],
    queryFn: () => api.get('/sysctl'),
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
      if (p.recommended && String(p.value) !== String(p.recommended)) {
        recommended[p.key] = p.recommended
      }
    }
    if (Object.keys(recommended).length === 0) { showToast('全部已是推荐值', 'info'); return }
    saveSysctl.mutate({ changes: recommended })
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>💻 系统</h1>

      {/* Sysctl */}
      <div className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
        <div className="flex items-center justify-between p-4 border-b" style={{ borderColor: 'var(--border)', background: 'var(--bg2)' }}>
          <h2 className="font-semibold">内核参数调优</h2>
          <div className="flex gap-2">
            <button onClick={handleApplyRecommended}
              className="px-3 py-1 rounded text-sm border"
              style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>
              一键应用推荐值
            </button>
            <button onClick={handleSave} disabled={saveSysctl.isPending || Object.keys(changes).length === 0}
              className="px-3 py-1 rounded text-sm text-white disabled:opacity-40"
              style={{ background: 'var(--accent)' }}>
              {saveSysctl.isPending ? '保存中...' : '保存修改'}
            </button>
          </div>
        </div>
        <table className="w-full">
          <thead>
            <tr style={{ background: 'var(--bg2)' }}>
              <th className="text-left px-4 py-2 text-xs font-medium" style={{ color: '#8b949e' }}>参数</th>
              <th className="text-left px-4 py-2 text-xs font-medium" style={{ color: '#8b949e' }}>说明</th>
              <th className="text-left px-4 py-2 text-xs font-medium" style={{ color: '#8b949e' }}>当前值</th>
              <th className="text-left px-4 py-2 text-xs font-medium" style={{ color: '#8b949e' }}>推荐值</th>
            </tr>
          </thead>
          <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
            {params.map((p: any) => {
              const mismatch = p.recommended && String(p.value) !== String(p.recommended)
              const currentVal = changes[p.key] ?? p.value
              return (
                <tr key={p.key} className="hover:bg-gray-800/30">
                  <td className="px-4 py-2 font-mono text-xs">{p.key}</td>
                  <td className="px-4 py-2 text-xs" style={{ color: '#8b949e' }}>{p.desc}</td>
                  <td className="px-4 py-2">
                    <input
                      value={currentVal}
                      onChange={(e) => handleChange(p.key, e.target.value)}
                      className="px-2 py-1 rounded border text-xs font-mono w-28"
                      style={{
                        background: 'var(--bg)',
                        borderColor: mismatch ? '#d29922' : 'var(--border)',
                        color: mismatch ? '#d29922' : 'var(--text)',
                      }}
                    />
                  </td>
                  <td className="px-4 py-2 text-xs font-mono" style={{ color: '#8b949e' }}>{p.recommended || '-'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
