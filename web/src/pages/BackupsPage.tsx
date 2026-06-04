

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'

interface BackupInfo {
  name: string
  timestamp: string
  size: number
}

function formatDate(ts: string) {
  const d = new Date(ts)
  return d.toLocaleString('zh-CN')
}

function formatSize(bytes: number) {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
}

export default function BackupsPage() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const { data, isLoading } = useQuery({ queryKey: ['backups'], queryFn: () => api.get('/backups') })
  const backups: BackupInfo[] = data?.backups || []

  const createMutation = useMutation({
    mutationFn: () => api.post('/backups/create'),
    onSuccess: (r: any) => { queryClient.invalidateQueries({ queryKey: ['backups'] }); showToast(r.ok ? '备份成功' : (r.error || '备份失败'), r.ok ? 'success' : 'error') },
    onError: (e: any) => showToast(e.message, 'error'),
  })

  const restoreMutation = useMutation({
    mutationFn: (name: string) => api.post('/backups/restore', { name }),
    onSuccess: (r: any) => { showToast(r.ok ? '恢复成功，Xray 已重启' : (r.error || '恢复失败'), r.ok ? 'success' : 'error') },
    onError: (e: any) => showToast(e.message, 'error'),
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>备份管理</h1>
        <button onClick={() => createMutation.mutate()} disabled={createMutation.isPending}
          className="px-4 py-2 rounded-lg text-sm text-white disabled:opacity-50" style={{ background: 'var(--accent)' }}>
          {createMutation.isPending ? '创建中...' : '立即备份'}
        </button>
      </div>

      <div className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
        <table className="w-full">
          <thead>
            <tr style={{ background: 'var(--bg2)' }}>
              <th className="text-left px-4 py-3 text-xs font-medium" style={{ color: '#8b949e' }}>文件名</th>
              <th className="text-left px-4 py-3 text-xs font-medium" style={{ color: '#8b949e' }}>时间</th>
              <th className="text-right px-4 py-3 text-xs font-medium" style={{ color: '#8b949e' }}>大小</th>
              <th className="text-right px-4 py-3 text-xs font-medium" style={{ color: '#8b949e' }}>操作</th>
            </tr>
          </thead>
          <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
            {backups.map((b, i) => (
              <tr key={i} className="hover:bg-gray-800/30">
                <td className="px-4 py-3 font-mono text-sm">{b.name}</td>
                <td className="px-4 py-3 text-sm" style={{ color: '#8b949e' }}>{formatDate(b.timestamp)}</td>
                <td className="px-4 py-3 text-right text-sm font-mono" style={{ color: '#8b949e' }}>{formatSize(b.size)}</td>
                <td className="px-4 py-3 text-right">
                  <button onClick={() => { if (confirm(`确认从 ${b.name} 恢复配置？当前配置将被覆盖。`)) restoreMutation.mutate(b.name) }}
                    disabled={restoreMutation.isPending} className="px-3 py-1 rounded text-xs text-white disabled:opacity-50" style={{ background: '#d29922' }}>
                    恢复
                  </button>
                </td>
              </tr>
            ))}
            {!isLoading && backups.length === 0 && (
              <tr><td colSpan={4} className="px-4 py-8 text-center" style={{ color: '#8b949e' }}>暂无备份</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="p-4 rounded-lg border text-sm" style={{ background: 'rgba(210,153,34,0.1)', borderColor: '#d29922', color: '#d29922' }}>
        恢复操作会覆盖当前 Xray 配置并重启服务。请谨慎操作。
      </div>
    </div>
  )
}
