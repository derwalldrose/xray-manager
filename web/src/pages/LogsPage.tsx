import { useEffect, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'

export default function LogsPage() {
  const [lines, setLines] = useState(200)
  const [filter, setFilter] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(true)
  const boxRef = useRef<HTMLDivElement | null>(null)

  const { data, refetch, isLoading } = useQuery({
    queryKey: ['logs', lines],
    queryFn: () => api.get(`/logs?lines=${lines}`),
    refetchInterval: autoRefresh ? 5000 : false,
  })

  const rawLogs = data?.logs || ''
  const logLines = rawLogs.split('\n').filter(Boolean)
  const filteredLines = filter
    ? logLines.filter((l: string) => l.toLowerCase().includes(filter.toLowerCase()))
    : logLines
  // Show newest at bottom, auto-scroll to bottom
  const displayLines = [...filteredLines].reverse()
  const filteredLogs = displayLines.join('\n')

  useEffect(() => {
    if (boxRef.current) boxRef.current.scrollTop = boxRef.current.scrollHeight
  }, [filteredLogs])

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>日志</h1>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex gap-2 flex-wrap">
          {[50, 200, 500, 1000].map((n) => (
            <button key={n} onClick={() => setLines(n)} className="px-3 py-1 rounded text-sm border" style={{ background: lines === n ? 'var(--accent)' : 'var(--bg2)', borderColor: 'var(--border)', color: lines === n ? '#fff' : 'var(--text)' }}>{n}行</button>
          ))}
        </div>
        <button onClick={() => refetch()} className="px-4 py-1 rounded text-sm text-white" style={{ background: 'var(--accent)' }}>刷新</button>
        <button onClick={() => setAutoRefresh(!autoRefresh)} className="px-4 py-1 rounded text-sm border" style={{ background: autoRefresh ? 'rgba(63,185,80,0.2)' : 'var(--bg2)', borderColor: 'var(--border)', color: autoRefresh ? '#3fb950' : 'var(--text)' }}>{autoRefresh ? '自动刷新开' : '自动刷新关'}</button>
        <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="过滤关键字..." className="flex-1 min-w-[200px] px-3 py-1 rounded border text-sm font-mono" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }} />
      </div>
      <div className="text-xs" style={{ color: '#8b949e' }}>最新日志在最下方，自动刷新 5 秒。</div>

      <div ref={boxRef} className="p-4 rounded-lg border font-mono text-xs whitespace-pre-wrap overflow-auto" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: '#8b949e', maxHeight: 'calc(100vh - 280px)' }}>
        {isLoading ? '加载中...' : filteredLogs || '(无日志)'}
      </div>
    </div>
  )
}
