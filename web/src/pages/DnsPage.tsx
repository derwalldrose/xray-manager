import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'

export default function DnsPage() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const { data } = useQuery({ queryKey: ['dns'], queryFn: () => api.get('/dns') })
  const { data: hostsData } = useQuery({ queryKey: ['dns-hosts'], queryFn: () => api.get('/dns/hosts') })
  const [tab, setTab] = useState<'servers' | 'hosts'>('servers')
  const [servers, setServers] = useState('')
  const [hosts, setHosts] = useState('')

  useEffect(() => {
    if (data) {
      const s = data.servers || []
      setServers(typeof s === 'string' ? s : s.map((x: any) => typeof x === 'string' ? x : JSON.stringify(x)).join('\n'))
    }
  }, [data])

  useEffect(() => {
    if (hostsData) {
      setHosts(Object.entries(hostsData || {}).map(([k, v]) => `${k} ${v}`).join('\n'))
    }
  }, [hostsData])

  const saveDns = useMutation({
    mutationFn: (dns: any) => api.post('/dns', dns),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['dns'] }); showToast('保存成功', 'success') },
    onError: (e: any) => showToast(e.message, 'error'),
  })

  const saveHosts = useMutation({
    mutationFn: (h: any) => api.post('/dns/hosts', h),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['dns-hosts'] }); showToast('保存成功', 'success') },
    onError: (e: any) => showToast(e.message, 'error'),
  })

  const handleSaveServers = () => {
    const lines = servers.split('\n').map(l => l.trim()).filter(Boolean)
    const parsed = lines.map(l => {
      if (l.startsWith('{')) { try { return JSON.parse(l) } catch { return l } }
      return l
    })
    saveDns.mutate({ servers: parsed, hosts: hostsData || {} })
  }

  const handleSaveHosts = () => {
    const lines = hosts.split('\n').map(l => l.trim()).filter(Boolean)
    const parsed: Record<string, string> = {}
    for (const line of lines) {
      const [domain, ...ip] = line.split(/\s+/)
      if (domain) parsed[domain] = ip.join(' ')
    }
    saveHosts.mutate(parsed)
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>DNS 配置</h1>

      <div className="flex gap-2 border-b pb-0" style={{ borderColor: 'var(--border)' }}>
        <button onClick={() => setTab('servers')} className={`px-4 py-2 text-sm font-medium rounded-t-lg -mb-[1px] ${tab === 'servers' ? 'border-t border-x' : ''}`} style={{ color: tab === 'servers' ? 'var(--accent)' : 'var(--text)', borderColor: tab === 'servers' ? 'var(--border)' : 'transparent', background: tab === 'servers' ? 'var(--bg)' : 'transparent' }}>DNS 服务器</button>
        <button onClick={() => setTab('hosts')} className={`px-4 py-2 text-sm font-medium rounded-t-lg -mb-[1px] ${tab === 'hosts' ? 'border-t border-x' : ''}`} style={{ color: tab === 'hosts' ? 'var(--accent)' : 'var(--text)', borderColor: tab === 'hosts' ? 'var(--border)' : 'transparent', background: tab === 'hosts' ? 'var(--bg)' : 'transparent' }}>Hosts</button>
      </div>

      {tab === 'servers' && (
        <div className="space-y-4">
          <p className="text-sm" style={{ color: '#8b949e' }}>每行一个 DNS 服务器。支持纯 IP 和 DoH JSON 格式。</p>
          <textarea value={servers} onChange={e => setServers(e.target.value)} className="w-full h-40 px-4 py-3 rounded-lg border font-mono text-sm resize-none" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}
            placeholder="8.8.8.8\n1.1.1.1" />
          <button onClick={handleSaveServers} disabled={saveDns.isPending} className="px-6 py-2 rounded-lg text-sm text-white disabled:opacity-50" style={{ background: 'var(--accent)' }}>{saveDns.isPending ? '保存中...' : '保存'}</button>
        </div>
      )}

      {tab === 'hosts' && (
        <div className="space-y-4">
          <p className="text-sm" style={{ color: '#8b949e' }}>每行一个映射: 域名 IP</p>
          <textarea value={hosts} onChange={e => setHosts(e.target.value)} className="w-full h-40 px-4 py-3 rounded-lg border font-mono text-sm resize-none" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}
            placeholder="domain:example.com 1.2.3.4" />
          <button onClick={handleSaveHosts} disabled={saveHosts.isPending} className="px-6 py-2 rounded-lg text-sm text-white disabled:opacity-50" style={{ background: 'var(--accent)' }}>{saveHosts.isPending ? '保存中...' : '保存'}</button>
        </div>
      )}
    </div>
  )
}
