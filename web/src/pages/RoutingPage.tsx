
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'

interface RoutingRule {
  type: string
  domain?: string[]
  ip?: string[]
  port?: string
  network?: string
  inboundTag?: string[]
  outboundTag?: string
  balancerTag?: string
}

const CONDITION_TYPES = [
  { value: 'domain', label: '域名' },
  { value: 'ip', label: 'IP' },
  { value: 'inbound', label: '入站Tag' },
  { value: 'network', label: '网络' },
  { value: 'port', label: '端口' },
]

const QUICK_RULES = [
  { label: '域名直连', type: 'domain', value: 'geosite:cn', outbound: 'direct' },
  { label: '域名阻止', type: 'domain', value: 'geosite:category-ads-all', outbound: 'block' },
  { label: 'IP 直连', type: 'ip', value: 'geoip:cn,geoip:private', outbound: 'direct' },
  { label: '阻止 UDP 443', type: 'port', value: '443', outbound: 'block', network: 'udp' },
]

export default function RoutingPage() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const { data, isLoading } = useQuery({ queryKey: ['routing'], queryFn: () => api.get('/routing') })

  const [condType, setCondType] = useState('domain')
  const [condValue, setCondValue] = useState('')
  const [outboundTag, setOutboundTag] = useState('direct')
  const [networkType] = useState('tcp')

  const rules: RoutingRule[] = data?.rules || []
  const domainStrategy: string = data?.domainStrategy || 'IPIfNonMatch'

  const saveMutation = useMutation({
    mutationFn: (payload: any) => api.post('/routing', payload),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['routing'] }); showToast('保存成功', 'success') },
    onError: (e: any) => { showToast(e.message || '保存失败', 'error') },
  })

  const addRule = (rule: RoutingRule) => {
    const newRules = [rule, ...rules]
    saveMutation.mutate({ rules: newRules, domainStrategy })
  }

  const removeRule = (index: number) => {
    if (!confirm('确认删除此规则?')) return
    const newRules = rules.filter((_, i) => i !== index)
    saveMutation.mutate({ rules: newRules, domainStrategy })
  }

  const moveRule = (index: number, dir: number) => {
    const target = index + dir
    if (target < 0 || target >= rules.length) return
    const newRules = [...rules]
    const [moved] = newRules.splice(index, 1)
    newRules.splice(target, 0, moved)
    saveMutation.mutate({ rules: newRules, domainStrategy })
  }

  const handleAddRule = () => {
    if (!condValue) { showToast('请输入匹配值', 'error'); return }
    const rule: RoutingRule = { type: 'field' }
    if (condType === 'domain') rule.domain = condValue.split(',').map(s => s.trim())
    else if (condType === 'ip') rule.ip = condValue.split(',').map(s => s.trim())
    else if (condType === 'inbound') rule.inboundTag = condValue.split(',').map(s => s.trim())
    else if (condType === 'network') { rule.network = condValue; if (networkType) rule.network = networkType }
    else if (condType === 'port') rule.port = condValue
    rule.outboundTag = outboundTag
    addRule(rule)
    setCondValue('')
  }

  const getRuleDesc = (r: RoutingRule): string => {
    if (r.domain) return r.domain.join(', ')
    if (r.ip) return r.ip.join(', ')
    if (r.inboundTag) return r.inboundTag.join(', ')
    if (r.port) return `端口:${r.port}` + (r.network ? `/${r.network}` : '')
    if (r.network) return r.network
    return r.outboundTag || r.balancerTag || '-'
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>路由规则</h1>

      {/* Domain Strategy */}
      <div className="flex items-center gap-3 p-3 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
        <span className="text-sm" style={{ color: '#8b949e' }}>域名策略:</span>
        <select value={domainStrategy} onChange={e => saveMutation.mutate({ rules, domainStrategy: e.target.value })} className="px-3 py-1 rounded border text-sm" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>
          <option value="AsIs">AsIs</option>
          <option value="IPIfNonMatch">IPIfNonMatch</option>
          <option value="IPOnDemand">IPOnDemand</option>
        </select>
      </div>

      {/* Quick Add */}
      <div className="flex flex-wrap gap-2">
        {QUICK_RULES.map((qr, i) => (
          <button key={i} onClick={() => {
            const rule: RoutingRule = { type: 'field', outboundTag: qr.outbound }
            if (qr.type === 'domain') rule.domain = qr.value.split(',')
            else if (qr.type === 'ip') rule.ip = qr.value.split(',')
            else if (qr.type === 'port') { rule.port = qr.value; if (qr.network) rule.network = qr.network }
            addRule(rule)
          }} className="px-3 py-1.5 rounded text-xs font-medium border" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>{qr.label}</button>
        ))}
      </div>

      {/* Add Form */}
      <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
          <select value={condType} onChange={e => setCondType(e.target.value)} className="px-3 py-2 rounded border text-sm" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>
            {CONDITION_TYPES.map(ct => <option key={ct.value} value={ct.value}>{ct.label}</option>)}
          </select>
          <input value={condValue} onChange={e => setCondValue(e.target.value)} placeholder={condType === 'domain' ? 'domain:example.com 或 geosite:cn' : condType === 'ip' ? 'ip/prefix 或 geoip:cn' : condType === 'port' ? '443' : '匹配值'} className="col-span-2 px-3 py-2 rounded border text-sm" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }} />
          <select value={outboundTag} onChange={e => setOutboundTag(e.target.value)} className="px-3 py-2 rounded border text-sm" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>
            <option value="direct">direct</option>
            <option value="block">block</option>
            <option value="proxy">proxy</option>
          </select>
        </div>
        <button onClick={handleAddRule} className="px-4 py-2 rounded-lg text-sm text-white" style={{ background: 'var(--accent)' }}>添加规则</button>
      </div>

      {/* Rule Table */}
      <div className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
        <table className="w-full">
          <thead>
            <tr style={{ background: 'var(--bg2)' }}>
              <th className="text-left px-4 py-3 text-xs font-medium w-12" style={{ color: '#8b949e' }}>#</th>
              <th className="text-left px-4 py-3 text-xs font-medium" style={{ color: '#8b949e' }}>匹配</th>
              <th className="text-left px-4 py-3 text-xs font-medium" style={{ color: '#8b949e' }}>出口</th>
              <th className="text-right px-4 py-3 text-xs font-medium w-24" style={{ color: '#8b949e' }}>操作</th>
            </tr>
          </thead>
          <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
            {rules.map((r, i) => (
              <tr key={i} className="hover:bg-gray-800/30">
                <td className="px-4 py-3 text-sm font-mono" style={{ color: '#8b949e' }}>{i + 1}</td>
                <td className="px-4 py-3 text-sm font-mono">{getRuleDesc(r)}</td>
                <td className="px-4 py-3 text-sm">
                  <span className="px-2 py-0.5 rounded text-xs" style={{ background: r.outboundTag === 'direct' ? 'rgba(63,185,80,0.2)' : r.outboundTag === 'block' ? 'rgba(139,148,158,0.2)' : 'rgba(56,139,253,0.2)', color: r.outboundTag === 'direct' ? '#3fb950' : r.outboundTag === 'block' ? '#8b949e' : '#58a6ff' }}>{r.outboundTag || r.balancerTag || '-'}</span>
                </td>
                <td className="px-4 py-3 text-right">
                  <div className="flex gap-1 justify-end">
                    <button onClick={() => moveRule(i, -1)} disabled={i === 0} className="px-2 py-1 rounded text-xs disabled:opacity-30" style={{ background: 'var(--bg)', color: 'var(--text)' }}>↑</button>
                    <button onClick={() => moveRule(i, 1)} disabled={i === rules.length - 1} className="px-2 py-1 rounded text-xs disabled:opacity-30" style={{ background: 'var(--bg)', color: 'var(--text)' }}>↓</button>
                    <button onClick={() => removeRule(i)} className="px-2 py-1 rounded text-xs text-white" style={{ background: '#f85149' }}>删除</button>
                  </div>
                </td>
              </tr>
            ))}
            {!isLoading && rules.length === 0 && (
              <tr><td colSpan={4} className="px-4 py-8 text-center" style={{ color: '#8b949e' }}>暂无规则</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
