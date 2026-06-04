import { useEffect, useState } from 'react'
import { useNodes, useTestNodes } from '../hooks/use-nodes'
import { useConnections, useConnect, useDisconnect } from '../hooks/use-connections'
import { useStatus } from '../hooks/use-status'
import { useToast } from '../components/Toast'
import { classNames } from '../lib/utils'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'

type BindingMode = 'global' | 'rule' | 'direct' | 'block' | 'dns' | 'custom'

export default function ConnectPage() {
  const queryClient = useQueryClient()
  const { data: nodesData, isLoading: nodesLoading } = useNodes()
  const { data: connData } = useConnections()
  const { data: status } = useStatus()
  const { data: tpStatus } = useQuery({ queryKey: ['tp-status'], queryFn: () => api.get('/transparent/status'), refetchInterval: 10000 })
  const { data: bypassData } = useQuery({ queryKey: ['tp-bypass'], queryFn: () => api.get('/transparent/bypass') })
  const { data: iptables } = useQuery({ queryKey: ['iptables-rules'], queryFn: () => api.get('/transparent/iptables'), refetchInterval: 10000 })
  const { data: routing } = useQuery({ queryKey: ['routing'], queryFn: () => api.get('/routing'), refetchInterval: 10000 })
  const { data: fullConfig } = useQuery({ queryKey: ['full-config-summary'], queryFn: () => api.get('/config'), refetchInterval: 10000 })
  const connect = useConnect()
  const disconnect = useDisconnect()
  const testNodes = useTestNodes()
  const { showToast } = useToast()

  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [strategy, setStrategy] = useState('roundRobin')
  const [transparentOnConnect, setTransparentOnConnect] = useState(false)
  const [testOutput, setTestOutput] = useState('')
  const [bypassText, setBypassText] = useState('')

  const nodes = nodesData?.nodes || []
  const connected = connData?.connected || []
  const config = fullConfig?.config
  const isActive = status?.running && connected.length > 0
  const tpActive = tpStatus?.active || false
  const dnsHijacked = tpStatus?.dnsHijacked || false

  useEffect(() => {
    if (Array.isArray(bypassData?.cidrs)) {
      setBypassText(bypassData.cidrs.join('\n'))
    }
  }, [bypassData])

  const saveBypass = useMutation({
    mutationFn: () => {
      const cidrs = bypassText.split(/\n|,/).map(s => s.trim()).filter(Boolean)
      return api.post('/transparent/bypass', { cidrs })
    },
    onSuccess: () => {
      showToast(tpActive ? '绕过 IP 段已保存，iptables 已重载' : '绕过 IP 段已保存', 'success')
      queryClient.invalidateQueries({ queryKey: ['tp-bypass'] })
      queryClient.invalidateQueries({ queryKey: ['tp-status'] })
      queryClient.invalidateQueries({ queryKey: ['iptables-rules'] })
    },
    onError: (e: any) => showToast(e.message || '保存绕过 IP 段失败', 'error'),
  })

  const saveInboundTarget = useMutation({
    mutationFn: ({ inboundTag, target }: { inboundTag: string; target: string }) => {
      const currentRules = routing?.rules || []
      const currentBalancers = routing?.balancers || []
      const targetRule = target.startsWith('balancer:')
        ? { type: 'field', inboundTag: [inboundTag], balancerTag: target.replace('balancer:', '') }
        : { type: 'field', inboundTag: [inboundTag], outboundTag: target }
      let replaced = false
      const nextRules = currentRules.map((rule: any) => {
        if (Array.isArray(rule.inboundTag) && rule.inboundTag.length === 1 && rule.inboundTag[0] === inboundTag) {
          replaced = true
          return targetRule
        }
        return rule
      })
      if (!replaced) nextRules.unshift(targetRule)
      return api.post('/routing', { rules: nextRules, balancers: currentBalancers, domainStrategy: routing?.domainStrategy || 'IPIfNonMatch' })
    },
    onSuccess: () => {
      showToast('入口绑定已保存，Xray 已重启', 'success')
      queryClient.invalidateQueries({ queryKey: ['routing'] })
      queryClient.invalidateQueries({ queryKey: ['full-config-summary'] })
    },
    onError: (e: any) => showToast(e.message || '保存失败', 'error'),
  })

  const enableTp = useMutation({
    mutationFn: () => api.post('/transparent/enable', { port: getTransparentPort(config) || 12345 }),
    onSuccess: () => { showToast('透明代理已启用', 'success'); queryClient.invalidateQueries({ queryKey: ['tp-status'] }) },
    onError: (e: any) => showToast(e.message, 'error'),
  })
  const disableTp = useMutation({
    mutationFn: () => api.post('/transparent/disable'),
    onSuccess: () => { showToast('透明代理已关闭', 'success'); queryClient.invalidateQueries({ queryKey: ['tp-status'] }) },
    onError: (e: any) => showToast(e.message, 'error'),
  })
  const toggleDns = useMutation({
    mutationFn: () => api.post('/transparent/toggle-dns'),
    onSuccess: (r: any) => { showToast(r.hijacked ? 'DNS 劫持已开启' : 'DNS 劫持已关闭', 'success'); queryClient.invalidateQueries({ queryKey: ['tp-status'] }) },
    onError: (e: any) => showToast(e.message, 'error'),
  })

  const toggleNode = (id: string) => {
    if (isActive) return
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  const handleConnect = async () => {
    if (selected.size === 0) { showToast('请至少选择一个节点', 'error'); return }
    try {
      await connect.mutateAsync({ nodeIds: Array.from(selected), strategy, transparent: transparentOnConnect })
      showToast('连接成功', 'success')
      queryClient.invalidateQueries({ queryKey: ['tp-status'] })
      queryClient.invalidateQueries({ queryKey: ['routing'] })
      queryClient.invalidateQueries({ queryKey: ['full-config-summary'] })
    } catch (e: any) {
      showToast(e.message || '连接失败', 'error')
    }
  }

  const handleDisconnect = async () => {
    if (!confirm('确认断开连接？')) return
    try {
      await disconnect.mutateAsync()
      showToast('已断开连接', 'success')
      setSelected(new Set())
      queryClient.invalidateQueries({ queryKey: ['routing'] })
      queryClient.invalidateQueries({ queryKey: ['full-config-summary'] })
    } catch (e: any) {
      showToast(e.message || '断开失败', 'error')
    }
  }

  const handleTestSelected = async () => {
    const ids = Array.from(selected)
    if (ids.length === 0) { showToast('请先选择节点', 'error'); return }
    setTestOutput('测试中...')
    try {
      const results = await testNodes.mutateAsync({ nodeIds: ids, mode: 'ping' })
      const lines = (results.results || []).map((r: any) => `${r.tag || r.nodeId}: ${r.ok ? r.latency + 'ms' : 'FAIL'} ${r.exitIp || ''}`)
      setTestOutput(lines.join('\n'))
    } catch (e: any) {
      setTestOutput('测试失败: ' + e.message)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>流量编排</h1>
          <p className="text-sm mt-1" style={{ color: '#8b949e' }}>动态入口、节点、出站组和透明代理状态集中控制；完整规则仍可在配置页高级编辑。</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <StatusPill label="Xray" active={!!status?.running} activeText="运行中" inactiveText="已停止" />
          <StatusPill label="透明代理" active={tpActive} activeText="运行中" inactiveText="关闭" />
          <StatusPill label="iptables" active={!!tpStatus?.hasIptables} activeText="已应用" inactiveText="未应用" />
          <StatusPill label="DNS 劫持" active={dnsHijacked} activeText="开启" inactiveText="关闭" warn={dnsHijacked} />
        </div>
      </div>

      <RuntimeSummary connected={connected} nodes={nodes} config={config} routing={routing} strategy={strategy} />

      <InboundOrchestrationCard
        config={config}
        routing={routing}
        saving={saveInboundTarget.isPending}
        onChange={(inboundTag, target) => saveInboundTarget.mutate({ inboundTag, target })}
      />

      <OutboundGroupsCard config={config} routing={routing} />

      <NodeSelectionCard
        nodes={nodes}
        loading={nodesLoading}
        selected={selected}
        locked={!!isActive}
        onToggle={toggleNode}
        onSelectAll={() => setSelected(new Set(nodes.map((n: any) => n.id)))}
        onClear={() => setSelected(new Set())}
        onTest={handleTestSelected}
      />

      {!isActive && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
            <label className="text-sm block mb-2" style={{ color: '#8b949e' }}>连接策略</label>
            <select value={strategy} onChange={(e) => setStrategy(e.target.value)} className="w-full px-3 py-2 rounded border text-sm" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>
              <option value="roundRobin">轮询 roundRobin</option>
              <option value="leastPing">最低延迟 leastPing</option>
              <option value="random">随机 random</option>
            </select>
          </div>
          <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
            <label className="flex items-center gap-3 cursor-pointer">
              <input type="checkbox" checked={transparentOnConnect} onChange={(e) => setTransparentOnConnect(e.target.checked)} className="w-4 h-4 accent-blue-500" />
              <span className="text-sm">连接时同时启用透明代理</span>
            </label>
            <p className="text-xs mt-2" style={{ color: '#8b949e' }}>这会应用 iptables REDIRECT；配置里有 transparent 入口不代表透明代理已开启。</p>
          </div>
        </div>
      )}

      <div className="flex gap-3 flex-wrap">
        {!isActive ? (
          <button onClick={handleConnect} disabled={connect.isPending || selected.size === 0} className="px-6 py-2 rounded-lg text-white font-medium disabled:opacity-40" style={{ background: '#3fb950' }}>
            {connect.isPending ? '连接中...' : '连接选中节点'}
          </button>
        ) : (
          <button onClick={handleDisconnect} disabled={disconnect.isPending} className="px-6 py-2 rounded-lg text-white font-medium disabled:opacity-40" style={{ background: '#f85149' }}>
            {disconnect.isPending ? '断开中...' : '断开连接'}
          </button>
        )}
        {tpActive ? (
          <button onClick={() => disableTp.mutate()} disabled={disableTp.isPending} className="px-6 py-2 rounded-lg text-white font-medium disabled:opacity-40" style={{ background: '#d29922' }}>关闭透明代理</button>
        ) : (
          <button onClick={() => enableTp.mutate()} disabled={enableTp.isPending || !status?.running} className="px-6 py-2 rounded-lg text-white font-medium disabled:opacity-40" style={{ background: '#58a6ff' }}>启用透明代理</button>
        )}
        <button onClick={() => toggleDns.mutate()} disabled={toggleDns.isPending} className="px-6 py-2 rounded-lg text-white font-medium disabled:opacity-40" style={{ background: dnsHijacked ? '#f85149' : '#8b949e' }}>
          {dnsHijacked ? '关闭 DNS 劫持' : '开启 DNS 劫持'}
        </button>
      </div>

      <TransparentDetails
        tpActive={tpActive}
        iptables={iptables}
        bypassText={bypassText}
        onBypassChange={setBypassText}
        onSaveBypass={() => saveBypass.mutate()}
        savingBypass={saveBypass.isPending}
      />

      {isActive && <div className="p-3 rounded-lg border text-sm" style={{ background: 'rgba(210,153,34,0.1)', borderColor: '#d29922', color: '#d29922' }}>连接运行中，节点选择已锁定。入口绑定和透明代理开关仍可按需调整。</div>}

      {testOutput && <pre className="p-4 rounded-lg border font-mono text-xs whitespace-pre-wrap overflow-auto max-h-60" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: '#8b949e' }}>{testOutput}</pre>}
    </div>
  )
}

function RuntimeSummary({ connected, nodes, config, routing, strategy }: { connected: any[]; nodes: any[]; config: any; routing: any; strategy: string }) {
  const activeNodes = connected.map(c => nodes.find(n => n.id === c.nodeId)).filter(Boolean)
  const inbounds = config?.inbounds || []
  const outbounds = config?.outbounds || []
  const balancers = routing?.balancers || config?.routing?.balancers || []
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      <MetricCard label="入口" value={`${inbounds.length} 个`} />
      <MetricCard label="出站" value={`${outbounds.length} 个`} />
      <MetricCard label="出站组" value={`${balancers.length} 个`} />
      <MetricCard label="连接节点" value={activeNodes.length ? `${activeNodes.length} 个` : '未连接'} hint={activeNodes.length > 1 ? strategy : undefined} />
    </div>
  )
}

function InboundOrchestrationCard({ config, routing, onChange, saving }: { config: any; routing: any; onChange: (inboundTag: string, target: string) => void; saving: boolean }) {
  const inbounds = config?.inbounds || []
  const outbounds = (config?.outbounds || []).map((o: any) => o.tag).filter(Boolean)
  const balancers = routing?.balancers || config?.routing?.balancers || []
  const rules = routing?.rules || config?.routing?.rules || []

  if (!config) return <Panel title="入口流量绑定"><div className="text-sm" style={{ color: '#8b949e' }}>加载当前配置中...</div></Panel>

  return (
    <Panel title="入口流量绑定" subtitle="动态代理的核心：每个入口可以绑定到单节点、出站组、direct/block/dns-out。复杂规则在配置页的路由规则里继续编辑。">
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-3">
        {inbounds.map((ib: any) => {
          const mapping = getInboundTarget(ib.tag, rules)
          const mode = inferMode(ib, mapping)
          return (
            <div key={ib.tag} className="rounded-lg border p-3 space-y-3" style={{ borderColor: 'var(--border)', background: 'var(--bg)' }}>
              <div className="flex items-start justify-between gap-3 flex-wrap">
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-sm font-semibold" style={{ color: 'var(--text)' }}>{ib.tag}</span>
                    <span className="px-2 py-0.5 rounded text-xs" style={{ background: mode.bg, color: mode.color }}>{mode.label}</span>
                  </div>
                  <div className="text-xs mt-1" style={{ color: '#8b949e' }}>{ib.protocol} · {ib.listen || '0.0.0.0'}:{ib.port}</div>
                </div>
                <div className="text-xs" style={{ color: mapping.ruleIndex ? '#58a6ff' : '#8b949e' }}>{mapping.ruleIndex ? `routing #${mapping.ruleIndex}` : '默认路由'}</div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-[1fr_auto] gap-2 items-center">
                <select value={mapping.value} onChange={(e) => onChange(ib.tag, e.target.value)} disabled={saving} className="px-3 py-2 rounded border text-sm disabled:opacity-50" style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}>
                  {mapping.value === '' && <option value="">未指定 / 默认路由</option>}
                  {balancers.map((b: any) => <option key={`balancer:${b.tag}`} value={`balancer:${b.tag}`}>出站组: {b.tag}</option>)}
                  {outbounds.map((tag: string) => <option key={tag} value={tag}>出站: {tag}</option>)}
                </select>
                <span className="text-xs font-mono" style={{ color: '#8b949e' }}>{mapping.display}</span>
              </div>
            </div>
          )
        })}
      </div>
    </Panel>
  )
}

function OutboundGroupsCard({ config, routing }: { config: any; routing: any }) {
  const balancers = routing?.balancers || config?.routing?.balancers || []
  const outbounds = config?.outbounds || []
  return (
    <Panel title="出站组" subtitle="组用于一个入口绑定多个节点；当前版本显示 live config 中的 balancer，后续可做成独立组管理。">
      {balancers.length === 0 ? (
        <div className="text-sm" style={{ color: '#8b949e' }}>当前没有出站组。</div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {balancers.map((b: any) => (
            <div key={b.tag} className="rounded-lg border p-3" style={{ background: 'var(--bg)', borderColor: 'var(--border)' }}>
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <span className="font-mono text-sm font-semibold" style={{ color: 'var(--text)' }}>{b.tag}</span>
                <span className="text-xs" style={{ color: '#8b949e' }}>{b.strategy?.type || 'roundRobin'}</span>
              </div>
              <div className="flex gap-2 flex-wrap mt-3">
                {(b.selector || []).map((tag: string) => {
                  const ob = outbounds.find((o: any) => o.tag === tag)
                  return <span key={tag} className="px-2 py-1 rounded text-xs font-mono" style={{ background: 'rgba(56,139,253,0.15)', color: '#58a6ff' }}>{tag}{ob?.protocol ? ` · ${ob.protocol}` : ''}</span>
                })}
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  )
}

function NodeSelectionCard({ nodes, loading, selected, locked, onToggle, onSelectAll, onClear, onTest }: any) {
  return (
    <Panel title="节点池" subtitle="导入/编辑节点不会立即改变运行配置；选中后点击连接才会应用到 Xray。">
      <div className="flex items-center justify-between gap-2 flex-wrap mb-3">
        <span className="text-sm" style={{ color: '#8b949e' }}>已选 {selected.size} / {nodes.length}</span>
        <div className="flex gap-2 flex-wrap">
          <button onClick={onSelectAll} disabled={locked} className="px-3 py-1 rounded text-sm border disabled:opacity-40" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>全选</button>
          <button onClick={onClear} disabled={locked} className="px-3 py-1 rounded text-sm border disabled:opacity-40" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>清空</button>
          <button onClick={onTest} disabled={selected.size === 0} className="px-3 py-1 rounded text-sm text-white disabled:opacity-40" style={{ background: 'var(--accent)' }}>测试选中</button>
        </div>
      </div>
      {loading ? <div className="p-6 text-center" style={{ color: '#8b949e' }}>加载中...</div> : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
          {nodes.map((node: any) => (
            <button key={node.id} onClick={() => onToggle(node.id)} disabled={locked} className={classNames('text-left rounded-lg border p-3 transition-colors disabled:cursor-not-allowed', selected.has(node.id) ? 'border-blue-500' : 'hover:border-blue-500/60')} style={{ background: selected.has(node.id) ? 'rgba(56,139,253,0.1)' : 'var(--bg)', borderColor: selected.has(node.id) ? '#58a6ff' : 'var(--border)' }}>
              <div className="flex items-center gap-2 flex-wrap">
                <input type="checkbox" checked={selected.has(node.id)} readOnly className="w-4 h-4 accent-blue-500" />
                <span className="font-mono text-sm font-medium" style={{ color: 'var(--text)' }}>{node.tag}</span>
                <span className="text-xs" style={{ color: '#8b949e' }}>{node.protocol}</span>
              </div>
              <div className="text-xs mt-1 truncate" style={{ color: '#8b949e' }}>{node.address}:{node.port}</div>
            </button>
          ))}
          {!loading && nodes.length === 0 && <div className="p-6 text-center rounded-lg border" style={{ color: '#8b949e', borderColor: 'var(--border)' }}>暂无节点，请先到节点页导入。</div>}
        </div>
      )}
    </Panel>
  )
}

function TransparentDetails({
  tpActive,
  iptables,
  bypassText,
  onBypassChange,
  onSaveBypass,
  savingBypass,
}: {
  tpActive: boolean
  iptables: any
  bypassText: string
  onBypassChange: (value: string) => void
  onSaveBypass: () => void
  savingBypass: boolean
}) {
  return (
    <Panel title="透明代理实际状态" subtitle={tpActive ? '运行中：iptables REDIRECT / DNS 劫持按状态生效。' : '未运行：配置中有 transparent 入口不代表已接管系统流量。'} right={<span className="text-xs font-mono" style={{ color: '#8b949e' }}>{iptables?.binary || 'iptables'}</span>}>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div>
          <div className="flex items-center justify-between gap-3 mb-2">
            <div>
              <h3 className="text-sm font-medium" style={{ color: 'var(--text)' }}>绕过 IP 段</h3>
              <p className="text-xs mt-1" style={{ color: '#8b949e' }}>每行一个 CIDR；保存后透明代理运行中会立即重载 iptables。</p>
            </div>
            <button onClick={onSaveBypass} disabled={savingBypass} className="px-3 py-1.5 rounded text-sm disabled:opacity-40" style={{ background: '#238636', color: 'white' }}>
              {savingBypass ? '保存中...' : '保存'}
            </button>
          </div>
          <textarea
            value={bypassText}
            onChange={(e) => onBypassChange(e.target.value)}
            rows={12}
            className="w-full px-3 py-2 rounded border font-mono text-xs"
            style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}
            placeholder={'192.168.0.0/16\n10.0.0.0/8\n1.2.3.4/32'}
          />
        </div>
        <div>
          <details open>
            <summary className="cursor-pointer text-sm" style={{ color: 'var(--accent)' }}>查看 iptables 规则</summary>
            <div className="grid grid-cols-1 gap-3 mt-3">
              <RuleBlock title="nat" text={iptables?.nat} />
              <RuleBlock title="filter" text={iptables?.filter} />
              <RuleBlock title="mangle" text={iptables?.mangle} />
            </div>
          </details>
        </div>
      </div>
    </Panel>
  )
}

function StatusPill({ label, active, activeText, inactiveText, warn }: { label: string; active: boolean; activeText: string; inactiveText: string; warn?: boolean }) {
  const color = active ? (warn ? '#d29922' : '#3fb950') : '#8b949e'
  return <span className="px-3 py-1 rounded text-xs" style={{ background: active ? `${color}22` : 'rgba(139,148,158,0.2)', color }}>{label}: {active ? activeText : inactiveText}</span>
}

function MetricCard({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}><div className="text-xs" style={{ color: '#8b949e' }}>{label}</div><div className="text-lg font-semibold mt-1" style={{ color: 'var(--text)' }}>{value}</div>{hint && <div className="text-xs mt-1" style={{ color: '#8b949e' }}>{hint}</div>}</div>
}

function Panel({ title, subtitle, right, children }: { title: string; subtitle?: string; right?: React.ReactNode; children: React.ReactNode }) {
  return <div className="p-4 rounded-lg border space-y-4" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}><div className="flex items-start justify-between gap-3 flex-wrap"><div><h2 className="text-sm font-medium" style={{ color: '#8b949e' }}>{title}</h2>{subtitle && <p className="text-xs mt-1" style={{ color: '#8b949e' }}>{subtitle}</p>}</div>{right}</div>{children}</div>
}

function RuleBlock({ title, text }: { title: string; text?: string }) {
  const filtered = (text || '').split('\n').filter(line => line.includes('XRAY_MGR') || line.includes('--dport 443') || line.startsWith('*') || line.startsWith(':') || line === 'COMMIT').join('\n')
  return <div className="rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border)' }}><div className="px-3 py-2 text-xs font-semibold" style={{ background: 'var(--bg)', color: 'var(--text)' }}>{title}</div><pre className="p-3 text-xs whitespace-pre-wrap overflow-auto max-h-64 font-mono" style={{ background: 'var(--bg)', color: '#8b949e' }}>{filtered || '无 XRAY_MGR / QUIC 相关规则'}</pre></div>
}

function getInboundTarget(inboundTag: string, rules: any[]) {
  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i]
    if (Array.isArray(rule.inboundTag) && rule.inboundTag.includes(inboundTag)) {
      if (rule.balancerTag) return { value: `balancer:${rule.balancerTag}`, display: `组:${rule.balancerTag}`, ruleIndex: i + 1 }
      if (rule.outboundTag) return { value: rule.outboundTag, display: rule.outboundTag, ruleIndex: i + 1 }
    }
  }
  return { value: '', display: '默认', ruleIndex: 0 }
}

function inferMode(ib: any, mapping: any): { label: string; color: string; bg: string; mode: BindingMode } {
  if (ib.tag === 'dns' || ib.protocol === 'dns') return { label: 'DNS', color: '#d29922', bg: 'rgba(210,153,34,0.15)', mode: 'dns' }
  if (mapping.value === 'direct') return { label: '直连', color: '#3fb950', bg: 'rgba(63,185,80,0.15)', mode: 'direct' }
  if (mapping.value === 'block') return { label: '阻断', color: '#f85149', bg: 'rgba(248,81,73,0.15)', mode: 'block' }
  if (mapping.value.startsWith('balancer:')) return { label: '出站组', color: '#58a6ff', bg: 'rgba(56,139,253,0.15)', mode: 'global' }
  if (mapping.value) return { label: '单出站', color: '#58a6ff', bg: 'rgba(56,139,253,0.15)', mode: 'global' }
  return { label: '默认', color: '#8b949e', bg: 'rgba(139,148,158,0.15)', mode: 'custom' }
}

function getTransparentPort(config: any) {
  return (config?.inbounds || []).find((i: any) => i.tag === 'transparent')?.port
}
