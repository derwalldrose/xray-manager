import { useEffect, useState } from 'react'
import { useNodes, useTestNodes } from '../hooks/use-nodes'
import { useConnections, useConnect, useDisconnect } from '../hooks/use-connections'
import { useStatus } from '../hooks/use-status'
import { useToast } from '../components/Toast'
import { classNames } from '../lib/utils'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'

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
  const { data: systemProxy } = useQuery({ queryKey: ['system-proxy'], queryFn: () => api.get('/system-proxy/status'), refetchInterval: 5000 })
  const connect = useConnect()
  const disconnect = useDisconnect()
  const testNodes = useTestNodes()
  const { showToast } = useToast()

  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [strategy, setStrategy] = useState('roundRobin')
  const [transparentOnConnect, setTransparentOnConnect] = useState(false)
  const [testOutput, setTestOutput] = useState('')
  const [bypassText, setBypassText] = useState('')
  const [proxyBypass, setProxyBypass] = useState(defaultProxyBypass)

  const isWindows = systemProxy?.supported === true
  const nodes = nodesData?.nodes || []
  const connected = connData?.connected || []
  const connectedIds = new Set(connected.map((c: any) => c.nodeId))
  const config = fullConfig?.config
  const isActive = status?.running && connected.length > 0

  // Sync selected with connected nodes when connection data changes
  useEffect(() => {
    if (connected.length > 0) {
      setSelected(new Set(connected.map((c: any) => c.nodeId)))
    }
  }, [connected])
  const tpActive = tpStatus?.active || false
  const dnsHijacked = tpStatus?.dnsHijacked || false

  useEffect(() => {
    if (Array.isArray(bypassData?.cidrs)) {
      setBypassText(bypassData.cidrs.join('\n'))
    }
  }, [bypassData])

  useEffect(() => {
    if (systemProxy?.ProxyOverride !== undefined) setProxyBypass(systemProxy.ProxyOverride || defaultProxyBypass)
  }, [systemProxy?.ProxyOverride])

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

  const enableSystemProxy = useMutation({
    mutationFn: () => api.post('/system-proxy/enable', { port: 10818, bypass: proxyBypass || defaultProxyBypass }),
    onSuccess: () => { showToast('系统代理已开启', 'success'); queryClient.invalidateQueries({ queryKey: ['system-proxy'] }) },
    onError: (e: any) => showToast(e.message || '开启系统代理失败', 'error'),
  })
  const disableSystemProxy = useMutation({
    mutationFn: () => api.post('/system-proxy/disable'),
    onSuccess: () => { showToast('系统代理已关闭', 'success'); queryClient.invalidateQueries({ queryKey: ['system-proxy'] }) },
    onError: (e: any) => showToast(e.message || '关闭系统代理失败', 'error'),
  })
  const applySystemProxyBypass = useMutation({
    mutationFn: () => api.post('/system-proxy/enable', { server: systemProxy?.ProxyServer || '127.0.0.1:10818', bypass: proxyBypass || defaultProxyBypass }),
    onSuccess: () => { showToast('系统代理绕过列表已应用', 'success'); queryClient.invalidateQueries({ queryKey: ['system-proxy'] }) },
    onError: (e: any) => showToast(e.message || '应用绕过列表失败', 'error'),
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
      await connect.mutateAsync({ nodeIds: Array.from(selected), strategy, transparent: isWindows ? false : transparentOnConnect })
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
          {isWindows ? (
            <StatusPill label="系统代理" active={systemProxy?.enabled === true} activeText="已开启" inactiveText="未开启" />
          ) : (
            <>
              <StatusPill label="透明代理" active={tpActive} activeText="运行中" inactiveText="关闭" />
              <StatusPill label="iptables" active={!!tpStatus?.hasIptables} activeText="已应用" inactiveText="未应用" />
              <StatusPill label="DNS 劫持" active={dnsHijacked} activeText="开启" inactiveText="关闭" warn={dnsHijacked} />
            </>
          )}
        </div>
      </div>

      {!isWindows && <RuntimeSummary connected={connected} nodes={nodes} config={config} routing={routing} strategy={strategy} />}

      {isWindows ? (
        <WindowsSystemProxyCard
          status={systemProxy}
          bypass={proxyBypass}
          setBypass={setProxyBypass}
          onEnable={() => enableSystemProxy.mutate()}
          onDisable={() => disableSystemProxy.mutate()}
          onApplyBypass={() => applySystemProxyBypass.mutate()}
          busy={enableSystemProxy.isPending || disableSystemProxy.isPending || applySystemProxyBypass.isPending}
        />
      ) : null}

      <NodeSelectionCard
        nodes={nodes}
        loading={nodesLoading}
        selected={selected}
        connectedIds={connectedIds}
        locked={!!isActive}
        onToggle={toggleNode}
        onSelectAll={() => setSelected(new Set(nodes.map((n: any) => n.id)))}
        onClear={() => setSelected(new Set())}
        onTest={handleTestSelected}
      />

      {!isActive && (
        <div className={isWindows ? 'grid grid-cols-1 gap-4' : 'grid grid-cols-1 md:grid-cols-2 gap-4'}>
          <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
            <label className="text-sm block mb-2" style={{ color: '#8b949e' }}>连接策略</label>
            <select value={strategy} onChange={(e) => setStrategy(e.target.value)} className="w-full px-3 py-2 rounded border text-sm" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>
              <option value="roundRobin">轮询 roundRobin</option>
              <option value="leastPing">最低延迟 leastPing</option>
              <option value="random">随机 random</option>
            </select>
          </div>
          {!isWindows && (
            <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
              <label className="flex items-center gap-3 cursor-pointer">
                <input type="checkbox" checked={transparentOnConnect} onChange={(e) => setTransparentOnConnect(e.target.checked)} className="w-4 h-4 accent-blue-500" />
                <span className="text-sm">连接时同时启用透明代理</span>
              </label>
              <p className="text-xs mt-2" style={{ color: '#8b949e' }}>这会应用 iptables REDIRECT；配置里有 transparent 入口不代表透明代理已开启。</p>
            </div>
          )}
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
        {!isWindows && (tpActive ? (
          <button onClick={() => disableTp.mutate()} disabled={disableTp.isPending} className="px-6 py-2 rounded-lg text-white font-medium disabled:opacity-40" style={{ background: '#d29922' }}>关闭透明代理</button>
        ) : (
          <button onClick={() => enableTp.mutate()} disabled={enableTp.isPending || !status?.running} className="px-6 py-2 rounded-lg text-white font-medium disabled:opacity-40" style={{ background: '#58a6ff' }}>启用透明代理</button>
        ))}
        {!isWindows && (
          <button onClick={() => toggleDns.mutate()} disabled={toggleDns.isPending} className="px-6 py-2 rounded-lg text-white font-medium disabled:opacity-40" style={{ background: dnsHijacked ? '#f85149' : '#8b949e' }}>
            {dnsHijacked ? '关闭 DNS 劫持' : '开启 DNS 劫持'}
          </button>
        )}
      </div>

      {!isWindows && (
        <TransparentDetails
          tpActive={tpActive}
          iptables={iptables}
          bypassText={bypassText}
          onBypassChange={setBypassText}
          onSaveBypass={() => saveBypass.mutate()}
          savingBypass={saveBypass.isPending}
        />
      )}

      {isActive && <div className="p-3 rounded-lg border text-sm" style={{ background: 'rgba(210,153,34,0.1)', borderColor: '#d29922', color: '#d29922' }}>{isWindows ? '连接运行中，节点选择已锁定。系统代理可按需开启/关闭。' : '连接运行中，节点选择已锁定。入口绑定和透明代理开关仍可按需调整。'}</div>}

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

function NodeSelectionCard({ nodes, loading, selected, connectedIds, locked, onToggle, onSelectAll, onClear, onTest }: any) {
  const hasConnected = connectedIds?.size > 0
  return (
    <Panel title="节点池" subtitle={hasConnected ? `${connectedIds.size} 个节点正在使用` : '选中后点击连接才会应用到 Xray。'}>
      <div className="flex items-center justify-between gap-2 flex-wrap mb-3">
        <span className="text-sm" style={{ color: '#8b949e' }}>{hasConnected ? `已连接 ${connectedIds.size} / ${nodes.length}` : `已选 ${selected.size} / ${nodes.length}`}</span>
        <div className="flex gap-2 flex-wrap">
          {!locked && <button onClick={onSelectAll} disabled={locked} className="px-3 py-1 rounded text-sm border disabled:opacity-40" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>全选</button>}
          {!locked && <button onClick={onClear} disabled={locked} className="px-3 py-1 rounded text-sm border disabled:opacity-40" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>清空</button>}
          <button onClick={onTest} disabled={selected.size === 0} className="px-3 py-1 rounded text-sm text-white disabled:opacity-40" style={{ background: 'var(--accent)' }}>测试选中</button>
        </div>
      </div>
      {loading ? <div className="p-6 text-center" style={{ color: '#8b949e' }}>加载中...</div> : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
          {nodes.map((node: any) => {
            const isConnected = connectedIds?.has(node.id)
            const isSelected = selected.has(node.id)
            const bg = isConnected ? 'rgba(63,185,80,0.1)' : isSelected ? 'rgba(56,139,253,0.1)' : 'var(--bg)'
            const borderColor = isConnected ? '#3fb950' : isSelected ? '#58a6ff' : 'var(--border)'
            return (
              <button key={node.id} onClick={() => onToggle(node.id)} disabled={locked} className={classNames('text-left rounded-lg border p-3 transition-colors disabled:cursor-not-allowed', isConnected ? 'border-green-500' : isSelected ? 'border-blue-500' : 'hover:border-blue-500/60')} style={{ background: bg, borderColor }}>
                <div className="flex items-center gap-2 flex-wrap">
                  {isConnected ? (
                    <span className="w-2.5 h-2.5 rounded-full bg-green-500 shrink-0" title="正在使用" />
                  ) : (
                    <input type="checkbox" checked={isSelected} readOnly className="w-4 h-4 accent-blue-500" />
                  )}
                  <span className="font-mono text-sm font-medium" style={{ color: 'var(--text)' }}>{node.tag}</span>
                  <span className="text-xs" style={{ color: '#8b949e' }}>{node.protocol}</span>
                  {isConnected && <span className="text-xs px-1.5 py-0.5 rounded" style={{ background: 'rgba(63,185,80,0.15)', color: '#3fb950' }}>使用中</span>}
                </div>
                <div className="text-xs mt-1 truncate" style={{ color: '#8b949e' }}>{node.address}:{node.port}</div>
              </button>
            )
          })}
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

function WindowsSystemProxyCard({ status, bypass, setBypass, onEnable, onDisable, onApplyBypass, busy }: { status: any; bypass: string; setBypass: (v: string) => void; onEnable: () => void; onDisable: () => void; onApplyBypass: () => void; busy: boolean }) {
  const enabled = status?.enabled === true
  return (
    <Panel title="Windows 系统代理" subtitle="Windows 原生模式不使用透明代理/iptables；连接节点后，把系统代理设置到本机 HTTP 入站 127.0.0.1:10818。">
      <div className="flex items-center justify-between gap-3 flex-wrap rounded-lg border p-3" style={{ borderColor: 'var(--border)', background: 'var(--bg)' }}>
        <div>
          <div className="text-sm font-medium" style={{ color: 'var(--text)' }}>{enabled ? '系统代理已开启' : '系统代理未开启'}</div>
          <div className="text-xs mt-1 font-mono" style={{ color: '#8b949e' }}>{status?.ProxyServer || '127.0.0.1:10818'}</div>
        </div>
        <div className="flex gap-2 flex-wrap">
          {enabled ? (
            <button onClick={onDisable} disabled={busy} className="px-4 py-2 rounded-lg text-sm text-white disabled:opacity-40" style={{ background: '#f85149' }}>关闭系统代理</button>
          ) : (
            <button onClick={onEnable} disabled={busy} className="px-4 py-2 rounded-lg text-sm text-white disabled:opacity-40" style={{ background: '#3fb950' }}>设置系统代理</button>
          )}
        </div>
      </div>
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <div className="text-sm font-medium" style={{ color: 'var(--text)' }}>绕过列表</div>
            <div className="text-xs mt-1" style={{ color: '#8b949e' }}>ProxyOverride，分号分隔；保存后会重新应用系统代理。</div>
          </div>
          <button onClick={onApplyBypass} disabled={busy} className="px-3 py-1.5 rounded text-sm text-white disabled:opacity-40" style={{ background: 'var(--accent)' }}>应用绕过列表</button>
        </div>
        <textarea value={bypass} onChange={(e) => setBypass(e.target.value)} rows={4}
          className="w-full px-3 py-2 rounded border font-mono text-xs"
          style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}
          placeholder={defaultProxyBypass}
        />
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

function getTransparentPort(config: any) {
  return (config?.inbounds || []).find((i: any) => i.tag === 'transparent')?.port
}

const defaultProxyBypass = '<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*'
