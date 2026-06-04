
import { useState, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useStatus } from '../hooks/use-status'
import { useConnections } from '../hooks/use-connections'
import { useNodes } from '../hooks/use-nodes'
import { api } from '../lib/api'
import { formatBytes } from '../lib/utils'

function StatCard({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
      <div className="text-xs mb-1" style={{ color: '#8b949e' }}>{label}</div>
      <div className="text-lg font-semibold font-mono" style={{ color: color || 'var(--text)' }}>{value}</div>
    </div>
  )
}

export default function DashboardPage() {
  const { data: status } = useStatus()
  const { data: connections } = useConnections()
  const { data: nodesData } = useNodes()
  const { data: logs } = useQuery({ queryKey: ['logs-5'], queryFn: () => api.get('/logs?lines=10') })

  const nodes = nodesData?.nodes || []
  const connected = connections?.connected || []
  const connectedNodes = connected.map((c: any) => nodes.find((n: any) => n.id === c.nodeId)).filter(Boolean)

  // Real-time traffic speed calculation via polling
  const prevRef = useRef({ rx: 0, tx: 0, ts: Date.now() })
  const [rxSpeed, setRxSpeed] = useState(0)
  const [txSpeed, setTxSpeed] = useState(0)

  // Calculate speed from traffic data if available
  const traffic = status?.traffic
  if (traffic) {
    const now = Date.now()
    const dt = (now - prevRef.current.ts) / 1000
    if (dt >= 2) {
      const dr = (traffic.rxSpeed - prevRef.current.rx)
      const dtc = (traffic.txSpeed - prevRef.current.tx)
      if (dr >= 0) setRxSpeed(Math.round(dr / dt))
      if (dtc >= 0) setTxSpeed(Math.round(dtc / dt))
      prevRef.current = { rx: traffic.rxSpeed, tx: traffic.txSpeed, ts: now }
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>仪表盘</h1>

      {/* Connection Status */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Xray 状态" value={status?.running ? '● 运行中' : '● 已停止'} color={status?.running ? '#3fb950' : '#f85149'} />
        <StatCard label="已连接节点" value={`${connected.length} 个`} color="#58a6ff" />
        <StatCard label="节点总数" value={`${nodes.length} 个`} />
        <StatCard label="版本" value={status?.version || '-'} />
      </div>

      {/* Real-time Traffic */}
      <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
        <h2 className="text-sm font-medium mb-3" style={{ color: '#8b949e' }}>实时流量</h2>
        <div className="grid grid-cols-2 gap-4">
          <div className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: '#8b949e' }}>下载速度</span>
            <span className="font-mono text-2xl font-bold" style={{ color: '#3fb950' }}>
              {formatBytes(rxSpeed)}/s
            </span>
          </div>
          <div className="flex flex-col gap-1">
            <span className="text-xs" style={{ color: '#8b949e' }}>上传速度</span>
            <span className="font-mono text-2xl font-bold" style={{ color: '#d29922' }}>
              {formatBytes(txSpeed)}/s
            </span>
          </div>
        </div>
        {traffic?.interfaces && (
          <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-2">
            {Object.entries(traffic.interfaces).map(([name, v]: [string, any]) => (
              name !== 'lo' && (
                <div key={name} className="flex items-center gap-2 text-xs p-2 rounded" style={{ background: 'var(--bg)' }}>
                  <span className="font-medium min-w-[80px]">{name}</span>
                  <span style={{ color: '#3fb950' }}>↓ {formatBytes(v.rx)}</span>
                  <span style={{ color: '#d29922' }}>↑ {formatBytes(v.tx)}</span>
                </div>
              )
            ))}
          </div>
        )}
      </div>

      {/* Connected Nodes */}
      {connectedNodes.length > 0 && (
        <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
          <h2 className="text-sm font-medium mb-3" style={{ color: '#8b949e' }}>已连接节点</h2>
          <div className="space-y-2">
            {connectedNodes.map((node: any) => (
              <div key={node.id} className="flex items-center gap-3 p-2 rounded flex-wrap" style={{ background: 'var(--bg)' }}>
                <span className="w-2 h-2 rounded-full shrink-0" style={{ background: '#3fb950' }} />
                <span className="font-medium font-mono text-sm">{node.tag}</span>
                <span className="text-xs" style={{ color: '#8b949e' }}>{node.protocol} · {node.address}:{node.port}</span>
                {node.latency && <span className="text-xs ml-auto font-mono" style={{ color: '#3fb950' }}>{node.latency}ms</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Listen Ports */}
      {status?.listenPorts?.length > 0 && (
        <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
          <h2 className="text-sm font-medium mb-3" style={{ color: '#8b949e' }}>监听端口</h2>
          <div className="flex flex-wrap gap-2">
            {status.listenPorts.map((p: string) => (
              <span key={p} className="px-2 py-1 rounded text-xs font-mono" style={{ background: 'var(--bg)', color: 'var(--accent)' }}>{p}</span>
            ))}
          </div>
        </div>
      )}

      {/* Recent Logs */}
      {logs?.logs && (
        <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
          <h2 className="text-sm font-medium mb-3" style={{ color: '#8b949e' }}>最近日志</h2>
          <pre className="text-xs font-mono whitespace-pre-wrap overflow-auto max-h-40" style={{ color: '#8b949e' }}>
            {logs.logs}
          </pre>
        </div>
      )}
    </div>
  )
}
