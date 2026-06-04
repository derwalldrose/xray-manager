import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useNodes, useImportNodes, useDeleteNode, useTestNodes, useUpdateNode } from '../hooks/use-nodes'
import { useToast } from '../components/Toast'
import Modal from '../components/Modal'

type EditTab = 'basic' | 'stream' | 'json'

export default function NodesPage() {
  const qc = useQueryClient()
  const { data: nodesData, isLoading } = useNodes()
  const { data: testUrls } = useQuery({ queryKey: ['test-urls'], queryFn: () => api.get('/nodes/test-urls') })
  const saveTestUrls = useMutation({
    mutationFn: (body: any) => api.post('/nodes/test-urls', body),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['test-urls'] }); showToast('测试 URL 已保存', 'success'); setShowUrls(false) },
  })
  const importNodes = useImportNodes()
  const deleteNode = useDeleteNode()
  const updateNode = useUpdateNode()
  const testNodes = useTestNodes()
  const { showToast } = useToast()

  const nodes = nodesData?.nodes || []
  const latencyOptions = testUrls?.latencyOptions || []
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [showImport, setShowImport] = useState(false)
  const [showUrls, setShowUrls] = useState(false)
  const [latencyUrl, setLatencyUrl] = useState('')
  const [speedUrl, setSpeedUrl] = useState('')
  const [importLinks, setImportLinks] = useState('')
  const [testResults, setTestResults] = useState<Record<string, any>>({})
  const [testing, setTesting] = useState(false)

  // Edit state
  const [editing, setEditing] = useState<any | null>(null)
  const [editTab, setEditTab] = useState<EditTab>('basic')
  const [editJson, setEditJson] = useState('')
  const [editBasic, setEditBasic] = useState({ tag: '', address: '', port: 443, network: 'tcp', security: 'none' })
  const [editStream, setEditStream] = useState({
    path: '', host: '', serviceName: '', sni: '', alpn: '',
    fingerprint: '', publicKey: '', shortId: '', flow: '',
  })

  useEffect(() => {
    if (testUrls) {
      setLatencyUrl(testUrls.latency || '')
      setSpeedUrl(testUrls.speed || '')
    }
  }, [testUrls])

  const toggleSelect = (id: string) => setSelected(prev => {
    const next = new Set(prev)
    next.has(id) ? next.delete(id) : next.add(id)
    return next
  })

  const openEdit = (node: any) => {
    setEditing(node)
    setEditTab('basic')
    const ss = node.streamSettings || {}
    const wsSettings = ss.wsSettings || {}
    const grpcSettings = ss.grpcSettings || {}
    const httpSettings = ss.httpSettings || {}
    const tlsSettings = ss.tlsSettings || {}
    const realitySettings = ss.realitySettings || {}
    const vnext = node.settings?.vnext?.[0] || {}
    const servers = node.settings?.servers?.[0] || {}
    setEditBasic({
      tag: node.tag || '',
      address: node.address || vnext.address || servers.address || '',
      port: Number(node.port) || Number(vnext.port) || Number(servers.port) || 443,
      network: ss.network || 'tcp',
      security: ss.security || 'none',
    })
    setEditStream({
      path: wsSettings.path || httpSettings.path || '',
      host: wsSettings.headers?.Host || httpSettings.host?.[0] || '',
      serviceName: grpcSettings.serviceName || '',
      sni: tlsSettings.serverName || realitySettings.serverName || '',
      alpn: (tlsSettings.alpn || realitySettings.alpn || []).join(','),
      fingerprint: realitySettings.fingerprint || tlsSettings.fingerprint || '',
      publicKey: realitySettings.publicKey || '',
      shortId: realitySettings.shortId || '',
      flow: vnext.users?.[0]?.flow || '',
    })
    setEditJson(JSON.stringify({ settings: node.settings || {}, streamSettings: ss, mux: node.mux || {} }, null, 2))
  }

  const handleSaveEdit = async () => {
    if (!editing) return
    try {
      const parsed = JSON.parse(editTab === 'json' ? editJson : '{}')
      const baseStream = editTab === 'json' ? (parsed.streamSettings || {}) : buildStreamSettings()
      const streamSettings = { ...baseStream, network: editBasic.network, security: editBasic.security }
      const settings = editTab === 'json' ? (parsed.settings || editing.settings || {}) : buildSettings()
      await updateNode.mutateAsync({
        nodeId: editing.id,
        config: {
          ...editing,
          tag: editBasic.tag,
          address: editBasic.address,
          port: Number(editBasic.port),
          settings,
          streamSettings,
          mux: editTab === 'json' ? parsed.mux : editing.mux,
        }
      })
      showToast('节点已保存', 'success')
      setEditing(null)
    } catch (e: any) {
      showToast(e.message || '保存失败，检查 JSON 格式', 'error')
    }
  }

  const buildStreamSettings = () => {
    const ss: any = {}
    if (editBasic.network === 'ws') {
      ss.wsSettings = { path: editStream.path || '/', headers: editStream.host ? { Host: editStream.host } : undefined }
    } else if (editBasic.network === 'grpc') {
      ss.grpcSettings = { serviceName: editStream.serviceName || '' }
    } else if (editBasic.network === 'h2') {
      ss.httpSettings = { path: editStream.path || '/', host: editStream.host ? [editStream.host] : undefined }
    }
    if (editBasic.security === 'tls') {
      ss.tlsSettings = {
        serverName: editStream.sni || undefined,
        alpn: editStream.alpn ? editStream.alpn.split(',').map(s => s.trim()).filter(Boolean) : undefined,
        fingerprint: editStream.fingerprint || undefined,
      }
    } else if (editBasic.security === 'reality') {
      ss.realitySettings = {
        serverName: editStream.sni || undefined,
        publicKey: editStream.publicKey || undefined,
        shortId: editStream.shortId || undefined,
        fingerprint: editStream.fingerprint || undefined,
      }
    }
    return ss
  }

  const buildSettings = () => {
    const s: any = JSON.parse(JSON.stringify(editing.settings || {}))
    if (s.vnext?.[0]) {
      s.vnext[0].address = editBasic.address
      s.vnext[0].port = Number(editBasic.port)
      if (s.vnext[0].users?.[0] && editStream.flow) s.vnext[0].users[0].flow = editStream.flow
    }
    if (s.servers?.[0]) {
      s.servers[0].address = editBasic.address
      s.servers[0].port = Number(editBasic.port)
    }
    return s
  }

  const handleImport = async () => {
    const links = importLinks.split('\n').map(l => l.trim()).filter(Boolean)
    if (!links.length) { showToast('请输入链接', 'error'); return }
    try {
      const result = await importNodes.mutateAsync(links)
      const parts = [`导入 ${result.imported || 0}`]
      if (result.skipped) parts.push(`跳过 ${result.skipped} 重复`)
      if (result.failed) parts.push(`失败 ${result.failed}`)
      showToast(parts.join('，'), result.imported ? 'success' : 'info')
      setImportLinks('')
      setShowImport(false)
    } catch (e: any) {
      showToast(e.message || '导入失败', 'error')
    }
  }

  const handleDelete = async (nodeId: string, tag: string) => {
    if (!confirm(`确认删除节点 ${tag}?`)) return
    try {
      await deleteNode.mutateAsync(nodeId)
      showToast(`已删除 ${tag}`, 'success')
    } catch (e: any) {
      showToast(e.message || '删除失败', 'error')
    }
  }

  const runTest = async (ids: string[], mode: 'ping' | 'speed') => {
    if (!ids.length) { showToast('请先选择节点', 'error'); return }
    setTesting(true)
    try {
      const result = await testNodes.mutateAsync({ nodeIds: ids, mode })
      const next: Record<string, any> = { ...testResults }
      for (const r of (result.results || [])) next[r.nodeId] = r
      setTestResults(next)
      showToast(`${mode === 'speed' ? '测速' : '延迟测试'}完成 (${result.results?.length || 0} 节点)`, 'success')
    } catch (e: any) {
      showToast(e.message || '测试失败', 'error')
    } finally {
      setTesting(false)
    }
  }

  // Dynamic stream fields based on network + security
  const showWsFields = editBasic.network === 'ws'
  const showGrpcFields = editBasic.network === 'grpc'
  const showH2Fields = editBasic.network === 'h2'
  const showTlsFields = editBasic.security === 'tls'
  const showRealityFields = editBasic.security === 'reality'
  const showFlowField = editing?.protocol === 'vless' && (showTlsFields || showRealityFields)

  return <div className="space-y-6">
    <div className="flex items-center justify-between gap-3 flex-wrap">
      <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>节点管理</h1>
      <div className="flex gap-2 flex-wrap">
        <button onClick={() => setSelected(new Set(nodes.map((n: any) => n.id)))} disabled={!nodes.length} className="px-3 py-2 rounded-lg text-sm border disabled:opacity-40" style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}>全选</button>
        <button onClick={() => setSelected(new Set())} disabled={!selected.size} className="px-3 py-2 rounded-lg text-sm border disabled:opacity-40" style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}>清空</button>
        <button onClick={() => runTest(Array.from(selected), 'ping')} disabled={testing || !selected.size} className="px-3 py-2 rounded-lg text-sm border disabled:opacity-40" style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}>{testing ? '测试中...' : '测试选中延迟'}</button>
        <button onClick={() => runTest(Array.from(selected), 'speed')} disabled={testing || !selected.size} className="px-3 py-2 rounded-lg text-sm border disabled:opacity-40" style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}>测试选中速度</button>
        <button onClick={() => setShowUrls(true)} className="px-3 py-2 rounded-lg text-sm border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}>测试 URL</button>
        <button onClick={() => setShowImport(true)} className="px-4 py-2 rounded-lg text-sm text-white" style={{ background: 'var(--accent)' }}>导入节点</button>
      </div>
    </div>

    <div className="rounded-lg border overflow-x-auto" style={{ borderColor: 'var(--border)' }}>
      <table className="w-full min-w-[920px]">
        <thead><tr style={{ background: 'var(--bg2)' }}>
          <Th></Th><Th>Tag</Th><Th>协议</Th><Th>地址</Th><Th>传输</Th><Th right>延迟/出口IP</Th><Th right>速度</Th><Th right>操作</Th>
        </tr></thead>
        <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
          {isLoading && <tr><td colSpan={8} className="px-4 py-8 text-center" style={{ color: 'var(--muted)' }}>加载中...</td></tr>}
          {!isLoading && nodes.length === 0 && <tr><td colSpan={8} className="px-4 py-8 text-center" style={{ color: 'var(--muted)' }}>暂无节点，点击右上角导入</td></tr>}
          {nodes.map((node: any) => {
            const result = testResults[node.id]
            return <tr key={node.id} className="hover:bg-gray-800/30 transition-colors">
              <td className="px-4 py-3"><input type="checkbox" checked={selected.has(node.id)} onChange={() => toggleSelect(node.id)} className="w-4 h-4 accent-blue-500" /></td>
              <td className="px-4 py-3 font-mono text-sm font-medium">{node.tag}</td>
              <td className="px-4 py-3 text-sm" style={{ color: 'var(--muted)' }}>{node.protocol}</td>
              <td className="px-4 py-3 text-sm font-mono truncate max-w-[240px]" style={{ color: 'var(--muted)' }}>{node.address}:{node.port}</td>
              <td className="px-4 py-3 text-sm" style={{ color: 'var(--muted)' }}>{node.streamSettings?.network || 'tcp'} / {node.streamSettings?.security || 'none'}</td>
              <td className="px-4 py-3 text-right font-mono text-xs">{result?.latency ? <div><span style={{ color: result.latency < 200 ? 'var(--success)' : 'var(--warning)' }}>{result.latency}ms</span>{result.exitIp && <div title={result.exitIp} style={{ color: 'var(--muted)' }}>{result.exitIp}</div>}</div> : <span style={{ color: 'var(--muted)' }}>-</span>}</td>
              <td className="px-4 py-3 text-right font-mono text-sm">{result?.speed ? <span style={{ color: 'var(--warning)' }}>{result.speed} Mbps</span> : <span style={{ color: 'var(--muted)' }}>-</span>}</td>
              <td className="px-4 py-3 text-right"><div className="flex gap-1 justify-end">
                <SmallButton onClick={() => runTest([node.id], 'ping')}>延迟</SmallButton>
                <SmallButton onClick={() => runTest([node.id], 'speed')}>测速</SmallButton>
                <SmallButton accent onClick={() => openEdit(node)}>编辑</SmallButton>
                <SmallButton danger onClick={() => handleDelete(node.id, node.tag)}>删除</SmallButton>
              </div></td>
            </tr>
          })}
        </tbody>
      </table>
    </div>

    <Modal isOpen={showUrls} onClose={() => setShowUrls(false)} title="测试 URL 配置">
      <div className="space-y-4">
        <div><label className="text-sm block mb-1" style={{ color: 'var(--muted)' }}>延迟测试 URL（建议返回出口 IP）</label>
          <select value={latencyOptions.includes(latencyUrl) ? latencyUrl : '__custom'} onChange={e => { if (e.target.value !== '__custom') setLatencyUrl(e.target.value) }} className="field mb-2">
            {latencyOptions.map((u: string) => <option key={u} value={u}>{u}</option>)}
            <option value="__custom">自定义...</option>
          </select>
          <input value={latencyUrl} onChange={e => setLatencyUrl(e.target.value)} className="field" />
        </div>
        <div><label className="text-sm block mb-1" style={{ color: 'var(--muted)' }}>测速 URL</label><input value={speedUrl} onChange={e => setSpeedUrl(e.target.value)} className="field" /></div>
        <div className="rounded border p-3 text-xs" style={{ borderColor: 'var(--border)', color: 'var(--muted)' }}><div className="font-medium mb-2" style={{ color: 'var(--text)' }}>常用测 IP 地址</div><div className="flex flex-wrap gap-2">{latencyOptions.map((u: string) => <button key={u} onClick={() => setLatencyUrl(u)} className="px-2 py-1 rounded border font-mono" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>{u}</button>)}</div></div>
        <div className="flex justify-end gap-3"><button onClick={() => setShowUrls(false)} className="px-4 py-2 rounded-lg text-sm border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}>取消</button><button onClick={() => saveTestUrls.mutate({ latency: latencyUrl, speed: speedUrl, latencyOptions })} className="px-4 py-2 rounded-lg text-sm text-white" style={{ background: 'var(--accent)' }}>保存</button></div>
      </div>
    </Modal>

    {/* ── Optimized Node Edit Modal ── */}
    <Modal isOpen={!!editing} onClose={() => setEditing(null)} title={editing ? `编辑节点 · ${editing.tag}` : '编辑节点'}>
      {editing && <div className="space-y-4">
        {/* Tab bar */}
        <div className="flex gap-2" style={{ borderBottom: '1px solid var(--border)', paddingBottom: 8, marginBottom: 4 }}>
          <button className={`edit-tab ${editTab === 'basic' ? 'active' : ''}`} onClick={() => setEditTab('basic')}>基础设置</button>
          <button className={`edit-tab ${editTab === 'stream' ? 'active' : ''}`} onClick={() => setEditTab('stream')}>传输设置</button>
          <button className={`edit-tab ${editTab === 'json' ? 'active' : ''}`} onClick={() => setEditTab('json')}>高级 JSON</button>
        </div>

        {/* ── Basic tab ── */}
        {editTab === 'basic' && <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <Field label="Tag（节点标签）"><input value={editBasic.tag} onChange={e => setEditBasic({ ...editBasic, tag: e.target.value })} className="field" placeholder="节点名称" /></Field>
          <Field label="协议"><input value={editing.protocol} readOnly className="field" /></Field>
          <Field label="地址"><input value={editBasic.address} onChange={e => setEditBasic({ ...editBasic, address: e.target.value })} className="field" placeholder="服务器地址" /></Field>
          <Field label="端口"><input type="number" value={editBasic.port} onChange={e => setEditBasic({ ...editBasic, port: +e.target.value })} className="field" placeholder="443" /></Field>
          <Field label="传输协议">
            <select value={editBasic.network} onChange={e => setEditBasic({ ...editBasic, network: e.target.value })} className="field">
              <option value="tcp">TCP</option>
              <option value="ws">WebSocket</option>
              <option value="grpc">gRPC</option>
              <option value="h2">HTTP/2</option>
              <option value="quic">QUIC</option>
            </select>
          </Field>
          <Field label="安全层">
            <select value={editBasic.security} onChange={e => setEditBasic({ ...editBasic, security: e.target.value })} className="field">
              <option value="none">None</option>
              <option value="tls">TLS</option>
              <option value="reality">Reality</option>
            </select>
          </Field>
        </div>}

        {/* ── Stream tab ── */}
        {editTab === 'stream' && <div className="space-y-4">
          {/* Network-specific settings */}
          <div className="rounded-lg border p-4 space-y-3" style={{ borderColor: 'var(--border)', background: 'var(--bg)' }}>
            <div className="text-sm font-medium mb-2" style={{ color: 'var(--accent)' }}>
              {editBasic.network === 'ws' ? 'WebSocket 设置' : editBasic.network === 'grpc' ? 'gRPC 设置' : editBasic.network === 'h2' ? 'HTTP/2 设置' : editBasic.network === 'quic' ? 'QUIC 设置' : 'TCP 设置'}
            </div>
            {showWsFields && <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <Field label="Path"><input value={editStream.path} onChange={e => setEditStream({ ...editStream, path: e.target.value })} className="field" placeholder="/" /></Field>
              <Field label="Host"><input value={editStream.host} onChange={e => setEditStream({ ...editStream, host: e.target.value })} className="field" placeholder="域名" /></Field>
            </div>}
            {showGrpcFields && <div className="grid grid-cols-1 gap-3">
              <Field label="serviceName"><input value={editStream.serviceName} onChange={e => setEditStream({ ...editStream, serviceName: e.target.value })} className="field" placeholder="grpc 服务名" /></Field>
            </div>}
            {showH2Fields && <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <Field label="Path"><input value={editStream.path} onChange={e => setEditStream({ ...editStream, path: e.target.value })} className="field" placeholder="/" /></Field>
              <Field label="Host"><input value={editStream.host} onChange={e => setEditStream({ ...editStream, host: e.target.value })} className="field" placeholder="域名" /></Field>
            </div>}
            {!showWsFields && !showGrpcFields && !showH2Fields && <div className="text-sm" style={{ color: 'var(--muted)' }}>TCP / QUIC 无额外传输参数</div>}
          </div>

          {/* Security-specific settings */}
          {(showTlsFields || showRealityFields) && <div className="rounded-lg border p-4 space-y-3" style={{ borderColor: 'var(--border)', background: 'var(--bg)' }}>
            <div className="text-sm font-medium mb-2" style={{ color: showRealityFields ? 'var(--success)' : 'var(--warning)' }}>
              {showRealityFields ? 'Reality 设置' : 'TLS 设置'}
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <Field label="SNI / serverName"><input value={editStream.sni} onChange={e => setEditStream({ ...editStream, sni: e.target.value })} className="field" placeholder="服务器域名" /></Field>
              <Field label="ALPN"><input value={editStream.alpn} onChange={e => setEditStream({ ...editStream, alpn: e.target.value })} className="field" placeholder="h2,http/1.1" /></Field>
              <Field label="fingerprint"><input value={editStream.fingerprint} onChange={e => setEditStream({ ...editStream, fingerprint: e.target.value })} className="field" placeholder="chrome" /></Field>
              {showRealityFields && <>
                <Field label="publicKey"><input value={editStream.publicKey} onChange={e => setEditStream({ ...editStream, publicKey: e.target.value })} className="field" placeholder="Reality 公钥" /></Field>
                <Field label="shortId"><input value={editStream.shortId} onChange={e => setEditStream({ ...editStream, shortId: e.target.value })} className="field" placeholder="shortId" /></Field>
              </>}
            </div>
          </div>}

          {/* Flow field for vless */}
          {showFlowField && <div className="rounded-lg border p-4" style={{ borderColor: 'var(--border)', background: 'var(--bg)' }}>
            <div className="text-sm font-medium mb-2" style={{ color: 'var(--accent)' }}>VLESS Flow</div>
            <div className="grid grid-cols-1 gap-3">
              <Field label="flow">
                <select value={editStream.flow} onChange={e => setEditStream({ ...editStream, flow: e.target.value })} className="field">
                  <option value="">无</option>
                  <option value="xtls-rprx-vision">xtls-rprx-vision</option>
                  <option value="xtls-rprx-vision-udp443">xtls-rprx-vision-udp443</option>
                </select>
              </Field>
            </div>
          </div>}

          {!showTlsFields && !showRealityFields && !showWsFields && !showGrpcFields && !showH2Fields && !showFlowField && <div className="text-sm py-4 text-center" style={{ color: 'var(--muted)' }}>当前配置无额外传输参数</div>}
        </div>}

        {/* ── JSON tab ── */}
        {editTab === 'json' && <div className="space-y-3">
          <div className="text-sm" style={{ color: 'var(--muted)' }}>直接编辑节点完整配置（settings / streamSettings / mux），保存时会覆盖传输设置中的手动编辑</div>
          <textarea value={editJson} onChange={e => setEditJson(e.target.value)} rows={16} className="field" style={{ resize: 'vertical', minHeight: 200 }} />
          {(() => { try { JSON.parse(editJson); return <div className="text-xs" style={{ color: 'var(--success)' }}>✓ JSON 格式有效</div> } catch { return <div className="text-xs" style={{ color: 'var(--danger)' }}>✗ JSON 格式无效</div> } })()}
        </div>}

        {/* Actions */}
        <div className="flex justify-end gap-3 pt-2" style={{ borderTop: '1px solid var(--border)' }}>
          <button onClick={() => setEditing(null)} className="px-4 py-2 rounded-lg text-sm border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}>取消</button>
          <button onClick={handleSaveEdit} disabled={editTab === 'json' && (() => { try { JSON.parse(editJson); return false } catch { return true } })()} className="px-4 py-2 rounded-lg text-sm text-white disabled:opacity-50" style={{ background: 'var(--accent)' }}>保存</button>
        </div>
      </div>}
    </Modal>

    <Modal isOpen={showImport} onClose={() => setShowImport(false)} title="批量导入节点"><div className="space-y-4"><p className="text-sm" style={{ color: 'var(--muted)' }}>粘贴分享链接（每行一个），支持 vless:// vmess:// ss:// trojan://</p><textarea value={importLinks} onChange={(e) => setImportLinks(e.target.value)} placeholder="vless://uuid@server:port?..." className="field" style={{ height: 192, resize: 'vertical' }} /><div className="flex justify-end gap-3"><button onClick={() => setShowImport(false)} className="px-4 py-2 rounded-lg text-sm border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}>取消</button><button onClick={handleImport} disabled={importNodes.isPending} className="px-4 py-2 rounded-lg text-sm text-white disabled:opacity-50" style={{ background: 'var(--accent)' }}>{importNodes.isPending ? '导入中...' : '导入'}</button></div></div></Modal>
  </div>
}

function Th({ children, right }: { children?: React.ReactNode; right?: boolean }) {
  return <th className={`px-4 py-3 text-xs font-medium ${right ? 'text-right' : 'text-left'}`} style={{ color: 'var(--muted)' }}>{children}</th>
}

function SmallButton({ children, onClick, danger, accent }: { children: React.ReactNode; onClick: () => void; danger?: boolean; accent?: boolean }) {
  const borderColor = danger ? 'var(--danger)' : accent ? 'var(--accent)' : 'var(--border)'
  const color = danger ? 'var(--danger)' : accent ? 'var(--accent)' : 'var(--text)'
  return <button onClick={onClick} className="px-3 py-1 rounded text-xs border" style={{ background: 'var(--bg)', borderColor, color }}>{children}</button>
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <label className="text-sm block" style={{ color: 'var(--muted)' }}>{label}<div className="mt-1.5">{children}</div></label>
}