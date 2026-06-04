import { useEffect, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useNodes, useImportNodes, useDeleteNode, useTestNodes, useUpdateNode } from '../hooks/use-nodes'
import { useToast } from '../components/Toast'
import Modal from '../components/Modal'

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
  const [editing, setEditing] = useState<any | null>(null)
  const [editJson, setEditJson] = useState('')
  const [editBasic, setEditBasic] = useState({ tag: '', address: '', port: 443, network: 'tcp', security: 'none' })

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
    setEditJson(JSON.stringify({ settings: node.settings || {}, streamSettings: node.streamSettings || {}, mux: node.mux || {} }, null, 2))
    setEditBasic({
      tag: node.tag || '',
      address: node.address || '',
      port: Number(node.port) || 443,
      network: node.streamSettings?.network || 'tcp',
      security: node.streamSettings?.security || 'none',
    })
  }

  const handleSaveEdit = async () => {
    if (!editing) return
    try {
      const parsed = JSON.parse(editJson || '{}')
      const streamSettings = { ...(parsed.streamSettings || {}), network: editBasic.network, security: editBasic.security }
      const settings = parsed.settings || editing.settings || {}
      if (settings.vnext?.[0]) { settings.vnext[0].address = editBasic.address; settings.vnext[0].port = Number(editBasic.port) }
      if (settings.servers?.[0]) { settings.servers[0].address = editBasic.address; settings.servers[0].port = Number(editBasic.port) }
      await updateNode.mutateAsync({ nodeId: editing.id, config: { ...editing, tag: editBasic.tag, address: editBasic.address, port: Number(editBasic.port), settings, streamSettings, mux: parsed.mux } })
      showToast('节点已保存', 'success')
      setEditing(null)
    } catch (e: any) {
      showToast(e.message || '保存失败，检查 JSON 格式', 'error')
    }
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
          {isLoading && <tr><td colSpan={8} className="px-4 py-8 text-center" style={{ color: '#8b949e' }}>加载中...</td></tr>}
          {!isLoading && nodes.length === 0 && <tr><td colSpan={8} className="px-4 py-8 text-center" style={{ color: '#8b949e' }}>暂无节点，点击右上角导入</td></tr>}
          {nodes.map((node: any) => {
            const result = testResults[node.id]
            return <tr key={node.id} className="hover:bg-gray-800/30 transition-colors">
              <td className="px-4 py-3"><input type="checkbox" checked={selected.has(node.id)} onChange={() => toggleSelect(node.id)} className="w-4 h-4 accent-blue-500" /></td>
              <td className="px-4 py-3 font-mono text-sm font-medium">{node.tag}</td>
              <td className="px-4 py-3 text-sm" style={{ color: '#8b949e' }}>{node.protocol}</td>
              <td className="px-4 py-3 text-sm font-mono truncate max-w-[240px]" style={{ color: '#8b949e' }}>{node.address}:{node.port}</td>
              <td className="px-4 py-3 text-sm" style={{ color: '#8b949e' }}>{node.streamSettings?.network || 'tcp'} / {node.streamSettings?.security || 'none'}</td>
              <td className="px-4 py-3 text-right font-mono text-xs">{result?.latency ? <div><span style={{ color: result.latency < 200 ? '#3fb950' : '#d29922' }}>{result.latency}ms</span>{result.exitIp && <div title={result.exitIp} style={{ color: '#8b949e' }}>{result.exitIp}</div>}</div> : <span style={{ color: '#8b949e' }}>-</span>}</td>
              <td className="px-4 py-3 text-right font-mono text-sm">{result?.speed ? <span style={{ color: '#d29922' }}>{result.speed} Mbps</span> : <span style={{ color: '#8b949e' }}>-</span>}</td>
              <td className="px-4 py-3 text-right"><div className="flex gap-1 justify-end">
                <SmallButton onClick={() => runTest([node.id], 'ping')}>延迟</SmallButton>
                <SmallButton onClick={() => runTest([node.id], 'speed')}>测速</SmallButton>
                <SmallButton onClick={() => openEdit(node)}>编辑</SmallButton>
                <SmallButton danger onClick={() => handleDelete(node.id, node.tag)}>删除</SmallButton>
              </div></td>
            </tr>
          })}
        </tbody>
      </table>
    </div>

    <Modal isOpen={showUrls} onClose={() => setShowUrls(false)} title="测试 URL 配置">
      <div className="space-y-4">
        <div><label className="text-sm block mb-1" style={{ color: '#8b949e' }}>延迟测试 URL（建议返回出口 IP）</label>
          <select value={latencyOptions.includes(latencyUrl) ? latencyUrl : '__custom'} onChange={e => { if (e.target.value !== '__custom') setLatencyUrl(e.target.value) }} className="w-full px-3 py-2 rounded border text-sm font-mono mb-2" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>
            {latencyOptions.map((u: string) => <option key={u} value={u}>{u}</option>)}
            <option value="__custom">自定义...</option>
          </select>
          <input value={latencyUrl} onChange={e => setLatencyUrl(e.target.value)} className="w-full px-3 py-2 rounded border text-sm font-mono" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }} />
        </div>
        <div><label className="text-sm block mb-1" style={{ color: '#8b949e' }}>测速 URL</label><input value={speedUrl} onChange={e => setSpeedUrl(e.target.value)} className="w-full px-3 py-2 rounded border text-sm font-mono" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }} /></div>
        <div className="rounded border p-3 text-xs" style={{ borderColor: 'var(--border)', color: '#8b949e' }}><div className="font-medium mb-2" style={{ color: 'var(--text)' }}>常用测 IP 地址</div><div className="flex flex-wrap gap-2">{latencyOptions.map((u: string) => <button key={u} onClick={() => setLatencyUrl(u)} className="px-2 py-1 rounded border font-mono" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>{u}</button>)}</div></div>
        <div className="flex justify-end gap-3"><button onClick={() => setShowUrls(false)} className="px-4 py-2 rounded-lg text-sm border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}>取消</button><button onClick={() => saveTestUrls.mutate({ latency: latencyUrl, speed: speedUrl, latencyOptions })} className="px-4 py-2 rounded-lg text-sm text-white" style={{ background: 'var(--accent)' }}>保存</button></div>
      </div>
    </Modal>

    <Modal isOpen={!!editing} onClose={() => setEditing(null)} title="查看/编辑节点">{editing && <div className="space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Field label="Tag"><input value={editBasic.tag} onChange={e => setEditBasic({ ...editBasic, tag: e.target.value })} className="field" /></Field>
        <Field label="协议"><input value={editing.protocol} readOnly className="field opacity-70" /></Field>
        <Field label="地址"><input value={editBasic.address} onChange={e => setEditBasic({ ...editBasic, address: e.target.value })} className="field" /></Field>
        <Field label="端口"><input type="number" value={editBasic.port} onChange={e => setEditBasic({ ...editBasic, port: +e.target.value })} className="field" /></Field>
        <Field label="传输"><select value={editBasic.network} onChange={e => setEditBasic({ ...editBasic, network: e.target.value })} className="field"><option value="tcp">tcp</option><option value="ws">ws</option><option value="grpc">grpc</option><option value="h2">h2</option><option value="quic">quic</option></select></Field>
        <Field label="安全"><select value={editBasic.security} onChange={e => setEditBasic({ ...editBasic, security: e.target.value })} className="field"><option value="none">none</option><option value="tls">tls</option><option value="reality">reality</option></select></Field>
      </div>
      <div><label className="text-sm block mb-1" style={{ color: '#8b949e' }}>高级 JSON（settings / streamSettings / mux）</label><textarea value={editJson} onChange={e => setEditJson(e.target.value)} rows={12} className="w-full px-3 py-2 rounded border text-sm font-mono" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }} /></div>
      <div className="flex justify-end gap-3"><button onClick={() => setEditing(null)} className="px-4 py-2 rounded-lg text-sm border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}>取消</button><button onClick={handleSaveEdit} className="px-4 py-2 rounded-lg text-sm text-white" style={{ background: 'var(--accent)' }}>保存</button></div>
    </div>}</Modal>

    <Modal isOpen={showImport} onClose={() => setShowImport(false)} title="批量导入节点"><div className="space-y-4"><p className="text-sm" style={{ color: '#8b949e' }}>粘贴分享链接（每行一个），支持 vless:// vmess:// ss:// trojan://</p><textarea value={importLinks} onChange={(e) => setImportLinks(e.target.value)} placeholder="vless://uuid@server:port?..." className="w-full h-48 px-4 py-3 rounded-lg border font-mono text-sm resize-none" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }} /><div className="flex justify-end gap-3"><button onClick={() => setShowImport(false)} className="px-4 py-2 rounded-lg text-sm border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}>取消</button><button onClick={handleImport} disabled={importNodes.isPending} className="px-4 py-2 rounded-lg text-sm text-white disabled:opacity-50" style={{ background: 'var(--accent)' }}>{importNodes.isPending ? '导入中...' : '导入'}</button></div></div></Modal>
  </div>
}

function Th({ children, right }: { children?: React.ReactNode; right?: boolean }) {
  return <th className={`px-4 py-3 text-xs font-medium ${right ? 'text-right' : 'text-left'}`} style={{ color: '#8b949e' }}>{children}</th>
}

function SmallButton({ children, onClick, danger }: { children: React.ReactNode; onClick: () => void; danger?: boolean }) {
  return <button onClick={onClick} className="px-3 py-1 rounded text-xs border" style={{ background: 'var(--bg)', borderColor: danger ? '#f85149' : 'var(--border)', color: danger ? '#f85149' : 'var(--text)' }}>{children}</button>
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <label className="text-sm block" style={{ color: '#8b949e' }}>{label}<div className="mt-1">{children}</div></label>
}
