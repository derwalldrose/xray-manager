import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'
import Modal from '../components/Modal'

interface Inbound {
  tag: string
  protocol: string
  port: number | string
  listen: string
  settings?: any
  sniffing?: any
}

export default function InboundsPage() {
  const queryClient = useQueryClient()
  const { showToast } = useToast()
  const { data, isLoading } = useQuery({ queryKey: ['inbounds'], queryFn: () => api.get('/inbounds') })
  const { data: routing } = useQuery({ queryKey: ['routing'], queryFn: () => api.get('/routing'), refetchInterval: 10000 })
  const [showAdd, setShowAdd] = useState(false)
  const [form, setForm] = useState({ tag: '', protocol: 'socks', listen: '0.0.0.0', port: 10810 })

  const inbounds: Inbound[] = data?.inbounds || []
  const rules = routing?.rules || []

  const addMutation = useMutation({
    mutationFn: (inbound: any) => api.post('/inbounds', { inbound }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['inbounds'] })
      queryClient.invalidateQueries({ queryKey: ['full-config-summary'] })
      setShowAdd(false)
      showToast('入口已添加，Xray 已重启', 'success')
      setForm({ tag: '', protocol: 'socks', listen: '0.0.0.0', port: 10810 })
    },
    onError: (e: any) => showToast(e.message || '添加失败', 'error'),
  })

  const deleteMutation = useMutation({
    mutationFn: (index: number) => api.delete(`/inbounds/${index}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['inbounds'] })
      queryClient.invalidateQueries({ queryKey: ['routing'] })
      queryClient.invalidateQueries({ queryKey: ['full-config-summary'] })
      showToast('入口已删除，Xray 已重启', 'success')
    },
    onError: (e: any) => showToast(e.message || '删除失败', 'error'),
  })

  const handleAdd = () => {
    if (!form.tag || !form.port) { showToast('请填写完整信息', 'error'); return }
    const settings = form.protocol === 'socks'
      ? { udp: true, auth: 'noauth' }
      : form.protocol === 'dokodemo-door'
        ? { network: 'tcp,udp', followRedirect: true }
        : {}
    addMutation.mutate({
      tag: form.tag,
      protocol: form.protocol,
      port: Number(form.port),
      listen: form.listen,
      settings,
      sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] },
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>入口设置</h1>
          <p className="text-sm mt-1" style={{ color: '#8b949e' }}>入口是动态代理的流量入口；入口绑定到哪个节点/出站组，请在“流量编排”页调整。</p>
        </div>
        <button onClick={() => setShowAdd(true)} className="px-4 py-2 rounded-lg text-sm text-white" style={{ background: 'var(--accent)' }}>添加入口</button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Metric label="入口数量" value={`${inbounds.length}`} />
        <Metric label="SOCKS/HTTP" value={`${inbounds.filter(i => ['socks', 'http'].includes(i.protocol)).length}`} />
        <Metric label="Dokodemo/DNS" value={`${inbounds.filter(i => i.protocol === 'dokodemo-door').length}`} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {inbounds.map((ib, i) => {
          const binding = getInboundTarget(ib.tag, rules)
          const systemLike = ['dns', 'transparent'].includes(ib.tag)
          return (
            <div key={`${ib.tag}-${i}`} className="rounded-lg border p-4 space-y-4" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-base font-semibold" style={{ color: 'var(--text)' }}>{ib.tag}</span>
                    <ProtocolBadge protocol={ib.protocol} />
                    {systemLike && <span className="px-2 py-0.5 rounded text-xs" style={{ background: 'rgba(210,153,34,0.15)', color: '#d29922' }}>系统入口</span>}
                  </div>
                  <div className="text-xs mt-1 font-mono" style={{ color: '#8b949e' }}>{ib.listen || '0.0.0.0'}:{ib.port}</div>
                </div>
                <button
                  onClick={() => { if (confirm(`删除入口 ${ib.tag}?\n相关 routing 规则请在路由页检查。`)) deleteMutation.mutate(i) }}
                  className="px-3 py-1 rounded text-xs text-white disabled:opacity-40"
                  disabled={deleteMutation.isPending || systemLike}
                  style={{ background: '#f85149' }}
                  title={systemLike ? '系统入口建议保留' : '删除入口'}
                >删除</button>
              </div>

              <div className="grid grid-cols-2 gap-3 text-sm">
                <Info label="UDP" value={ib.settings?.udp === false ? '关闭' : ib.protocol === 'socks' ? '开启' : '-'} />
                <Info label="Sniffing" value={ib.sniffing?.enabled ? '开启' : '关闭'} />
                <Info label="目标" value={binding.display} mono />
                <Info label="规则" value={binding.ruleIndex ? `#${binding.ruleIndex}` : '默认'} />
              </div>

              <div className="p-3 rounded-lg text-xs" style={{ background: 'var(--bg)', color: '#8b949e' }}>
                入口只定义“流量从哪里进来”。要把它绑定到单节点、出站组或 direct/block，请到“流量编排”页操作；复杂域名/IP 规则在“配置 → 路由规则”。
              </div>
            </div>
          )
        })}
        {!isLoading && inbounds.length === 0 && <div className="p-8 text-center rounded-lg border" style={{ borderColor: 'var(--border)', color: '#8b949e' }}>暂无入口</div>}
      </div>

      <Modal isOpen={showAdd} onClose={() => setShowAdd(false)} title="添加入口">
        <div className="space-y-4">
          <div className="p-3 rounded-lg text-xs" style={{ background: 'rgba(56,139,253,0.1)', color: '#58a6ff' }}>
            添加入口会写入当前 Xray config、测试配置并重启 Xray。添加后请到“流量编排”页选择该入口的目标出口。
          </div>
          <div>
            <label className="text-sm block mb-1" style={{ color: '#8b949e' }}>标签 Tag</label>
            <input value={form.tag} onChange={e => setForm({ ...form, tag: e.target.value })} placeholder="socks-office" className="w-full px-3 py-2 rounded border text-sm" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }} />
          </div>
          <div>
            <label className="text-sm block mb-1" style={{ color: '#8b949e' }}>协议</label>
            <select value={form.protocol} onChange={e => setForm({ ...form, protocol: e.target.value })} className="w-full px-3 py-2 rounded border text-sm" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }}>
              <option value="socks">SOCKS5</option>
              <option value="http">HTTP</option>
              <option value="dokodemo-door">Dokodemo-door</option>
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-sm block mb-1" style={{ color: '#8b949e' }}>监听地址</label>
              <input value={form.listen} onChange={e => setForm({ ...form, listen: e.target.value })} className="w-full px-3 py-2 rounded border text-sm" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }} />
            </div>
            <div>
              <label className="text-sm block mb-1" style={{ color: '#8b949e' }}>端口</label>
              <input type="number" value={form.port} onChange={e => setForm({ ...form, port: +e.target.value })} className="w-full px-3 py-2 rounded border text-sm" style={{ background: 'var(--bg)', borderColor: 'var(--border)', color: 'var(--text)' }} />
            </div>
          </div>
          <div className="flex justify-end gap-3 pt-2">
            <button onClick={() => setShowAdd(false)} className="px-4 py-2 rounded-lg text-sm border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)', color: 'var(--text)' }}>取消</button>
            <button onClick={handleAdd} disabled={addMutation.isPending} className="px-4 py-2 rounded-lg text-sm text-white disabled:opacity-50" style={{ background: 'var(--accent)' }}>{addMutation.isPending ? '添加中...' : '添加入口'}</button>
          </div>
        </div>
      </Modal>
    </div>
  )
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="p-4 rounded-lg border" style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}><div className="text-xs" style={{ color: '#8b949e' }}>{label}</div><div className="text-xl font-semibold mt-1" style={{ color: 'var(--text)' }}>{value}</div></div>
}

function ProtocolBadge({ protocol }: { protocol: string }) {
  const labels: Record<string, string> = { socks: 'SOCKS5', http: 'HTTP', 'dokodemo-door': 'Dokodemo' }
  return <span className="px-2 py-0.5 rounded text-xs" style={{ background: 'rgba(56,139,253,0.15)', color: '#58a6ff' }}>{labels[protocol] || protocol}</span>
}

function Info({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return <div className="rounded-lg p-2" style={{ background: 'var(--bg)' }}><div className="text-xs" style={{ color: '#8b949e' }}>{label}</div><div className={mono ? 'font-mono text-sm truncate' : 'text-sm'} style={{ color: 'var(--text)' }}>{value}</div></div>
}

function getInboundTarget(inboundTag: string, rules: any[]) {
  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i]
    if (Array.isArray(rule.inboundTag) && rule.inboundTag.includes(inboundTag)) {
      if (rule.balancerTag) return { display: `组:${rule.balancerTag}`, ruleIndex: i + 1 }
      if (rule.outboundTag) return { display: rule.outboundTag, ruleIndex: i + 1 }
    }
  }
  return { display: '默认路由', ruleIndex: 0 }
}
