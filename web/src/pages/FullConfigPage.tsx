import { useEffect, useMemo, useState } from 'react'
import { api } from '../lib/api'
import { useToast } from '../components/Toast'

interface FullConfigResponse {
  ok: boolean
  config: any
  raw: string
  path: string
}

interface TestResponse {
  ok: boolean
  output?: string
  error?: string
}

export default function FullConfigPage() {
  const { showToast } = useToast()
  const [raw, setRaw] = useState('')
  const [path, setPath] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [testing, setTesting] = useState(false)
  const [testOutput, setTestOutput] = useState('')
  const [error, setError] = useState<string | null>(null)

  const stats = useMemo(() => {
    try {
      const cfg = JSON.parse(raw || '{}')
      return {
        inbounds: Array.isArray(cfg.inbounds) ? cfg.inbounds.length : 0,
        outbounds: Array.isArray(cfg.outbounds) ? cfg.outbounds.length : 0,
        rules: Array.isArray(cfg.routing?.rules) ? cfg.routing.rules.length : 0,
        balancers: Array.isArray(cfg.routing?.balancers) ? cfg.routing.balancers.length : 0,
        loglevel: cfg.log?.loglevel || '未设置',
        valid: true,
      }
    } catch {
      return { inbounds: 0, outbounds: 0, rules: 0, balancers: 0, loglevel: 'JSON 无效', valid: false }
    }
  }, [raw])

  const loadConfig = async () => {
    try {
      setLoading(true)
      setError(null)
      const res = await api.get<FullConfigResponse>('/config')
      setRaw(res.raw || JSON.stringify(res.config, null, 2))
      setPath(res.path || '')
      setTestOutput('')
    } catch (e: any) {
      setError(e.message || '加载配置失败')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadConfig()
  }, [])

  const formatJson = () => {
    try {
      setRaw(JSON.stringify(JSON.parse(raw), null, 2) + '\n')
      showToast('已格式化 JSON', 'success')
    } catch (e: any) {
      showToast('JSON 格式错误：' + e.message, 'error')
    }
  }

  const copyConfig = async () => {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(raw)
      } else {
        const textarea = document.createElement('textarea')
        textarea.value = raw
        textarea.style.position = 'fixed'
        textarea.style.left = '-9999px'
        document.body.appendChild(textarea)
        textarea.focus()
        textarea.select()
        document.execCommand('copy')
        document.body.removeChild(textarea)
      }
      showToast('完整配置已复制', 'success')
    } catch (e: any) {
      showToast('复制失败：' + e.message, 'error')
    }
  }

  const testConfig = async () => {
    try {
      setTesting(true)
      setTestOutput('')
      const res = await api.post<TestResponse>('/config/test')
      setTestOutput(res.output || res.error || '')
      showToast(res.ok ? '配置测试通过' : '配置测试失败', res.ok ? 'success' : 'error')
    } catch (e: any) {
      setTestOutput(e.message || '测试失败')
      showToast('测试失败：' + e.message, 'error')
    } finally {
      setTesting(false)
    }
  }

  const saveConfig = async () => {
    let parsed: any
    try {
      parsed = JSON.parse(raw)
    } catch (e: any) {
      showToast('JSON 格式错误：' + e.message, 'error')
      return
    }

    if (!confirm('保存完整 Xray 配置会先备份、测试，通过后重启 xray。确认保存？')) return

    try {
      setSaving(true)
      const res = await api.post<{ ok: boolean; error?: string; rolled?: boolean }>('/config', { config: parsed })
      if (res.ok) {
        showToast('配置已保存并重启 Xray', 'success')
        await loadConfig()
      } else {
        showToast(res.error || '保存失败', 'error')
      }
    } catch (e: any) {
      showToast('保存失败：' + e.message, 'error')
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return <div className="card"><div className="text-sm" style={{ color: 'var(--text2)' }}>加载完整配置中...</div></div>
  }

  return (
    <div className="space-y-4">
      <div className="card space-y-4">
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div>
            <h2 className="text-lg font-semibold" style={{ color: 'var(--text)' }}>完整 Xray 配置</h2>
            <p className="text-sm mt-1" style={{ color: 'var(--text2)' }}>{path || '当前配置文件'}</p>
          </div>
          <div className="flex gap-2 flex-wrap">
            <button onClick={loadConfig} className="btn-secondary" disabled={loading}>刷新</button>
            <button onClick={formatJson} className="btn-secondary">格式化</button>
            <button onClick={copyConfig} className="btn-secondary">复制</button>
            <button onClick={testConfig} className="btn-secondary" disabled={testing}>{testing ? '测试中...' : '测试配置'}</button>
            <button onClick={saveConfig} className="btn-primary" disabled={saving || !stats.valid}>{saving ? '保存中...' : '保存并重启'}</button>
          </div>
        </div>

        {error && <div className="p-3 rounded-lg border border-red-500/40 bg-red-500/10 text-red-300 text-sm">{error}</div>}

        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Stat label="入站" value={stats.inbounds} />
          <Stat label="出站" value={stats.outbounds} />
          <Stat label="路由规则" value={stats.rules} />
          <Stat label="负载均衡" value={stats.balancers} />
          <Stat label="日志级别" value={stats.loglevel} />
        </div>

        {!stats.valid && <div className="p-3 rounded-lg border border-yellow-500/40 bg-yellow-500/10 text-yellow-200 text-sm">当前文本不是有效 JSON，保存前需要修正。</div>}

        <textarea
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          spellCheck={false}
          className="w-full min-h-[65vh] font-mono text-xs leading-5 rounded-xl p-4 border outline-none"
          style={{ background: 'var(--bg)', borderColor: stats.valid ? 'var(--border)' : '#ef4444', color: 'var(--text)' }}
        />
      </div>

      {testOutput && (
        <div className="card space-y-2">
          <h3 className="font-semibold" style={{ color: 'var(--text)' }}>配置测试输出</h3>
          <pre className="text-xs whitespace-pre-wrap overflow-auto max-h-64 rounded-lg p-3" style={{ background: 'var(--bg)', color: 'var(--text2)' }}>{testOutput}</pre>
        </div>
      )}
    </div>
  )
}

function Stat({ label, value }: { label: string; value: any }) {
  return (
    <div className="rounded-lg border p-3" style={{ borderColor: 'var(--border)', background: 'var(--bg2)' }}>
      <div className="text-xs" style={{ color: 'var(--text2)' }}>{label}</div>
      <div className="text-lg font-semibold truncate" style={{ color: 'var(--text)' }}>{value}</div>
    </div>
  )
}
