import { useState } from 'react'
import SettingsPage from './SettingsPage'
import InboundsPage from './InboundsPage'
import RoutingPage from './RoutingPage'
import DnsPage from './DnsPage'
import SystemPage from './SystemPage'
import BackupsPage from './BackupsPage'
import FullConfigPage from './FullConfigPage'

const tabs = [
  { id: 'settings', label: '基础/Geo', comp: SettingsPage },
  { id: 'full', label: '完整配置', comp: FullConfigPage },
  { id: 'inbounds', label: '入口', comp: InboundsPage },
  { id: 'routing', label: '路由规则', comp: RoutingPage },
  { id: 'dns', label: 'DNS', comp: DnsPage },
  { id: 'sysctl', label: '内核参数', comp: SystemPage },
  { id: 'backups', label: '备份', comp: BackupsPage },
]

export default function ConfigPage() {
  const [active, setActive] = useState('settings')
  const item = tabs.find(t => t.id === active) || tabs[0]
  const Component = item.comp
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <h1 className="text-2xl font-bold" style={{ color: 'var(--text)' }}>配置</h1>
        <div className="flex gap-2 flex-wrap">
          {tabs.map(t => (
            <button key={t.id} onClick={() => setActive(t.id)} className="px-3 py-1.5 rounded-lg text-sm border" style={{ background: active === t.id ? 'var(--accent)' : 'var(--bg2)', borderColor: 'var(--border)', color: active === t.id ? '#fff' : 'var(--text)' }}>{t.label}</button>
          ))}
        </div>
      </div>
      <Component />
    </div>
  )
}
