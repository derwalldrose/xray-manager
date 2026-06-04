import { Outlet, NavLink } from 'react-router-dom'
import Sidebar from './Sidebar'

const mobileTabs = [
  { path: '/', label: '概览' },
  { path: '/connect', label: '连接' },
  { path: '/nodes', label: '节点' },
  { path: '/config', label: '配置' },
  { path: '/logs', label: '日志' },
]

export default function Layout() {
  return (
    <div className="flex h-screen bg-bg">
      <Sidebar />
      <main className="flex-1 overflow-auto p-4 md:p-6">
        <Outlet />
      </main>

      {/* Mobile bottom nav */}
      <nav className="fixed bottom-0 left-0 right-0 h-14 flex items-center justify-around border-t md:hidden"
        style={{ background: 'var(--bg2)', borderColor: 'var(--border)' }}>
        {mobileTabs.map(({ path, label }) => (
          <NavLink key={path} to={path} end={path === '/'}
            className={({ isActive }) => `flex flex-col items-center gap-0.5 px-3 py-1 text-[10px] transition-colors ${isActive ? 'text-accent' : ''}`}
            style={{ color: 'var(--text)' }}>
            <span className="font-medium">{label}</span>
          </NavLink>
        ))}
      </nav>
    </div>
  )
}
