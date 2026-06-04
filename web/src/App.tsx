import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useAuthStore } from './stores/auth-store'
import Layout from './components/Layout'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import ConnectPage from './pages/ConnectPage'
import NodesPage from './pages/NodesPage'
import SettingsPage from './pages/SettingsPage'
import ConfigPage from './pages/ConfigPage'
import LogsPage from './pages/LogsPage'
import SystemPage from './pages/SystemPage'
import InboundsPage from './pages/InboundsPage'
import RoutingPage from './pages/RoutingPage'
import DnsPage from './pages/DnsPage'
import BackupsPage from './pages/BackupsPage'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((state) => state.token)
  if (!token) {
    return <Navigate to="/login" replace />
  }
  return <>{children}</>
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            <Route index element={<DashboardPage />} />
            <Route path="connect" element={<ConnectPage />} />
            <Route path="nodes" element={<NodesPage />} />
            <Route path="inbounds" element={<InboundsPage />} />
            <Route path="routing" element={<RoutingPage />} />
            <Route path="dns" element={<DnsPage />} />
            <Route path="config" element={<ConfigPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="logs" element={<LogsPage />} />
            <Route path="system" element={<SystemPage />} />
            <Route path="backups" element={<BackupsPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
