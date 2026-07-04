import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { Sidebar } from './components/Sidebar'
import { Overview } from './pages/Overview'
import { Inventory } from './pages/Inventory'
import { AuditLog } from './pages/AuditLog'

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex min-h-screen" style={{ backgroundColor: '#0A0E1A', color: '#E5E7EB' }}>
        <Sidebar />
        <main className="flex-1 overflow-y-auto">
          <Routes>
            <Route path="/" element={<Navigate to="/overview" replace />} />
            <Route path="/overview" element={<Overview />} />
            <Route path="/inventory" element={<Inventory />} />
            <Route path="/audit-log" element={<AuditLog />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
