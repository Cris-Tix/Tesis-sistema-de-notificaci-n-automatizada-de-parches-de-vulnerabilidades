import { Link, useLocation } from 'react-router-dom'
import { useEffect, useRef, useState, type ComponentProps } from 'react'
import { api } from '../api/client'
import type { SystemStatus } from '../types'

type SVG = ComponentProps<'svg'>

const WORKFLOW_LABELS: Record<string, string> = {
  'workflow-collection':    'Collection',
  'workflow-correlation':   'Correlation',
  'workflow-prioritization':'Prioritization',
  'workflow-alerts':        'Alerts',
  'workflow-monitoring':    'Monitoring',
}

function StatusDot({ status }: { status: string }) {
  const color =
    status === 'SUCCESS' ? '#22C55E' :
    status === 'FAILED'  ? '#EF4444' : '#F59E0B'
  return (
    <span
      className="inline-block w-2 h-2 rounded-full flex-shrink-0"
      style={{ backgroundColor: color }}
    />
  )
}

const NAV = [
  { to: '/overview',   label: 'Overview',   Icon: GridIcon },
  { to: '/inventory',  label: 'Inventario', Icon: DbIcon },
  { to: '/audit-log',  label: 'Audit Log',  Icon: ListIcon },
]

export function Sidebar() {
  const { pathname } = useLocation()
  const [status, setStatus] = useState<SystemStatus | null>(null)
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null)
  const fnRef = useRef<() => void>()

  const fetchStatus = async () => {
    try {
      const d = await api.systemStatus()
      setStatus(d)
      setLastRefresh(new Date())
    } catch { /* silent */ }
  }

  fnRef.current = fetchStatus

  useEffect(() => {
    fnRef.current?.()
    const id = setInterval(() => fnRef.current?.(), 30_000)
    return () => clearInterval(id)
  }, [])

  return (
    <aside
      className="flex flex-col w-60 min-h-screen flex-shrink-0"
      style={{ backgroundColor: '#0E1B32', borderRight: '1px solid #1E2A3A' }}
    >
      {/* Logo */}
      <div className="px-5 py-5" style={{ borderBottom: '1px solid #1E2A3A' }}>
        <div className="flex items-center gap-3">
          <div
            className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ backgroundColor: '#1F3A6B' }}
          >
            <ShieldIcon className="w-5 h-5 text-white" />
          </div>
          <div>
            <p className="text-white font-bold text-sm leading-tight">VulnPatch</p>
            <p className="text-xs leading-tight" style={{ color: '#6B7280' }}>Notifier Dashboard</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-0.5">
        {NAV.map(({ to, label, Icon }) => {
          const active = pathname === to || pathname.startsWith(to + '/')
          return (
            <Link
              key={to}
              to={to}
              className="flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors"
              style={{
                backgroundColor: active ? '#1F3A6B' : 'transparent',
                color: active ? '#FFFFFF' : '#9CA3AF',
              }}
              onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.backgroundColor = '#162040' }}
              onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.backgroundColor = 'transparent' }}
            >
              <Icon className="w-5 h-5 flex-shrink-0" />
              {label}
            </Link>
          )
        })}
      </nav>

      {/* System Status */}
      <div className="px-4 py-4" style={{ borderTop: '1px solid #1E2A3A' }}>
        <p className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: '#374151' }}>
          Estado del sistema
        </p>

        <div className="flex items-center gap-2 mb-2">
          <StatusDot status={status?.db_status === 'connected' ? 'SUCCESS' : 'FAILED'} />
          <span className="text-xs" style={{ color: '#9CA3AF' }}>
            PostgreSQL {status?.db_status === 'connected' ? 'conectado' : 'desconectado'}
          </span>
        </div>

        {status && (
          <p className="text-xs mb-3" style={{ color: '#6B7280' }}>
            {status.active_vulnerabilities} vulns activas
          </p>
        )}

        <div className="space-y-1.5">
          {(status?.workflows ?? []).map(wf => (
            <div key={wf.workflow_name} className="flex items-center justify-between gap-2">
              <span className="text-xs truncate" style={{ color: '#6B7280' }}>
                {WORKFLOW_LABELS[wf.workflow_name] ?? wf.workflow_name}
              </span>
              <StatusDot status={wf.status} />
            </div>
          ))}
        </div>

        {lastRefresh && (
          <p className="mt-3 text-xs" style={{ color: '#374151' }}>
            Sync: {lastRefresh.toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit' })}
          </p>
        )}
      </div>
    </aside>
  )
}

// ── Icons ─────────────────────────────────────────────────────────────────────

function ShieldIcon(p: SVG) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} {...p}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
      />
    </svg>
  )
}

function GridIcon(p: SVG) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} {...p}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z"
      />
    </svg>
  )
}

function DbIcon(p: SVG) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} {...p}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 5.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125"
      />
    </svg>
  )
}

function ListIcon(p: SVG) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} {...p}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"
      />
    </svg>
  )
}
