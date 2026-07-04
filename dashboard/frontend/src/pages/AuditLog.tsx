import { useState, useEffect } from 'react'
import { api } from '../api/client'
import { usePolling } from '../hooks/usePolling'
import type { AuditEntry, PaginatedResponse } from '../types'

const LIMIT = 50

const WORKFLOW_LABELS: Record<string, string> = {
  'workflow-collection':    'Collection',
  'workflow-correlation':   'Correlation',
  'workflow-prioritization':'Prioritization',
  'workflow-alerts':        'Alerts',
  'workflow-monitoring':    'Monitoring',
}

const STATUS_STYLE: Record<string, { bg: string; text: string }> = {
  SUCCESS: { bg: 'rgba(34,197,94,0.15)',  text: '#4ADE80' },
  FAILED:  { bg: 'rgba(239,68,68,0.15)',  text: '#F87171' },
  PARTIAL: { bg: 'rgba(245,158,11,0.15)', text: '#FCD34D' },
}

function StatusBadge({ status }: { status: string }) {
  const s = STATUS_STYLE[status] ?? { bg: 'rgba(100,100,100,0.2)', text: '#9CA3AF' }
  return (
    <span
      className="inline-block px-2 py-0.5 rounded text-xs font-semibold"
      style={{ backgroundColor: s.bg, color: s.text }}
    >
      {status}
    </span>
  )
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString('es-AR', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function fmtMs(ms: number | null) {
  if (ms === null) return '—'
  if (ms < 1000) return `${ms} ms`
  return `${(ms / 1000).toFixed(1)} s`
}

export function AuditLog() {
  const [data, setData] = useState<PaginatedResponse<AuditEntry> | null>(null)
  const [workflow, setWorkflow] = useState('')
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(1)

  const fetchLog = () => {
    api.auditLog({
      page,
      limit: LIMIT,
      workflow: workflow || undefined,
      status: status || undefined,
    })
      .then(setData)
      .catch(console.error)
  }

  usePolling(fetchLog, 30_000)
  useEffect(fetchLog, [page, workflow, status])

  const totalPages = data ? Math.ceil(data.total / LIMIT) : 1

  const selectCls = "px-3 py-2 rounded text-sm outline-none"
  const selectStyle = { backgroundColor: '#111827', border: '1px solid #1E2A3A', color: '#E5E7EB' }

  return (
    <div className="p-6 space-y-5">
      <h1 className="text-xl font-bold text-white">Audit Log</h1>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <select
          value={workflow}
          onChange={e => { setWorkflow(e.target.value); setPage(1) }}
          className={selectCls}
          style={selectStyle}
        >
          <option value="">Todos los workflows</option>
          {Object.entries(WORKFLOW_LABELS).map(([k, v]) => (
            <option key={k} value={k}>{v}</option>
          ))}
        </select>

        <select
          value={status}
          onChange={e => { setStatus(e.target.value); setPage(1) }}
          className={selectCls}
          style={selectStyle}
        >
          <option value="">Todos los estados</option>
          <option value="SUCCESS">SUCCESS</option>
          <option value="FAILED">FAILED</option>
          <option value="PARTIAL">PARTIAL</option>
        </select>

        {(workflow || status) && (
          <button
            onClick={() => { setWorkflow(''); setStatus(''); setPage(1) }}
            className="px-3 py-2 rounded text-sm"
            style={{ backgroundColor: '#1E2A3A', color: '#9CA3AF' }}
          >
            Limpiar filtros
          </button>
        )}

        <span className="ml-auto text-sm self-center" style={{ color: '#6B7280' }}>
          {data ? `${data.total} registros` : ''}
        </span>
      </div>

      {/* Table */}
      <div className="rounded-xl overflow-hidden" style={{ backgroundColor: '#111827', border: '1px solid #1E2A3A' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '1px solid #1E2A3A' }}>
                {['#', 'Workflow', 'Estado', 'Registros', 'Duración', 'Error', 'Ejecutado'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: '#6B7280' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(data?.items ?? []).map(entry => (
                <tr
                  key={entry.id}
                  style={{ borderBottom: '1px solid #1E2A3A' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.backgroundColor = '#162040'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.backgroundColor = ''}
                >
                  <td className="px-4 py-3 text-xs tabular-nums" style={{ color: '#6B7280' }}>
                    {entry.id}
                  </td>
                  <td className="px-4 py-3">
                    <p className="font-medium" style={{ color: '#E5E7EB' }}>
                      {WORKFLOW_LABELS[entry.workflow_name] ?? entry.workflow_name}
                    </p>
                    {entry.execution_id && (
                      <p className="text-xs font-mono" style={{ color: '#4B5563' }}>{entry.execution_id}</p>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={entry.status} />
                  </td>
                  <td className="px-4 py-3 tabular-nums" style={{ color: '#9CA3AF' }}>
                    {entry.records_processed ?? '—'}
                  </td>
                  <td className="px-4 py-3 tabular-nums text-xs" style={{ color: '#9CA3AF' }}>
                    {fmtMs(entry.execution_time_ms)}
                  </td>
                  <td className="px-4 py-3 max-w-xs">
                    {entry.error_message ? (
                      <span
                        className="text-xs block truncate"
                        style={{ color: '#F87171' }}
                        title={entry.error_message}
                      >
                        {entry.error_message}
                      </span>
                    ) : (
                      <span style={{ color: '#4B5563' }}>—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-xs whitespace-nowrap" style={{ color: '#9CA3AF' }}>
                    {fmtDate(entry.executed_at)}
                  </td>
                </tr>
              ))}
              {(data?.items ?? []).length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-10 text-center text-sm" style={{ color: '#6B7280' }}>
                    Sin registros de auditoría
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="px-5 py-3 flex items-center justify-between" style={{ borderTop: '1px solid #1E2A3A' }}>
          <span className="text-xs" style={{ color: '#6B7280' }}>
            {data && data.total > 0
              ? `${(page - 1) * LIMIT + 1}–${Math.min(page * LIMIT, data.total)} de ${data.total}`
              : ''}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1 rounded text-xs disabled:opacity-40"
              style={{ backgroundColor: '#1E2A3A', color: '#9CA3AF' }}
            >
              ← Anterior
            </button>
            <span className="px-2 py-1 text-xs" style={{ color: '#9CA3AF' }}>{page} / {totalPages}</span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-3 py-1 rounded text-xs disabled:opacity-40"
              style={{ backgroundColor: '#1E2A3A', color: '#9CA3AF' }}
            >
              Siguiente →
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
