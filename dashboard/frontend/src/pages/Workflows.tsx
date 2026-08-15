import { useEffect, useRef, useState } from 'react'
import { api } from '../api/client'
import type { WorkflowRun, WorkflowSummary } from '../types'

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

const POLL_INTERVAL_MS = 2_000
const POLL_TIMEOUT_MS = 5 * 60 * 1000

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

function runSummary(run: WorkflowRun): string {
  if (run.status === 'FAILED') return run.error_message ?? 'Falló sin mensaje de error'
  const n = run.records_processed
  if (n === null || n === undefined) return run.error_message ?? 'Sin detalle de registros'

  switch (run.workflow_name) {
    case 'workflow-collection':     return `${n} CVEs procesadas`
    case 'workflow-correlation':    return `${n} correlaciones encontradas`
    case 'workflow-prioritization': return `${n} risk scores calculados`
    case 'workflow-alerts':         return `${n} notificaciones enviadas`
    case 'workflow-monitoring':     return `${n} SLA vencidos detectados`
    default:                        return `${n} registros procesados`
  }
}

interface RunState {
  running: boolean
  timedOut: boolean
}

export function Workflows() {
  const [items, setItems] = useState<WorkflowSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [runState, setRunState] = useState<Record<string, RunState>>({})
  const pollRefs = useRef<Record<string, { interval: number; timeout: number }>>({})

  const fetchList = () => {
    api.workflows()
      .then(setItems)
      .catch(console.error)
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchList()
    const refs = pollRefs.current
    return () => {
      Object.values(refs).forEach(({ interval, timeout }) => {
        window.clearInterval(interval)
        window.clearTimeout(timeout)
      })
    }
  }, [])

  const clearPoll = (name: string) => {
    const p = pollRefs.current[name]
    if (p) {
      window.clearInterval(p.interval)
      window.clearTimeout(p.timeout)
      delete pollRefs.current[name]
    }
  }

  const startPolling = (name: string, since: string) => {
    clearPoll(name)

    const interval = window.setInterval(async () => {
      try {
        const res = await api.workflowStatus(name, since)
        if (res.is_new && res.last_run) {
          clearPoll(name)
          setRunState(s => ({ ...s, [name]: { running: false, timedOut: false } }))
          setItems(prev => prev.map(it =>
            it.workflow_name === name ? { ...it, last_run: res.last_run } : it
          ))
        }
      } catch {
        // Transient network hiccup — keep polling, don't kill the loop over one failed request.
      }
    }, POLL_INTERVAL_MS)

    const timeout = window.setTimeout(() => {
      clearPoll(name)
      setRunState(s => ({ ...s, [name]: { running: false, timedOut: true } }))
    }, POLL_TIMEOUT_MS)

    pollRefs.current[name] = { interval, timeout }
  }

  const handleTrigger = async (name: string) => {
    setRunState(s => ({ ...s, [name]: { running: true, timedOut: false } }))
    try {
      const res = await api.triggerWorkflow(name)
      startPolling(name, res.triggered_at)
    } catch (e) {
      setRunState(s => ({ ...s, [name]: { running: false, timedOut: false } }))
      console.error(e)
    }
  }

  return (
    <div className="p-6 space-y-5">
      <h1 className="text-xl font-bold text-white">Ejecutar Workflows</h1>
      <p className="text-sm" style={{ color: '#6B7280' }}>
        Disparo manual de cada etapa del pipeline. El resultado se confirma contra el mismo Audit Log.
      </p>

      <div className="space-y-3">
        {loading && (
          <div
            className="rounded-xl p-6 text-center text-sm"
            style={{ backgroundColor: '#111827', border: '1px solid #1E2A3A', color: '#6B7280' }}
          >
            Cargando...
          </div>
        )}

        {items.map(item => {
          const state = runState[item.workflow_name] ?? { running: false, timedOut: false }
          const run = item.last_run

          return (
            <div
              key={item.workflow_name}
              className="rounded-xl p-5 flex items-center gap-5"
              style={{ backgroundColor: '#111827', border: '1px solid #1E2A3A' }}
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3 mb-1">
                  <h2 className="text-base font-semibold text-white">
                    {WORKFLOW_LABELS[item.workflow_name] ?? item.workflow_name}
                  </h2>
                  {run && !state.running && <StatusBadge status={run.status} />}
                </div>

                <p className="text-sm mb-2" style={{ color: '#9CA3AF' }}>
                  {item.description}
                </p>

                {state.running ? (
                  <div className="flex items-center gap-2 text-sm" style={{ color: '#60A5FA' }}>
                    <Spinner />
                    Ejecutando...
                  </div>
                ) : state.timedOut ? (
                  <p className="text-xs" style={{ color: '#FCD34D' }}>
                    No se detectó resultado todavía — revisá Audit Log.
                  </p>
                ) : run ? (
                  <div className="text-xs" style={{ color: '#6B7280' }}>
                    <span>{runSummary(run)}</span>
                    <span className="mx-2">·</span>
                    <span>{fmtDate(run.executed_at)}</span>
                  </div>
                ) : (
                  <p className="text-xs" style={{ color: '#4B5563' }}>
                    Sin ejecuciones registradas todavía
                  </p>
                )}
              </div>

              <button
                onClick={() => handleTrigger(item.workflow_name)}
                disabled={state.running}
                className="px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2 flex-shrink-0 transition-colors disabled:cursor-not-allowed"
                style={{
                  backgroundColor: state.running ? '#1E2A3A' : '#1F3A6B',
                  color: state.running ? '#6B7280' : '#fff',
                }}
                onMouseEnter={e => { if (!state.running) (e.currentTarget as HTMLElement).style.backgroundColor = '#28477f' }}
                onMouseLeave={e => { if (!state.running) (e.currentTarget as HTMLElement).style.backgroundColor = '#1F3A6B' }}
              >
                {state.running ? (
                  <>
                    <Spinner />
                    Ejecutando...
                  </>
                ) : (
                  'Ejecutar ahora'
                )}
              </button>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function Spinner() {
  return (
    <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="2.5" strokeOpacity="0.25" />
      <path d="M21 12a9 9 0 00-9-9" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
  )
}
