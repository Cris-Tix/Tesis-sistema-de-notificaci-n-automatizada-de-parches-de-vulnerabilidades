import { useState, useEffect } from 'react'
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'
import { api } from '../api/client'
import { usePolling } from '../hooks/usePolling'
import { KPICard } from '../components/KPICard'
import { TierBadge } from '../components/TierBadge'
import type { KPIs, TierDist, Vulnerability, PaginatedResponse } from '../types'

const TIER_COLORS: Record<string, string> = {
  CRITICAL: '#A32D2D',
  HIGH:     '#185FA5',
  MEDIUM:   '#3B6D11',
  LOW:      '#5F5E5A',
}
const TIERS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
const LIMIT = 20

function SlaStatus({ exceeded, hours }: { exceeded: boolean; hours: number | null }) {
  if (exceeded) return <span style={{ color: '#F87171' }}>Vencido</span>
  if (hours === null) return <span style={{ color: '#6B7280' }}>—</span>
  if (hours < 0) return <span style={{ color: '#F87171' }}>Vencido</span>
  if (hours < 24) return <span style={{ color: '#FCD34D' }}>{Math.round(hours)}h rest.</span>
  return <span style={{ color: '#86EFAC' }}>{Math.floor(hours / 24)}d rest.</span>
}

export function Overview() {
  const [kpis, setKpis] = useState<KPIs | null>(null)
  const [dist, setDist] = useState<TierDist[]>([])
  const [vulns, setVulns] = useState<PaginatedResponse<Vulnerability> | null>(null)
  const [tier, setTier] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchBase = async () => {
    try {
      const [k, d] = await Promise.all([api.kpis(), api.distribution()])
      setKpis(k)
      setDist(d)
      setError(null)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Error de conexión')
    } finally {
      setLoading(false)
    }
  }

  usePolling(fetchBase, 30_000)

  useEffect(() => {
    api.vulnerabilities({ tier: tier ?? undefined, page, limit: LIMIT })
      .then(setVulns)
      .catch(console.error)
  }, [tier, page])

  const changeTier = (t: string | null) => { setTier(t); setPage(1) }
  const totalPages = vulns ? Math.ceil(vulns.total / LIMIT) : 1

  const slaLabel = kpis?.sla_compliance_pct !== null && kpis?.sla_compliance_pct !== undefined
    ? `${kpis.sla_compliance_pct}%`
    : '—'
  const slaColor = kpis?.sla_compliance_pct !== null && kpis?.sla_compliance_pct !== undefined
    ? (kpis.sla_compliance_pct >= 85 ? '#22C55E' : '#EF4444')
    : '#6B7280'

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-bold text-white">Overview</h1>

      {error && (
        <div className="rounded-lg px-4 py-3 text-sm" style={{ backgroundColor: '#2D1515', color: '#F87171', border: '1px solid #7F1D1D' }}>
          Error: {error}
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <KPICard
          title="CVEs Procesados"
          value={loading ? '...' : (kpis?.total_cves ?? 0)}
          subtitle="Total en base de datos"
          accentColor="#1F3A6B"
          icon={<DocIcon />}
        />
        <KPICard
          title="Vulnerabilidades CRITICAL"
          value={loading ? '...' : (kpis?.critical_vulnerabilities ?? 0)}
          subtitle="Con tier CRITICAL asignado"
          accentColor="#A32D2D"
          icon={<AlertIcon />}
        />
        <KPICard
          title="Alertas Pendientes"
          value={loading ? '...' : (kpis?.pending_alerts ?? 0)}
          subtitle="No remediadas ni FP"
          accentColor="#D97706"
          icon={<BellIcon />}
        />
        <KPICard
          title="SLA Compliance"
          value={loading ? '...' : slaLabel}
          subtitle="Remediaciones dentro del SLA"
          accentColor={slaColor}
          icon={<CheckIcon />}
        />
      </div>

      {/* Distribution Chart */}
      <div
        className="rounded-xl p-5"
        style={{ backgroundColor: '#111827', border: '1px solid #1E2A3A' }}
      >
        <h2 className="text-sm font-semibold text-white mb-4">Distribución por Criticality Tier</h2>
        {dist.length === 0 ? (
          <p className="text-sm text-center py-8" style={{ color: '#6B7280' }}>Sin datos</p>
        ) : (
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={dist}
                dataKey="count"
                nameKey="criticality_tier"
                cx="50%"
                cy="50%"
                outerRadius={80}
                innerRadius={44}
                paddingAngle={3}
              >
                {dist.map(entry => (
                  <Cell
                    key={entry.criticality_tier}
                    fill={TIER_COLORS[entry.criticality_tier] ?? '#555'}
                  />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: '#1F2937', border: '1px solid #374151', borderRadius: '8px' }}
                itemStyle={{ color: '#E5E7EB' }}
                labelStyle={{ color: '#fff' }}
              />
              <Legend
                formatter={v => (
                  <span style={{ color: '#9CA3AF', fontSize: '12px' }}>{v}</span>
                )}
              />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Vulnerabilities Table */}
      <div
        className="rounded-xl"
        style={{ backgroundColor: '#111827', border: '1px solid #1E2A3A' }}
      >
        <div className="px-5 py-4 flex flex-wrap items-center gap-3" style={{ borderBottom: '1px solid #1E2A3A' }}>
          <h2 className="text-sm font-semibold text-white mr-2">Applicable Vulnerabilities</h2>
          <button
            onClick={() => changeTier(null)}
            className="px-3 py-1 rounded text-xs font-medium transition-colors"
            style={{
              backgroundColor: tier === null ? '#1F3A6B' : '#1E2A3A',
              color: tier === null ? '#fff' : '#9CA3AF',
            }}
          >
            Todos
          </button>
          {TIERS.map(t => (
            <button
              key={t}
              onClick={() => changeTier(t)}
              className="px-3 py-1 rounded text-xs font-medium transition-colors"
              style={{
                backgroundColor: tier === t ? TIER_COLORS[t] + '33' : '#1E2A3A',
                color: tier === t ? '#fff' : '#9CA3AF',
                borderLeft: `2px solid ${tier === t ? TIER_COLORS[t] : 'transparent'}`,
              }}
            >
              {t}
            </button>
          ))}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr style={{ borderBottom: '1px solid #1E2A3A' }}>
                {['CVE ID', 'Asset', 'CVSS', 'Risk Score', 'Tier', 'SLA'].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider" style={{ color: '#6B7280' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(vulns?.items ?? []).map(v => (
                <tr
                  key={v.av_id}
                  style={{ borderBottom: '1px solid #1E2A3A' }}
                  onMouseEnter={e => (e.currentTarget as HTMLElement).style.backgroundColor = '#162040'}
                  onMouseLeave={e => (e.currentTarget as HTMLElement).style.backgroundColor = ''}
                >
                  <td className="px-4 py-3 font-mono">
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="hover:underline"
                      style={{ color: '#60A5FA' }}
                    >
                      {v.cve_id}
                    </a>
                  </td>
                  <td className="px-4 py-3">
                    <p className="font-medium text-white">{v.asset_name ?? v.product ?? '—'}</p>
                    <p className="text-xs" style={{ color: '#6B7280' }}>{v.vendor} {v.version}</p>
                  </td>
                  <td className="px-4 py-3 tabular-nums" style={{ color: '#E5E7EB' }}>
                    {v.cvss_v3_base_score?.toFixed(1) ?? v.cvss_v2_base_score?.toFixed(1) ?? '—'}
                  </td>
                  <td className="px-4 py-3 tabular-nums font-semibold" style={{ color: '#E5E7EB' }}>
                    {v.risk_score?.toFixed(2) ?? '—'}
                  </td>
                  <td className="px-4 py-3">
                    <TierBadge tier={v.criticality_tier} />
                  </td>
                  <td className="px-4 py-3">
                    <SlaStatus exceeded={v.sla_exceeded} hours={v.sla_hours_remaining} />
                  </td>
                </tr>
              ))}
              {(vulns?.items ?? []).length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-10 text-center text-sm" style={{ color: '#6B7280' }}>
                    Sin vulnerabilidades{tier ? ` con tier ${tier}` : ''}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="px-5 py-3 flex items-center justify-between" style={{ borderTop: '1px solid #1E2A3A' }}>
          <span className="text-xs" style={{ color: '#6B7280' }}>
            {vulns
              ? `${(page - 1) * LIMIT + 1}–${Math.min(page * LIMIT, vulns.total)} de ${vulns.total}`
              : ''}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="px-3 py-1 rounded text-xs disabled:opacity-40 transition-colors"
              style={{ backgroundColor: '#1E2A3A', color: '#9CA3AF' }}
            >
              ← Anterior
            </button>
            <span className="px-3 py-1 text-xs" style={{ color: '#9CA3AF' }}>
              {page} / {totalPages}
            </span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-3 py-1 rounded text-xs disabled:opacity-40 transition-colors"
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

// ── Inline icons ──────────────────────────────────────────────────────────────

function DocIcon() {
  return (
    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"
      />
    </svg>
  )
}

function AlertIcon() {
  return (
    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
      />
    </svg>
  )
}

function BellIcon() {
  return (
    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0"
      />
    </svg>
  )
}

function CheckIcon() {
  return (
    <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round"
        d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
      />
    </svg>
  )
}
