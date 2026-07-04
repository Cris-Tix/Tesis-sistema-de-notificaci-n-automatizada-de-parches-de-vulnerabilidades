import type { ReactNode } from 'react'

interface Props {
  title: string
  value: string | number
  subtitle?: string
  accentColor?: string
  icon: ReactNode
}

export function KPICard({ title, value, subtitle, accentColor = '#1F3A6B', icon }: Props) {
  return (
    <div
      className="rounded-xl p-5 flex flex-col gap-3"
      style={{ backgroundColor: '#111827', border: '1px solid #1E2A3A' }}
    >
      <div className="flex items-start justify-between">
        <span className="text-sm font-medium leading-tight" style={{ color: '#9CA3AF' }}>
          {title}
        </span>
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
          style={{ backgroundColor: accentColor + '28' }}
        >
          <span style={{ color: accentColor }}>{icon}</span>
        </div>
      </div>
      <p className="text-3xl font-bold text-white tabular-nums">{value}</p>
      {subtitle && (
        <p className="text-xs" style={{ color: '#6B7280' }}>
          {subtitle}
        </p>
      )}
    </div>
  )
}
