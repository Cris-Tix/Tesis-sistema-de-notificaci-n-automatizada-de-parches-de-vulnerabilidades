const COLORS: Record<string, { bg: string; text: string }> = {
  CRITICAL: { bg: 'rgba(163,45,45,0.2)', text: '#F87171' },
  HIGH:     { bg: 'rgba(24,95,165,0.2)',  text: '#60A5FA' },
  MEDIUM:   { bg: 'rgba(59,109,17,0.2)',  text: '#86EFAC' },
  LOW:      { bg: 'rgba(95,94,90,0.2)',   text: '#9CA3AF' },
}

export function TierBadge({ tier }: { tier: string | null | undefined }) {
  if (!tier) return <span style={{ color: '#6B7280' }}>—</span>
  const c = COLORS[tier] ?? { bg: 'rgba(50,50,50,0.3)', text: '#9CA3AF' }
  return (
    <span
      className="inline-block px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide"
      style={{ backgroundColor: c.bg, color: c.text }}
    >
      {tier}
    </span>
  )
}
