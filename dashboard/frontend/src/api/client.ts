import type {
  KPIs,
  Vulnerability,
  PaginatedResponse,
  TierDist,
  InventoryItem,
  AuditEntry,
  SystemStatus,
  WorkflowSummary,
  WorkflowTriggerResponse,
  WorkflowStatusResponse,
} from '../types'

const BASE = '/api'

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  })
  if (res.status === 204) return undefined as T
  let data: Record<string, unknown>
  try {
    data = await res.json()
  } catch {
    throw new Error(`HTTP ${res.status}`)
  }
  if (!res.ok) throw new Error((data.detail as string) ?? `HTTP ${res.status}`)
  return data as T
}

function qs(params: Record<string, string | number | undefined>): string {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
  }
  const s = q.toString()
  return s ? `?${s}` : ''
}

export const api = {
  kpis: (): Promise<KPIs> =>
    req('/kpis'),

  vulnerabilities: (p: { tier?: string; page?: number; limit?: number }): Promise<PaginatedResponse<Vulnerability>> =>
    req(`/vulnerabilities${qs({ tier: p.tier, page: p.page, limit: p.limit })}`),

  distribution: (): Promise<TierDist[]> =>
    req('/vulnerabilities/distribution'),

  inventory: (p: { page?: number; limit?: number; search?: string }): Promise<PaginatedResponse<InventoryItem>> =>
    req(`/inventory${qs({ page: p.page, limit: p.limit, search: p.search })}`),

  createInventory: (body: unknown): Promise<InventoryItem> =>
    req('/inventory', { method: 'POST', body: JSON.stringify(body) }),

  updateInventory: (id: number, body: unknown): Promise<InventoryItem> =>
    req(`/inventory/${id}`, { method: 'PUT', body: JSON.stringify(body) }),

  deleteInventory: (id: number): Promise<void> =>
    req(`/inventory/${id}`, { method: 'DELETE' }),

  auditLog: (p: { page?: number; limit?: number; workflow?: string; status?: string }): Promise<PaginatedResponse<AuditEntry>> =>
    req(`/audit-log${qs({ page: p.page, limit: p.limit, workflow: p.workflow, status: p.status })}`),

  systemStatus: (): Promise<SystemStatus> =>
    req('/system-status'),

  workflows: (): Promise<WorkflowSummary[]> =>
    req('/workflows'),

  triggerWorkflow: (name: string): Promise<WorkflowTriggerResponse> =>
    req(`/workflows/${name}/trigger`, { method: 'POST' }),

  workflowStatus: (name: string, since?: string): Promise<WorkflowStatusResponse> =>
    req(`/workflows/${name}/status${qs({ since })}`),
}
