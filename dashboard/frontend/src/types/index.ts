export interface KPIs {
  total_cves: number
  critical_vulnerabilities: number
  pending_alerts: number
  sla_compliance_pct: number | null
}

export interface Vulnerability {
  av_id: number
  risk_score: number | null
  criticality_tier: string | null
  sla_deadline: string | null
  correlation_confidence: string
  shodan_exposed: boolean
  kev_listed: boolean
  exploit_available: boolean
  correlation_created_at: string
  correlation_updated_at: string
  cve_pk: number
  cve_id: string
  cve_description: string
  cvss_v3_base_score: number | null
  cvss_v3_vector: string | null
  cvss_v3_severity: string | null
  cvss_v2_base_score: number | null
  cwe_id: string | null
  published_date: string
  last_modified_date: string | null
  cve_status: string
  software_pk: number
  cpe_uri: string
  vendor: string | null
  product: string | null
  version: string | null
  asset_name: string | null
  ip_address: string | null
  asset_criticality: string
  exposed_to_internet: boolean
  owner_team: string | null
  sla_exceeded: boolean
  sla_hours_remaining: number | null
}

export interface PaginatedResponse<T> {
  total: number
  page: number
  limit: number
  items: T[]
}

export interface TierDist {
  criticality_tier: string
  count: number
}

export interface InventoryItem {
  id: number
  cpe_uri: string
  vendor: string | null
  product: string | null
  version: string | null
  asset_name: string | null
  ip_address: string | null
  criticality: string
  exposed_to_internet: boolean
  owner_team: string | null
  notes: string | null
  created_at: string
  updated_at: string
}

export interface AuditEntry {
  id: number
  workflow_name: string
  execution_id: string | null
  status: string
  records_processed: number | null
  error_message: string | null
  execution_time_ms: number | null
  executed_at: string
}

export interface SystemStatus {
  workflows: Array<{
    workflow_name: string
    status: string
    executed_at: string
    execution_time_ms: number | null
  }>
  active_vulnerabilities: number
  db_status: string
}
