# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**VulnPatchNotifier** — Thesis project at UTN Facultad Regional Mendoza. An automated Security Orchestration, Automation and Response (SOAR) pipeline for vulnerability patch notifications. Orchestrated with n8n (self-hosted, no-code/low-code), backed by PostgreSQL and Redis, deployed via Docker Compose.

**Status**: Specification-driven development. All specs live in `docs/`. Implementation files (`docker-compose.yml`, `db/`, `workflows/`) are yet to be created.

## Development Commands

```bash
# Start all services (n8n, PostgreSQL, Redis)
docker-compose up -d

# Stop services
docker-compose down

# Access n8n UI
open http://localhost:5678

# Database setup (once PostgreSQL is running)
psql -h localhost -U <user> -d <db> -f db/schema.sql
psql -h localhost -U <user> -d <db> -f db/seed.sql
```

n8n workflows are imported via the UI: **Settings → Import workflow** (JSON files from `workflows/`).

## Architecture

**5-stage pipeline** — all stages are n8n workflows triggered by cron or webhook:

| Stage | Trigger | What it does |
|-------|---------|--------------|
| Collection | Daily 02:00 UTC | NVD API → parse CVEs → upsert `cves` table |
| Correlation | After collection | CPE matching (exact → wildcard → semver → heuristic) → `applicable_vulnerabilities` |
| Prioritization | After correlation | Risk score = weighted formula using CVSS + Shodan exposure + CISA KEV → assigns `criticality_tier` |
| Alerts | After prioritization | Email (HTML) + Slack (Block Kit) → `vulnerability_alerts` |
| Monitoring | Hourly cron | SLA overdue check → escalation channel |

**Risk score formula**: `(0.35×CVSS_base) + (0.25×CVSS_temporal) + (0.20×Exposure) + (0.15×Criticality) + KEV_bonus`, capped at 10.0.

**Criticality tiers**: CRITICAL ≥8.5 (SLA: 24h), HIGH 7.0–8.4 (72h), MEDIUM 5.0–6.9 (7d), LOW <5.0 (30d).

**Remediation state machine**: `notified → acknowledged → in_progress → remediated` (terminal). Also `notified/acknowledged → false_positive` (terminal). No backwards transitions.

## Database Schema (5 tables)

```
cves                          -- CVEs from NVD API
software_inventory            -- Organization assets with CPE URIs
applicable_vulnerabilities    -- CVE↔Asset correlations with risk scores
vulnerability_alerts          -- Alert tracking + remediation lifecycle
audit_log                     -- Workflow execution history (status: SUCCESS/FAILED/PARTIAL)
```

Views: `v_applicable_vulnerabilities_full`, `v_sla_compliance_metrics`.

## Environment Variables

All defined in `.env.example` (never commit `.env`):

```
NVD_API_KEY, SHODAN_API_KEY
POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD
N8N_HOST, N8N_PORT, N8N_BASIC_AUTH_USER, N8N_BASIC_AUTH_PASSWORD
SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD
SECURITY_TEAM_EMAIL, SLACK_WEBHOOK_URL, SLACK_WEBHOOK_ESCALATION
CISA_KEV_CACHE_TTL_HOURS      # default: 24
```

Shodan failure fallback: `Exposure_factor = 3` (conservative default).

## Key Constraints

- NVD collection must be idempotent (`ON CONFLICT DO UPDATE`) — no duplicates on re-run.
- CVEs without CPE configurations cannot be correlated.
- CISA KEV catalog is cached 24h globally (not per-CVE lookup).
- MTTR is measured from `sent_at` (alert send time), not from acknowledgement.
- Alert color codes: CRITICAL=#ff0000, HIGH=#ff8800, MEDIUM=#ffdd00, LOW=#0088ff.

## Spec-Driven Development (OpenSpec)

New features follow this workflow:

```bash
openspec new change "<name>"         # scaffold change directory
openspec status --change "<name>" --json
openspec list --json
```

Artifacts per change: `openspec/changes/<name>/proposal.md`, `design.md`, `tasks.md`.
Completed changes archive to `openspec/changes/archive/YYYY-MM-DD-<name>/`.

User stories (43 total across 9 epics) and acceptance criteria are in `docs/Historias_de_Usuario.txt` and `docs/Especificacion_Tecnica.txt`.

## Testing / Verification

No automated test framework configured. Verification is done by:
1. Manual workflow execution in n8n UI
2. SQL queries against PostgreSQL to validate state
3. Postman for API response verification

Key metrics targets: MTTD < 4h, MTTR < 24h for CRITICAL, SLA compliance > 85%, false positive rate < 5%.
