-- =============================================================================
-- VulnPatchNotifier — Database Schema
-- PostgreSQL 16
-- Schema: vulnerability_management
-- =============================================================================

-- Create dedicated schema
CREATE SCHEMA IF NOT EXISTS vulnerability_management;

-- Set search path for this session so all objects land in the right schema
SET search_path TO vulnerability_management, public;

-- =============================================================================
-- TABLE: cves
-- CVEs collected from NVD API 2.0
-- =============================================================================
CREATE TABLE IF NOT EXISTS vulnerability_management.cves (
    id                  SERIAL          PRIMARY KEY,
    cve_id              VARCHAR(20)     NOT NULL UNIQUE,          -- CVE-YYYY-NNNNN
    description         TEXT            NOT NULL,
    cvss_v3_base_score  DECIMAL(3,1)    NULL,                    -- 0.0 – 10.0
    cvss_v3_vector      VARCHAR(100)    NULL,
    cvss_v3_severity    VARCHAR(20)     NULL,                    -- CRITICAL/HIGH/MEDIUM/LOW
    cvss_v2_base_score  DECIMAL(3,1)    NULL,                    -- fallback when v3 unavailable
    cwe_id              VARCHAR(20)     NULL,
    published_date      TIMESTAMP       NOT NULL,
    last_modified_date  TIMESTAMP       NULL,
    configurations      JSONB           NULL,                    -- CPEs with AND/OR operators
    patch_references    JSONB           NULL,                    -- advisory / patch URLs
    status              VARCHAR(20)     NOT NULL DEFAULT 'unprocessed',  -- unprocessed/correlated/prioritized
    created_at          TIMESTAMP       NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP       NOT NULL DEFAULT NOW(),

    CONSTRAINT cves_status_check
        CHECK (status IN ('unprocessed', 'correlated', 'prioritized')),

    CONSTRAINT cves_cvss_v3_base_score_range
        CHECK (cvss_v3_base_score IS NULL OR (cvss_v3_base_score >= 0.0 AND cvss_v3_base_score <= 10.0)),

    CONSTRAINT cves_cvss_v2_base_score_range
        CHECK (cvss_v2_base_score IS NULL OR (cvss_v2_base_score >= 0.0 AND cvss_v2_base_score <= 10.0)),

    CONSTRAINT cves_cvss_v3_severity_check
        CHECK (cvss_v3_severity IS NULL OR cvss_v3_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'))
);

COMMENT ON TABLE  vulnerability_management.cves IS 'CVEs collected from NVD API 2.0. Populated by workflow-collection.';
COMMENT ON COLUMN vulnerability_management.cves.configurations IS 'Raw CPE configurations JSON from NVD (AND/OR nodes).';
COMMENT ON COLUMN vulnerability_management.cves.status IS 'Pipeline stage: unprocessed → correlated → prioritized.';

-- =============================================================================
-- TABLE: software_inventory
-- Organization asset inventory with CPE URIs
-- =============================================================================
CREATE TABLE IF NOT EXISTS vulnerability_management.software_inventory (
    id                  SERIAL          PRIMARY KEY,
    cpe_uri             VARCHAR(255)    NOT NULL UNIQUE,          -- cpe:2.3:a:vendor:product:version:...
    vendor              VARCHAR(100)    NULL,
    product             VARCHAR(100)    NULL,
    version             VARCHAR(50)     NULL,
    asset_name          VARCHAR(100)    NULL,
    ip_address          INET            NULL,
    criticality         VARCHAR(20)     NOT NULL,                -- CRITICAL/HIGH/MEDIUM/LOW
    exposed_to_internet BOOLEAN         NOT NULL DEFAULT FALSE,
    owner_team          VARCHAR(100)    NULL,
    notes               TEXT            NULL,
    created_at          TIMESTAMP       NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMP       NOT NULL DEFAULT NOW(),

    CONSTRAINT software_inventory_criticality_check
        CHECK (criticality IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),

    CONSTRAINT software_inventory_cpe_format
        CHECK (cpe_uri LIKE 'cpe:2.3:%')
);

COMMENT ON TABLE  vulnerability_management.software_inventory IS 'Organizational software asset inventory. Must use CPE 2.3 URIs.';
COMMENT ON COLUMN vulnerability_management.software_inventory.exposed_to_internet IS 'Known exposure (prior knowledge). shodan_exposed in applicable_vulnerabilities is Shodan-confirmed.';

-- =============================================================================
-- TABLE: applicable_vulnerabilities
-- CVE ↔ Asset correlations with risk scores
-- =============================================================================
CREATE TABLE IF NOT EXISTS vulnerability_management.applicable_vulnerabilities (
    id                      SERIAL          PRIMARY KEY,
    cve_id                  INTEGER         NOT NULL
                                REFERENCES vulnerability_management.cves(id) ON DELETE CASCADE,
    software_id             INTEGER         NOT NULL
                                REFERENCES vulnerability_management.software_inventory(id) ON DELETE RESTRICT,
    risk_score              DECIMAL(4,2)    NULL,                -- 0.00 – 10.00, capped
    criticality_tier        VARCHAR(20)     NULL,                -- CRITICAL/HIGH/MEDIUM/LOW
    sla_deadline            TIMESTAMP       NULL,                -- auto-calculated by trigger
    correlation_confidence  VARCHAR(20)     NOT NULL DEFAULT 'HIGH',  -- HIGH/MEDIUM/LOW
    shodan_exposed          BOOLEAN         NOT NULL DEFAULT FALSE,
    kev_listed              BOOLEAN         NOT NULL DEFAULT FALSE,
    exploit_available       BOOLEAN         NOT NULL DEFAULT FALSE,
    created_at              TIMESTAMP       NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMP       NOT NULL DEFAULT NOW(),

    CONSTRAINT applicable_vulnerabilities_unique_pair
        UNIQUE (cve_id, software_id),

    CONSTRAINT applicable_vulnerabilities_risk_score_range
        CHECK (risk_score IS NULL OR (risk_score >= 0.00 AND risk_score <= 10.00)),

    CONSTRAINT applicable_vulnerabilities_criticality_tier_check
        CHECK (criticality_tier IS NULL OR criticality_tier IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),

    CONSTRAINT applicable_vulnerabilities_confidence_check
        CHECK (correlation_confidence IN ('HIGH', 'MEDIUM', 'LOW'))
);

COMMENT ON TABLE  vulnerability_management.applicable_vulnerabilities IS 'CVE-to-asset correlations produced by workflow-correlation. Risk scores updated by workflow-prioritization.';
COMMENT ON COLUMN vulnerability_management.applicable_vulnerabilities.sla_deadline IS 'Auto-set by set_sla_deadline trigger on INSERT based on criticality_tier.';

-- =============================================================================
-- TABLE: vulnerability_alerts
-- Alert tracking + remediation lifecycle state machine
-- States: notified → acknowledged → in_progress → remediated | false_positive
-- =============================================================================
CREATE TABLE IF NOT EXISTS vulnerability_management.vulnerability_alerts (
    id                          SERIAL          PRIMARY KEY,
    applicable_vulnerability_id INTEGER         NOT NULL
                                    REFERENCES vulnerability_management.applicable_vulnerabilities(id) ON DELETE CASCADE,
    alert_type                  VARCHAR(20)     NOT NULL,        -- EMAIL/SLACK/WEBHOOK
    recipient                   VARCHAR(255)    NOT NULL,
    subject                     VARCHAR(255)    NULL,
    message_body                TEXT            NULL,
    sent_at                     TIMESTAMP       NOT NULL DEFAULT NOW(),
    status                      VARCHAR(20)     NOT NULL DEFAULT 'notified',  -- state machine
    acknowledged_at             TIMESTAMP       NULL,
    acknowledged_by             VARCHAR(100)    NULL,
    remediation_started_at      TIMESTAMP       NULL,
    remediation_completed_at    TIMESTAMP       NULL,
    remediation_notes           TEXT            NULL,
    patch_version               VARCHAR(50)     NULL,
    verification_method         VARCHAR(100)    NULL,
    created_at                  TIMESTAMP       NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMP       NOT NULL DEFAULT NOW(),

    CONSTRAINT vulnerability_alerts_status_check
        CHECK (status IN ('notified', 'acknowledged', 'in_progress', 'remediated', 'false_positive')),

    CONSTRAINT vulnerability_alerts_alert_type_check
        CHECK (alert_type IN ('EMAIL', 'SLACK', 'WEBHOOK')),

    -- Ensure remediation_completed_at is after remediation_started_at
    CONSTRAINT vulnerability_alerts_remediation_order
        CHECK (
            remediation_completed_at IS NULL
            OR remediation_started_at IS NULL
            OR remediation_completed_at >= remediation_started_at
        )
);

COMMENT ON TABLE  vulnerability_management.vulnerability_alerts IS 'Sent alerts and their remediation lifecycle. State machine: notified → acknowledged → in_progress → remediated | false_positive.';

-- =============================================================================
-- TABLE: audit_log
-- Workflow execution history
-- =============================================================================
CREATE TABLE IF NOT EXISTS vulnerability_management.audit_log (
    id                  SERIAL          PRIMARY KEY,
    workflow_name       VARCHAR(100)    NOT NULL,
    execution_id        VARCHAR(100)    NULL,                    -- n8n execution ID
    status              VARCHAR(20)     NOT NULL,                -- SUCCESS/FAILED/PARTIAL
    records_processed   INTEGER         NULL,
    error_message       TEXT            NULL,
    execution_time_ms   INTEGER         NULL,
    executed_at         TIMESTAMP       NOT NULL DEFAULT NOW(),

    CONSTRAINT audit_log_status_check
        CHECK (status IN ('SUCCESS', 'FAILED', 'PARTIAL'))
);

COMMENT ON TABLE vulnerability_management.audit_log IS 'Immutable execution log for every n8n workflow run.';

-- =============================================================================
-- TRIGGER FUNCTION: generic updated_at auto-update
-- =============================================================================
CREATE OR REPLACE FUNCTION vulnerability_management.fn_set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION vulnerability_management.fn_set_updated_at() IS 'Generic BEFORE UPDATE trigger function that sets updated_at = NOW().';

-- updated_at triggers for all tables that carry the column
CREATE TRIGGER update_cves_updated_at
    BEFORE UPDATE ON vulnerability_management.cves
    FOR EACH ROW EXECUTE FUNCTION vulnerability_management.fn_set_updated_at();

CREATE TRIGGER update_inventory_updated_at
    BEFORE UPDATE ON vulnerability_management.software_inventory
    FOR EACH ROW EXECUTE FUNCTION vulnerability_management.fn_set_updated_at();

CREATE TRIGGER update_applicable_updated_at
    BEFORE UPDATE ON vulnerability_management.applicable_vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION vulnerability_management.fn_set_updated_at();

CREATE TRIGGER update_alerts_updated_at
    BEFORE UPDATE ON vulnerability_management.vulnerability_alerts
    FOR EACH ROW EXECUTE FUNCTION vulnerability_management.fn_set_updated_at();

-- =============================================================================
-- TRIGGER FUNCTION: auto-calculate sla_deadline on INSERT
-- Criticality tiers → deadlines:
--   CRITICAL  → NOW() + 24 hours
--   HIGH      → NOW() + 72 hours
--   MEDIUM    → NOW() + 7 days
--   LOW       → NOW() + 30 days
-- If criticality_tier is NULL at INSERT time the deadline remains NULL and
-- must be recalculated when the UPDATE sets criticality_tier (handled below).
-- =============================================================================
CREATE OR REPLACE FUNCTION vulnerability_management.fn_set_sla_deadline()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    -- Only calculate when criticality_tier is known
    IF NEW.criticality_tier IS NOT NULL THEN
        CASE NEW.criticality_tier
            WHEN 'CRITICAL' THEN
                NEW.sla_deadline = NOW() + INTERVAL '24 hours';
            WHEN 'HIGH' THEN
                NEW.sla_deadline = NOW() + INTERVAL '72 hours';
            WHEN 'MEDIUM' THEN
                NEW.sla_deadline = NOW() + INTERVAL '7 days';
            WHEN 'LOW' THEN
                NEW.sla_deadline = NOW() + INTERVAL '30 days';
            ELSE
                NEW.sla_deadline = NULL;
        END CASE;
    END IF;
    RETURN NEW;
END;
$$;

COMMENT ON FUNCTION vulnerability_management.fn_set_sla_deadline() IS 'BEFORE INSERT/UPDATE trigger that auto-calculates sla_deadline from criticality_tier. CRITICAL=24h, HIGH=72h, MEDIUM=7d, LOW=30d.';

-- Fire on INSERT (when workflow-correlation inserts a row with criticality_tier still NULL,
-- the deadline stays NULL). Fire on UPDATE too so that when workflow-prioritization
-- sets criticality_tier the deadline is computed in the same statement.
CREATE TRIGGER set_sla_deadline
    BEFORE INSERT OR UPDATE OF criticality_tier
    ON vulnerability_management.applicable_vulnerabilities
    FOR EACH ROW EXECUTE FUNCTION vulnerability_management.fn_set_sla_deadline();

-- =============================================================================
-- INDEXES
-- =============================================================================

-- cves — common query patterns
CREATE INDEX IF NOT EXISTS idx_cves_status
    ON vulnerability_management.cves (status);

CREATE INDEX IF NOT EXISTS idx_cves_published_date
    ON vulnerability_management.cves (published_date);

CREATE INDEX IF NOT EXISTS idx_cves_cvss_v3_severity
    ON vulnerability_management.cves (cvss_v3_severity);

-- BRIN index for append-heavy timestamp column (low maintenance cost)
CREATE INDEX IF NOT EXISTS idx_cves_created_at_brin
    ON vulnerability_management.cves USING BRIN (created_at);

-- GIN index for JSONB columns to allow @>, ?, and @? operators
CREATE INDEX IF NOT EXISTS idx_cves_configurations_gin
    ON vulnerability_management.cves USING GIN (configurations);

-- software_inventory
CREATE INDEX IF NOT EXISTS idx_software_inventory_criticality
    ON vulnerability_management.software_inventory (criticality);

CREATE INDEX IF NOT EXISTS idx_software_inventory_ip_address
    ON vulnerability_management.software_inventory (ip_address);

CREATE INDEX IF NOT EXISTS idx_software_inventory_exposed
    ON vulnerability_management.software_inventory (exposed_to_internet);

-- applicable_vulnerabilities
CREATE INDEX IF NOT EXISTS idx_applicable_vuln_cve_id
    ON vulnerability_management.applicable_vulnerabilities (cve_id);

CREATE INDEX IF NOT EXISTS idx_applicable_vuln_software_id
    ON vulnerability_management.applicable_vulnerabilities (software_id);

CREATE INDEX IF NOT EXISTS idx_applicable_vuln_risk_score
    ON vulnerability_management.applicable_vulnerabilities (risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_applicable_vuln_criticality_tier
    ON vulnerability_management.applicable_vulnerabilities (criticality_tier);

CREATE INDEX IF NOT EXISTS idx_applicable_vuln_sla_deadline
    ON vulnerability_management.applicable_vulnerabilities (sla_deadline);

-- Partial index: rows awaiting prioritization (risk_score IS NULL)
CREATE INDEX IF NOT EXISTS idx_applicable_vuln_unprioritized
    ON vulnerability_management.applicable_vulnerabilities (id)
    WHERE risk_score IS NULL;

-- vulnerability_alerts
CREATE INDEX IF NOT EXISTS idx_alerts_applicable_vulnerability_id
    ON vulnerability_management.vulnerability_alerts (applicable_vulnerability_id);

CREATE INDEX IF NOT EXISTS idx_alerts_status
    ON vulnerability_management.vulnerability_alerts (status);

CREATE INDEX IF NOT EXISTS idx_alerts_sent_at_brin
    ON vulnerability_management.vulnerability_alerts USING BRIN (sent_at);

-- Partial index: active (non-terminal) alerts — used by SLA monitoring workflow
CREATE INDEX IF NOT EXISTS idx_alerts_active
    ON vulnerability_management.vulnerability_alerts (applicable_vulnerability_id, status)
    WHERE status NOT IN ('remediated', 'false_positive');

-- audit_log
CREATE INDEX IF NOT EXISTS idx_audit_log_workflow_name
    ON vulnerability_management.audit_log (workflow_name);

CREATE INDEX IF NOT EXISTS idx_audit_log_executed_at_brin
    ON vulnerability_management.audit_log USING BRIN (executed_at);

CREATE INDEX IF NOT EXISTS idx_audit_log_status
    ON vulnerability_management.audit_log (status);

-- =============================================================================
-- VIEW: v_applicable_vulnerabilities_full
-- Full JOIN of cves + software_inventory + applicable_vulnerabilities
-- Ordered by risk_score DESC (highest-risk first)
-- =============================================================================
CREATE OR REPLACE VIEW vulnerability_management.v_applicable_vulnerabilities_full AS
SELECT
    -- applicable_vulnerabilities columns
    av.id                       AS av_id,
    av.risk_score,
    av.criticality_tier,
    av.sla_deadline,
    av.correlation_confidence,
    av.shodan_exposed,
    av.kev_listed,
    av.exploit_available,
    av.created_at               AS correlation_created_at,
    av.updated_at               AS correlation_updated_at,

    -- cves columns
    c.id                        AS cve_pk,
    c.cve_id,
    c.description               AS cve_description,
    c.cvss_v3_base_score,
    c.cvss_v3_vector,
    c.cvss_v3_severity,
    c.cvss_v2_base_score,
    c.cwe_id,
    c.published_date,
    c.last_modified_date,
    c.status                    AS cve_status,

    -- software_inventory columns
    si.id                       AS software_pk,
    si.cpe_uri,
    si.vendor,
    si.product,
    si.version,
    si.asset_name,
    si.ip_address,
    si.criticality              AS asset_criticality,
    si.exposed_to_internet,
    si.owner_team,

    -- Derived: is the SLA already exceeded (for non-terminal alerts)?
    CASE
        WHEN av.sla_deadline IS NOT NULL AND NOW() > av.sla_deadline THEN TRUE
        ELSE FALSE
    END                         AS sla_exceeded,

    -- Derived: hours remaining until SLA deadline (negative = overdue)
    CASE
        WHEN av.sla_deadline IS NOT NULL
        THEN EXTRACT(EPOCH FROM (av.sla_deadline - NOW())) / 3600.0
        ELSE NULL
    END                         AS sla_hours_remaining

FROM vulnerability_management.applicable_vulnerabilities av
JOIN vulnerability_management.cves              c  ON c.id  = av.cve_id
JOIN vulnerability_management.software_inventory si ON si.id = av.software_id
ORDER BY av.risk_score DESC NULLS LAST;

COMMENT ON VIEW vulnerability_management.v_applicable_vulnerabilities_full IS
    'Full denormalized view of correlations, CVE details, and asset info. Ordered by risk_score DESC.';

-- =============================================================================
-- VIEW: v_sla_compliance_metrics
-- Aggregated SLA compliance metrics per criticality_tier
-- =============================================================================
CREATE OR REPLACE VIEW vulnerability_management.v_sla_compliance_metrics AS
WITH alert_state AS (
    -- One row per applicable_vulnerability: latest alert status + whether remediated in time
    SELECT
        av.id                       AS av_id,
        av.criticality_tier,
        av.sla_deadline,
        va.status                   AS alert_status,
        va.remediation_completed_at,
        va.sent_at,
        -- Within SLA: remediated AND completed before or on the deadline
        CASE
            WHEN va.status = 'remediated'
                 AND av.sla_deadline IS NOT NULL
                 AND va.remediation_completed_at <= av.sla_deadline
            THEN TRUE
            ELSE FALSE
        END                         AS remediated_within_sla,
        -- Exceeded SLA: deadline passed and not yet in terminal state
        CASE
            WHEN av.sla_deadline IS NOT NULL
                 AND NOW() > av.sla_deadline
                 AND va.status NOT IN ('remediated', 'false_positive')
            THEN TRUE
            ELSE FALSE
        END                         AS currently_overdue
    FROM vulnerability_management.applicable_vulnerabilities av
    -- Include only correlations that generated at least one alert
    JOIN vulnerability_management.vulnerability_alerts va
        ON va.applicable_vulnerability_id = av.id
    WHERE av.criticality_tier IS NOT NULL
)
SELECT
    criticality_tier,
    COUNT(*)                                            AS total_alerts,
    COUNT(*) FILTER (WHERE alert_status = 'remediated')             AS total_remediated,
    COUNT(*) FILTER (WHERE remediated_within_sla = TRUE)            AS within_sla,
    COUNT(*) FILTER (WHERE alert_status = 'remediated'
                     AND remediated_within_sla = FALSE)             AS exceeded_sla,
    COUNT(*) FILTER (WHERE currently_overdue = TRUE)                AS currently_overdue,
    COUNT(*) FILTER (WHERE alert_status = 'false_positive')         AS false_positives,
    COUNT(*) FILTER (WHERE alert_status NOT IN ('remediated','false_positive')) AS pending,
    -- SLA compliance % = within_sla / total_remediated (NULL-safe)
    CASE
        WHEN COUNT(*) FILTER (WHERE alert_status = 'remediated') = 0 THEN NULL
        ELSE ROUND(
            100.0 * COUNT(*) FILTER (WHERE remediated_within_sla = TRUE)
                  / NULLIF(COUNT(*) FILTER (WHERE alert_status = 'remediated'), 0),
            2
        )
    END                                                             AS compliance_pct,
    -- Average hours to remediate (MTTR per tier)
    ROUND(
        CAST(
            AVG(
                EXTRACT(EPOCH FROM (remediation_completed_at - sent_at)) / 3600.0
            ) FILTER (WHERE alert_status = 'remediated')
        AS NUMERIC),
        2
    )                                                               AS avg_mttr_hours
FROM alert_state
GROUP BY criticality_tier
ORDER BY
    CASE criticality_tier
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH'     THEN 2
        WHEN 'MEDIUM'   THEN 3
        WHEN 'LOW'      THEN 4
        ELSE 5
    END;

COMMENT ON VIEW vulnerability_management.v_sla_compliance_metrics IS
    'Aggregated SLA compliance metrics per criticality_tier: total, within_sla, exceeded_sla, compliance_pct, avg_mttr_hours.';

-- =============================================================================
-- GRANT minimum required privileges to n8n application user
-- The user is created by Docker via POSTGRES_USER env var; we grant schema usage
-- and full table-level access here so the schema init is self-contained.
-- =============================================================================
DO $$
BEGIN
    -- Only grant if the role exists (idempotent)
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user) THEN
        EXECUTE format(
            'GRANT USAGE ON SCHEMA vulnerability_management TO %I',
            current_user
        );
        EXECUTE format(
            'GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA vulnerability_management TO %I',
            current_user
        );
        EXECUTE format(
            'GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA vulnerability_management TO %I',
            current_user
        );
    END IF;
END;
$$;

-- =============================================================================
-- End of schema
-- =============================================================================
