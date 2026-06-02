-- =============================================================================
-- VulnPatchNotifier — Seed Data
-- PostgreSQL 16 / Schema: vulnerability_management
-- Run after schema.sql. Safe to re-run (ON CONFLICT DO NOTHING).
-- =============================================================================

SET search_path TO vulnerability_management, public;

-- =============================================================================
-- software_inventory — 8 assets across all criticality tiers
-- =============================================================================
INSERT INTO vulnerability_management.software_inventory
    (cpe_uri, vendor, product, version, asset_name, ip_address, criticality, exposed_to_internet, owner_team, notes)
VALUES
    -- CRITICAL assets
    ('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
     'Apache', 'Log4j', '2.14.1',
     'api-gateway-prod', '10.0.1.10', 'CRITICAL', TRUE, 'platform',
     'Public-facing API gateway. Log4Shell vector.'),

    ('cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*',
     'OpenSSL', 'OpenSSL', '3.0.0',
     'auth-service-prod', '10.0.1.20', 'CRITICAL', FALSE, 'security',
     'Internal auth service. OpenSSL 3.x range.'),

    -- HIGH assets
    ('cpe:2.3:a:nginx:nginx:1.22.0:*:*:*:*:*:*:*',
     'nginx', 'nginx', '1.22.0',
     'web-frontend-prod', '10.0.2.10', 'HIGH', TRUE, 'frontend',
     'Customer-facing web server.'),

    ('cpe:2.3:a:postgresql:postgresql:14.5:*:*:*:*:*:*:*',
     'PostgreSQL', 'PostgreSQL', '14.5',
     'db-primary-prod', '10.0.2.20', 'HIGH', FALSE, 'data',
     'Primary production database.'),

    -- MEDIUM assets
    ('cpe:2.3:a:python:python:3.9.0:*:*:*:*:*:*:*',
     'Python', 'Python', '3.9.0',
     'ml-pipeline-staging', '10.0.3.10', 'MEDIUM', FALSE, 'data-science',
     'ML training pipeline. Staging environment.'),

    ('cpe:2.3:a:redis:redis:7.0.0:*:*:*:*:*:*:*',
     'Redis', 'Redis', '7.0.0',
     'cache-layer-prod', '10.0.3.20', 'MEDIUM', FALSE, 'platform',
     'Session and queue cache.'),

    -- LOW assets
    ('cpe:2.3:a:curl:curl:7.85.0:*:*:*:*:*:*:*',
     'curl', 'curl', '7.85.0',
     'batch-jobs-dev', '10.0.4.10', 'LOW', FALSE, 'devops',
     'Internal batch job runner. Dev environment.'),

    ('cpe:2.3:a:jquery:jquery:3.5.1:*:*:*:*:*:*:*',
     'jQuery', 'jQuery', '3.5.1',
     'admin-panel-internal', '10.0.4.20', 'LOW', FALSE, 'frontend',
     'Internal admin UI. Not internet-exposed.')

ON CONFLICT (cpe_uri) DO NOTHING;

-- =============================================================================
-- cves — 10 CVEs covering all severity bands + KEV + temporal/v2 fallback cases
-- =============================================================================
INSERT INTO vulnerability_management.cves
    (cve_id, description, cvss_v3_base_score, cvss_v3_vector, cvss_v3_severity,
     cvss_v2_base_score, cwe_id, published_date, last_modified_date,
     configurations, patch_references, status)
VALUES
    -- CRITICAL — Log4Shell (KEV listed)
    ('CVE-2021-44228',
     'Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
     10.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'CRITICAL',
     9.3, 'CWE-917',
     '2021-12-10 00:00:00', '2023-04-03 00:00:00',
     '{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}]}]}'::jsonb,
     '[{"url":"https://logging.apache.org/log4j/2.x/security.html","source":"Apache"},{"url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog","source":"CISA KEV"}]'::jsonb,
     'prioritized'),

    -- CRITICAL — OpenSSL infinite loop
    ('CVE-2022-0778',
     'The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop forever for non-prime moduli. Affects OpenSSL 1.0.2, 1.1.1, and 3.0.',
     7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'HIGH',
     5.0, 'CWE-835',
     '2022-03-15 00:00:00', '2023-02-28 00:00:00',
     '{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*"}]}]}'::jsonb,
     '[{"url":"https://www.openssl.org/news/secadv/20220315.txt","source":"OpenSSL"}]'::jsonb,
     'prioritized'),

    -- HIGH — nginx HTTP/2 rapid reset
    ('CVE-2023-44487',
     'The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.',
     7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'HIGH',
     NULL, 'CWE-400',
     '2023-10-10 00:00:00', '2023-11-05 00:00:00',
     '{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:nginx:nginx:1.22.0:*:*:*:*:*:*:*"}]}]}'::jsonb,
     '[{"url":"https://nginx.org/en/CHANGES","source":"nginx"},{"url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog","source":"CISA KEV"}]'::jsonb,
     'prioritized'),

    -- HIGH — PostgreSQL privilege escalation
    ('CVE-2023-2454',
     'Row security policies disabling is triggered incorrectly for queries on temporarily-dropped relations. An authenticated attacker with CREATE privilege could exploit this to read rows they should not have access to.',
     7.2, 'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', 'HIGH',
     NULL, 'CWE-284',
     '2023-05-11 00:00:00', '2023-06-15 00:00:00',
     '{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:postgresql:postgresql:14.5:*:*:*:*:*:*:*"}]}]}'::jsonb,
     '[{"url":"https://www.postgresql.org/about/news/postgresql-154-149-1312-1216-and-1121-released-2637/","source":"PostgreSQL"}]'::jsonb,
     'prioritized'),

    -- MEDIUM — Python tarball path traversal
    ('CVE-2023-24329',
     'An issue in the urllib.parse component of Python before 3.11.4 allows attackers to bypass blocklisting methods by supplying a URL that starts with blank characters.',
     7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', 'HIGH',
     NULL, 'CWE-20',
     '2023-02-17 00:00:00', '2023-07-10 00:00:00',
     '{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:python:python:3.9.0:*:*:*:*:*:*:*"}]}]}'::jsonb,
     '[{"url":"https://python-security.readthedocs.io/vuln/cve-2023-24329.html","source":"Python Security"}]'::jsonb,
     'correlated'),

    -- MEDIUM — Redis EVAL sandbox escape
    ('CVE-2022-24736',
     'An attacker attempting to load a specially crafted Lua script can cause NULL pointer dereference which will result with a crash of the redis-server process.',
     5.5, 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H', 'MEDIUM',
     NULL, 'CWE-476',
     '2022-04-27 00:00:00', '2022-06-02 00:00:00',
     '{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:redis:redis:7.0.0:*:*:*:*:*:*:*"}]}]}'::jsonb,
     '[{"url":"https://github.com/redis/redis/security/advisories/GHSA-647x-m9gh-4jcq","source":"GitHub"}]'::jsonb,
     'correlated'),

    -- LOW — curl cookie injection
    ('CVE-2023-38545',
     'A heap-based buffer overflow in the SOCKS5 proxy handshake. When curl is given a very long hostname to resolve via a SOCKS5 proxy, curl passes on the hostname to the proxy, which can cause a buffer overflow.',
     9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'CRITICAL',
     NULL, 'CWE-787',
     '2023-10-11 00:00:00', '2023-11-01 00:00:00',
     '{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:curl:curl:7.85.0:*:*:*:*:*:*:*"}]}]}'::jsonb,
     '[{"url":"https://curl.se/docs/CVE-2023-38545.html","source":"curl"}]'::jsonb,
     'correlated'),

    -- LOW — jQuery XSS
    ('CVE-2020-11023',
     'In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing <option> elements from untrusted sources, even after sanitizing it, to one of jQuery''s DOM manipulation methods may execute untrusted code.',
     6.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 'MEDIUM',
     NULL, 'CWE-79',
     '2020-04-29 00:00:00', '2023-01-12 00:00:00',
     '{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:jquery:jquery:3.5.1:*:*:*:*:*:*:*"}]}]}'::jsonb,
     '[{"url":"https://github.com/jquery/jquery/security/advisories/GHSA-jpcq-cgw6-v4j6","source":"GitHub"}]'::jsonb,
     'unprocessed'),

    -- Edge case: CVSS v3 NULL — only v2 available (older CVE)
    ('CVE-2019-11358',
     'jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution.',
     NULL, NULL, NULL,
     6.1, 'CWE-79',
     '2019-04-20 00:00:00', '2022-11-07 00:00:00',
     '{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:jquery:jquery:3.5.1:*:*:*:*:*:*:*"}]}]}'::jsonb,
     '[{"url":"https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/","source":"jQuery Blog"}]'::jsonb,
     'unprocessed'),

    -- Edge case: no CPE configurations — cannot be correlated
    ('CVE-2024-99999',
     'Hypothetical unstructured advisory: vendor published a security bulletin without CPE data. Used to verify that the correlation workflow correctly skips CVEs with NULL configurations.',
     8.1, 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 'HIGH',
     NULL, 'CWE-200',
     '2024-01-15 00:00:00', NULL,
     NULL,
     NULL,
     'unprocessed')

ON CONFLICT (cve_id) DO NOTHING;

-- =============================================================================
-- applicable_vulnerabilities — correlations with risk scores
-- Covers: all criticality tiers, SLA overdue, SLA pending, no risk score yet
-- =============================================================================
INSERT INTO vulnerability_management.applicable_vulnerabilities
    (cve_id, software_id, risk_score, criticality_tier, sla_deadline,
     correlation_confidence, shodan_exposed, kev_listed, exploit_available)
VALUES
    -- CVE-2021-44228 (Log4Shell) ↔ api-gateway-prod — CRITICAL, KEV, Shodan exposed
    (
        (SELECT id FROM vulnerability_management.cves WHERE cve_id = 'CVE-2021-44228'),
        (SELECT id FROM vulnerability_management.software_inventory WHERE asset_name = 'api-gateway-prod'),
        9.80, 'CRITICAL',
        NOW() - INTERVAL '48 hours',   -- deliberately overdue (SLA was 24h)
        'HIGH', TRUE, TRUE, TRUE
    ),

    -- CVE-2022-0778 (OpenSSL loop) ↔ auth-service-prod — HIGH
    (
        (SELECT id FROM vulnerability_management.cves WHERE cve_id = 'CVE-2022-0778'),
        (SELECT id FROM vulnerability_management.software_inventory WHERE asset_name = 'auth-service-prod'),
        7.60, 'HIGH',
        NOW() + INTERVAL '24 hours',   -- within SLA window
        'HIGH', FALSE, FALSE, FALSE
    ),

    -- CVE-2023-44487 (HTTP/2 Rapid Reset) ↔ web-frontend-prod — HIGH, KEV, Shodan exposed
    (
        (SELECT id FROM vulnerability_management.cves WHERE cve_id = 'CVE-2023-44487'),
        (SELECT id FROM vulnerability_management.software_inventory WHERE asset_name = 'web-frontend-prod'),
        8.20, 'HIGH',
        NOW() - INTERVAL '12 hours',   -- overdue
        'HIGH', TRUE, TRUE, TRUE
    ),

    -- CVE-2023-2454 (PostgreSQL) ↔ db-primary-prod — HIGH
    (
        (SELECT id FROM vulnerability_management.cves WHERE cve_id = 'CVE-2023-2454'),
        (SELECT id FROM vulnerability_management.software_inventory WHERE asset_name = 'db-primary-prod'),
        7.10, 'HIGH',
        NOW() + INTERVAL '60 hours',
        'MEDIUM', FALSE, FALSE, FALSE
    ),

    -- CVE-2023-24329 (Python) ↔ ml-pipeline-staging — MEDIUM
    (
        (SELECT id FROM vulnerability_management.cves WHERE cve_id = 'CVE-2023-24329'),
        (SELECT id FROM vulnerability_management.software_inventory WHERE asset_name = 'ml-pipeline-staging'),
        5.40, 'MEDIUM',
        NOW() + INTERVAL '5 days',
        'MEDIUM', FALSE, FALSE, FALSE
    ),

    -- CVE-2022-24736 (Redis) ↔ cache-layer-prod — MEDIUM
    (
        (SELECT id FROM vulnerability_management.cves WHERE cve_id = 'CVE-2022-24736'),
        (SELECT id FROM vulnerability_management.software_inventory WHERE asset_name = 'cache-layer-prod'),
        5.10, 'MEDIUM',
        NOW() + INTERVAL '6 days',
        'HIGH', FALSE, FALSE, FALSE
    ),

    -- CVE-2023-38545 (curl SOCKS5 heap overflow) ↔ batch-jobs-dev — CRITICAL score but LOW asset
    (
        (SELECT id FROM vulnerability_management.cves WHERE cve_id = 'CVE-2023-38545'),
        (SELECT id FROM vulnerability_management.software_inventory WHERE asset_name = 'batch-jobs-dev'),
        6.20, 'MEDIUM',       -- risk score lowered by asset criticality weight
        NOW() + INTERVAL '7 days',
        'HIGH', FALSE, FALSE, TRUE
    ),

    -- CVE-2020-11023 (jQuery XSS) ↔ admin-panel-internal — LOW
    (
        (SELECT id FROM vulnerability_management.cves WHERE cve_id = 'CVE-2020-11023'),
        (SELECT id FROM vulnerability_management.software_inventory WHERE asset_name = 'admin-panel-internal'),
        3.80, 'LOW',
        NOW() + INTERVAL '29 days',
        'LOW', FALSE, FALSE, FALSE
    ),

    -- Edge case: correlated but risk_score not yet calculated (workflow-prioritization pending)
    (
        (SELECT id FROM vulnerability_management.cves WHERE cve_id = 'CVE-2019-11358'),
        (SELECT id FROM vulnerability_management.software_inventory WHERE asset_name = 'admin-panel-internal'),
        NULL, NULL, NULL,
        'LOW', FALSE, FALSE, FALSE
    )

ON CONFLICT (cve_id, software_id) DO NOTHING;

-- =============================================================================
-- vulnerability_alerts — one per correlation, covering all state machine states
-- =============================================================================
INSERT INTO vulnerability_management.vulnerability_alerts
    (applicable_vulnerability_id, alert_type, recipient, subject, message_body,
     sent_at, status, acknowledged_at, acknowledged_by,
     remediation_started_at, remediation_completed_at, remediation_notes,
     patch_version, verification_method)
VALUES
    -- Log4Shell alert — ESCALATED (overdue, still in_progress)
    (
        (SELECT av.id FROM vulnerability_management.applicable_vulnerabilities av
         JOIN vulnerability_management.cves c ON c.id = av.cve_id
         WHERE c.cve_id = 'CVE-2021-44228'),
        'EMAIL', 'security-team@company.com',
        '[CRITICAL] CVE-2021-44228 Log4Shell detected on api-gateway-prod',
        'Risk score: 9.80. SLA deadline has passed. Immediate action required.',
        NOW() - INTERVAL '72 hours',
        'in_progress',
        NOW() - INTERVAL '60 hours', 'j.smith',
        NOW() - INTERVAL '50 hours', NULL,
        'Upgrade in progress to Log4j 2.17.1. Rollback plan ready.',
        NULL, NULL
    ),

    -- Log4Shell Slack duplicate alert
    (
        (SELECT av.id FROM vulnerability_management.applicable_vulnerabilities av
         JOIN vulnerability_management.cves c ON c.id = av.cve_id
         WHERE c.cve_id = 'CVE-2021-44228'),
        'SLACK', '#security-alerts',
        NULL,
        'CRITICAL CVE-2021-44228 on api-gateway-prod. SLA overdue. CC: @platform-team',
        NOW() - INTERVAL '72 hours',
        'in_progress',
        NOW() - INTERVAL '60 hours', 'j.smith',
        NOW() - INTERVAL '50 hours', NULL,
        NULL, NULL, NULL
    ),

    -- OpenSSL alert — acknowledged, remediation not yet started
    (
        (SELECT av.id FROM vulnerability_management.applicable_vulnerabilities av
         JOIN vulnerability_management.cves c ON c.id = av.cve_id
         WHERE c.cve_id = 'CVE-2022-0778'),
        'EMAIL', 'security-team@company.com',
        '[HIGH] CVE-2022-0778 OpenSSL 3.0.0 on auth-service-prod',
        'Risk score: 7.60. SLA deadline: 72 hours from alert.',
        NOW() - INTERVAL '6 hours',
        'acknowledged',
        NOW() - INTERVAL '4 hours', 'a.garcia',
        NULL, NULL, NULL, NULL, NULL
    ),

    -- HTTP/2 Rapid Reset — notified only (fresh, no ack yet)
    (
        (SELECT av.id FROM vulnerability_management.applicable_vulnerabilities av
         JOIN vulnerability_management.cves c ON c.id = av.cve_id
         WHERE c.cve_id = 'CVE-2023-44487'),
        'SLACK', '#security-alerts',
        NULL,
        'HIGH CVE-2023-44487 HTTP/2 Rapid Reset on web-frontend-prod. SLA: 72h.',
        NOW() - INTERVAL '14 hours',
        'notified',
        NULL, NULL, NULL, NULL, NULL, NULL, NULL
    ),

    -- PostgreSQL — fully remediated within SLA
    (
        (SELECT av.id FROM vulnerability_management.applicable_vulnerabilities av
         JOIN vulnerability_management.cves c ON c.id = av.cve_id
         WHERE c.cve_id = 'CVE-2023-2454'),
        'EMAIL', 'data-team@company.com',
        '[HIGH] CVE-2023-2454 PostgreSQL 14.5 on db-primary-prod',
        'Risk score: 7.10. SLA deadline: 72 hours from alert.',
        NOW() - INTERVAL '48 hours',
        'remediated',
        NOW() - INTERVAL '46 hours', 'r.chen',
        NOW() - INTERVAL '44 hours',
        NOW() - INTERVAL '10 hours',
        'Upgraded to PostgreSQL 14.9. Verified via pg_version query and regression tests.',
        '14.9', 'SQL query + integration tests'
    ),

    -- Python urllib — notified
    (
        (SELECT av.id FROM vulnerability_management.applicable_vulnerabilities av
         JOIN vulnerability_management.cves c ON c.id = av.cve_id
         WHERE c.cve_id = 'CVE-2023-24329'),
        'EMAIL', 'data-science@company.com',
        '[MEDIUM] CVE-2023-24329 Python 3.9.0 on ml-pipeline-staging',
        'Risk score: 5.40. SLA deadline: 7 days.',
        NOW() - INTERVAL '2 hours',
        'notified',
        NULL, NULL, NULL, NULL, NULL, NULL, NULL
    ),

    -- Redis — false positive (internal-only, mitigating control in place)
    (
        (SELECT av.id FROM vulnerability_management.applicable_vulnerabilities av
         JOIN vulnerability_management.cves c ON c.id = av.cve_id
         WHERE c.cve_id = 'CVE-2022-24736'),
        'SLACK', '#security-alerts',
        NULL,
        'MEDIUM CVE-2022-24736 Redis 7.0.0 on cache-layer-prod.',
        NOW() - INTERVAL '5 days',
        'false_positive',
        NOW() - INTERVAL '4 days', 'a.garcia',
        NULL, NULL,
        'Redis is not accessible from outside the VPC and Lua scripting is disabled. Accepted as false positive.',
        NULL, NULL
    ),

    -- curl — notified
    (
        (SELECT av.id FROM vulnerability_management.applicable_vulnerabilities av
         JOIN vulnerability_management.cves c ON c.id = av.cve_id
         WHERE c.cve_id = 'CVE-2023-38545'),
        'EMAIL', 'devops@company.com',
        '[MEDIUM] CVE-2023-38545 curl 7.85.0 on batch-jobs-dev',
        'Risk score: 6.20 (asset criticality LOW reduces tier to MEDIUM). SLA: 7 days.',
        NOW() - INTERVAL '1 hour',
        'notified',
        NULL, NULL, NULL, NULL, NULL, NULL, NULL
    ),

    -- jQuery — notified (LOW tier, long SLA)
    (
        (SELECT av.id FROM vulnerability_management.applicable_vulnerabilities av
         JOIN vulnerability_management.cves c ON c.id = av.cve_id
         WHERE c.cve_id = 'CVE-2020-11023'),
        'EMAIL', 'frontend@company.com',
        '[LOW] CVE-2020-11023 jQuery 3.5.1 on admin-panel-internal',
        'Risk score: 3.80. SLA deadline: 30 days.',
        NOW() - INTERVAL '1 day',
        'notified',
        NULL, NULL, NULL, NULL, NULL, NULL, NULL
    )

ON CONFLICT DO NOTHING;

-- =============================================================================
-- audit_log — workflow execution history (one run per workflow, mixed results)
-- =============================================================================
INSERT INTO vulnerability_management.audit_log
    (workflow_name, execution_id, status, records_processed, error_message, execution_time_ms, executed_at)
VALUES
    ('workflow-collection',    'exec-col-001', 'SUCCESS', 142, NULL,              4823, NOW() - INTERVAL '25 hours'),
    ('workflow-collection',    'exec-col-002', 'PARTIAL',  98,
     'NVD API rate limit hit after 98 records. Retry scheduled.',                 7201, NOW() - INTERVAL '1 hour'),
    ('workflow-correlation',   'exec-cor-001', 'SUCCESS',  89, NULL,              2150, NOW() - INTERVAL '24 hours 55 minutes'),
    ('workflow-prioritization','exec-pri-001', 'SUCCESS',  89, NULL,              1388, NOW() - INTERVAL '24 hours 50 minutes'),
    ('workflow-alerts',        'exec-ale-001', 'SUCCESS',   9, NULL,               945, NOW() - INTERVAL '24 hours 45 minutes'),
    ('workflow-monitoring',    'exec-mon-001', 'SUCCESS',   2,
     NULL,                                                                         312, NOW() - INTERVAL '2 hours'),
    ('workflow-monitoring',    'exec-mon-002', 'FAILED',    0,
     'Connection timeout to PostgreSQL after 30s. Check DB health.',              30012, NOW() - INTERVAL '1 hour')

ON CONFLICT DO NOTHING;
