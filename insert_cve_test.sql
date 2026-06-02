INSERT INTO vulnerability_management.cves (
  cve_id, description, cvss_v3_base_score, cvss_v3_vector,
  cvss_v3_severity, published_date, configurations, status
) VALUES (
  'CVE-2024-7347',
  'nginx before 1.26.2 allows a worker process crash via a specially crafted MP4 file in the ngx_http_mp4_module.',
  5.5,
  'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H',
  'MEDIUM',
  '2024-08-14',
  '[{"nodes":[{"cpeMatch":[{"criteria":"cpe:2.3:a:nginx:nginx:1.22.0:*:*:*:*:*:*:*","vulnerable":true,"matchCriteriaId":"test-001"}],"operator":"OR","negate":false}]}]',
  'unprocessed'
) ON CONFLICT (cve_id) DO NOTHING;
