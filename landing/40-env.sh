#!/bin/sh
# Generates env.js at container start from docker-compose env vars, so the
# landing's cross-links are not hardcoded to localhost and survive redeploys
# to another host. Runs via nginx's /docker-entrypoint.d/ before nginx starts.
set -e

: "${DASHBOARD_URL:=http://localhost:3001}"
: "${LANDING_URL:=http://localhost:3002}"

cat > /usr/share/nginx/html/env.js <<EOF
window.__ENV__ = {
  DASHBOARD_URL: "${DASHBOARD_URL}",
  LANDING_URL: "${LANDING_URL}"
};
EOF

echo "[40-env.sh] env.js -> DASHBOARD_URL=${DASHBOARD_URL} LANDING_URL=${LANDING_URL}"
