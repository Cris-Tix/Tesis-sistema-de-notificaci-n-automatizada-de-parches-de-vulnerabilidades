#!/bin/sh
# Generates env.js at container start from docker-compose env vars, so the
# dashboard's link back to the landing is not hardcoded to localhost and
# survives redeploys to another host. Runs via nginx's /docker-entrypoint.d/.
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
