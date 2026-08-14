// Default runtime config. Overwritten at container start by /docker-entrypoint.d/40-env.sh
// from the DASHBOARD_URL / LANDING_URL environment variables injected by docker-compose.
window.__ENV__ = {
  DASHBOARD_URL: "http://localhost:3001",
  LANDING_URL: "http://localhost:3002"
};
