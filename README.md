
## FIX ERROR workflow-alerts
- Solución: limpiar las alertas del seed para poder probar

docker exec -i vuln_postgres psql -U postgres -d vulnerability_mgmt -c "
SET search_path TO vulnerability_management;
DELETE FROM vulnerability_alerts;
"