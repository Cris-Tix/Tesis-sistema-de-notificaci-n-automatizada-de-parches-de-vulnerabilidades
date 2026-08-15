# VulnPatchNotifier

Sistema de notificación automatizada de parches de vulnerabilidades mediante integración de NVD API, Shodan, CISA KEV y motor de orquestación n8n con base de datos PostgreSQL y tracking de remediación.

## 🚀 Instalación y ejecución

### Arquitectura de servicios

| Servicio          | Descripción                                        | Puerto host          |
|--------------------|-----------------------------------------------------|----------------------|
| `postgres`         | Base de datos (esquema `vulnerability_management`)  | `5433` → 5432 interno |
| `redis`            | Cola de ejecución para n8n (no expuesto)            | —                    |
| `n8n`               | Motor de orquestación (5 workflows)                 | `5678`               |
| `vuln-api`         | Backend del dashboard                               | `8000`               |
| `vuln-dashboard`   | Frontend React (Nginx)                              | `3001`               |
| `landing`          | Landing page estática (Nginx)                       | `3002`               |

### Requisitos previos

- Docker y Docker Compose
- API Key de [NVD](https://nvd.nist.gov/developers/request-an-api-key)
- API Key de [Shodan](https://account.shodan.io/)
- Cuenta SMTP (Gmail con App Password, Mailtrap, u otro proveedor)
- Webhook de Slack (opcional, hay uno de escalación separado)

### 1. Clonar el repositorio

```bash
git clone https://github.com/Cris-Tix/Tesis-sistema-de-notificacion-automatizada-de-parches-de-vulnerabilidades.git
cd Tesis-sistema-de-notificacion-automatizada-de-parches-de-vulnerabilidades
```

### 2. Configurar variables de entorno

Copiá el archivo de ejemplo:

```bash
cp .env.example .env
```

Completá en `.env`:

```env
# PostgreSQL
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=vulnerability_mgmt
POSTGRES_USER=postgres
POSTGRES_PASSWORD=tu_password_seguro

# n8n
N8N_HOST=localhost
N8N_PORT=5678
N8N_PROTOCOL=http
N8N_WEBHOOK_URL=http://localhost:5678/
N8N_BASIC_AUTH_USER=admin
N8N_BASIC_AUTH_PASSWORD=tu_password_n8n
GENERIC_TIMEZONE=UTC
TZ=UTC

# APIs externas
NVD_API_KEY=tu_api_key_nvd          # https://nvd.nist.gov/developers/request-an-api-key
SHODAN_API_KEY=tu_api_key_shodan    # https://account.shodan.io/
CISA_KEV_CACHE_TTL_HOURS=24

# SMTP (ejemplo con Gmail; también funciona con Mailtrap u otro proveedor)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tu_email@gmail.com
SMTP_PASSWORD=tu_app_password        # usar App Password de Gmail, no la contraseña de la cuenta

# Destinos de alerta
SECURITY_TEAM_EMAIL=security@tuempresa.com
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
SLACK_WEBHOOK_ESCALATION=https://hooks.slack.com/services/...

# Cross-navegación entre landing y dashboard (opcional; estos son los valores por defecto)
DASHBOARD_URL=http://localhost:3001
LANDING_URL=http://localhost:3002
```

> `N8N_INTERNAL_URL` (usado por `vuln-api` para disparar workflows manualmente, ver más abajo) no requiere configuración: por defecto apunta a `http://n8n:5678`, el nombre del servicio en la red interna de Docker.

> **Nota:** `POSTGRES_HOST=postgres` corresponde a la red interna de Docker — n8n y `vuln-api` se conectan por el nombre del servicio, no por `localhost`. Para conectarte desde tu máquina (pgAdmin, DBeaver, psql) usá `localhost:5433` (ver más abajo).

### 3. Construir y levantar los contenedores

```bash
docker compose build
docker compose up -d
```

Esto construye las imágenes de `vuln-api`, `vuln-dashboard` y `landing` (Dockerfiles propios en `./dashboard/backend`, `./dashboard/frontend` y `./landing`) y descarga las imágenes oficiales de `postgres`, `redis` y `n8n`.

Verificá el estado de todos los servicios:

```bash
docker compose ps
```

El esquema SQL (`./db/schema.sql`) se ejecuta automáticamente en el primer arranque del contenedor de Postgres — no hace falta correrlo a mano.

Si querés cargar datos de ejemplo (`./db/seed.sql`), corré manualmente después del primer arranque — no se monta automáticamente como el schema:

```bash
docker compose exec -T postgres psql -U ${POSTGRES_USER} -d ${POSTGRES_DB} -f - < db/seed.sql
```

### 4. Importar los workflows en n8n

1. Accedé a `http://localhost:5678`
2. Iniciá sesión con `N8N_BASIC_AUTH_USER` / `N8N_BASIC_AUTH_PASSWORD`
3. Importá los 5 workflows JSON desde la carpeta `workflows/` (Collection, Correlation, Prioritization, Alerts, Monitoring)
4. Activá cada uno desde el toggle superior derecho

### 5. Acceder al dashboard y la landing

- Landing page: `http://localhost:3002`
- Dashboard: `http://localhost:3001` — Overview, **Inventario** (alta/edición/baja de assets, no solo lectura), Audit Log y **Workflows**. El backend (`vuln-api`) corre en `http://localhost:8000` (`/api/health` para chequear que esté vivo).

La sección **Workflows** del dashboard permite disparar manualmente cada una de las 5 etapas del pipeline ("Ejecutar ahora") además del cron/encadenado normal, y confirma el resultado sondeando `audit_log`. Cada workflow tiene su propio nodo Webhook Trigger (`collection-trigger`, `correlation-trigger`, `prioritization-trigger`, `alerts-trigger`, `monitoring-trigger`) — recordá que el workflow debe estar **activo** en n8n (paso 4) para que el webhook responda.

### Conectarse a la base de datos desde el host

Como Postgres mapea `5433` (no el `5432` estándar) al host, para conectarte desde tu máquina usá:

```bash
psql -h localhost -p 5433 -U tu_usuario -d tu_base
```

### Detener el entorno

```bash
docker compose down          # detiene contenedores, conserva datos
docker compose down -v       # ⚠️ también borra los volúmenes (postgres_data, n8n_data)
```

### Logs y troubleshooting

```bash
docker compose logs -f n8n
docker compose logs -f postgres
docker compose logs -f vuln-api
docker compose logs -f vuln-dashboard
docker compose logs -f landing
docker compose restart n8n
```

## 📄 Licencia

Proyecto Final Integrador — Tecnicatura Universitaria en Programación, UTN Facultad Regional Mendoza. Desarrollado por el grupo "Compila pero no corre".
