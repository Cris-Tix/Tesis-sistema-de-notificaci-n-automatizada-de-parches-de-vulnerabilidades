from __future__ import annotations

import os
from datetime import date, datetime
from decimal import Decimal
from typing import Optional

import psycopg2
import psycopg2.errors
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

app = FastAPI(title="VulnPatchNotifier API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _conn():
    conn = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        dbname=os.getenv("POSTGRES_DB", ""),
        user=os.getenv("POSTGRES_USER", ""),
        password=os.getenv("POSTGRES_PASSWORD", ""),
        options="-c search_path=vulnerability_management,public",
    )
    conn.cursor_factory = psycopg2.extras.RealDictCursor
    return conn


def _j(obj: object) -> object:
    """Recursively make psycopg2 result JSON-serializable."""
    if isinstance(obj, dict):
        return {k: _j(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_j(v) for v in obj]
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    return obj


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/api/health")
def health():
    try:
        conn = _conn()
        conn.close()
        return {"status": "ok", "db": "connected"}
    except Exception as exc:
        return {"status": "error", "db": str(exc)}


# ── KPIs ──────────────────────────────────────────────────────────────────────

@app.get("/api/kpis")
def kpis():
    conn = _conn()
    try:
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) AS n FROM cves")
        total_cves = cur.fetchone()["n"]

        cur.execute(
            "SELECT COUNT(*) AS n FROM applicable_vulnerabilities "
            "WHERE criticality_tier = 'CRITICAL'"
        )
        critical_vulns = cur.fetchone()["n"]

        cur.execute(
            "SELECT COUNT(*) AS n FROM vulnerability_alerts "
            "WHERE status NOT IN ('remediated', 'false_positive')"
        )
        pending_alerts = cur.fetchone()["n"]

        cur.execute(
            "SELECT COALESCE(SUM(within_sla), 0) AS ws, "
            "COALESCE(SUM(total_remediated), 0) AS tr "
            "FROM v_sla_compliance_metrics"
        )
        row = cur.fetchone()
        ws, tr = int(row["ws"]), int(row["tr"])
        sla_pct = round(100.0 * ws / tr, 1) if tr else None

        return {
            "total_cves": int(total_cves),
            "critical_vulnerabilities": int(critical_vulns),
            "pending_alerts": int(pending_alerts),
            "sla_compliance_pct": sla_pct,
        }
    finally:
        conn.close()


# ── Vulnerabilities ───────────────────────────────────────────────────────────

@app.get("/api/vulnerabilities")
def vulnerabilities(
    tier: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
):
    conn = _conn()
    try:
        cur = conn.cursor()
        offset = (page - 1) * limit
        params: list = []
        where = "WHERE 1=1"
        if tier:
            where += " AND criticality_tier = %s"
            params.append(tier)

        cur.execute(
            f"SELECT COUNT(*) AS n FROM v_applicable_vulnerabilities_full {where}",
            params,
        )
        total = int(cur.fetchone()["n"])

        cur.execute(
            f"SELECT * FROM v_applicable_vulnerabilities_full {where} "
            "LIMIT %s OFFSET %s",
            params + [limit, offset],
        )
        items = [dict(r) for r in cur.fetchall()]
        return _j({"total": total, "page": page, "limit": limit, "items": items})
    finally:
        conn.close()


@app.get("/api/vulnerabilities/distribution")
def distribution():
    conn = _conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT criticality_tier, COUNT(*) AS count "
            "FROM applicable_vulnerabilities "
            "WHERE criticality_tier IS NOT NULL "
            "GROUP BY criticality_tier "
            "ORDER BY CASE criticality_tier "
            "WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 "
            "WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 END"
        )
        return _j([dict(r) for r in cur.fetchall()])
    finally:
        conn.close()


# ── Software Inventory (CRUD) ─────────────────────────────────────────────────

@app.get("/api/inventory")
def inventory_list(
    page: int = Query(1, ge=1),
    limit: int = Query(25, ge=1, le=100),
    search: Optional[str] = Query(None),
):
    conn = _conn()
    try:
        cur = conn.cursor()
        offset = (page - 1) * limit
        params: list = []
        where = "WHERE 1=1"
        if search:
            where += (
                " AND (vendor ILIKE %s OR product ILIKE %s "
                "OR asset_name ILIKE %s OR cpe_uri ILIKE %s)"
            )
            params.extend([f"%{search}%"] * 4)

        cur.execute(f"SELECT COUNT(*) AS n FROM software_inventory {where}", params)
        total = int(cur.fetchone()["n"])

        cur.execute(
            f"SELECT * FROM software_inventory {where} "
            "ORDER BY CASE criticality "
            "WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 "
            "WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 END, asset_name "
            "LIMIT %s OFFSET %s",
            params + [limit, offset],
        )
        items = [dict(r) for r in cur.fetchall()]
        return _j({"total": total, "page": page, "limit": limit, "items": items})
    finally:
        conn.close()


class _InvBody(BaseModel):
    cpe_uri: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    asset_name: Optional[str] = None
    ip_address: Optional[str] = None
    criticality: str
    exposed_to_internet: bool = False
    owner_team: Optional[str] = None
    notes: Optional[str] = None


@app.post("/api/inventory", status_code=201)
def inventory_create(body: _InvBody):
    conn = _conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO software_inventory "
            "(cpe_uri,vendor,product,version,asset_name,ip_address,"
            "criticality,exposed_to_internet,owner_team,notes) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
            (
                body.cpe_uri,
                body.vendor or None,
                body.product or None,
                body.version or None,
                body.asset_name or None,
                body.ip_address or None,
                body.criticality,
                body.exposed_to_internet,
                body.owner_team or None,
                body.notes or None,
            ),
        )
        conn.commit()
        return _j(dict(cur.fetchone()))
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise HTTPException(400, "CPE URI ya existe en el inventario")
    except psycopg2.errors.CheckViolation as exc:
        conn.rollback()
        raise HTTPException(400, f"Valor inválido: {exc.pgerror}")
    except Exception as exc:
        conn.rollback()
        raise HTTPException(500, str(exc))
    finally:
        conn.close()


@app.put("/api/inventory/{item_id}")
def inventory_update(item_id: int, body: _InvBody):
    conn = _conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE software_inventory SET "
            "cpe_uri=%s,vendor=%s,product=%s,version=%s,asset_name=%s,"
            "ip_address=%s,criticality=%s,exposed_to_internet=%s,"
            "owner_team=%s,notes=%s WHERE id=%s RETURNING *",
            (
                body.cpe_uri,
                body.vendor or None,
                body.product or None,
                body.version or None,
                body.asset_name or None,
                body.ip_address or None,
                body.criticality,
                body.exposed_to_internet,
                body.owner_team or None,
                body.notes or None,
                item_id,
            ),
        )
        conn.commit()
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Asset no encontrado")
        return _j(dict(row))
    except HTTPException:
        raise
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise HTTPException(400, "CPE URI ya existe en el inventario")
    except psycopg2.errors.CheckViolation as exc:
        conn.rollback()
        raise HTTPException(400, f"Valor inválido: {exc.pgerror}")
    except Exception as exc:
        conn.rollback()
        raise HTTPException(500, str(exc))
    finally:
        conn.close()


@app.delete("/api/inventory/{item_id}", status_code=204)
def inventory_delete(item_id: int):
    conn = _conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM software_inventory WHERE id=%s RETURNING id", (item_id,)
        )
        conn.commit()
        if not cur.fetchone():
            raise HTTPException(404, "Asset no encontrado")
        return Response(status_code=204)
    except HTTPException:
        raise
    except psycopg2.errors.ForeignKeyViolation:
        conn.rollback()
        raise HTTPException(
            409, "No se puede eliminar: el asset tiene vulnerabilidades asociadas"
        )
    except Exception as exc:
        conn.rollback()
        raise HTTPException(500, str(exc))
    finally:
        conn.close()


# ── Audit Log ─────────────────────────────────────────────────────────────────

@app.get("/api/audit-log")
def audit_log(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    workflow: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
):
    conn = _conn()
    try:
        cur = conn.cursor()
        offset = (page - 1) * limit
        params: list = []
        where = "WHERE 1=1"
        if workflow:
            where += " AND workflow_name = %s"
            params.append(workflow)
        if status:
            where += " AND status = %s"
            params.append(status)

        cur.execute(f"SELECT COUNT(*) AS n FROM audit_log {where}", params)
        total = int(cur.fetchone()["n"])

        cur.execute(
            f"SELECT * FROM audit_log {where} "
            "ORDER BY executed_at DESC LIMIT %s OFFSET %s",
            params + [limit, offset],
        )
        items = [dict(r) for r in cur.fetchall()]
        return _j({"total": total, "page": page, "limit": limit, "items": items})
    finally:
        conn.close()


# ── System Status ─────────────────────────────────────────────────────────────

@app.get("/api/system-status")
def system_status():
    conn = _conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT DISTINCT ON (workflow_name) "
            "workflow_name, status, executed_at, execution_time_ms "
            "FROM audit_log ORDER BY workflow_name, executed_at DESC"
        )
        workflows = [dict(r) for r in cur.fetchall()]

        cur.execute(
            "SELECT COUNT(*) AS n FROM applicable_vulnerabilities "
            "WHERE criticality_tier IS NOT NULL"
        )
        active_vulns = int(cur.fetchone()["n"])

        return _j(
            {
                "workflows": workflows,
                "active_vulnerabilities": active_vulns,
                "db_status": "connected",
            }
        )
    finally:
        conn.close()
