from fastapi import APIRouter, HTTPException, Query, Response, UploadFile, File
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from typing import Optional, List
import os

from app.database import get_db_connection, get_setting, set_setting, audit_log_event
from app.auth import authenticate_user, check_permission
from app.monitoring import monitoring_service
from app.detection import model_manager
from app.reports_gen import generate_pdf_report, generate_csv_report

router = APIRouter(prefix="/api")

# Pydantic Request Models
class LoginRequest(BaseModel):
    username: str
    password: str

class SettingsRequest(BaseModel):
    critical_threshold: int
    high_threshold: int
    monitor_interval: float
    ml_enabled: str
    selected_interface: Optional[str] = ""

class IncidentUpdateRequest(BaseModel):
    status: str
    description: Optional[str] = None

class AlertUpdateRequest(BaseModel):
    status: str

class SimulationRequest(BaseModel):
    scenario: Optional[str] = "Critical Event"

# 1. Authentication Endpoints
@router.post("/auth/login")
def login(req: LoginRequest):
    user = authenticate_user(req.username, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    return {"success": True, "user": user}

@router.post("/auth/logout")
def logout(username: str = Query("admin")):
    audit_log_event(username, "Logged out from web platform")
    return {"success": True}

# 2. Dashboard Telemetry & Chart Endpoints
@router.get("/dashboard/stats")
def get_dashboard_stats(source_type: Optional[str] = None):
    conn = get_db_connection()
    where_clause = ""
    params = []
    if source_type and source_type != "ALL":
        where_clause = "WHERE source_type = ?"
        params.append(source_type)

    stats = conn.execute(f"""
    SELECT
        COUNT(*) AS events,
        COUNT(DISTINCT device) AS devices,
        SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) AS critical,
        SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) AS high,
        SUM(CASE WHEN severity='MEDIUM' THEN 1 ELSE 0 END) AS medium,
        SUM(CASE WHEN severity='LOW' THEN 1 ELSE 0 END) AS low,
        COALESCE(AVG(risk), 0) AS avg_risk
    FROM events
    {where_clause}
    """, params).fetchone()

    recent_events = conn.execute(f"""
        SELECT * FROM events {where_clause} ORDER BY id DESC LIMIT 15
    """, params).fetchall()
    
    recent_list = [dict(r) for r in recent_events]
    mon_status = monitoring_service.get_status()
    ml_status = model_manager.get_status()

    inc_where = ""
    inc_params = []
    if source_type and source_type != "ALL":
        inc_where = "AND source_type = ?"
        inc_params.append(source_type)

    open_incidents = conn.execute(f"SELECT COUNT(*) FROM incidents WHERE status != 'RESOLVED' {inc_where}", inc_params).fetchone()[0]
    active_alerts = conn.execute(f"SELECT COUNT(*) FROM alerts WHERE status != 'ACKNOWLEDGED' AND status != 'RESOLVED' {inc_where}", inc_params).fetchone()[0]

    proto_rows = conn.execute(f"""
        SELECT protocol, COUNT(*) as cnt FROM events {where_clause} GROUP BY protocol
    """, params).fetchall()
    protocols = {r["protocol"]: r["cnt"] for r in proto_rows}

    return {
        "status": mon_status["mode"],
        "running": mon_status["running"],
        "packets_captured": mon_status["packets_captured"],
        "last_packet_time": mon_status.get("last_packet_time"),
        "selected_interface": mon_status.get("selected_interface"),
        "last_error": mon_status["last_error"],
        "events": stats["events"] or 0,
        "devices": stats["devices"] or 0,
        "critical": stats["critical"] or 0,
        "high": stats["high"] or 0,
        "medium": stats["medium"] or 0,
        "low": stats["low"] or 0,
        "open_incidents": open_incidents or 0,
        "active_alerts": active_alerts or 0,
        "protocols": protocols,
        "avg_risk": round(stats["avg_risk"] or 0, 1),
        "ml_status": ml_status,
        "recent_events": recent_list
    }

@router.get("/dashboard/risk-history")
def get_risk_history(source_type: Optional[str] = None):
    conn = get_db_connection()
    where_clause = ""
    params = []
    if source_type and source_type != "ALL":
        where_clause = "WHERE source_type = ?"
        params.append(source_type)

    rows = conn.execute(f"""
        SELECT timestamp, risk, traffic, packets, severity, source_type
        FROM events
        {where_clause}
        ORDER BY id DESC LIMIT 30
    """, params).fetchall()
    
    reversed_rows = list(reversed([dict(r) for r in rows]))
    
    labels = [r["timestamp"].split(" ")[-1] if " " in r["timestamp"] else r["timestamp"] for r in reversed_rows]
    risks = [r["risk"] for r in reversed_rows]
    traffics = [r["traffic"] for r in reversed_rows]
    packets = [r["packets"] for r in reversed_rows]
    
    return {
        "labels": labels,
        "risks": risks,
        "traffics": traffics,
        "packets": packets
    }

# 3. Events Endpoints
@router.get("/events")
def get_events(
    search: Optional[str] = None,
    severity: Optional[str] = None,
    protocol: Optional[str] = None,
    source_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
):
    conn = get_db_connection()
    query = "SELECT * FROM events WHERE 1=1"
    params = []

    if search:
        query += " AND (device LIKE ? OR source_ip LIKE ? OR destination_ip LIKE ? OR factors LIKE ?)"
        pattern = f"%{search}%"
        params.extend([pattern, pattern, pattern, pattern])

    if severity and severity != "ALL":
        query += " AND severity=?"
        params.append(severity)

    if protocol and protocol != "ALL":
        query += " AND protocol=?"
        params.append(protocol)

    if source_type and source_type != "ALL":
        query += " AND source_type=?"
        params.append(source_type)

    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]

@router.get("/events/{event_id}")
def get_event_detail(event_id: int):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Event not found")
    return dict(row)

# 4. Incidents Endpoints
@router.get("/incidents")
def get_incidents(status: Optional[str] = None):
    conn = get_db_connection()
    if status and status != "ALL":
        rows = conn.execute("SELECT * FROM incidents WHERE status=? ORDER BY id DESC", (status,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]

@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: int, req: IncidentUpdateRequest, username: str = Query("admin")):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")

    desc = req.description or row["description"]
    conn.execute("UPDATE incidents SET status=?, description=? WHERE id=?", (req.status, desc, incident_id))
    conn.commit()
    
    audit_log_event(username, f"Updated Incident #{incident_id} status to {req.status}")
    return {"success": True, "message": f"Incident #{incident_id} updated to {req.status}."}

# 5. Devices Endpoints
@router.get("/devices")
def get_devices():
    conn = get_db_connection()
    devices = conn.execute("SELECT * FROM device_baseline ORDER BY samples DESC").fetchall()
    
    result = []
    for d in devices:
        dev_dict = dict(d)
        # Fetch related incident count
        inc_count = conn.execute("SELECT COUNT(*) FROM incidents WHERE device=?", (dev_dict["device"],)).fetchone()[0]
        # Fetch max risk
        max_risk = conn.execute("SELECT MAX(risk) FROM events WHERE device=?", (dev_dict["device"],)).fetchone()[0] or 0
        dev_dict["incident_count"] = inc_count
        dev_dict["max_risk"] = max_risk
        result.append(dev_dict)
        
    return result

@router.get("/devices/{device_name}")
def get_device_detail(device_name: str):
    conn = get_db_connection()
    base = conn.execute("SELECT * FROM device_baseline WHERE device=?", (device_name,)).fetchone()
    events = conn.execute("SELECT * FROM events WHERE device=? ORDER BY id DESC LIMIT 20", (device_name,)).fetchall()
    incidents = conn.execute("SELECT * FROM incidents WHERE device=? ORDER BY id DESC", (device_name,)).fetchall()
    
    return {
        "baseline": dict(base) if base else None,
        "recent_events": [dict(e) for e in events],
        "incidents": [dict(i) for i in incidents]
    }

# 6. Alerts Endpoints
@router.get("/alerts")
def get_alerts():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100").fetchall()
    return [dict(r) for r in rows]

@router.patch("/alerts/{alert_id}")
def update_alert(alert_id: int, req: AlertUpdateRequest, username: str = Query("admin")):
    conn = get_db_connection()
    conn.execute("UPDATE alerts SET status=? WHERE id=?", (req.status, alert_id))
    conn.commit()
    audit_log_event(username, f"Updated Alert #{alert_id} status to {req.status}")
    return {"success": True}

# 7. Audit Log Endpoint
@router.get("/audit")
def get_audit_log():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200").fetchall()
    return [dict(r) for r in rows]

# 8. Settings Endpoints
@router.get("/settings")
def get_settings():
    return {
        "critical_threshold": int(get_setting("critical_threshold", "80")),
        "high_threshold": int(get_setting("high_threshold", "60")),
        "monitor_interval": float(get_setting("monitor_interval", "1.5")),
        "ml_enabled": get_setting("ml_enabled", "1"),
        "selected_interface": get_setting("selected_interface", "")
    }

@router.put("/settings")
@router.post("/settings")
def save_settings(req: SettingsRequest, username: str = Query("admin"), role: str = Query("ADMIN")):
    if not check_permission(role, ["ADMIN"]):
        raise HTTPException(status_code=403, detail="Permission denied. Admin role required.")

    set_setting("critical_threshold", req.critical_threshold)
    set_setting("high_threshold", req.high_threshold)
    set_setting("monitor_interval", req.monitor_interval)
    set_setting("ml_enabled", req.ml_enabled)
    if req.selected_interface is not None:
        set_setting("selected_interface", req.selected_interface)
    audit_log_event(username, "Updated SOC Security Thresholds & Settings")
    return {"success": True, "message": "Settings updated successfully."}

# 9. Monitoring Control Endpoints
@router.get("/monitoring/interfaces")
def get_monitoring_interfaces():
    return monitoring_service.get_available_interfaces()

@router.get("/monitoring/status")
def get_monitoring_status():
    return monitoring_service.get_status()

@router.post("/monitoring/start")
def start_monitoring(username: str = Query("admin"), role: str = Query("ADMIN")):
    if not check_permission(role, ["ADMIN", "ANALYST"]):
        raise HTTPException(status_code=403, detail="Permission denied. Read-only viewer role.")

    success, msg = monitoring_service.start_monitoring(username=username)
    status = monitoring_service.get_status()
    return {
        "success": success,
        "message": msg,
        "status": status
    }

@router.post("/monitoring/pause")
@router.post("/monitoring/stop")
def pause_monitoring(username: str = Query("admin"), role: str = Query("ADMIN")):
    if not check_permission(role, ["ADMIN", "ANALYST"]):
        raise HTTPException(status_code=403, detail="Permission denied. Read-only viewer role.")

    success, msg = monitoring_service.pause_monitoring(username=username)
    return {
        "success": success,
        "message": msg,
        "status": monitoring_service.get_status()
    }

@router.post("/monitoring/simulate")
def trigger_simulation(req: SimulationRequest, username: str = Query("admin"), role: str = Query("ADMIN")):
    if not check_permission(role, ["ADMIN", "ANALYST"]):
        raise HTTPException(status_code=403, detail="Permission denied. Read-only viewer role.")

    event = monitoring_service.trigger_simulation(scenario=req.scenario, username=username)
    return {"success": True, "event": event}

# 10. Model Management Endpoints
@router.get("/models/status")
def get_ml_status():
    return model_manager.get_status()

@router.post("/models/train")
def train_ml_model(username: str = Query("admin"), role: str = Query("ADMIN")):
    if not check_permission(role, ["ADMIN"]):
        raise HTTPException(status_code=403, detail="Permission denied. Admin role required.")

    success, msg = model_manager.train_on_history()
    audit_log_event(username, f"Initiated Deep Learning Autoencoder training. Result: {msg}")
    return {"success": success, "message": msg}

@router.post("/models/evaluate")
def evaluate_ml_model(username: str = Query("admin"), role: str = Query("ADMIN")):
    if not check_permission(role, ["ADMIN", "ANALYST"]):
        raise HTTPException(status_code=403, detail="Permission denied.")

    success, res = model_manager.evaluate_current_model()
    audit_log_event(username, f"Evaluated Deep Learning Autoencoder model. Result: {res}")
    return {"success": success, "evaluation": res}

@router.post("/models/import-dataset")
async def import_dataset(file: UploadFile = File(...), username: str = Query("admin"), role: str = Query("ADMIN")):
    if not check_permission(role, ["ADMIN"]):
        raise HTTPException(status_code=403, detail="Permission denied. Admin role required.")

    content = await file.read()
    csv_text = content.decode('utf-8', errors='ignore')
    success, msg = model_manager.import_dataset_csv(csv_text, file.filename)
    audit_log_event(username, f"Dataset Import '{file.filename}'. Result: {msg}")
    return {"success": success, "message": msg}

@router.get("/datasets")
def get_datasets():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM datasets ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]

@router.get("/models/registry")
def get_model_registry():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM model_registry ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]

@router.get("/models/evaluations")
def get_model_evaluations():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM model_evaluations ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]

@router.get("/system/status")
def get_system_status():
    import platform
    import sys
    mon = monitoring_service.get_status()
    ml = model_manager.get_status()
    return {
        "platform": platform.platform(),
        "python_version": sys.version.split(" ")[0],
        "local_ip": monitoring_service.local_ip,
        "hostname": platform.node(),
        "monitoring": mon,
        "ml_status": ml,
        "database": "SQLite (sentinel_x_v2.db)",
        "server_status": "ONLINE"
    }

# 11. Reports Download Endpoints
@router.get("/reports/download/pdf")
def download_pdf_report(username: str = Query("admin"), source_type: str = Query("REAL")):
    try:
        pdf_path = generate_pdf_report(source_type=source_type)
        audit_log_event(username, f"Generated PDF Security Report ({os.path.basename(pdf_path)}) [Source: {source_type}]")
        return FileResponse(
            path=pdf_path,
            filename=os.path.basename(pdf_path),
            media_type="application/pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/reports/download/csv")
def download_csv_report(username: str = Query("admin"), source_type: str = Query("REAL")):
    csv_data = generate_csv_report(source_type=source_type)
    audit_log_event(username, f"Exported Network Telemetry Data as CSV [Source: {source_type}]")
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=sentinel_x_telemetry_{source_type.lower()}.csv"}
    )
