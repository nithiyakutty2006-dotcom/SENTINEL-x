from app.database import get_db_connection, get_setting, now_string
from ml.model_manager import ModelManager
from datetime import datetime

model_manager = ModelManager()

def update_baseline(event, connection=None):
    conn = connection or get_db_connection()
    device = event["device"]
    packets = event["packets"]
    traffic = event["traffic"]
    connections = event["connections"]

    row = conn.execute("""
        SELECT avg_packets, avg_traffic, avg_connections, samples
        FROM device_baseline
        WHERE device=?
    """, (device,)).fetchone()

    if row is None:
        conn.execute("""
            INSERT INTO device_baseline(device, avg_packets, avg_traffic, avg_connections, samples, last_seen)
            VALUES(?,?,?,?,?,?)
        """, (device, packets, traffic, connections, 1, now_string()))
    else:
        samples = row["samples"] + 1
        avg_packets = ((row["avg_packets"] * row["samples"]) + packets) / samples
        avg_traffic = ((row["avg_traffic"] * row["samples"]) + traffic) / samples
        avg_connections = ((row["avg_connections"] * row["samples"]) + connections) / samples

        conn.execute("""
            UPDATE device_baseline
            SET avg_packets=?, avg_traffic=?, avg_connections=?, samples=?, last_seen=?
            WHERE device=?
        """, (avg_packets, avg_traffic, avg_connections, samples, now_string(), device))
    if connection is None:
        conn.commit()
        conn.close()

def detect_anomaly(event):
    conn = get_db_connection()
    device = event["device"]
    rule_score = 0.0
    baseline_score = 0.0
    factors = []

    # 1. Rule-Based Analysis
    if (event.get("packets") or 0) > 2000:
        rule_score += 35.0
        factors.append("[Rule] Abnormally High Packet Count (>2000 pkts)")
    if (event.get("traffic") or 0.0) > 8.0:
        rule_score += 30.0
        factors.append("[Rule] Large Data Transfer (>8MB)")
    if (event.get("connections") or 0) > 100:
        rule_score += 25.0
        factors.append("[Rule] Excessive Connections (>100 conns)")
    if event.get("unknown", 0) > 10:
        rule_score += 20.0
        factors.append("[Rule] Multiple Unknown Destinations (>10)")
    if event.get("destination_port_known", True) and event.get("port") in [22, 3389, 4444, 1337, 8080]:
        rule_score += 20.0
        factors.append(f"[Rule] Suspicious Destination Port ({event['port']})")
    if event.get("packets") is None or event.get("traffic") is None:
        factors.append("[Telemetry] TCP connection state observed; packet and byte counters unavailable")
    if event.get("destination_port_known") is False:
        factors.append("[Telemetry] Local/remote endpoints observed; connection direction is unknown")

    # 2. Statistical Baseline Profiling
    row = conn.execute("""
        SELECT avg_packets, avg_traffic, avg_connections, samples
        FROM device_baseline
        WHERE device=?
    """, (device,)).fetchone()
    conn.close()

    if (
        row
        and row["samples"] >= 3
        and event.get("packets") is not None
        and event.get("traffic") is not None
    ):
        pkt_ratio = event["packets"] / max(row["avg_packets"], 1.0)
        trf_ratio = event["traffic"] / max(row["avg_traffic"], 0.01)
        conn_ratio = event["connections"] / max(row["avg_connections"], 1.0)

        if pkt_ratio > 3.0:
            score = min(35.0, pkt_ratio * 5.0)
            baseline_score += score
            factors.append(f"[Baseline] Packet Rate Spike ({pkt_ratio:.1f}x baseline)")
        if trf_ratio > 3.0:
            score = min(30.0, trf_ratio * 4.5)
            baseline_score += score
            factors.append(f"[Baseline] Traffic Volume Volatility ({trf_ratio:.1f}x baseline)")
        if conn_ratio > 3.0:
            score = min(25.0, conn_ratio * 4.0)
            baseline_score += score
            factors.append(f"[Baseline] Concurrent Connection Spike ({conn_ratio:.1f}x baseline)")

    # 3. Deep Learning Autoencoder Anomaly Score
    ai_score = None
    ai_risk_score = 0.0
    model_status_text = "NOT TRAINED"
    ml_enabled = get_setting("ml_enabled", "1") == "1"
    
    if (
        ml_enabled
        and model_manager.inference.loaded
        and event.get("packets") is not None
        and event.get("traffic") is not None
    ):
        model_status_text = "READY"
        dl_score, is_anomaly, mse = model_manager.inference.predict(event)
        ai_score = dl_score
        ai_risk_score = dl_score if dl_score is not None else 0.0
        if dl_score is not None and (is_anomaly or dl_score > 30.0):
            factors.append(f"[Deep Learning Autoencoder] Anomaly Detected (Score: {dl_score:.1f}%, MSE: {mse:.4f})")
    elif not ml_enabled:
        model_status_text = "DISABLED"
    elif model_manager.inference.loaded:
        model_status_text = "SKIPPED: COUNTERS UNAVAILABLE"

    # Forced simulation override
    if event.get("forced"):
        rule_score = max(rule_score, 90.0)
        baseline_score = max(baseline_score, 80.0)
        factors.append("[Simulation] Synthetic Critical Threat Triggered")

    # Combine Scores (0-100 scale)
    weighted_score = (rule_score * 0.4) + (baseline_score * 0.3) + (ai_risk_score * 0.3)
    combined_risk = int(min(100.0, max(rule_score * 0.8, baseline_score * 0.8, weighted_score)))

    critical_threshold = int(get_setting("critical_threshold", "80"))
    high_threshold = int(get_setting("high_threshold", "60"))

    if combined_risk >= critical_threshold:
        severity = "CRITICAL"
    elif combined_risk >= high_threshold:
        severity = "HIGH"
    elif combined_risk >= 31:
        severity = "MEDIUM"
    elif combined_risk >= 10:
        severity = "LOW"
    else:
        severity = "NORMAL"

    if not factors:
        factors.append("Normal Baseline Network Telemetry")

    source_type = event.get("source_type", "REAL")

    return {
        "rule_score": round(rule_score, 1),
        "baseline_score": round(baseline_score, 1),
        "ai_score": round(ai_score, 1) if ai_score is not None else None,
        "combined_risk": combined_risk,
        "severity": severity,
        "factors": factors,
        "model_status": model_status_text,
        "source_type": source_type
    }

def process_event(event):
    conn = get_db_connection()
    detection = detect_anomaly(event)

    risk = detection["combined_risk"]
    severity = detection["severity"]
    ai_score = detection["ai_score"]
    rule_score = detection["rule_score"]
    baseline_score = detection["baseline_score"]
    factors = detection["factors"]
    source_type = detection["source_type"]

    event["risk"] = risk
    event["severity"] = severity
    event["ai_score"] = ai_score
    event["rule_score"] = rule_score
    event["baseline_score"] = baseline_score
    event["factors"] = factors
    event["source_type"] = source_type
    byte_count = event.get("bytes")
    if "bytes" not in event:
        traffic = event.get("traffic")
        byte_count = int(traffic * 1024 * 1024) if traffic is not None else None

    # 1. Insert Event into SQLite
    conn.execute("""
    INSERT INTO events(
        timestamp, device, source_ip, destination_ip, port, protocol,
        packets, traffic, connections, unknown, risk, severity, ai_score,
        rule_score, baseline_score, factors, source_type, source_port, bytes,
        flow_id, sensor_id, event_id, connection_state, endpoint_mode
    )
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        event["timestamp"], event["device"], event["source_ip"], event["destination_ip"],
        event["port"], event["protocol"], event["packets"], event["traffic"],
        event["connections"], event["unknown"], risk, severity, ai_score,
        rule_score, baseline_score, ", ".join(factors), source_type,
        event.get("source_port", 0), byte_count,
        event.get("flow_id"), event.get("sensor_id"), event.get("event_id"),
        event.get("connection_state"), event.get("endpoint_mode")
    ))

    # Keep real, live-sensor, and demo inventory separate from imported datasets.
    if (
        source_type in {"REAL", "LIVE", "DEMO"}
        and event.get("packets") is not None
        and event.get("traffic") is not None
    ):
        update_baseline(event, conn)

    # 3. Deduplicated Incident & Alert Triggering
    if risk >= 60:
        # Check if an open incident exists for this device in the last 15 seconds to prevent flood
        recent_incident = conn.execute("""
            SELECT id FROM incidents
            WHERE device=? AND status != 'RESOLVED'
              AND datetime(timestamp) > datetime(?, '-15 seconds')
        """, (event["device"], event["timestamp"])).fetchone()

        if not recent_incident:
            conn.execute("""
            INSERT INTO incidents(timestamp, device, risk, severity, status, description, source_type)
            VALUES(?,?,?,?,?,?,?)
            """, (
                event["timestamp"], event["device"], risk, severity, "OPEN",
                f"Suspicious activity requiring analyst verification on {event['device']} "
                f"({', '.join(factors)}). This is not a confirmed malicious event.",
                source_type
            ))
            
            conn.execute("""
            INSERT INTO alerts(timestamp, device, risk, severity, channel, status, source_type)
            VALUES(?,?,?,?,?,?,?)
            """, (
                event["timestamp"], event["device"], risk, severity, "SOC DASHBOARD & EMAIL", "TRIGGERED", source_type
            ))
    conn.commit()
    conn.close()

    return event
