import unittest
import os
import json
import sqlite3
import secrets
import time
from unittest.mock import patch
from fastapi.testclient import TestClient
from main import app
from app.database import get_db_connection, init_db
from app.auth import authenticate_user, check_permission
from app.passwords import hash_password
from app.detection import detect_anomaly, process_event
from ml.preprocessing import FeatureScaler
from ml.inference import ModelInference
from app.monitoring import monitoring_service
from app.reports_gen import generate_csv_report

client = TestClient(app)

class TestSentinelXCompleteSuite(unittest.TestCase):
    def setUp(self):
        init_db()
        self.test_password = secrets.token_urlsafe()
        conn = get_db_connection()
        conn.execute(
            "INSERT OR REPLACE INTO users(username, password, role) VALUES(?,?,?)",
            ("admin", hash_password(self.test_password), "ADMIN")
        )
        conn.commit()

    # 1. Syntax & Imports test
    def test_01_imports(self):
        from app.api import router
        self.assertIsNotNone(router)

    # 2. Application Root URL Response
    def test_02_root_url(self):
        response = client.get("/")
        self.assertEqual(response.status_code, 200)

    # 3. Authentication Success & Failure
    def test_03_authentication(self):
        user_ok = authenticate_user("admin", self.test_password)
        self.assertIsNotNone(user_ok)
        self.assertEqual(user_ok["role"], "ADMIN")

        user_fail = authenticate_user("admin", self.test_password + "-wrong")
        self.assertIsNone(user_fail)

    def test_03a_login_api_accepts_configured_credentials(self):
        response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": self.test_password},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["user"], {"username": "admin", "role": "ADMIN"})

    def test_03b_login_api_rejects_incorrect_credentials(self):
        response = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": self.test_password + "-wrong"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Invalid username or password.")

    def test_03c_login_api_reports_missing_configuration(self):
        conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("""
            CREATE TABLE users(
                username TEXT PRIMARY KEY,
                password TEXT,
                role TEXT
            )
        """)
        try:
            with patch("app.auth.get_db_connection", return_value=conn):
                response = client.post(
                    "/api/auth/login",
                    json={"username": "admin", "password": self.test_password},
                )
        finally:
            conn.close()

        self.assertEqual(response.status_code, 503)
        self.assertIn("SENTINEL_ADMIN_USERNAME", response.json()["detail"])
        self.assertIn("SENTINEL_ADMIN_PASSWORD", response.json()["detail"])

    # 4. Role-Based Permissions
    def test_04_role_permissions(self):
        self.assertTrue(check_permission("ADMIN", ["ADMIN"]))
        self.assertTrue(check_permission("ANALYST", ["ADMIN", "ANALYST"]))
        self.assertFalse(check_permission("VIEWER", ["ADMIN"]))

    # 5. Dashboard API Summary & Graph Endpoints
    def test_05_dashboard_apis(self):
        res_stats = client.get("/api/dashboard/stats")
        self.assertEqual(res_stats.status_code, 200)
        data_stats = res_stats.json()
        self.assertIn("events", data_stats)
        self.assertIn("critical", data_stats)
        self.assertIn("open_incidents", data_stats)
        self.assertIn("active_alerts", data_stats)
        self.assertIn("protocols", data_stats)

        res_graph = client.get("/api/dashboard/risk-history")
        self.assertEqual(res_graph.status_code, 200)
        data_graph = res_graph.json()
        self.assertIn("labels", data_graph)
        self.assertIn("risks", data_graph)

    # 6. Events API & Filtering
    def test_06_events_api(self):
        res = client.get("/api/events?limit=10")
        self.assertEqual(res.status_code, 200)
        self.assertIsInstance(res.json(), list)

    # 7. Risk Calculation & Severity Classification
    def test_07_risk_detection_engine(self):
        sample_event = {
            "timestamp": "2026-10-09 12:00:00",
            "device": "TEST-DEVICE-01",
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.1",
            "port": 4444,
            "protocol": "TCP",
            "packets": 5000,
            "traffic": 15.0,
            "connections": 200,
            "unknown": 20,
            "source_type": "REAL"
        }
        res = detect_anomaly(sample_event)
        self.assertGreaterEqual(res["combined_risk"], 60)
        self.assertIn(res["severity"], ["HIGH", "CRITICAL"])
        self.assertTrue(len(res["factors"]) > 0)

    # 8. Database Persistence & Event Processing
    def test_08_event_processing(self):
        sample_event = {
            "timestamp": "2026-10-09 12:05:00",
            "device": "TEST-PERSIST-DEV",
            "source_ip": "192.168.1.99",
            "destination_ip": "10.0.0.2",
            "port": 80,
            "protocol": "TCP",
            "packets": 100,
            "traffic": 0.5,
            "connections": 5,
            "unknown": 0,
            "source_type": "REAL"
        }
        processed = process_event(sample_event)
        self.assertIn("risk", processed)
        
        conn = get_db_connection()
        row = conn.execute("SELECT * FROM events WHERE device='TEST-PERSIST-DEV' ORDER BY id DESC LIMIT 1").fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["device"], "TEST-PERSIST-DEV")

    # 9. Incidents & Status Updates
    def test_09_incidents_lifecycle(self):
        res = client.get("/api/incidents")
        self.assertEqual(res.status_code, 200)

    # 10. Alerts & Status Updates
    def test_10_alerts_lifecycle(self):
        res = client.get("/api/alerts")
        self.assertEqual(res.status_code, 200)

    # 11. Settings Get & Post
    def test_11_settings_persistence(self):
        res_get = client.get("/api/settings")
        self.assertEqual(res_get.status_code, 200)

    # 12. Reports Export
    def test_12_reports_export(self):
        csv_str = generate_csv_report()
        self.assertIn("ID,Timestamp,Device", csv_str)

    # 13. ML Preprocessing & Feature Extraction
    def test_13_ml_preprocessing(self):
        scaler = FeatureScaler()
        scaler.fit([[10, 1.5, 5, 0, 80, 1], [100, 5.0, 50, 2, 443, 2]])
        transformed = scaler.transform([[10, 1.5, 5, 0, 80, 1]])
        self.assertEqual(transformed.shape, (1, 6))

    # 14. ML Inference Engine Initialization
    def test_14_ml_inference(self):
        inf = ModelInference()
        features = inf.extract_features({
            "packets": 1000,
            "traffic": 2.5,
            "connections": 20,
            "unknown": 0,
            "port": 80,
            "protocol": "TCP"
        })
        self.assertEqual(len(features), 6)

    # 15. Real vs Demo Mode Separation
    def test_15_monitoring_demo_separation(self):
        sim_res = client.post("/api/monitoring/simulate", json={"scenario": "Critical Event"})
        self.assertEqual(sim_res.status_code, 200)
        event = sim_res.json()["event"]
        self.assertEqual(event["source_type"], "DEMO")

    # 16. PDF Report Generation
    def test_16_pdf_report_generation(self):
        from app.reports_gen import generate_pdf_report
        pdf_file = generate_pdf_report()
        self.assertTrue(os.path.exists(pdf_file))
        self.assertTrue(pdf_file.endswith(".pdf"))

    # 17. System Diagnostics API
    def test_17_system_status_api(self):
        res = client.get("/api/system/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["server_status"], "ONLINE")
        self.assertIn("monitoring", data)
        self.assertIn("ml_status", data)

    # 18. Datasets and Model Registry Endpoints
    def test_18_datasets_and_registry_api(self):
        res_ds = client.get("/api/datasets")
        self.assertEqual(res_ds.status_code, 200)
        self.assertIsInstance(res_ds.json(), list)

        res_reg = client.get("/api/models/registry")
        self.assertEqual(res_reg.status_code, 200)
        self.assertIsInstance(res_reg.json(), list)

    # 19. Available Network Interfaces Endpoint
    def test_19_interfaces_endpoint(self):
        res = client.get("/api/monitoring/interfaces")
        self.assertEqual(res.status_code, 200)
        ifaces = res.json()
        self.assertIsInstance(ifaces, list)
        self.assertGreater(len(ifaces), 0)
        self.assertIn("name", ifaces[0])
        self.assertIn("id", ifaces[0])

    # 20. Real vs Demo Stats Isolation
    def test_20_real_demo_stats_isolation(self):
        res_real = client.get("/api/dashboard/stats?source_type=REAL")
        self.assertEqual(res_real.status_code, 200)
        data_real = res_real.json()

        res_demo = client.get("/api/dashboard/stats?source_type=DEMO")
        self.assertEqual(res_demo.status_code, 200)
        data_demo = res_demo.json()

        self.assertIsInstance(data_real["events"], int)
        self.assertIsInstance(data_demo["events"], int)

    # 21. Monitoring Startup Failure Is Reported
    def test_21_monitoring_capture_start_failure(self):
        original_mode = monitoring_service.monitoring_mode
        monitoring_service.pause_monitoring()
        monitoring_service.monitoring_mode = "real"
        try:
            with patch("app.monitoring.sniff", side_effect=PermissionError("capture permission denied")):
                response = client.post("/api/monitoring/start?username=admin&role=ADMIN")

            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertFalse(data["success"])
            self.assertIn("capture permission denied", data["message"])
            self.assertEqual(data["status"]["mode"], "ERROR")
            self.assertFalse(data["status"]["running"])
        finally:
            monitoring_service.pause_monitoring()
            monitoring_service.monitoring_mode = original_mode

    # 22. Demo Monitoring Emits Labeled Events and Stops
    def test_22_demo_monitoring_start_and_stop(self):
        original_mode = monitoring_service.monitoring_mode
        original_demo_event_count = monitoring_service.demo_event_count
        monitoring_service.pause_monitoring()
        monitoring_service.monitoring_mode = "demo"
        monitoring_service.demo_event_count = 4
        try:
            with patch(
                "app.monitoring.get_setting",
                side_effect=lambda key, default: "0.2" if key == "monitor_interval" else default
            ), patch("app.monitoring.process_event", wraps=process_event) as process_event_mock:
                started = client.post("/api/monitoring/start?username=admin&role=ADMIN")
                self.assertEqual(started.status_code, 200)
                self.assertTrue(started.json()["success"])
                self.assertEqual(started.json()["status"]["mode"], "DEMO MONITORING")
                self.assertIn("not real network traffic", started.json()["message"])
                status = client.get("/api/monitoring/status")
                self.assertEqual(status.status_code, 200)
                self.assertEqual(status.json()["mode"], "DEMO MONITORING")
                self.assertTrue(status.json()["running"])

                deadline = time.monotonic() + 3
                row = None
                while time.monotonic() < deadline:
                    conn = get_db_connection()
                    try:
                        row = conn.execute(
                            "SELECT source_type FROM events WHERE device='DEMO-SENSOR-01' ORDER BY id DESC LIMIT 1"
                        ).fetchone()
                    finally:
                        conn.close()
                    if row:
                        break
                    time.sleep(0.05)

                self.assertIsNotNone(row)
                self.assertEqual(row["source_type"], "DEMO")
                conn = get_db_connection()
                generated_threat = conn.execute("""
                    SELECT risk, source_type FROM events
                    WHERE device='DEMO-SENSOR-01'
                    ORDER BY id DESC LIMIT 1
                """).fetchone()
                self.assertGreaterEqual(generated_threat["risk"], 60)
                self.assertEqual(generated_threat["source_type"], "DEMO")
                demo_device = next(
                    device for device in client.get("/api/devices").json()
                    if device["device"] == "DEMO-SENSOR-01"
                )
                self.assertEqual(demo_device["source_type"], "DEMO")
                stopped = client.post("/api/monitoring/stop?username=admin&role=ADMIN")
                self.assertEqual(stopped.status_code, 200)
                self.assertTrue(stopped.json()["success"])
                self.assertFalse(stopped.json()["status"]["running"])
                self.assertEqual(stopped.json()["status"]["mode"], "IDLE")
                calls_at_pause = process_event_mock.call_count
                time.sleep(0.3)
                self.assertEqual(process_event_mock.call_count, calls_at_pause)

                restarted = client.post("/api/monitoring/start?username=admin&role=ADMIN")
                self.assertEqual(restarted.status_code, 200)
                self.assertTrue(restarted.json()["success"])
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline and process_event_mock.call_count <= calls_at_pause:
                    time.sleep(0.05)
                self.assertGreater(process_event_mock.call_count, calls_at_pause)
                self.assertTrue(client.post(
                    "/api/monitoring/pause?username=admin&role=ADMIN"
                ).json()["success"])
        finally:
            monitoring_service.pause_monitoring()
            monitoring_service.monitoring_mode = original_mode
            monitoring_service.demo_event_count = original_demo_event_count

    # 23. Demo Events Persist, Register a Device, and Trigger Qualified Alerts
    def test_23_demo_event_persistence_inventory_and_detection(self):
        device = f"DEMO-REGRESSION-{secrets.token_hex(4)}"
        benign_event = {
            "timestamp": "2026-10-25 12:00:00",
            "device": device,
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "port": 443,
            "protocol": "TCP",
            "packets": 100,
            "traffic": 0.5,
            "connections": 10,
            "unknown": 0,
            "source_type": "DEMO",
        }
        process_event(benign_event)

        conn = get_db_connection()
        self.assertIsNone(conn.execute(
            "SELECT id FROM incidents WHERE device=?", (device,)
        ).fetchone())
        self.assertIsNone(conn.execute(
            "SELECT id FROM alerts WHERE device=?", (device,)
        ).fetchone())

        threat_event = {
            **benign_event,
            "timestamp": "2026-10-25 12:00:01",
            "port": 8080,
            "packets": 2501,
            "traffic": 8.1,
            "connections": 101,
            "unknown": 11,
        }
        processed = process_event(threat_event)
        self.assertGreaterEqual(processed["risk"], 60)
        self.assertEqual(processed["source_type"], "DEMO")

        events = client.get(f"/api/events?search={device}&source_type=DEMO")
        incidents = client.get("/api/incidents?status=ALL")
        alerts = client.get("/api/alerts")
        devices = client.get("/api/devices")
        self.assertEqual(events.status_code, 200)
        self.assertEqual(incidents.status_code, 200)
        self.assertEqual(alerts.status_code, 200)
        self.assertEqual(devices.status_code, 200)
        self.assertTrue(any(row["device"] == device and row["source_type"] == "DEMO"
                            for row in events.json()))
        self.assertTrue(any(row["device"] == device and row["source_type"] == "DEMO"
                            for row in incidents.json()))
        self.assertTrue(any(row["device"] == device and row["source_type"] == "DEMO"
                            for row in alerts.json()))
        self.assertTrue(any(row["device"] == device and row["source_type"] == "DEMO"
                            for row in devices.json()))

    # 23. Demo Startup Processing Failure Is Reported
    def test_24_demo_monitoring_start_failure_is_reported(self):
        original_mode = monitoring_service.monitoring_mode
        monitoring_service.pause_monitoring()
        monitoring_service.monitoring_mode = "demo"
        try:
            with patch(
                "app.monitoring.process_event",
                side_effect=RuntimeError("demo event processing failed")
            ):
                response = client.post("/api/monitoring/start?username=admin&role=ADMIN")

            self.assertEqual(response.status_code, 200)
            data = response.json()
            self.assertFalse(data["success"])
            self.assertIn("demo event processing failed", data["message"])
            self.assertEqual(data["status"]["mode"], "ERROR")
            self.assertFalse(data["status"]["running"])
        finally:
            monitoring_service.pause_monitoring()
            monitoring_service.monitoring_mode = original_mode

if __name__ == '__main__':
    unittest.main()
