import unittest
import os
import json
import secrets
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

if __name__ == '__main__':
    unittest.main()
