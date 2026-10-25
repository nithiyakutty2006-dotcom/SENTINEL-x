import json
import os
import secrets
import time
import unittest
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient
from scapy.all import Ether, IP, Raw, TCP

from main import app
from app.database import get_db_connection
from app.sensor_auth import sign_sensor_request
from sensor.windows_sensor import FlowAccumulator


client = TestClient(app)


class TestSensorIngestion(unittest.TestCase):
    def setUp(self):
        self.sensor_id = f"test-windows-sensor-{uuid.uuid4().hex}"
        self.secret = secrets.token_urlsafe(48)
        self.environment = patch.dict(os.environ, {
            "SENTINEL_SENSOR_ID": self.sensor_id,
            "SENTINEL_SENSOR_SECRET": self.secret,
        })
        self.environment.start()

    def tearDown(self):
        self.environment.stop()

    def _signed_post(self, path, payload, nonce=None, timestamp=None, signature_override=None):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time())) if timestamp is None else str(timestamp)
        nonce = nonce or secrets.token_urlsafe(24)
        signature = signature_override or sign_sensor_request(
            self.secret, timestamp, nonce, body
        )
        return client.post(
            path,
            content=body,
            headers={
                "content-type": "application/json",
                "x-sentinel-sensor-id": self.sensor_id,
                "x-sentinel-timestamp": timestamp,
                "x-sentinel-nonce": nonce,
                "x-sentinel-signature": signature,
            },
        )

    def _event(self, **overrides):
        event = {
            "event_id": str(uuid.uuid4()),
            "flow_id": secrets.token_hex(12),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 52341,
            "destination_port": 443,
            "protocol": "TCP",
            "packets": 12,
            "bytes": 8400,
            "connections": 1,
        }
        event.update(overrides)
        return event

    def test_sensor_ingestion_requires_authentication_and_configuration(self):
        with patch.dict(os.environ, {
            "SENTINEL_SENSOR_ID": self.sensor_id,
            "SENTINEL_SENSOR_SECRET": self.secret,
        }):
            response = client.post(
                "/api/sensors/ingest",
                json={"events": [self._event()]},
            )
        self.assertEqual(response.status_code, 401)

        with patch.dict(os.environ, {
            "SENTINEL_SENSOR_ID": "",
            "SENTINEL_SENSOR_SECRET": "",
        }):
            response = client.post(
                "/api/sensors/ingest",
                content=b'{"events":[]}',
                headers={"content-type": "application/json"},
            )
        self.assertEqual(response.status_code, 503)

    def test_sensor_ingestion_rejects_malformed_payload(self):
        response = self._signed_post("/api/sensors/ingest", {"events": [{"packets": -1}]})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("-1", response.text)

    def test_sensor_ingestion_persists_validated_live_metadata_and_dashboard_state(self):
        event = self._event()
        response = self._signed_post("/api/sensors/ingest", {"events": [event]})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {"success": True, "accepted": 1, "duplicates": 0})

        conn = get_db_connection()
        row = conn.execute(
            "SELECT * FROM events WHERE sensor_id=? AND event_id=?",
            (self.sensor_id, event["event_id"]),
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["source_type"], "LIVE")
        self.assertEqual(row["device"], self.sensor_id)
        self.assertEqual(row["source_port"], event["source_port"])
        self.assertEqual(row["port"], event["destination_port"])
        self.assertEqual(row["bytes"], event["bytes"])
        self.assertIsNone(row["ai_score"])

        device_response = client.get("/api/devices")
        dashboard_response = client.get("/api/dashboard/stats")
        self.assertEqual(device_response.status_code, 200)
        self.assertEqual(dashboard_response.status_code, 200)
        sensor_device = next(
            item for item in device_response.json() if item["device"] == self.sensor_id
        )
        self.assertEqual(sensor_device["source_type"], "LIVE")
        self.assertIn("LIVE", dashboard_response.json()["source_types"])
        self.assertEqual(dashboard_response.json()["sensor"]["status"], "ONLINE")

    def test_flow_accumulator_emits_metadata_without_payload_fields(self):
        accumulator = FlowAccumulator()
        packet = (
            Ether()
            / IP(src="192.0.2.10", dst="198.51.100.20")
            / TCP(sport=52341, dport=443)
            / Raw(load=b"not-for-telemetry")
        )
        accumulator.packet_seen(packet)

        events = accumulator.take_events()
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["source_ip"], "192.0.2.10")
        self.assertEqual(event["destination_ip"], "198.51.100.20")
        self.assertEqual(event["source_port"], 52341)
        self.assertEqual(event["destination_port"], 443)
        self.assertEqual(event["protocol"], "TCP")
        self.assertEqual(event["packets"], 1)
        self.assertNotIn("payload", event)
        self.assertNotIn("raw", event)

    def test_signed_sensor_requests_reject_replay_and_deduplicate_event_ids(self):
        event = self._event()
        nonce = secrets.token_urlsafe(24)
        payload = {"events": [event]}
        first = self._signed_post("/api/sensors/ingest", payload, nonce=nonce)
        replay = self._signed_post("/api/sensors/ingest", payload, nonce=nonce)
        duplicate = self._signed_post("/api/sensors/ingest", payload)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(replay.status_code, 409)
        self.assertEqual(duplicate.status_code, 200)
        self.assertEqual(duplicate.json()["accepted"], 0)
        self.assertEqual(duplicate.json()["duplicates"], 1)

        conn = get_db_connection()
        count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE sensor_id=? AND event_id=?",
            (self.sensor_id, event["event_id"]),
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)

    def test_sensor_heartbeat_and_detection_create_suspicion_not_confirmation(self):
        heartbeat = self._signed_post("/api/sensors/heartbeat", {})
        self.assertEqual(heartbeat.status_code, 200)
        status = client.get("/api/sensors/health")
        self.assertTrue(status.json()["online"])

        event = self._event(
            source_port=51515,
            destination_port=8080,
            packets=2501,
            bytes=9_000_000,
            connections=101,
        )
        response = self._signed_post("/api/sensors/ingest", {"events": [event]})
        self.assertEqual(response.status_code, 200, response.text)
        conn = get_db_connection()
        incident = conn.execute(
            "SELECT description, source_type FROM incidents WHERE device=?",
            (self.sensor_id,),
        ).fetchone()
        alert = conn.execute(
            "SELECT source_type FROM alerts WHERE device=?",
            (self.sensor_id,),
        ).fetchone()
        conn.close()
        self.assertIsNotNone(incident)
        self.assertIn("requiring analyst verification", incident["description"])
        self.assertIn("not a confirmed malicious event", incident["description"])
        self.assertEqual(incident["source_type"], "LIVE")
        self.assertEqual(alert["source_type"], "LIVE")

    def test_sensor_ingestion_rejects_invalid_signature_and_expired_request(self):
        event = self._event()
        bad_signature = self._signed_post(
            "/api/sensors/ingest",
            {"events": [event]},
            signature_override="0" * 64,
        )
        expired = self._signed_post(
            "/api/sensors/ingest",
            {"events": [event]},
            timestamp=int(time.time()) - 600,
        )
        self.assertEqual(bad_signature.status_code, 401)
        self.assertEqual(expired.status_code, 401)

    def test_sensor_requests_are_rate_limited(self):
        with patch("app.sensor_auth.SENSOR_MAX_REQUESTS_PER_WINDOW", 1):
            first = self._signed_post("/api/sensors/heartbeat", {})
            limited = self._signed_post("/api/sensors/heartbeat", {})

        self.assertEqual(first.status_code, 200)
        self.assertEqual(limited.status_code, 429)


if __name__ == "__main__":
    unittest.main()
