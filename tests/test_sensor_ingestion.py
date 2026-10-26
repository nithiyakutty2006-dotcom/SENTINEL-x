import json
import os
import secrets
import subprocess
import time
import unittest
import uuid
from datetime import datetime, timezone
from urllib.error import URLError
from unittest.mock import patch

from fastapi.testclient import TestClient

from main import app
from app.database import get_db_connection
from app.detection import process_event
from app.passwords import hash_password
from app.sensor_auth import sign_sensor_request
from sensor import windows_sensor
from sensor.windows_sensor import ConnectionTracker


client = TestClient(app)


class TestSensorIngestion(unittest.TestCase):
    def setUp(self):
        self.sensor_id = f"test-windows-sensor-{uuid.uuid4().hex}"
        self.secret = secrets.token_urlsafe(48)
        self.web_username = f"sensor-test-{uuid.uuid4().hex}"
        self.web_password = secrets.token_urlsafe(32)
        client.cookies.clear()
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO users(username, password, role) VALUES(?,?,?)",
            (self.web_username, hash_password(self.web_password), "ADMIN"),
        )
        conn.commit()
        conn.close()
        login = client.post(
            "/api/auth/login",
            json={"username": self.web_username, "password": self.web_password},
        )
        self.assertEqual(login.status_code, 200)
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
            "local_ip": "192.0.2.10",
            "remote_ip": "198.51.100.20",
            "local_port": 52341,
            "remote_port": 443,
            "protocol": "TCP",
            "connections": 1,
            "connection_state": "ESTABLISHED",
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
            health = client.get("/api/sensors/health")
            response = client.post(
                "/api/sensors/ingest",
                content=b'{"events":[]}',
                headers={"content-type": "application/json"},
            )
        self.assertEqual(health.json()["status"], "NOT CONFIGURED")
        self.assertIn("SENTINEL_SENSOR_ID", health.json()["message"])
        self.assertIn("SENTINEL_SENSOR_SECRET", health.json()["message"])
        self.assertEqual(response.status_code, 503)

    def test_sensor_authentication_failure_is_explicit(self):
        with patch.dict(os.environ, {
            "SENTINEL_SENSOR_ID": f"other-{uuid.uuid4().hex}",
            "SENTINEL_SENSOR_SECRET": self.secret,
        }):
            response = self._signed_post("/api/sensors/validate", {})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Sensor authentication failed.")

    def test_sensor_accepts_http_only_for_local_backend_urls(self):
        with patch.dict(os.environ, {
            "SENTINEL_SENSOR_URL": "http://127.0.0.1:8011",
            "SENTINEL_SENSOR_ID": self.sensor_id,
            "SENTINEL_SENSOR_SECRET": self.secret,
        }):
            self.assertEqual(
                windows_sensor._sensor_configuration()[0],
                "http://127.0.0.1:8011",
            )
        with patch.dict(os.environ, {
            "SENTINEL_SENSOR_URL": "http://example.com",
            "SENTINEL_SENSOR_ID": self.sensor_id,
            "SENTINEL_SENSOR_SECRET": self.secret,
        }):
            with self.assertRaisesRegex(RuntimeError, "HTTPS"):
                windows_sensor._sensor_configuration()

    def test_sensor_finds_windows_powershell_outside_path(self):
        with patch.object(windows_sensor.shutil, "which", return_value=None), patch.dict(
            os.environ, {"SystemRoot": r"C:\Windows"}
        ), patch.object(windows_sensor.os.path, "isfile", return_value=True):
            self.assertEqual(
                windows_sensor._powershell_executable(),
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            )

    def test_powershell_timeout_is_bounded_and_reported_clearly(self):
        with patch.object(
            windows_sensor,
            "_powershell_executable",
            return_value=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ), patch.object(
            windows_sensor.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="powershell.exe", timeout=20),
        ) as run:
            with self.assertRaisesRegex(
                RuntimeError, "Windows networking query timed out after 20 seconds"
            ):
                windows_sensor._run_powershell("Get-NetAdapter")

        self.assertEqual(
            run.call_args.kwargs["timeout"],
            windows_sensor.POWERSHELL_TIMEOUT_SECONDS,
        )
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_transient_poll_failure_retries_queued_telemetry(self):
        snapshot = [{
            "local_ip": "192.0.2.10",
            "remote_ip": "198.51.100.20",
            "local_port": 52341,
            "remote_port": 443,
            "connection_state": "Established",
        }]
        upload_bodies = []

        def signed_request(_server_url, _sensor_id, _secret, path, body):
            if path.endswith("/heartbeat"):
                return {"success": True}
            upload_bodies.append(json.loads(body))
            if len(upload_bodies) == 1:
                raise URLError("temporary network interruption")
            return {"success": True, "accepted": 1, "duplicates": 0}

        with patch.object(
            windows_sensor,
            "_sensor_configuration",
            return_value=("http://127.0.0.1:8011", self.sensor_id, self.secret),
        ), patch.object(
            windows_sensor,
            "check_configuration",
            return_value=([{"Name": "Wi-Fi"}], {}),
        ), patch.object(
            windows_sensor,
            "_run_powershell",
            side_effect=[snapshot, RuntimeError("temporary PowerShell failure")],
        ) as poll, patch.object(
            windows_sensor,
            "_signed_request",
            side_effect=signed_request,
        ), patch.object(
            windows_sensor.stop_event,
            "wait",
            side_effect=[False, False, True],
        ), patch.object(
            windows_sensor.logger,
            "exception",
        ) as log_error:
            windows_sensor.run_sensor("Wi-Fi")

        self.assertEqual(poll.call_count, 2)
        self.assertEqual(len(upload_bodies), 2)
        event_id = upload_bodies[0]["events"][0]["event_id"]
        self.assertEqual(upload_bodies[1]["events"][0]["event_id"], event_id)
        self.assertEqual(log_error.call_count, 2)

    def test_sensor_identity_can_be_checked_without_marking_it_online(self):
        response = self._signed_post("/api/sensors/validate", {})
        self.assertEqual(response.status_code, 200)
        status = client.get("/api/sensors/health").json()
        self.assertTrue(status["configured"])
        self.assertFalse(status["online"])
        self.assertNotIn("sensor_id", status)

    def test_sensor_health_starts_offline_and_reports_upload_error_codes(self):
        status = client.get("/api/sensors/health")
        self.assertEqual(status.status_code, 200)
        self.assertFalse(status.json()["online"])
        self.assertIsNone(status.json()["last_upload"])

        heartbeat = self._signed_post(
            "/api/sensors/heartbeat",
            {"last_upload_error": "NETWORK_ERROR"},
        )
        self.assertEqual(heartbeat.status_code, 200)
        status = client.get("/api/sensors/health")
        self.assertTrue(status.json()["online"])
        self.assertEqual(status.json()["status"], "ERROR")
        self.assertEqual(status.json()["last_upload_error"], "NETWORK_ERROR")
        upload = self._signed_post("/api/sensors/ingest", {"events": [self._event()]})
        self.assertEqual(upload.status_code, 200)
        status = client.get("/api/sensors/health")
        self.assertEqual(status.json()["status"], "CONNECTED")
        self.assertTrue(status.json()["has_recent_events"])
        self.assertIsNone(status.json()["last_upload_error"])
        self.assertIsNotNone(status.json()["last_upload"])

    def test_authenticated_heartbeat_does_not_prove_recent_event_ingestion(self):
        heartbeat = self._signed_post("/api/sensors/heartbeat", {})
        self.assertEqual(heartbeat.status_code, 200)

        status = client.get("/api/sensors/health").json()
        self.assertTrue(status["connected"])
        self.assertFalse(status["has_recent_events"])
        self.assertEqual(status["status"], "NO RECENT EVENTS")

        conn = get_db_connection()
        stale_event = datetime.fromtimestamp(
            time.time() - windows_sensor.HEARTBEAT_INTERVAL_SECONDS * 10,
            timezone.utc,
        ).strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(
            "UPDATE sensors SET last_event=? WHERE sensor_id=?",
            (stale_event, self.sensor_id),
        )
        conn.commit()
        conn.close()

        status = client.get("/api/sensors/health").json()
        self.assertTrue(status["connected"])
        self.assertFalse(status["has_recent_events"])
        self.assertEqual(status["status"], "NO RECENT EVENTS")

    def test_configured_sensor_with_stale_heartbeat_is_offline(self):
        conn = get_db_connection()
        conn.execute(
            """
            INSERT OR REPLACE INTO sensors(
                sensor_id, last_heartbeat_epoch, last_event, last_upload_epoch,
                last_upload_error
            ) VALUES(?,?,?,?,?)
            """,
            (self.sensor_id, time.time() - 120, None, None, None),
        )
        conn.commit()
        conn.close()

        status = client.get("/api/sensors/health").json()
        self.assertTrue(status["configured"])
        self.assertFalse(status["online"])
        self.assertEqual(status["status"], "DISCONNECTED")

    def test_sensor_ingestion_rejects_malformed_payload(self):
        response = self._signed_post(
            "/api/sensors/ingest",
            {"events": [self._event(
                source_type="DEMO",
                packets=1,
                bytes=1,
                payload="not allowed",
            )]},
        )
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("DEMO", response.text)
        self.assertNotIn("not allowed", response.text)

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
        self.assertEqual(row["source_ip"], event["local_ip"])
        self.assertEqual(row["destination_ip"], event["remote_ip"])
        self.assertEqual(row["source_port"], event["local_port"])
        self.assertEqual(row["port"], event["remote_port"])
        self.assertIsNone(row["bytes"])
        self.assertIsNone(row["packets"])
        self.assertIsNone(row["traffic"])
        self.assertEqual(row["connection_state"], "ESTABLISHED")
        self.assertEqual(row["endpoint_mode"], "LOCAL_REMOTE")
        self.assertIsNone(row["ai_score"])

        device_response = client.get("/api/devices")
        dashboard_response = client.get("/api/dashboard/stats")
        self.assertEqual(device_response.status_code, 200)
        self.assertEqual(dashboard_response.status_code, 200)
        self.assertIsNone(dashboard_response.json()["persisted_packet_count"])
        sensor_device = next(
            item for item in device_response.json() if item["device"] == self.sensor_id
        )
        self.assertEqual(sensor_device["source_type"], "LIVE")
        self.assertIn("LIVE", dashboard_response.json()["source_types"])
        status = dashboard_response.json()["sensor"]
        self.assertEqual(status["status"], "CONNECTED")
        self.assertTrue(status["has_recent_events"])
        self.assertIsNotNone(status["last_upload"])
        self.assertIsNone(status["last_upload_error"])
        self.assertNotIn("sensor_id", status)
        self.assertNotIn("sensor_secret", status)
        live_devices = client.get("/api/devices?source_type=LIVE").json()
        self.assertIn(self.sensor_id, [item["device"] for item in live_devices])

    def test_demo_events_are_excluded_from_live_dashboard_statistics(self):
        live_before = client.get("/api/dashboard/stats?source_type=LIVE").json()["events"]
        demo_before = client.get("/api/dashboard/stats?source_type=DEMO").json()["events"]
        process_event({
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "device": "DEMO-ONLY-TEST-DEVICE",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "port": 443,
            "protocol": "TCP",
            "packets": 1,
            "traffic": 0.001,
            "connections": 1,
            "unknown": 0,
            "source_type": "DEMO",
        })

        live_after = client.get("/api/dashboard/stats?source_type=LIVE").json()["events"]
        demo_after = client.get("/api/dashboard/stats?source_type=DEMO").json()["events"]
        self.assertEqual(live_after, live_before)
        self.assertEqual(demo_after, demo_before + 1)
        live_devices = client.get("/api/devices?source_type=LIVE").json()
        self.assertNotIn("DEMO-ONLY-TEST-DEVICE", [item["device"] for item in live_devices])

    def test_connection_tracker_emits_no_packet_or_payload_data_and_deduplicates(self):
        tracker = ConnectionTracker()
        snapshot = [{
            "local_ip": "192.0.2.10",
            "remote_ip": "198.51.100.20",
            "local_port": 52341,
            "remote_port": 443,
            "connection_state": "Established",
        }]
        events = tracker.update(snapshot)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["local_ip"], "192.0.2.10")
        self.assertEqual(event["remote_ip"], "198.51.100.20")
        self.assertEqual(event["local_port"], 52341)
        self.assertEqual(event["remote_port"], 443)
        self.assertEqual(event["protocol"], "TCP")
        self.assertNotIn("packets", event)
        self.assertNotIn("bytes", event)
        self.assertEqual(event["connection_state"], "ESTABLISHED")
        self.assertNotIn("payload", event)
        self.assertNotIn("raw", event)
        self.assertEqual(tracker.update(snapshot), [])
        tracker.update([])
        self.assertEqual(len(tracker.update(snapshot)), 1)

        ipv6_event = ConnectionTracker().update([{
            "local_ip": "2001:db8::2",
            "remote_ip": "2001:db8::1",
            "local_port": 52342,
            "remote_port": 443,
            "connection_state": "Established",
        }])[0]
        self.assertEqual(ipv6_event["local_ip"], "2001:db8::2")
        self.assertEqual(ipv6_event["remote_ip"], "2001:db8::1")

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

    def test_sensor_heartbeat_and_normal_connection_do_not_create_false_alerts(self):
        heartbeat = self._signed_post("/api/sensors/heartbeat", {})
        self.assertEqual(heartbeat.status_code, 200)
        status = client.get("/api/sensors/health")
        self.assertTrue(status.json()["online"])

        event = self._event(connection_state="ESTABLISHED")
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
        self.assertIsNone(incident)
        self.assertIsNone(alert)

    def test_failed_upload_is_retried_without_changing_event_identity(self):
        snapshot = [{
            "local_ip": "192.0.2.10",
            "remote_ip": "198.51.100.20",
            "local_port": 52341,
            "remote_port": 443,
            "connection_state": "Established",
        }]
        polls = []

        def poll_connections(*_args, **_kwargs):
            polls.append(True)
            if len(polls) > 1:
                windows_sensor.stop_event.set()
            return snapshot

        with patch.object(
            windows_sensor,
            "_sensor_configuration",
            return_value=("https://sentinel.example", self.sensor_id, self.secret),
        ), patch.object(
            windows_sensor,
            "check_configuration",
            return_value=([{"Name": "Wi-Fi"}], {"configured": True}),
        ), patch.object(
            windows_sensor,
            "_run_powershell",
            side_effect=poll_connections,
        ), patch.object(
            windows_sensor,
            "POLL_INTERVAL_SECONDS",
            0.01,
        ), patch.object(
            windows_sensor,
            "HEARTBEAT_INTERVAL_SECONDS",
            0,
        ), patch.object(
            windows_sensor,
            "_signed_request",
            side_effect=[
                {"success": True},
                URLError("offline"),
                {"success": True},
                {"success": True, "accepted": 1},
                {"success": True},
            ],
        ) as send:
            windows_sensor.run_sensor("Wi-Fi")

        self.assertEqual(send.call_count, 5)
        failed_batch = json.loads(send.call_args_list[1].args[4])
        failed_upload_heartbeat = json.loads(send.call_args_list[2].args[4])
        retried_batch = json.loads(send.call_args_list[3].args[4])
        self.assertEqual(
            failed_batch["events"][0]["event_id"],
            retried_batch["events"][0]["event_id"],
        )
        self.assertEqual(failed_upload_heartbeat, {"last_upload_error": "NETWORK_ERROR"})

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
