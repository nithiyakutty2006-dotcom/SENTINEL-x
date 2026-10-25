import hmac
import os
import re
import sqlite3
import time

from app.database import get_db_connection
from sensor.signing import sign_sensor_request

SENSOR_REQUEST_TTL_SECONDS = 300
SENSOR_RATE_WINDOW_SECONDS = 60
SENSOR_MAX_REQUESTS_PER_WINDOW = 120
_SENSOR_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_NONCE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class SensorRequestError(Exception):
    def __init__(self, status_code, detail):
        super().__init__(detail)
        self.status_code = status_code


def configured_sensor():
    sensor_id = os.environ.get("SENTINEL_SENSOR_ID", "").strip()
    secret = os.environ.get("SENTINEL_SENSOR_SECRET", "")
    if not sensor_id and not secret:
        return None
    if not sensor_id or not secret:
        raise SensorRequestError(
            503, "Sensor ingestion is not configured on this service."
        )
    if not _SENSOR_ID_PATTERN.fullmatch(sensor_id) or len(secret) < 32:
        raise SensorRequestError(
            503, "Sensor ingestion configuration is invalid."
        )
    return sensor_id, secret


def verify_sensor_request(sensor_id, timestamp, nonce, signature, body, now=None):
    configured = configured_sensor()
    if configured is None:
        raise SensorRequestError(503, "Sensor ingestion is not configured on this service.")
    expected_sensor_id, secret = configured
    if not hmac.compare_digest(
        sensor_id.encode("utf-8"), expected_sensor_id.encode("utf-8")
    ):
        raise SensorRequestError(401, "Sensor authentication failed.")
    if len(timestamp) > 12 or not timestamp.isascii() or not timestamp.isdecimal():
        raise SensorRequestError(401, "Sensor request timestamp is invalid.")
    if not _NONCE_PATTERN.fullmatch(nonce or ""):
        raise SensorRequestError(401, "Sensor request nonce is invalid.")

    current_time = time.time() if now is None else now
    request_time = int(timestamp)
    if abs(current_time - request_time) > SENSOR_REQUEST_TTL_SECONDS:
        raise SensorRequestError(401, "Sensor request has expired.")

    expected_signature = sign_sensor_request(secret, timestamp, nonce, body)
    if not re.fullmatch(r"[0-9a-f]{64}", signature or ""):
        raise SensorRequestError(401, "Sensor authentication failed.")
    if not hmac.compare_digest(signature or "", expected_signature):
        raise SensorRequestError(401, "Sensor authentication failed.")

    conn = get_db_connection()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cutoff = current_time - SENSOR_RATE_WINDOW_SECONDS
        conn.execute("DELETE FROM sensor_nonces WHERE created_at < ?", (current_time - 600,))
        conn.execute("DELETE FROM sensor_requests WHERE requested_at < ?", (cutoff,))
        request_count = conn.execute(
            "SELECT COUNT(*) FROM sensor_requests WHERE sensor_id=?",
            (expected_sensor_id,),
        ).fetchone()[0]
        if request_count >= SENSOR_MAX_REQUESTS_PER_WINDOW:
            conn.rollback()
            raise SensorRequestError(429, "Sensor request rate limit exceeded.")

        conn.execute(
            "INSERT INTO sensor_nonces(sensor_id, nonce, created_at) VALUES(?,?,?)",
            (expected_sensor_id, nonce, current_time),
        )
        conn.execute(
            "INSERT INTO sensor_requests(sensor_id, requested_at) VALUES(?,?)",
            (expected_sensor_id, current_time),
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        raise SensorRequestError(409, "Sensor request was already submitted.") from exc
    finally:
        conn.close()

    return expected_sensor_id
