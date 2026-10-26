import argparse
import ctypes
import hashlib
import ipaddress
import json
import logging
import os
import platform
import shutil
import signal
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from sensor.signing import sign_sensor_request

DEFAULT_SERVER_URL = "https://sentinel-x-72rs.onrender.com"
POLL_INTERVAL_SECONDS = 2
HEARTBEAT_INTERVAL_SECONDS = 30
MAX_PENDING_EVENTS = 500
MAX_BATCH_EVENTS = 100
logger = logging.getLogger("sentinel_sensor")
stop_event = threading.Event()
POWERSHELL_TIMEOUT_SECONDS = 20

_POWERSHELL_ADAPTERS = r"""
$ErrorActionPreference = 'Stop'
$adapters = @(Get-NetAdapter -IncludeHidden |
    Where-Object { $_.Status -eq 'Up' } |
    Select-Object Name, InterfaceDescription, Status)
ConvertTo-Json -InputObject $adapters -Compress
"""

_POWERSHELL_TCP_CONNECTIONS = r"""
$ErrorActionPreference = 'Stop'
$addresses = @(Get-NetIPAddress -InterfaceAlias $env:SENTINEL_SENSOR_INTERFACE `
    -AddressState Preferred -ErrorAction Stop |
    Select-Object -ExpandProperty IPAddress)
if ($addresses.Count -eq 0) { throw 'No preferred IP addresses found on the selected interface.' }
$connections = @(Get-NetTCPConnection -ErrorAction Stop |
    Where-Object {
        ($addresses -contains $_.LocalAddress) -and
        ($_.RemotePort -gt 0) -and
        ($_.RemoteAddress -ne '0.0.0.0') -and
        ($_.RemoteAddress -ne '::')
    } |
    ForEach-Object {
        [pscustomobject]@{
            local_ip = $_.LocalAddress
            local_port = [int]$_.LocalPort
            remote_ip = $_.RemoteAddress
            remote_port = [int]$_.RemotePort
            connection_state = $_.State.ToString()
        }
    })
ConvertTo-Json -InputObject $connections -Compress
"""


def _sensor_configuration():
    server_url = os.environ.get("SENTINEL_SENSOR_URL", DEFAULT_SERVER_URL).rstrip("/")
    sensor_id = os.environ.get("SENTINEL_SENSOR_ID", "").strip()
    secret = os.environ.get("SENTINEL_SENSOR_SECRET", "")
    parsed_url = urlsplit(server_url)
    local_http = (
        parsed_url.scheme == "http"
        and parsed_url.hostname in {"localhost", "127.0.0.1", "::1"}
    )
    if parsed_url.scheme != "https" and not local_http:
        raise RuntimeError(
            "SENTINEL_SENSOR_URL must use HTTPS; HTTP is allowed only for localhost."
        )
    if not parsed_url.netloc or parsed_url.username or parsed_url.password:
        raise RuntimeError("SENTINEL_SENSOR_URL must be a valid URL without credentials.")
    if not sensor_id or not secret or len(secret) < 32:
        raise RuntimeError(
            "Set SENTINEL_SENSOR_ID and a SENTINEL_SENSOR_SECRET of at least 32 characters."
        )
    return server_url, sensor_id, secret


def _powershell_executable():
    executable = shutil.which("powershell.exe")
    if executable:
        return executable
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    executable = os.path.join(
        system_root,
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
    )
    if os.path.isfile(executable):
        return executable
    return None


def _run_powershell(script, interface=None):
    executable = _powershell_executable()
    if executable is None:
        raise RuntimeError("Windows PowerShell was not found.")
    env = os.environ.copy()
    if interface is not None:
        env["SENTINEL_SENSOR_INTERFACE"] = interface
    try:
        result = subprocess.run(
            [
                executable,
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "RemoteSigned",
                "-Command",
                script,
            ],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=POWERSHELL_TIMEOUT_SECONDS,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            "Windows networking query timed out after "
            f"{POWERSHELL_TIMEOUT_SECONDS} seconds. Check the Windows "
            "networking cmdlets and selected interface, then retry."
        ) from exc
    if result.returncode:
        message = result.stderr.strip() or "Windows networking query failed."
        raise RuntimeError(message)
    output = result.stdout.strip()
    return json.loads(output) if output else []


def _signed_request(server_url, sensor_id, secret, path, body):
    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    signature = sign_sensor_request(secret, timestamp, nonce, body)
    request = Request(
        server_url + path,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Sentinel-Sensor-Id": sensor_id,
            "X-Sentinel-Timestamp": timestamp,
            "X-Sentinel-Nonce": nonce,
            "X-Sentinel-Signature": signature,
        },
    )
    with urlopen(request, timeout=20) as response:
        return json.loads(response.read())


def _public_health(server_url):
    try:
        with urlopen(server_url + "/api/sensors/health", timeout=15) as response:
            return json.loads(response.read())
    except HTTPError as exc:
        if exc.code == 404:
            raise RuntimeError(
                "The backend does not expose /api/sensors/health. Deploy the "
                "SENTINEL-X sensor API before running this sensor."
            ) from exc
        raise RuntimeError(
            f"The backend sensor health check failed with HTTP {exc.code}."
        ) from exc
    except (TimeoutError, URLError) as exc:
        raise RuntimeError(
            "Could not reach the backend sensor health endpoint before the "
            "15-second timeout. Check that Uvicorn is running and the sensor URL is correct."
        ) from exc


def _is_admin():
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def check_configuration():
    server_url, sensor_id, secret = _sensor_configuration()
    if platform.system() != "Windows":
        raise RuntimeError("The connection-table sensor is intended to run on Windows.")
    if _powershell_executable() is None:
        raise RuntimeError("Windows PowerShell was not found.")
    adapters = _run_powershell(_POWERSHELL_ADAPTERS)
    if isinstance(adapters, dict):
        adapters = [adapters]
    if not adapters:
        raise RuntimeError("No active Windows network interfaces were found.")
    health = _public_health(server_url)
    if not health.get("configured"):
        raise RuntimeError(
            health.get("message")
            or "The backend has not been configured for sensor ingestion. Set "
            "SENTINEL_SENSOR_ID and SENTINEL_SENSOR_SECRET on the backend."
        )
    try:
        validation = _signed_request(
            server_url, sensor_id, secret, "/api/sensors/validate", b"{}"
        )
    except HTTPError as exc:
        if exc.code == 401:
            raise RuntimeError(
                "Sensor authentication failed. Confirm the configured sensor ID "
                "and secret match the backend."
            ) from exc
        if exc.code == 404:
            raise RuntimeError(
                "The backend does not expose /api/sensors/validate. Deploy the "
                "SENTINEL-X sensor API before running this sensor."
            ) from exc
        if exc.code == 503:
            raise RuntimeError(
                "The backend sensor authentication is not configured or is invalid."
            ) from exc
        raise RuntimeError(
            f"The backend sensor validation failed with HTTP {exc.code}."
        ) from exc
    except (TimeoutError, URLError) as exc:
        raise RuntimeError(
            "The signed sensor validation request did not complete within "
            "20 seconds. Check the backend and local network connection."
        ) from exc
    if not validation.get("success"):
        raise RuntimeError("The backend rejected the sensor identity or secret.")
    return adapters, health


def _normalize_connection_state(state):
    value = str(state).replace("_", "").replace(" ", "").upper()
    return {
        "SYNRECEIVED": "SYN_RECEIVED",
        "FINWAIT1": "FIN_WAIT_1",
        "FINWAIT2": "FIN_WAIT_2",
        "CLOSEWAIT": "CLOSE_WAIT",
        "LASTACK": "LAST_ACK",
        "TIMEWAIT": "TIME_WAIT",
        "DELETETCB": "DELETE_TCB",
    }.get(value, value if value in {
        "CLOSED", "LISTEN", "SYN_SENT", "ESTABLISHED", "CLOSING", "UNKNOWN",
    } else "UNKNOWN")


class ConnectionTracker:
    def __init__(self):
        self.previous = {}

    def update(self, snapshot):
        current = {}
        events = []
        for connection in snapshot:
            local_ip = str(ipaddress.ip_address(connection["local_ip"]))
            remote_ip = str(ipaddress.ip_address(connection["remote_ip"]))
            local_port = int(connection["local_port"])
            remote_port = int(connection["remote_port"])
            if not 1 <= local_port <= 65535 or not 1 <= remote_port <= 65535:
                continue
            state = _normalize_connection_state(connection["connection_state"])
            key = (local_ip, local_port, remote_ip, remote_port)
            current[key] = state
            if self.previous.get(key) == state:
                continue

            timestamp = datetime.now(timezone.utc).isoformat()
            flow_id = hashlib.sha256("|".join(map(str, key)).encode("utf-8")).hexdigest()[:32]
            events.append({
                "event_id": str(uuid.uuid4()),
                "flow_id": flow_id,
                "timestamp": timestamp,
                "local_ip": local_ip,
                "remote_ip": remote_ip,
                "local_port": local_port,
                "remote_port": remote_port,
                "protocol": "TCP",
                "connections": 1,
                "connection_state": state,
            })
        self.previous = current
        return events


def _upload_error_code(error):
    if isinstance(error, HTTPError):
        return "HTTP_ERROR"
    if isinstance(error, (URLError, TimeoutError, OSError)):
        return "NETWORK_ERROR"
    return "INVALID_RESPONSE"


def run_sensor(interface):
    server_url, sensor_id, secret = _sensor_configuration()
    adapters, _ = check_configuration()
    adapter_names = {adapter.get("Name") for adapter in adapters}
    if interface not in adapter_names:
        raise RuntimeError("Select an active interface name printed by --check.")

    initial_heartbeat = _signed_request(
        server_url, sensor_id, secret, "/api/sensors/heartbeat", b"{}"
    )
    if not initial_heartbeat.get("success"):
        raise RuntimeError("The backend rejected the authenticated sensor heartbeat.")

    stop_event.clear()
    tracker = ConnectionTracker()
    pending = []
    last_upload_error = None
    last_heartbeat = time.monotonic()
    logger.info("Started Windows TCP connection metadata sensor %s on %s.", sensor_id, interface)
    logger.info("No packet capture is used; packet payloads are never read.")
    if not _is_admin():
        logger.warning(
            "This terminal is not elevated. Windows may omit connections owned by other users."
        )

    try:
        while not stop_event.wait(POLL_INTERVAL_SECONDS):
            try:
                snapshot = _run_powershell(_POWERSHELL_TCP_CONNECTIONS, interface)
                if isinstance(snapshot, dict):
                    snapshot = [snapshot]
                pending.extend(tracker.update(snapshot))
            except (
                KeyError,
                OSError,
                RuntimeError,
                TypeError,
                ValueError,
                subprocess.SubprocessError,
            ):
                logger.exception(
                    "Windows TCP connection polling failed; queued telemetry will be retried."
                )

            if len(pending) > MAX_PENDING_EVENTS:
                dropped = len(pending) - MAX_PENDING_EVENTS
                pending = pending[-MAX_PENDING_EVENTS:]
                logger.error("Pending telemetry limit exceeded; dropped %s oldest events.", dropped)

            while pending:
                batch = pending[:MAX_BATCH_EVENTS]
                body = json.dumps({"events": batch}, separators=(",", ":")).encode("utf-8")
                try:
                    result = _signed_request(
                        server_url, sensor_id, secret, "/api/sensors/ingest", body
                    )
                    if not result.get("success"):
                        raise ValueError("Backend returned an unsuccessful upload response.")
                    del pending[:len(batch)]
                    last_upload_error = None
                    logger.info(
                        "Telemetry accepted: %s events; %s duplicate event IDs.",
                        result.get("accepted", 0),
                        result.get("duplicates", 0),
                    )
                except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
                    last_upload_error = _upload_error_code(exc)
                    logger.exception("Telemetry upload failed; events remain queued in memory.")
                    break

            now = time.monotonic()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL_SECONDS:
                heartbeat = json.dumps(
                    {"last_upload_error": last_upload_error},
                    separators=(",", ":"),
                ).encode("utf-8")
                try:
                    _signed_request(
                        server_url, sensor_id, secret, "/api/sensors/heartbeat", heartbeat
                    )
                    last_heartbeat = now
                except (HTTPError, URLError, TimeoutError, OSError, ValueError):
                    logger.exception("Sensor heartbeat failed; check network and backend status.")
    finally:
        stop_event.set()
        logger.info(
            "Sensor stopped. %s unsent events remain in the non-persistent retry queue.",
            len(pending),
        )


def main():
    parser = argparse.ArgumentParser(
        description="Opt-in Windows TCP connection metadata sensor for SENTINEL-X."
    )
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--check", action="store_true", help="Check Windows interfaces and backend without collecting.")
    actions.add_argument("--run", action="store_true", help="Start connection-table polling after explicit invocation.")
    parser.add_argument("--interface", help="Exact active Windows interface name; required with --run.")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    try:
        if args.check:
            adapters, health = check_configuration()
            print("Configuration checks passed; no packet capture or connection polling was started.")
            print("Active interfaces:")
            for adapter in adapters:
                print(f"  {adapter['Name']}: {adapter.get('InterfaceDescription', '')}")
            print(f"Backend sensor status: {health['status']}")
            if not _is_admin():
                print("Note: run an elevated terminal for the broadest TCP connection visibility.")
            return 0

        if not args.interface:
            parser.error("--interface is required with --run.")
        signal.signal(signal.SIGINT, lambda *_: stop_event.set())
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
        run_sensor(args.interface)
        return 0
    except (RuntimeError, HTTPError, URLError, OSError, ValueError, subprocess.SubprocessError) as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
