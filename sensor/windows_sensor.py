import argparse
import ctypes
import hashlib
import json
import logging
import os
import platform
import signal
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from scapy.all import IP, IPv6, TCP, UDP, conf, get_if_list, sniff
from scapy.arch.libpcap import L2pcapListenSocket, open_pcap

from sensor.signing import sign_sensor_request

DEFAULT_SERVER_URL = "https://sentinel-x-72rs.onrender.com"
CAPTURE_SNAPLEN = 128
UPLOAD_INTERVAL_SECONDS = 10
HEARTBEAT_INTERVAL_SECONDS = 30
MAX_PENDING_EVENTS = 500
MAX_BATCH_EVENTS = 100
logger = logging.getLogger("sentinel_sensor")
stop_event = threading.Event()


class MetadataOnlyPcapSocket(L2pcapListenSocket):
    """Use a bounded libpcap snapshot; packet prefixes may transiently contain payload."""

    def __init__(self, interface):
        self.type = 3
        self.outs = None
        self.iface = interface
        self.promisc = False
        self.monitor = False
        capture = open_pcap(
            device=interface,
            snaplen=CAPTURE_SNAPLEN,
            promisc=False,
            to_ms=100,
            monitor=False,
        )
        super(L2pcapListenSocket, self).__init__(capture)
        self.pcap_fd.setfilter("ip or ip6")


class FlowAccumulator:
    def __init__(self):
        self.lock = threading.Lock()
        self.flows = {}

    def packet_seen(self, packet):
        network_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if network_layer is None:
            return
        if packet.haslayer(IP):
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            network_bytes = int(packet[IP].len or len(packet))
        else:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst
            network_bytes = int(packet[IPv6].plen or 0) + 40

        source_port = 0
        destination_port = 0
        protocol = "OTHER"
        if packet.haslayer(TCP):
            protocol = "TCP"
            source_port = int(packet[TCP].sport)
            destination_port = int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            source_port = int(packet[UDP].sport)
            destination_port = int(packet[UDP].dport)

        key = (source_ip, destination_ip, source_port, destination_port, protocol)
        with self.lock:
            flow = self.flows.setdefault(key, {
                "packets": 0,
                "bytes": 0,
                "connections": 1,
            })
            flow["packets"] += 1
            flow["bytes"] += network_bytes

    def take_events(self):
        with self.lock:
            flows, self.flows = self.flows, {}
        timestamp = datetime.now(timezone.utc).isoformat()
        events = []
        for key, counts in flows.items():
            flow_id = hashlib.sha256(
                "|".join(map(str, key)).encode("utf-8")
            ).hexdigest()[:32]
            events.append({
                "event_id": str(uuid.uuid4()),
                "flow_id": flow_id,
                "timestamp": timestamp,
                "source_ip": key[0],
                "destination_ip": key[1],
                "source_port": key[2],
                "destination_port": key[3],
                "protocol": key[4],
                **counts,
            })
        return events


def _sensor_configuration():
    server_url = os.environ.get("SENTINEL_SENSOR_URL", DEFAULT_SERVER_URL).rstrip("/")
    sensor_id = os.environ.get("SENTINEL_SENSOR_ID", "").strip()
    secret = os.environ.get("SENTINEL_SENSOR_SECRET", "")
    if not server_url.startswith("https://"):
        raise RuntimeError("SENTINEL_SENSOR_URL must use HTTPS.")
    if not sensor_id or not secret or len(secret) < 32:
        raise RuntimeError(
            "Set SENTINEL_SENSOR_ID and a SENTINEL_SENSOR_SECRET of at least 32 characters."
        )
    return server_url, sensor_id, secret


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
    with urlopen(server_url + "/api/sensors/health", timeout=15) as response:
        return json.loads(response.read())


def _is_admin():
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def check_configuration():
    server_url, sensor_id, _ = _sensor_configuration()
    if platform.system() != "Windows":
        raise RuntimeError("The bundled packet sensor is intended to run on Windows.")
    if not conf.use_pcap:
        raise RuntimeError("Scapy cannot access Npcap. Install Npcap and restart the terminal.")
    interfaces = get_if_list()
    if not interfaces:
        raise RuntimeError("No Npcap interfaces were found.")
    if not _is_admin():
        raise RuntimeError(
            "This terminal is not elevated. Run VS Code as Administrator to access Npcap."
        )
    health = _public_health(server_url)
    if not health.get("configured"):
        raise RuntimeError("The Render service has not been configured for sensor ingestion.")
    if health.get("sensor_id") != sensor_id:
        raise RuntimeError("This PC's sensor identity does not match the Render configuration.")
    return interfaces, health


def _capture(capture_socket, accumulator):
    try:
        sniff(
            opened_socket=capture_socket,
            prn=accumulator.packet_seen,
            store=False,
            stop_filter=lambda _: stop_event.is_set(),
        )
    except Exception:
        if not stop_event.is_set():
            logger.exception("Packet capture stopped unexpectedly.")
            stop_event.set()
    finally:
        capture_socket.close()


def run_sensor(interface):
    server_url, sensor_id, secret = _sensor_configuration()
    interfaces, _ = check_configuration()
    if interface not in interfaces:
        raise RuntimeError("The requested interface was not found in the Npcap interface list.")

    stop_event.clear()
    accumulator = FlowAccumulator()
    capture_socket = MetadataOnlyPcapSocket(interface)
    capture_thread = threading.Thread(
        target=_capture, args=(capture_socket, accumulator), name="sentinel-pcap", daemon=True
    )
    capture_thread.start()
    pending = []
    last_heartbeat = 0
    logger.info("Started metadata sensor %s on the selected interface.", sensor_id)
    logger.info("Only flow metadata is parsed, retained, or uploaded.")
    logger.warning(
        "Npcap temporarily delivers a bounded packet prefix to this process; "
        "use a metadata-only flow exporter for a strict no-payload capture boundary."
    )
    try:
        while not stop_event.wait(UPLOAD_INTERVAL_SECONDS):
            pending.extend(accumulator.take_events())
            if len(pending) > MAX_PENDING_EVENTS:
                dropped = len(pending) - MAX_PENDING_EVENTS
                pending = pending[-MAX_PENDING_EVENTS:]
                logger.error("Pending telemetry limit exceeded; dropped %s oldest flow records.", dropped)

            now = time.monotonic()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL_SECONDS:
                try:
                    _signed_request(server_url, sensor_id, secret, "/api/sensors/heartbeat", b"{}")
                    last_heartbeat = now
                    logger.info("Sensor heartbeat accepted.")
                except (HTTPError, URLError, TimeoutError, OSError, ValueError):
                    logger.exception("Sensor heartbeat failed; check service URL and Render ingestion settings.")

            if pending:
                batch = pending[:MAX_BATCH_EVENTS]
                body = json.dumps({"events": batch}, separators=(",", ":")).encode("utf-8")
                try:
                    result = _signed_request(server_url, sensor_id, secret, "/api/sensors/ingest", body)
                    if result.get("success"):
                        del pending[:len(batch)]
                        logger.info(
                            "Telemetry accepted: %s events; %s duplicate event IDs.",
                            result.get("accepted", 0),
                            result.get("duplicates", 0),
                        )
                except (HTTPError, URLError, TimeoutError, OSError, ValueError):
                    logger.exception("Telemetry upload failed; records remain queued for retry.")
    finally:
        stop_event.set()
        capture_socket.close()
        capture_thread.join(timeout=3)
        pending.extend(accumulator.take_events())
        logger.warning(
            "Sensor stopped with %s unsent flow records; the in-memory retry queue "
            "will be lost when this process exits.",
            len(pending),
        )


def main():
    parser = argparse.ArgumentParser(
        description="Opt-in Windows network metadata sensor for SENTINEL-X."
    )
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--check", action="store_true", help="Check configuration and Npcap without capturing.")
    actions.add_argument("--run", action="store_true", help="Start packet capture after explicit invocation.")
    parser.add_argument("--interface", help="Exact Npcap interface name; required with --run.")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    try:
        if args.check:
            interfaces, health = check_configuration()
            print("Configuration and Npcap checks passed; packet capture was not started.")
            print("Available interfaces:")
            for interface in interfaces:
                print(f"  {interface}")
            print(f"Render sensor status: {health['status']}")
            return 0

        if not args.interface:
            parser.error("--interface is required with --run.")
        signal.signal(signal.SIGINT, lambda *_: stop_event.set())
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, lambda *_: stop_event.set())
        run_sensor(args.interface)
        return 0
    except (RuntimeError, HTTPError, URLError, OSError) as exc:
        logger.error("%s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
