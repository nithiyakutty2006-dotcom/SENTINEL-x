import threading
import time
import random
import socket
import platform
import logging
import os
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
from app.database import now_string, audit_log_event, get_setting
from app.detection import process_event

logger = logging.getLogger(__name__)


class MonitoringService:
    def __init__(self):
        self.running = False
        self.mode = "IDLE"
        configured_mode = os.environ.get("SENTINEL_MONITORING_MODE", "auto").strip().lower()
        if configured_mode not in {"auto", "real", "demo"}:
            raise ValueError("SENTINEL_MONITORING_MODE must be 'auto', 'real', or 'demo'.")
        self.monitoring_mode = (
            "demo" if configured_mode == "demo" or
            (configured_mode == "auto" and os.environ.get("RENDER"))
            else "real"
        )
        self.lock = threading.Lock()
        self.lifecycle_lock = threading.RLock()
        self.stop_event = threading.Event()
        self.packet_counts = defaultdict(int)
        self.byte_counts = defaultdict(int)
        self.connection_counts = defaultdict(int)
        self.protocol_counts = defaultdict(int)
        self.total_packets_captured = 0
        self.demo_event_count = 0
        self.last_packet_time = None
        self.capture_thread = None
        self.accumulator_thread = None
        self.capture_ready = threading.Event()
        self.demo_ready = threading.Event()
        self.last_error = None
        self.selected_interface = None
        self.local_ip = self._get_local_ip()

    def get_available_interfaces(self):
        from scapy.all import IFACES
        ifaces_list = []
        for k, v in IFACES.items():
            ifaces_list.append({
                "id": k,
                "name": v.name,
                "description": v.description,
                "ip": v.ip or ""
            })
        return ifaces_list

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def capture_packet(self, packet):
        if not self.running:
            return
        if IP not in packet:
            return

        src = packet[IP].src
        dst = packet[IP].dst
        protocol = "OTHER"
        port = 0
        if TCP in packet:
            protocol = "TCP"
            port = int(packet[TCP].dport)
        elif UDP in packet:
            protocol = "UDP"
            port = int(packet[UDP].dport)

        key = (src, dst, port, protocol)
        with self.lock:
            self.total_packets_captured += 1
            self.last_packet_time = now_string()
            self.packet_counts[key] += 1
            self.byte_counts[key] += len(packet)
            self.connection_counts[key] += 1
            self.protocol_counts[protocol] += 1

    def build_real_events(self):
        events = []
        current_time = now_string()
        hostname = platform.node()
        device_name = f"{hostname} ({self.local_ip})"

        with self.lock:
            for key in list(self.packet_counts.keys()):
                src, dst, port, protocol = key
                packets = self.packet_counts[key]
                total_bytes = self.byte_counts[key]
                connections = self.connection_counts[key]
                traffic_mb = round(total_bytes / (1024 * 1024), 4)

                event = {
                    "timestamp": current_time,
                    "device": device_name,
                    "source_ip": src,
                    "destination_ip": dst,
                    "port": port,
                    "protocol": protocol,
                    "packets": packets,
                    "traffic": traffic_mb,
                    "connections": connections,
                    "unknown": 0,
                    "source_type": "REAL"
                }
                events.append(event)

            self.packet_counts.clear()
            self.byte_counts.clear()
            self.connection_counts.clear()

        return events

    def _sniff_loop(self):
        try:
            iface_to_use = get_setting("selected_interface", "")
            if not iface_to_use or iface_to_use.strip() == "":
                iface_to_use = None

            if iface_to_use:
                sniff(
                    iface=iface_to_use,
                    prn=self.capture_packet,
                    store=False,
                    stop_filter=lambda x: not self.running,
                    started_callback=self.capture_ready.set
                )
            else:
                sniff(
                    prn=self.capture_packet,
                    store=False,
                    stop_filter=lambda x: not self.running,
                    started_callback=self.capture_ready.set
                )
        except Exception as e:
            self.running = False
            capture_guidance = (
                "Ensure Npcap is installed with WinPcap compatibility."
                if platform.system() == "Windows"
                else "Verify the selected interface and packet-capture permissions."
            )
            self.last_error = f"Packet capture failed: {e}. {capture_guidance}"
            self.mode = "ERROR"
            self.capture_ready.set()
            logger.exception("Network packet capture failed")

    def _accumulator_loop(self):
        while self.running:
            try:
                events = self.build_real_events()
                for event in events:
                    process_event(event)
                interval = float(get_setting("monitor_interval", "1.5"))
            except (ValueError, TypeError):
                interval = 1.5
            except Exception as e:
                self._set_error(f"Monitoring event processing failed: {e}")
                logger.exception("Monitoring event processing failed")
                return
            self.stop_event.wait(max(0.2, interval))

    def _demo_loop(self):
        while self.running:
            try:
                self.demo_event_count += 1
                is_threat_simulation = self.demo_event_count % 5 == 0
                event = {
                    "timestamp": now_string(),
                    "device": "DEMO-SENSOR-01",
                    "source_ip": "192.0.2.10",
                    "destination_ip": "198.51.100.20",
                    "port": 8080 if is_threat_simulation else random.choice([53, 80, 443]),
                    "protocol": random.choice(["TCP", "UDP"]),
                    "packets": 2501 if is_threat_simulation else random.randint(10, 250),
                    "traffic": 8.1 if is_threat_simulation else round(random.uniform(0.01, 1.5), 3),
                    "connections": 101 if is_threat_simulation else random.randint(1, 20),
                    "unknown": 11 if is_threat_simulation else 0,
                    "source_type": "DEMO"
                }
                process_event(event)
                if self.stop_event.is_set():
                    self.demo_ready.set()
                    return
                self.mode = "DEMO MONITORING"
                self.demo_ready.set()
                interval = float(get_setting("monitor_interval", "1.5"))
            except (ValueError, TypeError):
                interval = 1.5
            except Exception as e:
                self._set_error(f"Demo monitoring event processing failed: {e}")
                self.demo_ready.set()
                logger.exception("Demo monitoring event processing failed")
                return
            self.stop_event.wait(max(0.2, interval))

    def _set_error(self, message):
        self.running = False
        self.mode = "ERROR"
        self.last_error = message

    def start_monitoring(self, username="admin"):
        with self.lifecycle_lock:
            return self._start_monitoring(username)

    def _start_monitoring(self, username):
        if self.running:
            return True, "Monitoring is already active."

        self.stop_event.clear()
        self.running = True
        self.last_error = None

        if self.monitoring_mode == "demo":
            self.mode = "STARTING DEMO"
            self.demo_ready.clear()
            self.accumulator_thread = threading.Thread(target=self._demo_loop, daemon=True)
            try:
                self.accumulator_thread.start()
            except Exception as e:
                self._set_error(f"Could not start demo monitoring worker: {e}")
                logger.exception("Could not start demo monitoring worker")
                return False, self.last_error
            if not self.demo_ready.wait(timeout=3):
                self.stop_event.set()
                self._set_error("Demo monitoring did not produce its first event within 3 seconds.")
                logger.error(self.last_error)
                self.accumulator_thread.join()
                return False, self.last_error
            if self.last_error:
                return False, self.last_error
            audit_log_event(username, "Started Demo Monitoring with simulated security events")
            logger.info("Demo monitoring started; synthetic events are labeled DEMO")
            return True, "Demo Monitoring started. Events are simulated and are not real network traffic."

        self.mode = "REAL MONITORING"
        self.capture_ready.clear()
        self.capture_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        try:
            self.capture_thread.start()
        except Exception as e:
            self._set_error(f"Could not start packet capture worker: {e}")
            logger.exception("Could not start packet capture worker")
            return False, self.last_error
        if not self.capture_ready.wait(timeout=3):
            if self.last_error:
                self.running = False
                self.mode = "ERROR"
                return False, self.last_error
            self._set_error("Packet capture did not initialize within 3 seconds.")
            return False, self.last_error
        if self.last_error:
            self.running = False
            self.mode = "ERROR"
            return False, self.last_error

        self.accumulator_thread = threading.Thread(target=self._accumulator_loop, daemon=True)
        self.accumulator_thread.start()

        audit_log_event(username, "Started Real Network Monitoring via Scapy")
        return True, "Real Scapy Network Monitoring started successfully."

    def pause_monitoring(self, username="admin"):
        with self.lifecycle_lock:
            return self._pause_monitoring(username)

    def _pause_monitoring(self, username):
        if not self.running:
            return True, "Monitoring is already paused."

        self.running = False
        self.stop_event.set()
        if self.mode != "ERROR":
            self.mode = "IDLE"
        if self.monitoring_mode == "demo" and self.accumulator_thread:
            self.accumulator_thread.join()
        audit_log_event(username, "Paused Network Monitoring")
        logger.info("Monitoring paused")
        return True, "Network Monitoring paused."

    def trigger_simulation(self, scenario="Critical Event", username="admin"):
        hostname = platform.node()
        device_name = f"{hostname} ({self.local_ip})"

        devices = [device_name, "DEMO-SERVER-01", "DEMO-WORKSTATION-02", "DEMO-FIREWALL-01"]
        event = {
            "timestamp": now_string(),
            "device": random.choice(devices),
            "source_ip": f"192.168.1.{random.randint(10, 250)}",
            "destination_ip": f"10.0.0.{random.randint(10, 250)}",
            "port": random.choice([80, 443, 22, 53, 3389, 4444]),
            "protocol": random.choice(["TCP", "UDP", "HTTP", "HTTPS"]),
            "packets": random.randint(300, 2500),
            "traffic": round(random.uniform(0.5, 12), 2),
            "connections": random.randint(5, 150),
            "unknown": random.randint(0, 15),
            "source_type": "DEMO"
        }

        if scenario == "Critical Event":
            event["packets"] = random.randint(6000, 12000)
            event["traffic"] = round(random.uniform(18, 45), 2)
            event["connections"] = random.randint(180, 400)
            event["unknown"] = random.randint(15, 35)
            event["forced"] = True

        processed_event = process_event(event)
        audit_log_event(username, f"Executed Demo Simulation: {scenario}")
        return processed_event

    def get_status(self):
        return {
            "running": self.running,
            "mode": self.mode,
            "packets_captured": self.total_packets_captured,
            "last_packet_time": self.last_packet_time,
            "selected_interface": get_setting("selected_interface", "DEFAULT"),
            "last_error": self.last_error
        }

monitoring_service = MonitoringService()
