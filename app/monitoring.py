import threading
import time
import random
import socket
import platform
from collections import defaultdict
from scapy.all import sniff, IP, TCP, UDP
from app.database import now_string, audit_log_event, get_setting
from app.detection import process_event

class MonitoringService:
    def __init__(self):
        self.running = False
        self.mode = "IDLE"
        self.lock = threading.Lock()
        self.packet_counts = defaultdict(int)
        self.byte_counts = defaultdict(int)
        self.connection_counts = defaultdict(int)
        self.protocol_counts = defaultdict(int)
        self.total_packets_captured = 0
        self.last_packet_time = None
        self.capture_thread = None
        self.accumulator_thread = None
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
                    stop_filter=lambda x: not self.running
                )
            else:
                sniff(
                    prn=self.capture_packet,
                    store=False,
                    stop_filter=lambda x: not self.running
                )
        except Exception as e:
            self.running = False
            self.last_error = f"Packet Sniff Error: {str(e)}. (Ensure Npcap is installed on Windows with WinPcap compatibility)."
            self.mode = "ERROR"

    def _accumulator_loop(self):
        while self.running:
            events = self.build_real_events()
            for event in events:
                process_event(event)
            try:
                interval = float(get_setting("monitor_interval", "1.5"))
            except (ValueError, TypeError):
                interval = 1.5
            time.sleep(max(0.2, interval))

    def start_monitoring(self, username="admin"):
        if self.running:
            return True, "Monitoring is already active."

        self.running = True
        self.mode = "REAL MONITORING"
        self.last_error = None

        self.capture_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.capture_thread.start()

        self.accumulator_thread = threading.Thread(target=self._accumulator_loop, daemon=True)
        self.accumulator_thread.start()

        audit_log_event(username, "Started Real Network Monitoring via Scapy")
        return True, "Real Scapy Network Monitoring started successfully."

    def pause_monitoring(self, username="admin"):
        if not self.running:
            return True, "Monitoring is already paused."

        self.running = False
        self.mode = "IDLE"
        audit_log_event(username, "Paused Network Monitoring")
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
