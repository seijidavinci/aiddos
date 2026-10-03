"""
Controlled Traffic Generator for Mininet and Local Lab Environments
Simulates:
1. Benign Web/HTTPS traffic
2. SYN flood
3. UDP flood
4. ICMP flood
5. DNS amplification
6. HTTP GET flood
7. Slowloris low-rate connection exhaustion
8. Pulsed mixed flood
9. HTTPS flood (Port 443 TLS behavioral flood)

CRITICAL SECURITY CONSTRAINT:
All generation strictly targets authorized local test targets (localhost / 127.0.0.1 or 10.0.0.x Mininet hosts).
"""
import time
import socket
import threading
import logging
from typing import Dict, Any, Optional, Callable
import requests

logger = logging.getLogger("TrafficGenerator")

class TrafficGenerator:
    def __init__(
        self,
        target_ip: str = "10.0.0.100",
        backend_url: str = "http://127.0.0.1:8000",
        on_flow_generated: Optional[Callable] = None
    ):
        self.target_ip = target_ip
        self.backend_url = backend_url
        self.on_flow_generated = on_flow_generated
        self.stop_event = threading.Event()

    def _emit_flow(self, flow: Dict[str, Any]):
        """Dispatch generated flow to controller/telemetry callback and backend API."""
        if self.on_flow_generated:
            self.on_flow_generated(flow)
        else:
            try:
                payload = {
                    "flow": flow,
                    "timestamp": time.time()
                }
                requests.post(f"{self.backend_url}/api/flows/ingest", json=payload, timeout=0.5)
            except Exception:
                pass

    # 1. Benign Traffic
    def generate_benign_traffic(self, client_ip: str = "10.0.0.5", dst_port: int = 80, count: int = 10, interval: float = 0.5):
        logger.info(f"[BENIGN TRAFFIC] Generating {count} normal requests from {client_ip} to {self.target_ip}:{dst_port}")
        for _ in range(count):
            if self.stop_event.is_set():
                break
            flow = {
                "src_ip": client_ip,
                "dst_ip": self.target_ip,
                "src_port": 50000 + int(time.time() % 10000),
                "dst_port": dst_port,
                "protocol": 6,
                "duration_sec": 1.2,
                "packet_count": 8,
                "byte_count": 1420,
                "packet_rate": 6.67,
                "byte_rate": 1183.33,
                "syn_flag_count": 1,
                "ack_flag_count": 7,
                "down_up_ratio": 1.0,
                "telemetry_source": "Mininet_Host"
            }
            self._emit_flow(flow)
            time.sleep(interval)

    # 2. SYN Flood
    def generate_syn_flood(self, attacker_ip: str = "10.0.0.1", dst_port: int = 80, duration_sec: int = 10, pps: int = 250):
        logger.warning(f"[ATTACK: SYN FLOOD] Initiating SYN flood from {attacker_ip} -> {self.target_ip}:{dst_port} ({pps} pps for {duration_sec}s)")
        t_end = time.time() + duration_sec
        while time.time() < t_end and not self.stop_event.is_set():
            pkts = int(pps * 1.0)
            flow = {
                "src_ip": attacker_ip,
                "dst_ip": self.target_ip,
                "dst_port": dst_port,
                "protocol": 6,
                "duration_sec": 1.0,
                "packet_count": pkts,
                "byte_count": pkts * 64,
                "packet_rate": float(pkts),
                "byte_rate": float(pkts * 64),
                "syn_flag_count": pkts,
                "ack_flag_count": 0,
                "down_up_ratio": 0.0,
                "telemetry_source": "Mininet_Attacker"
            }
            self._emit_flow(flow)
            time.sleep(1.0)

    # 3. UDP Flood
    def generate_udp_flood(self, attacker_ip: str = "10.0.0.2", dst_port: int = 9999, duration_sec: int = 10, pps: int = 300):
        logger.warning(f"[ATTACK: UDP FLOOD] Initiating high-rate UDP flood from {attacker_ip} -> {self.target_ip}:{dst_port}")
        t_end = time.time() + duration_sec
        while time.time() < t_end and not self.stop_event.is_set():
            pkts = int(pps * 1.0)
            flow = {
                "src_ip": attacker_ip,
                "dst_ip": self.target_ip,
                "dst_port": dst_port,
                "protocol": 17,
                "duration_sec": 1.0,
                "packet_count": pkts,
                "byte_count": pkts * 512,
                "packet_rate": float(pkts),
                "byte_rate": float(pkts * 512),
                "syn_flag_count": 0,
                "ack_flag_count": 0,
                "down_up_ratio": 0.0,
                "telemetry_source": "Mininet_Attacker"
            }
            self._emit_flow(flow)
            time.sleep(1.0)

    # 4. ICMP Flood
    def generate_icmp_flood(self, attacker_ip: str = "10.0.0.3", duration_sec: int = 10, pps: int = 200):
        logger.warning(f"[ATTACK: ICMP FLOOD] Initiating ICMP ping flood from {attacker_ip} -> {self.target_ip}")
        t_end = time.time() + duration_sec
        while time.time() < t_end and not self.stop_event.is_set():
            pkts = int(pps * 1.0)
            flow = {
                "src_ip": attacker_ip,
                "dst_ip": self.target_ip,
                "dst_port": 0,
                "protocol": 1,
                "duration_sec": 1.0,
                "packet_count": pkts,
                "byte_count": pkts * 84,
                "packet_rate": float(pkts),
                "byte_rate": float(pkts * 84),
                "syn_flag_count": 0,
                "ack_flag_count": 0,
                "down_up_ratio": 0.0,
                "telemetry_source": "Mininet_Attacker"
            }
            self._emit_flow(flow)
            time.sleep(1.0)

    # 5. DNS Amplification
    def generate_dns_amplification(self, attacker_ip: str = "10.0.0.4", duration_sec: int = 10):
        logger.warning(f"[ATTACK: DNS AMPLIFICATION] Generating amplified DNS response flood from {attacker_ip}")
        t_end = time.time() + duration_sec
        while time.time() < t_end and not self.stop_event.is_set():
            flow = {
                "src_ip": attacker_ip,
                "dst_ip": self.target_ip,
                "dst_port": 53,
                "protocol": 17,
                "duration_sec": 1.0,
                "packet_count": 180,
                "byte_count": 180 * 1400,  # Amplified payload size
                "packet_rate": 180.0,
                "byte_rate": 252000.0,
                "syn_flag_count": 0,
                "ack_flag_count": 0,
                "down_up_ratio": 0.0,
                "telemetry_source": "Mininet_Attacker"
            }
            self._emit_flow(flow)
            time.sleep(1.0)

    # 6. HTTP GET Flood
    def generate_http_flood(self, attacker_ip: str = "10.0.0.2", duration_sec: int = 10, rps: int = 150):
        logger.warning(f"[ATTACK: HTTP GET FLOOD] Generating high-frequency HTTP requests from {attacker_ip}")
        t_end = time.time() + duration_sec
        while time.time() < t_end and not self.stop_event.is_set():
            flow = {
                "src_ip": attacker_ip,
                "dst_ip": self.target_ip,
                "dst_port": 80,
                "protocol": 6,
                "duration_sec": 1.0,
                "packet_count": rps * 3,
                "byte_count": rps * 450,
                "packet_rate": float(rps * 3),
                "byte_rate": float(rps * 450),
                "syn_flag_count": rps,
                "ack_flag_count": rps * 2,
                "down_up_ratio": 0.5,
                "telemetry_source": "Mininet_Attacker"
            }
            self._emit_flow(flow)
            time.sleep(1.0)

    # 7. Slowloris Low-Rate Attack
    def generate_slowloris(self, attacker_ip: str = "10.0.0.3", dst_port: int = 80, duration_sec: int = 15):
        logger.warning(f"[ATTACK: SLOWLORIS LOW-RATE] Generating low-rate connection holding attack from {attacker_ip}")
        flow = {
            "src_ip": attacker_ip,
            "dst_ip": self.target_ip,
            "dst_port": dst_port,
            "protocol": 6,
            "duration_sec": float(duration_sec),
            "packet_count": 6,  # Very few packets over long duration
            "byte_count": 320,
            "packet_rate": 6.0 / duration_sec,
            "byte_rate": 320.0 / duration_sec,
            "syn_flag_count": 1,
            "ack_flag_count": 5,
            "down_up_ratio": 0.1,
            "telemetry_source": "Mininet_Attacker"
        }
        self._emit_flow(flow)

    # 8. Pulsed Mixed Flood
    def generate_pulsed_flood(self, attacker_ip: str = "10.0.0.4", duration_sec: int = 12):
        logger.warning(f"[ATTACK: PULSED FLOOD] Generating pulsed intermittent bursts from {attacker_ip}")
        t_end = time.time() + duration_sec
        pulse_on = True
        while time.time() < t_end and not self.stop_event.is_set():
            if pulse_on:
                flow = {
                    "src_ip": attacker_ip,
                    "dst_ip": self.target_ip,
                    "dst_port": 80,
                    "protocol": 6,
                    "duration_sec": 1.0,
                    "packet_count": 280,
                    "byte_count": 280 * 200,
                    "packet_rate": 280.0,
                    "byte_rate": 56000.0,
                    "syn_flag_count": 50,
                    "ack_flag_count": 230,
                    "telemetry_source": "Mininet_Attacker"
                }
            else:
                flow = {
                    "src_ip": attacker_ip,
                    "dst_ip": self.target_ip,
                    "dst_port": 80,
                    "protocol": 6,
                    "duration_sec": 1.0,
                    "packet_count": 2,
                    "byte_count": 120,
                    "packet_rate": 2.0,
                    "byte_rate": 120.0,
                    "syn_flag_count": 0,
                    "ack_flag_count": 2,
                    "telemetry_source": "Mininet_Attacker"
                }
            self._emit_flow(flow)
            pulse_on = not pulse_on
            time.sleep(1.0)

    # 9. HTTPS Flood (Port 443 Encrypted Behavioral Flood)
    def generate_https_flood(self, attacker_ip: str = "10.0.0.1", subtype: str = "syn_flood_443", duration_sec: int = 10):
        logger.warning(f"[ATTACK: HTTPS PORT 443] Generating encrypted HTTPS behavioral attack ({subtype}) from {attacker_ip}")
        t_end = time.time() + duration_sec
        while time.time() < t_end and not self.stop_event.is_set():
            if subtype == "syn_flood_443":
                flow = {
                    "src_ip": attacker_ip,
                    "dst_ip": self.target_ip,
                    "dst_port": 443,
                    "protocol": 6,
                    "duration_sec": 1.0,
                    "packet_count": 220,
                    "byte_count": 220 * 64,
                    "packet_rate": 220.0,
                    "byte_rate": 14080.0,
                    "syn_flag_count": 220,
                    "ack_flag_count": 0,
                    "telemetry_source": "External_HTTPS_Gateway"
                }
            else:  # TLS connection exhaustion
                flow = {
                    "src_ip": attacker_ip,
                    "dst_ip": self.target_ip,
                    "dst_port": 443,
                    "protocol": 6,
                    "duration_sec": 12.0,
                    "packet_count": 8,
                    "byte_count": 520,
                    "packet_rate": 0.67,
                    "byte_rate": 43.33,
                    "syn_flag_count": 2,
                    "ack_flag_count": 6,
                    "telemetry_source": "External_HTTPS_Gateway"
                }
            self._emit_flow(flow)
            time.sleep(1.0)
