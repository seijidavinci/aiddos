"""
External Network Telemetry Sniffer and Replay Module
Supports monitoring live authorized external traffic entering a server or gateway,
aggregating packet tuples into flows, and streaming to the ML detection engine.
"""
import time
import socket
import threading
import logging
from typing import Dict, Any, Callable, Optional
from collections import defaultdict
from telemetry.normalizer import NormalizedFlow

logger = logging.getLogger("ExternalSniffer")

class ExternalTrafficSniffer:
    def __init__(self, interface: str = "0.0.0.0", port: int = 8443, callback: Optional[Callable] = None):
        self.interface = interface
        self.port = port
        self.callback = callback
        self.running = False
        self._thread = None
        self._flows = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "start_time": time.time(),
            "last_time": time.time(),
            "syn_count": 0,
            "ack_count": 0
        })

    def start_listener(self):
        """Start raw or TCP telemetry listener on specified port."""
        self.running = True
        self._thread = threading.Thread(target=self._listener_loop, daemon=True)
        self._thread.start()
        logger.info(f"External Telemetry Listener active on {self.interface}:{self.port}")

    def stop(self):
        self.running = False

    def _listener_loop(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.interface, self.port))
            s.listen(128)
            s.settimeout(1.0)
        except Exception as e:
            logger.warning(f"Could not bind external listener to {self.port}: {e}")
            return

        while self.running:
            try:
                conn, addr = s.accept()
                # Record incoming external connection
                src_ip, src_port = addr
                self._record_connection(src_ip, src_port, self.port)
                conn.close()
            except socket.timeout:
                self._flush_active_flows()
                continue
            except Exception as e:
                if self.running:
                    logger.debug(f"External listener error: {e}")

    def _record_connection(self, src_ip: str, src_port: int, dst_port: int, byte_len: int = 250):
        key = (src_ip, dst_port)
        now = time.time()
        f = self._flows[key]
        f["packet_count"] += 1
        f["byte_count"] += byte_len
        f["last_time"] = now
        f["syn_count"] += 1
        f["ack_count"] += 1

    def _flush_active_flows(self):
        now = time.time()
        for (src_ip, dst_port), f in list(self._flows.items()):
            if now - f["last_time"] >= 1.0 and f["packet_count"] > 0:
                duration = max(now - f["start_time"], 0.1)
                norm_flow = NormalizedFlow(
                    src_ip=src_ip,
                    dst_ip="10.0.0.100",
                    protocol=6,
                    src_port=0,
                    dst_port=dst_port,
                    duration_sec=duration,
                    packet_count=f["packet_count"],
                    byte_count=f["byte_count"],
                    syn_flag_count=f["syn_count"],
                    ack_flag_count=f["ack_count"],
                    telemetry_source="External_Gateway"
                )
                if self.callback:
                    self.callback(norm_flow.to_dict())
                del self._flows[(src_ip, dst_port)]

    def replay_flow_stream(self, flows: list, delay_sec: float = 0.5):
        """Replay simulated or pcap-extracted flows through the telemetry engine."""
        for flow in flows:
            if not self.running:
                break
            if self.callback:
                self.callback(flow)
            time.sleep(delay_sec)
