"""
NetFlow v5 / v9 and IPFIX Telemetry Collector
Listens on UDP (default 2055) and decodes binary flow exports into normalized records.
"""
import socket
import struct
import threading
import logging
import time
from typing import Callable, Optional
from telemetry.normalizer import TelemetryNormalizer

logger = logging.getLogger("NetFlowCollector")

class NetFlowCollector:
    def __init__(self, host: str = "0.0.0.0", port: int = 2055, callback: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.callback = callback
        self.running = False
        self._sock = None
        self._thread = None

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()
        logger.info(f"NetFlow/IPFIX UDP Collector listening on {self.host}:{self.port}")

    def stop(self):
        self.running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def _listen_loop(self):
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind((self.host, self.port))
            self._sock.settimeout(1.0)
        except Exception as e:
            logger.warning(f"Could not bind NetFlow socket on port {self.port} (may already be in use or lack permissions): {e}")
            return

        while self.running:
            try:
                data, addr = self._sock.recvfrom(8192)
                self._parse_datagram(data)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    logger.error(f"Error receiving NetFlow datagram: {e}")

    def _parse_datagram(self, data: bytes):
        if len(data) < 24:
            return
        version = struct.unpack("!H", data[:2])[0]
        if version == 5:
            self._parse_netflow_v5(data)
        elif version in (9, 10):  # 9 = NetFlow v9, 10 = IPFIX
            self._parse_ipfix_header(data)

    def _parse_netflow_v5(self, data: bytes):
        header = data[:24]
        version, count, sys_uptime, unix_secs, unix_nsecs, flow_seq = struct.unpack("!HHIIII", header[:24])
        offset = 24
        for _ in range(min(count, 30)):
            if len(data) < offset + 48:
                break
            rec_bytes = data[offset:offset+48]
            src_ip = socket.inet_ntoa(rec_bytes[0:4])
            dst_ip = socket.inet_ntoa(rec_bytes[4:8])
            d_pkts = struct.unpack("!I", rec_bytes[16:20])[0]
            d_octets = struct.unpack("!I", rec_bytes[20:24])[0]
            first_ms = struct.unpack("!I", rec_bytes[24:28])[0]
            last_ms = struct.unpack("!I", rec_bytes[28:32])[0]
            src_port = struct.unpack("!H", rec_bytes[32:34])[0]
            dst_port = struct.unpack("!H", rec_bytes[34:36])[0]
            tcp_flags = rec_bytes[37]
            proto = rec_bytes[38]

            rec = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dPkts": d_pkts,
                "dOctets": d_octets,
                "first": first_ms,
                "last": last_ms,
                "src_port": src_port,
                "dst_port": dst_port,
                "tcp_flags": tcp_flags,
                "prot": proto
            }
            norm_flow = TelemetryNormalizer.from_netflow_v5(rec)
            if self.callback:
                self.callback(norm_flow.to_dict())
            offset += 48

    def _parse_ipfix_header(self, data: bytes):
        # Header length 16 bytes for IPFIX
        if len(data) >= 16:
            version, length, export_time = struct.unpack("!HHI", data[:8])
            logger.debug(f"Received IPFIX packet (len={length}, time={export_time})")
