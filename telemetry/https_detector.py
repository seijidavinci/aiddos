"""
HTTPS / TLS Behavioral DDoS Detection Subsystem
Analyzes encrypted traffic targeting TCP Port 443 WITHOUT payload decryption.
Extracts observable transport-layer metadata and leverages the trained ML engine
to differentiate legitimate web browsing from TLS exhaustion, SYN floods,
and low-rate connection attacks.
"""
import time
from typing import Dict, Any, List
from collections import defaultdict, deque
import numpy as np

class HTTPSBehavioralAnalyzer:
    def __init__(self, window_sec: float = 5.0):
        self.window_sec = window_sec
        # Sliding windows by IP: deque of timestamps
        self.connection_history = defaultdict(lambda: deque())
        self.syn_history = defaultdict(lambda: deque())
        self.ack_history = defaultdict(lambda: deque())

    def record_packet(self, src_ip: str, tcp_flags: int, byte_len: int, now: float = None):
        """Record packet-level metadata for rolling-window statistics."""
        if now is None:
            now = time.time()
        
        # Check SYN (0x02) and ACK (0x10)
        is_syn = bool(tcp_flags & 0x02)
        is_ack = bool(tcp_flags & 0x10)

        conn_q = self.connection_history[src_ip]
        conn_q.append((now, byte_len))

        if is_syn and not is_ack:
            self.syn_history[src_ip].append(now)
        if is_ack:
            self.ack_history[src_ip].append(now)

        # Prune old entries
        cutoff = now - self.window_sec
        while conn_q and conn_q[0][0] < cutoff:
            conn_q.popleft()
        while self.syn_history[src_ip] and self.syn_history[src_ip][0] < cutoff:
            self.syn_history[src_ip].popleft()
        while self.ack_history[src_ip] and self.ack_history[src_ip][0] < cutoff:
            self.ack_history[src_ip].popleft()

    def analyze_https_flow(self, flow: Dict[str, Any], predictor=None) -> Dict[str, Any]:
        """
        Analyze a TCP 443 flow record using observable metadata and ML inference.
        Returns behavioral breakdown and final verdict.
        """
        src_ip = flow.get("src_ip", "0.0.0.0")
        dst_port = int(flow.get("dst_port", 443))
        pkts = float(flow.get("packet_count", 1))
        bytes_count = float(flow.get("byte_count", 64))
        duration = max(float(flow.get("duration_sec", 1.0)), 0.001)
        pps = pkts / duration
        bps = bytes_count / duration
        avg_pkt_size = bytes_count / pkts

        now = time.time()
        cutoff = now - self.window_sec

        # Rolling window stats
        recent_conns = len([t for t, _ in self.connection_history[src_ip] if t >= cutoff])
        connection_rate = recent_conns / self.window_sec

        recent_syns = len([t for t in self.syn_history[src_ip] if t >= cutoff])
        recent_acks = len([t for t in self.ack_history[src_ip] if t >= cutoff])

        # Behavioral heuristics indicators
        syn_ack_ratio = (recent_syns + 1.0) / (recent_acks + 1.0)
        is_syn_flood = (recent_syns > 20 and syn_ack_ratio > 3.0) or (flow.get("syn_flag_count", 0) > 10 and flow.get("ack_flag_count", 0) == 0)
        is_conn_exhaustion = (duration > 15.0 and pps < 1.0 and bytes_count < 1000)
        is_rate_flooding = (pps > 150.0 and avg_pkt_size < 120)

        # Inject enriched features into flow dict
        enriched_flow = dict(flow)
        enriched_flow["protocol"] = 6
        enriched_flow["dst_port"] = 443
        enriched_flow["duration_sec"] = duration
        enriched_flow["packet_count"] = pkts
        enriched_flow["byte_count"] = bytes_count
        enriched_flow["packet_rate"] = pps
        enriched_flow["byte_rate"] = bps
        enriched_flow["packet_size_mean"] = avg_pkt_size
        enriched_flow["syn_flag_count"] = max(flow.get("syn_flag_count", 0), recent_syns)
        enriched_flow["ack_flag_count"] = max(flow.get("ack_flag_count", 0), recent_acks)

        # Run ML model if available
        ml_is_ddos = False
        ml_prob = 0.0
        ml_category = "benign_https"

        if predictor is not None:
            pred = predictor.predict_flow(enriched_flow)
            ml_is_ddos = pred["is_ddos"]
            ml_prob = pred["probability"]
            ml_category = pred["category"]

        # Behavioral classification
        attack_subtype = "none"
        if is_syn_flood:
            attack_subtype = "tcp_syn_flood_443"
        elif is_conn_exhaustion:
            attack_subtype = "low_rate_slowloris_tls"
        elif is_rate_flooding:
            attack_subtype = "https_request_rate_flood"
        elif connection_rate > 30.0:
            attack_subtype = "tls_connection_flood"

        is_ddos = ml_is_ddos or (attack_subtype != "none")
        final_category = attack_subtype if attack_subtype != "none" else (ml_category if ml_is_ddos else "benign_https")
        confidence = max(ml_prob, 0.85 if is_ddos else 0.95)

        return {
            "src_ip": src_ip,
            "dst_port": dst_port,
            "is_https": True,
            "is_ddos": is_ddos,
            "category": final_category,
            "confidence": round(confidence, 4),
            "connection_rate_per_sec": round(connection_rate, 2),
            "syn_ack_ratio": round(syn_ack_ratio, 2),
            "packets_per_sec": round(pps, 2),
            "bytes_per_sec": round(bps, 2),
            "average_packet_size": round(avg_pkt_size, 2),
            "flow_duration_sec": round(duration, 2),
            "payload_decrypted": False,  # Strict compliance: ZERO payload decryption
            "detection_method": "Observable Transport Metadata & ML"
        }
