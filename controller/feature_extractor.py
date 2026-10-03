"""
OpenFlow Flow Stats Feature Extractor
Extracts the 14 live features directly from OpenFlow 1.3 flow stats messages.
"""
import numpy as np
from typing import Dict, Any, List
from src.feature_engineering import extract_features_from_live_flow

class OpenFlowFeatureExtractor:
    @staticmethod
    def from_ofp_flow_stat(stat, prev_stat=None, delta_time: float = 2.0) -> Dict[str, Any]:
        """
        Translates an OpenFlow 1.3 OFPFlowStatsReply item into normalized telemetry.
        """
        match = stat.match
        duration_sec = stat.duration_sec + (stat.duration_nsec * 1e-9)
        packet_count = stat.packet_count
        byte_count = stat.byte_count

        # Compute delta rates if previous stat exists
        if prev_stat is not None and delta_time > 0:
            delta_pkts = max(0, packet_count - prev_stat.packet_count)
            delta_bytes = max(0, byte_count - prev_stat.byte_count)
            packet_rate = delta_pkts / delta_time
            byte_rate = delta_bytes / delta_time
        else:
            safe_dur = max(duration_sec, 0.001)
            packet_rate = packet_count / safe_dur
            byte_rate = byte_count / safe_dur

        packet_size_mean = byte_count / max(packet_count, 1)

        # Extract IPs and ports from match
        src_ip = match.get("ipv4_src", "0.0.0.0")
        dst_ip = match.get("ipv4_dst", "0.0.0.0")
        protocol = match.get("ip_proto", 6)
        dst_port = match.get("tcp_dst") or match.get("udp_dst") or 80

        flow_dict = {
            "src_ip": str(src_ip),
            "dst_ip": str(dst_ip),
            "protocol": protocol,
            "dst_port": dst_port,
            "duration_sec": duration_sec,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "packet_rate": packet_rate,
            "byte_rate": byte_rate,
            "packet_size_mean": packet_size_mean,
            "packet_size_std": 0.0,
            "flow_iat_mean": duration_sec / max(packet_count - 1, 1),
            "flow_iat_std": 0.0,
            "syn_flag_count": 0,
            "ack_flag_count": 0,
            "down_up_ratio": 0.0
        }
        return flow_dict
