"""
Flow Monitor Module
Maintains historical flow statistics state and calculates delta metrics across polling intervals.
"""
import time
from typing import Dict, Any, Optional

class FlowMonitor:
    def __init__(self):
        # Key: (src_ip, dst_ip, protocol, dst_port) -> { 'packet_count', 'byte_count', 'timestamp' }
        self.flow_history: Dict[tuple, Dict[str, Any]] = {}

    def get_flow_key(self, flow: Dict[str, Any]) -> tuple:
        return (
            flow.get("src_ip", "0.0.0.0"),
            flow.get("dst_ip", "0.0.0.0"),
            int(flow.get("protocol", 6)),
            int(flow.get("dst_port", 80))
        )

    def update_and_calculate_rates(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Updates flow history and computes accurate instantaneous packet_rate and byte_rate.
        """
        key = self.get_flow_key(flow)
        now = time.time()
        current_pkts = float(flow.get("packet_count", 0))
        current_bytes = float(flow.get("byte_count", 0))

        updated_flow = dict(flow)

        if key in self.flow_history:
            prev = self.flow_history[key]
            delta_t = max(now - prev["timestamp"], 0.1)
            delta_pkts = max(0.0, current_pkts - prev["packet_count"])
            delta_bytes = max(0.0, current_bytes - prev["byte_count"])

            updated_flow["packet_rate"] = delta_pkts / delta_t
            updated_flow["byte_rate"] = delta_bytes / delta_t
        else:
            dur = max(float(flow.get("duration_sec", 0.001)), 0.001)
            updated_flow["packet_rate"] = current_pkts / dur
            updated_flow["byte_rate"] = current_bytes / dur

        self.flow_history[key] = {
            "packet_count": current_pkts,
            "byte_count": current_bytes,
            "timestamp": now
        }
        return updated_flow

    def prune_stale_flows(self, timeout_sec: float = 60.0):
        """Remove flow records inactive for longer than timeout_sec."""
        now = time.time()
        keys_to_remove = [k for k, v in self.flow_history.items() if now - v["timestamp"] > timeout_sec]
        for k in keys_to_remove:
            del self.flow_history[k]
