"""
Unified Telemetry Ingestion Hub
Aggregates flows from OpenFlow, NetFlow, IPFIX, and External Sockets,
routes to HTTPS behavioral analyzer, runs ML detection, and triggers mitigation.
"""
import time
import logging
from typing import Dict, Any, List, Optional
from src.predict import DDoSPredictor
from telemetry.https_detector import HTTPSBehavioralAnalyzer
from mitigation.rule_manager import MitigationRuleManager

logger = logging.getLogger("TelemetryHub")

class TelemetryHub:
    def __init__(self, mitigation_mgr: MitigationRuleManager, predictor: Optional[DDoSPredictor] = None):
        self.mitigation_mgr = mitigation_mgr
        self.predictor = predictor or DDoSPredictor()
        self.https_analyzer = HTTPSBehavioralAnalyzer(window_sec=5.0)
        self.recent_flows: List[Dict[str, Any]] = []
        self.recent_detections: List[Dict[str, Any]] = []
        self.max_history = 500

    def ingest_flow(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest a normalized flow and execute full detection pipeline."""
        src_ip = flow_dict.get("src_ip", "0.0.0.0")
        dst_port = int(flow_dict.get("dst_port", 80))

        # Check if already mitigated
        if self.mitigation_mgr.is_blocked(src_ip):
            res = {
                "status": "DROPPED",
                "is_ddos": True,
                "category": "active_mitigation",
                "src_ip": src_ip,
                "confidence": 1.0,
                "flow": flow_dict
            }
            return res

        # Check if HTTPS / Port 443
        if dst_port == 443:
            analysis = self.https_analyzer.analyze_https_flow(flow_dict, self.predictor)
            is_ddos = analysis["is_ddos"]
            category = analysis["category"]
            confidence = analysis["confidence"]
        else:
            pred = self.predictor.predict_flow(flow_dict)
            is_ddos = pred["is_ddos"]
            category = pred["category"]
            confidence = pred["confidence"]

        record = {
            "timestamp": time.time(),
            "flow": flow_dict,
            "is_ddos": is_ddos,
            "category": category,
            "confidence": confidence,
            "src_ip": src_ip,
            "dst_ip": flow_dict.get("dst_ip", "10.0.0.100"),
            "dst_port": dst_port,
            "protocol": flow_dict.get("protocol", 6),
            "telemetry_source": flow_dict.get("telemetry_source", "OpenFlow")
        }

        # Automated mitigation on detection
        if is_ddos:
            is_new_block = self.mitigation_mgr.block_ip(
                ip_address=src_ip,
                category=category,
                confidence=confidence,
                flow_details=flow_dict
            )
            record["mitigation_triggered"] = is_new_block
            self.recent_detections.append(record)
            if len(self.recent_detections) > self.max_history:
                self.recent_detections.pop(0)

        self.recent_flows.append(record)
        if len(self.recent_flows) > self.max_history:
            self.recent_flows.pop(0)

        return record
