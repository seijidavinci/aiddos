"""
High-Fidelity Cross-Platform SDN Switch & OpenFlow 1.3 Controller Simulator
Faithfully emulates:
- OpenFlow 1.3 Switch with DPID 1 and flow table
- Periodic flow statistics polling every FLOW_POLL_INTERVAL
- Real-time feature extraction and ML model inference
- Automated OpenFlow DROP rule installation with timeout and duplicate prevention
- Direct communication with FastAPI Backend
"""
import time
import json
import logging
import threading
import requests
from typing import Dict, Any, List
from src.config import (
    FLOW_POLL_INTERVAL, DETECTION_THRESHOLD, MITIGATION_ENABLED,
    BLOCK_DURATION, BACKEND_HOST, BACKEND_PORT
)
from src.predict import DDoSPredictor
from controller.flow_monitor import FlowMonitor
from mitigation.rule_manager import MitigationRuleManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("SDNSimulator")

class SDNSwitchSimulator:
    def __init__(self, dpid: int = 1):
        self.dpid = dpid
        # Flow table: list of rules
        self.flow_table: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self.install_table_miss()

    def install_table_miss(self):
        with self._lock:
            self.flow_table = [{
                "priority": 0,
                "match": {},
                "action": "CONTROLLER",
                "packet_count": 0,
                "byte_count": 0,
                "duration_sec": 0.0
            }]

    def install_drop_rule(self, src_ip: str, priority: int = 1000, timeout: int = 60):
        with self._lock:
            # Check existing
            for r in self.flow_table:
                if r.get("match", {}).get("ipv4_src") == src_ip and r["action"] == "DROP":
                    r["expires_at"] = time.time() + timeout
                    return False

            rule = {
                "priority": priority,
                "match": {"ipv4_src": src_ip},
                "action": "DROP",
                "installed_at": time.time(),
                "expires_at": time.time() + timeout,
                "packet_count": 0,
                "byte_count": 0
            }
            self.flow_table.append(rule)
            logger.info(f"[SWITCH DPID {self.dpid}] OpenFlow 1.3 DROP rule installed for {src_ip} (Timeout: {timeout}s)")
            return True

    def remove_expired_rules(self):
        now = time.time()
        with self._lock:
            active = []
            for r in self.flow_table:
                if r["action"] == "DROP" and r.get("expires_at", 0) <= now:
                    logger.info(f"[SWITCH DPID {self.dpid}] OpenFlow 1.3 DROP rule expired for {r['match'].get('ipv4_src')}")
                else:
                    active.append(r)
            self.flow_table = active

    def inject_traffic_flow(self, flow_dict: Dict[str, Any]):
        """Inject a simulated network flow into the switch."""
        src_ip = flow_dict.get("src_ip", "10.0.0.1")
        # Check if dropped
        with self._lock:
            for r in self.flow_table:
                if r["action"] == "DROP" and r.get("match", {}).get("ipv4_src") == src_ip:
                    r["packet_count"] += flow_dict.get("packet_count", 1)
                    r["byte_count"] += flow_dict.get("byte_count", 64)
                    return "DROPPED"

        # Otherwise record active flow
        flow_entry = {
            "priority": 10,
            "match": {
                "ipv4_src": src_ip,
                "ipv4_dst": flow_dict.get("dst_ip", "10.0.0.100"),
                "ip_proto": flow_dict.get("protocol", 6),
                "dst_port": flow_dict.get("dst_port", 80)
            },
            "action": "OUTPUT:PORT_1",
            "packet_count": flow_dict.get("packet_count", 10),
            "byte_count": flow_dict.get("byte_count", 1500),
            "duration_sec": flow_dict.get("duration_sec", 1.0),
            "syn_flag_count": flow_dict.get("syn_flag_count", 0),
            "ack_flag_count": flow_dict.get("ack_flag_count", 0),
            "down_up_ratio": flow_dict.get("down_up_ratio", 0.0),
            "last_seen": time.time()
        }
        with self._lock:
            # Replace existing flow for this src
            self.flow_table = [r for r in self.flow_table if r.get("match", {}).get("ipv4_src") != src_ip or r["action"] == "DROP"]
            self.flow_table.append(flow_entry)
        return "FORWARDED"

    def get_flow_stats(self) -> List[Dict[str, Any]]:
        self.remove_expired_rules()
        with self._lock:
            return list(self.flow_table)

class SDNEndToEndEngine:
    def __init__(self, backend_url: str = f"http://{BACKEND_HOST}:{BACKEND_PORT}"):
        self.switch = SDNSwitchSimulator(dpid=1)
        self.monitor = FlowMonitor()
        self.mitigation_mgr = MitigationRuleManager(default_duration=BLOCK_DURATION, enabled=MITIGATION_ENABLED)
        self.predictor = DDoSPredictor(threshold=DETECTION_THRESHOLD)
        self.backend_url = backend_url
        self.running = False
        self._thread = None

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._detection_loop, daemon=True)
        self._thread.start()
        logger.info("SDN End-to-End Engine & Continuous Detection Loop started.")

    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2.0)
        self.mitigation_mgr.shutdown()

    def process_incoming_flow(self, raw_flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Directly process a single incoming flow (from Mininet, Scapy, or replay).
        Applies SDN switch matching, ML prediction, and automated mitigation.
        """
        src_ip = raw_flow.get("src_ip", "10.0.0.1")
        # Check switch drop table
        switch_action = self.switch.inject_traffic_flow(raw_flow)
        if switch_action == "DROPPED":
            return {
                "status": "DROPPED",
                "action": "MITIGATED_DROP",
                "is_ddos": True,
                "src_ip": src_ip,
                "reason": "Active OpenFlow DROP rule in effect"
            }

        # Flow rate tracking
        flow = self.monitor.update_and_calculate_rates(raw_flow)
        
        # Run ML Inference
        verdict = self.predictor.predict_flow(flow)
        flow["is_ddos"] = verdict["is_ddos"]
        flow["category"] = verdict["category"]
        flow["probability"] = verdict["probability"]
        flow["status"] = "DDoS" if verdict["is_ddos"] else "Normal"

        if verdict["is_ddos"]:
            logger.warning(
                f"[SDN ML DETECTOR] Attack Detected! Src: {src_ip} | Type: {verdict['category']} | Prob: {verdict['probability']:.4f}"
            )
            # Automated mitigation
            is_new = self.mitigation_mgr.block_ip(
                ip_address=src_ip,
                duration=BLOCK_DURATION,
                category=verdict["category"],
                confidence=verdict["probability"],
                flow_details=flow
            )
            if is_new:
                self.switch.install_drop_rule(src_ip=src_ip, timeout=BLOCK_DURATION)

        # Notify backend
        self._relay_to_backend(flow, verdict)
        return {
            "status": switch_action,
            "is_ddos": verdict["is_ddos"],
            "category": verdict["category"],
            "probability": verdict["probability"],
            "flow": flow
        }

    def _detection_loop(self):
        """Continuous SDN Flow Statistics Polling Loop (every FLOW_POLL_INTERVAL)."""
        while self.running:
            time.sleep(FLOW_POLL_INTERVAL)

            # Periodically remove flow-history entries that have gone stale.
            # This prevents unbounded memory growth during long-running
            # simulation and telemetry sessions.
            self.monitor.prune_stale_flows(timeout_sec=60.0)

            stats = self.switch.get_flow_stats()
            for r in stats:
                if r["priority"] <= 0 or r["action"] == "DROP":
                    continue
                match = r.get("match", {})
                src_ip = match.get("ipv4_src")
                if not src_ip:
                    continue

                flow = {
                    "src_ip": src_ip,
                    "dst_ip": match.get("ipv4_dst", "10.0.0.100"),
                    "protocol": match.get("ip_proto", 6),
                    "dst_port": match.get("dst_port", 80),
                    "duration_sec": r.get("duration_sec", 2.0),
                    "packet_count": r.get("packet_count", 10),
                    "byte_count": r.get("byte_count", 1000),
                    "syn_flag_count": r.get("syn_flag_count", 0),
                    "ack_flag_count": r.get("ack_flag_count", 0),
                    "down_up_ratio": r.get("down_up_ratio", 0.0)
                }
                flow = self.monitor.update_and_calculate_rates(flow)
                verdict = self.predictor.predict_flow(flow)

                if verdict["is_ddos"]:
                    is_new = self.mitigation_mgr.block_ip(
                        ip_address=src_ip,
                        duration=BLOCK_DURATION,
                        category=verdict["category"],
                        confidence=verdict["probability"],
                        flow_details=flow
                    )
                    if is_new:
                        self.switch.install_drop_rule(src_ip, timeout=BLOCK_DURATION)

                self._relay_to_backend(flow, verdict)

    def _relay_to_backend(self, flow: Dict[str, Any], verdict: Dict[str, Any]):
        try:
            payload = {
                "flow": flow,
                "verdict": verdict,
                "timestamp": time.time()
            }
            requests.post(f"{self.backend_url}/api/flows/ingest", json=payload, timeout=0.5)
        except Exception:
            pass
