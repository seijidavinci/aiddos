"""
Ryu OpenFlow 1.3 DDoS Detection & Automated Mitigation Controller
Connects to OpenFlow 1.3 switches, polls flow statistics periodically,
runs real-time ML inference, and installs automated DROP rules upon detection.
"""
import time
import json
import logging
import requests
from typing import Dict, Any

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, icmp
    from ryu.lib import hub
    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False
    # Mock base class if running in environments where ryu is not installed
    class app_manager:
        class RyuApp:
            pass

from src.config import (
    FLOW_POLL_INTERVAL, DETECTION_THRESHOLD, MITIGATION_ENABLED,
    BLOCK_DURATION, BACKEND_HOST, BACKEND_PORT
)
from src.predict import DDoSPredictor
from controller.flow_monitor import FlowMonitor
from controller.feature_extractor import OpenFlowFeatureExtractor
from mitigation.rule_manager import MitigationRuleManager
from mitigation.openflow_mitigation import OpenFlowMitigationEngine

logger = logging.getLogger("RyuDDoSController")

class DDoSOpenFlowController(app_manager.RyuApp):
    if RYU_AVAILABLE:
        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSOpenFlowController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor = FlowMonitor()
        self.mitigation_mgr = MitigationRuleManager(default_duration=BLOCK_DURATION, enabled=MITIGATION_ENABLED)
        self.of_mitigation = OpenFlowMitigationEngine(controller=self)
        self.backend_url = f"http://{BACKEND_HOST}:{BACKEND_PORT}"

        # Initialize ML Predictor
        try:
            self.predictor = DDoSPredictor(threshold=DETECTION_THRESHOLD)
            logger.info("ML DDoSPredictor successfully loaded in SDN Controller.")
        except Exception as e:
            logger.error(f"Error loading ML Predictor in SDN Controller: {e}")
            self.predictor = None

        if RYU_AVAILABLE:
            self.monitor_thread = hub.spawn(self._monitor_loop)

    if RYU_AVAILABLE:
        @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
        def _state_change_handler(self, ev):
            datapath = ev.datapath
            if ev.state == MAIN_DISPATCHER:
                if datapath.id not in self.datapaths:
                    logger.info(f"Switch connected: Datapath ID {datapath.id}")
                    self.datapaths[datapath.id] = datapath
            elif ev.state == "DEAD":
                if datapath.id in self.datapaths:
                    logger.info(f"Switch disconnected: Datapath ID {datapath.id}")
                    del self.datapaths[datapath.id]

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features_handler(self, ev):
            """Install default Table-Miss flow entry (forward to Controller)."""
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            
            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=0,
                match=match,
                instructions=inst
            )
            datapath.send_msg(mod)
            logger.info(f"Installed table-miss entry on switch {datapath.id}")

        def _monitor_loop(self):
            """Periodic flow polling thread."""
            while True:
                for dp in self.datapaths.values():
                    self._request_flow_stats(dp)
                hub.sleep(FLOW_POLL_INTERVAL)

        def _request_flow_stats(self, datapath):
            """Send OFPFlowStatsRequest to switch."""
            parser = datapath.ofproto_parser
            req = parser.OFPFlowStatsRequest(datapath)
            datapath.send_msg(req)

        @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
        def flow_stats_reply_handler(self, ev):
            """Handle flow statistics reply, run ML detection, and trigger mitigation."""
            body = ev.msg.body
            datapath = ev.msg.datapath

            for stat in body:
                # Ignore table-miss rule (priority 0) and mitigation DROP rules (priority 1000+)
                if stat.priority <= 0 or stat.priority >= 1000:
                    continue

                # Extract telemetry and features
                raw_flow = OpenFlowFeatureExtractor.from_ofp_flow_stat(stat)
                flow = self.monitor.update_and_calculate_rates(raw_flow)
                src_ip = flow["src_ip"]

                # Run ML Prediction if predictor is ready
                if self.predictor is not None and src_ip != "0.0.0.0":
                    verdict = self.predictor.predict_flow(flow)
                    flow["is_ddos"] = verdict["is_ddos"]
                    flow["category"] = verdict["category"]
                    flow["probability"] = verdict["probability"]

                    if verdict["is_ddos"]:
                        logger.warning(
                            f"[ALERT: DDoS DETECTED] Src: {src_ip} -> Dst: {flow['dst_ip']}:{flow['dst_port']} "
                            f"| Category: {verdict['category']} | Prob: {verdict['probability']:.4f}"
                        )
                        # Trigger automated mitigation
                        is_new_block = self.mitigation_mgr.block_ip(
                            ip_address=src_ip,
                            duration=BLOCK_DURATION,
                            category=verdict["category"],
                            confidence=verdict["probability"],
                            flow_details=flow
                        )
                        if is_new_block:
                            # Install OpenFlow DROP rule
                            self.of_mitigation.install_drop_rule(
                                datapath=datapath,
                                src_ip=src_ip,
                                duration=BLOCK_DURATION,
                                priority=1000
                            )

                    # Relay flow & detection event to backend API
                    self._send_to_backend(flow, verdict)

        def _send_to_backend(self, flow: Dict[str, Any], verdict: Dict[str, Any]):
            """Send telemetry event to FastAPI backend asynchronously."""
            try:
                payload = {
                    "flow": flow,
                    "verdict": verdict,
                    "timestamp": time.time()
                }
                # Fire and forget POST to avoid blocking the OpenFlow reactor
                requests.post(f"{self.backend_url}/api/flows/ingest", json=payload, timeout=0.5)
            except Exception:
                pass  # Avoid crashing controller if backend is momentarily restarting
