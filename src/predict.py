"""
Real-time Inference Engine for DDoS SDN Framework
Loads trained model and scaler, predicts DDoS probability and class for live incoming flows.
"""
import os
import joblib
import numpy as np
from typing import Dict, Any, Tuple
from src.config import BEST_MODEL_PATH, SCALER_PATH, DETECTION_THRESHOLD
from src.feature_engineering import extract_features_from_live_flow
from src.preprocessing import PreprocessingPipeline

class DDoSPredictor:
    def __init__(self, model_path: str = str(BEST_MODEL_PATH), threshold: float = DETECTION_THRESHOLD):
        self.model_path = model_path
        self.threshold = threshold
        self.pipeline = PreprocessingPipeline()
        self.model = None
        self._load_model()

    def _load_model(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        else:
            raise FileNotFoundError(f"Trained model not found at {self.model_path}. Train models first.")

    def predict_flow(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a live flow dictionary and return detection verdict.
        Input flow_dict keys:
        - duration_sec, packet_count, byte_count
        - syn_flag_count, ack_flag_count, down_up_ratio
        - protocol (e.g. 6 for TCP, 17 for UDP, 1 for ICMP)
        - dst_port (e.g. 80, 443, 53)
        """
        # 1. Feature extraction
        raw_vector = extract_features_from_live_flow(flow_dict)

        # 2. Scaling
        scaled_vector = self.pipeline.transform_live_vector(raw_vector)

        # 3. Model inference
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(scaled_vector)[0]
            ddos_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
        else:
            pred = self.model.predict(scaled_vector)[0]
            ddos_prob = 1.0 if pred == 1 else 0.0

        is_ddos = bool(ddos_prob >= self.threshold)

        # Classification rule / category determination
        category = "benign"
        if is_ddos:
            proto = int(flow_dict.get("protocol", flow_dict.get("ip_proto", 6)))
            dst_port = int(flow_dict.get("dst_port", flow_dict.get("tcp_dst", 80)))
            syns = float(flow_dict.get("syn_flag_count", 0))
            pkts = float(flow_dict.get("packet_count", 1))
            dur = float(flow_dict.get("duration_sec", 1.0))
            pps = pkts / max(dur, 0.001)

            if dst_port == 443:
                category = "https_flood"
            elif proto == 6 and syns / max(pkts, 1) > 0.6:
                category = "syn_flood"
            elif proto == 17 and dst_port == 53:
                category = "dns_amplification"
            elif proto == 17:
                category = "udp_flood"
            elif proto == 1:
                category = "icmp_flood"
            elif pps < 5.0 and dur > 10.0:
                category = "slowloris_low_rate"
            elif dst_port == 80 and pps > 50.0:
                category = "http_get_flood"
            else:
                category = "pulsed_mixed_flood"

        return {
            "is_ddos": is_ddos,
            "probability": round(ddos_prob, 4),
            "confidence": round(ddos_prob if is_ddos else 1.0 - ddos_prob, 4),
            "category": category,
            "threshold": self.threshold
        }
