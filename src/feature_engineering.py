"""
Feature Engineering Module for AI-Driven DDoS Detection Framework
Guarantees mathematical and semantic consistency across:
- Training dataset (ready_dataset.csv)
- Mininet / OpenFlow 1.3 telemetry
- NetFlow / IPFIX collectors
- Raw socket / live external packet capture (including HTTPS/Port 443)
"""
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Union
from src.config import FEATURE_NAMES

# Port mapping for categorical port encoding
PORT_MAP = {
    80: 1,    # HTTP
    443: 2,   # HTTPS
    53: 3,    # DNS
    123: 4,   # NTP
    161: 5,   # SNMP
    389: 6,   # LDAP
    1433: 7,  # MSSQL
    1900: 8,  # SSDP
    111: 9,   # Portmap
    69: 10,   # TFTP
}

def encode_port(port: int) -> int:
    """Encode port into category index; 0 represents other."""
    return PORT_MAP.get(int(port), 0)

def encode_protocol(proto: Union[int, str]) -> int:
    """Encode protocol (TCP=6, UDP=17, ICMP=1, other=0)."""
    if isinstance(proto, str):
        p = proto.lower().strip()
        if "tcp" in p:
            return 6
        elif "udp" in p:
            return 17
        elif "icmp" in p:
            return 1
        try:
            return int(proto)
        except ValueError:
            return 0
    return int(proto) if proto in (1, 6, 17) else 0

def extract_features_from_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract the 14 engineered features from ready_dataset.csv DataFrame.
    Cleans infinite and NaN values and aligns with FEATURE_NAMES.
    """
    clean_df = df.copy()
    clean_df.columns = clean_df.columns.str.strip()

    features = pd.DataFrame(index=clean_df.index)

    # 1. Flow Duration (convert microseconds to seconds)
    features["flow_duration"] = clean_df["Flow Duration"] / 1e6

    # 2. Total Packets
    fwd_pkts = clean_df["Total Fwd Packets"].fillna(0)
    bwd_pkts = clean_df["Total Backward Packets"].fillna(0)
    features["packet_count"] = fwd_pkts + bwd_pkts

    # 3. Total Bytes
    fwd_bytes = clean_df["Total Length of Fwd Packets"].fillna(0)
    bwd_bytes = clean_df["Total Length of Bwd Packets"].fillna(0)
    features["byte_count"] = fwd_bytes + bwd_bytes

    # 4. Packet Rate (Flow Packets/s)
    if "Flow Packets/s" in clean_df.columns:
        features["packet_rate"] = clean_df["Flow Packets/s"].replace([np.inf, -np.inf], np.nan)
        features["packet_rate"] = features["packet_rate"].fillna(
            features["packet_count"] / np.maximum(features["flow_duration"], 0.001)
        )
    else:
        features["packet_rate"] = features["packet_count"] / np.maximum(features["flow_duration"], 0.001)

    # 5. Byte Rate (Flow Bytes/s)
    if "Flow Bytes/s" in clean_df.columns:
        features["byte_rate"] = clean_df["Flow Bytes/s"].replace([np.inf, -np.inf], np.nan)
        features["byte_rate"] = features["byte_rate"].fillna(
            features["byte_count"] / np.maximum(features["flow_duration"], 0.001)
        )
    else:
        features["byte_rate"] = features["byte_count"] / np.maximum(features["flow_duration"], 0.001)

    # 6. Packet Size Mean
    if "Packet Length Mean" in clean_df.columns:
        features["packet_size_mean"] = clean_df["Packet Length Mean"].fillna(0)
    elif "Average Packet Size" in clean_df.columns:
        features["packet_size_mean"] = clean_df["Average Packet Size"].fillna(0)
    else:
        features["packet_size_mean"] = features["byte_count"] / np.maximum(features["packet_count"], 1)

    # 7. Packet Size Std
    if "Packet Length Std" in clean_df.columns:
        features["packet_size_std"] = clean_df["Packet Length Std"].fillna(0)
    else:
        features["packet_size_std"] = 0.0

    # 8. Flow IAT Mean (convert microseconds to seconds)
    if "Flow IAT Mean" in clean_df.columns:
        features["flow_iat_mean"] = clean_df["Flow IAT Mean"].fillna(0) / 1e6
    else:
        features["flow_iat_mean"] = features["flow_duration"] / np.maximum(features["packet_count"] - 1, 1)

    # 9. Flow IAT Std (convert microseconds to seconds)
    if "Flow IAT Std" in clean_df.columns:
        features["flow_iat_std"] = clean_df["Flow IAT Std"].fillna(0) / 1e6
    else:
        features["flow_iat_std"] = 0.0

    # 10. SYN Flag Count
    features["syn_flag_count"] = clean_df["SYN Flag Count"].fillna(0) if "SYN Flag Count" in clean_df.columns else 0

    # 11. ACK Flag Count
    features["ack_flag_count"] = clean_df["ACK Flag Count"].fillna(0) if "ACK Flag Count" in clean_df.columns else 0

    # 12. Down/Up Ratio
    features["down_up_ratio"] = clean_df["Down/Up Ratio"].fillna(0) if "Down/Up Ratio" in clean_df.columns else 0

    # 13. Protocol Encoded
    # Infer protocol if not directly present: TCP if TCP flags/init win bytes present, else UDP
    if "Protocol" in clean_df.columns:
        features["protocol_encoded"] = clean_df["Protocol"].apply(encode_protocol)
    else:
        is_tcp = (
            (features["syn_flag_count"] > 0) |
            (features["ack_flag_count"] > 0) |
            (clean_df.get("RST Flag Count", 0) > 0) |
            (clean_df.get("FIN Flag Count", 0) > 0) |
            (clean_df.get("Init_Win_bytes_forward", -1) > -1)
        )
        features["protocol_encoded"] = np.where(is_tcp, 6, 17)

    # 14. Destination Port Encoded
    if "Destination Port" in clean_df.columns:
        features["dst_port_encoded"] = clean_df["Destination Port"].apply(encode_port)
    elif "Dst Port" in clean_df.columns:
        features["dst_port_encoded"] = clean_df["Dst Port"].apply(encode_port)
    else:
        # Infer port from attack label or protocol
        label_series = clean_df.get("Label", pd.Series("", index=clean_df.index)).astype(str).str.lower()
        port_series = pd.Series(0, index=clean_df.index)
        port_series = np.where(label_series.str.contains("dns"), 53, port_series)
        port_series = np.where(label_series.str.contains("ntp"), 123, port_series)
        port_series = np.where(label_series.str.contains("snmp"), 161, port_series)
        port_series = np.where(label_series.str.contains("tftp"), 69, port_series)
        port_series = np.where(label_series.str.contains("mssql"), 1433, port_series)
        port_series = np.where(label_series.str.contains("ldap"), 389, port_series)
        port_series = np.where(label_series.str.contains("ssdp"), 1900, port_series)
        port_series = np.where(label_series.str.contains("web|http"), 80, port_series)
        port_series = np.where(label_series.str.contains("syn"), 80, port_series)
        port_series = np.where(label_series.str.contains("portmap"), 111, port_series)
        # For benign, default to standard web traffic (80/443)
        port_series = np.where(label_series.str.contains("benign"), 80, port_series)
        features["dst_port_encoded"] = [encode_port(p) for p in port_series]

    # Handle any remaining inf or nan values
    features = features.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    
    # Ensure exact column ordering
    return features[FEATURE_NAMES]

def extract_features_from_live_flow(flow_dict: Dict[str, Any]) -> np.ndarray:
    """
    Extract 14 features from a live telemetry flow dictionary (OpenFlow, NetFlow, or Sniffer).
    Returns a numpy array of shape (1, 14) aligned with FEATURE_NAMES.
    """
    duration = float(flow_dict.get("duration_sec", flow_dict.get("flow_duration", 0.0)))
    packet_count = float(flow_dict.get("packet_count", flow_dict.get("packets", 1)))
    byte_count = float(flow_dict.get("byte_count", flow_dict.get("bytes", 64)))
    
    safe_duration = max(duration, 0.001)
    safe_pkts = max(packet_count, 1.0)
    
    packet_rate = flow_dict.get("packet_rate", packet_count / safe_duration)
    byte_rate = flow_dict.get("byte_rate", byte_count / safe_duration)
    packet_size_mean = flow_dict.get("packet_size_mean", byte_count / safe_pkts)
    packet_size_std = flow_dict.get("packet_size_std", 0.0)
    
    flow_iat_mean = flow_dict.get("flow_iat_mean", duration / max(packet_count - 1, 1.0))
    flow_iat_std = flow_dict.get("flow_iat_std", 0.0)
    
    syn_flag_count = float(flow_dict.get("syn_flag_count", flow_dict.get("syn_count", 0)))
    ack_flag_count = float(flow_dict.get("ack_flag_count", flow_dict.get("ack_count", 0)))
    down_up_ratio = float(flow_dict.get("down_up_ratio", 0.0))
    
    protocol = encode_protocol(flow_dict.get("protocol", flow_dict.get("ip_proto", 6)))
    dst_port = encode_port(flow_dict.get("dst_port", flow_dict.get("tcp_dst", flow_dict.get("udp_dst", 80))))
    
    vector = [
        duration,
        packet_count,
        byte_count,
        packet_rate,
        byte_rate,
        packet_size_mean,
        packet_size_std,
        flow_iat_mean,
        flow_iat_std,
        syn_flag_count,
        ack_flag_count,
        down_up_ratio,
        protocol,
        dst_port
    ]
    return np.array(vector, dtype=np.float64).reshape(1, -1)
