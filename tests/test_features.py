"""
Unit Tests for Feature Engineering & Pipeline Consistency
"""
import numpy as np
import pandas as pd
import pytest
from src.config import FEATURE_NAMES
from src.feature_engineering import (
    extract_features_from_df,
    extract_features_from_live_flow,
    encode_port,
    encode_protocol
)

def test_feature_count_and_order():
    assert len(FEATURE_NAMES) == 14, "Feature pipeline must contain exactly 14 features"
    
    # Test with dummy raw DataFrame
    dummy_df = pd.DataFrame({
        "Flow Duration": [1000000],
        "Total Fwd Packets": [5],
        "Total Backward Packets": [5],
        "Total Length of Fwd Packets": [500.0],
        "Total Length of Bwd Packets": [1000.0],
        "Flow Packets/s": [10.0],
        "Flow Bytes/s": [1500.0],
        "Packet Length Mean": [150.0],
        "Packet Length Std": [10.0],
        "Flow IAT Mean": [100000.0],
        "Flow IAT Std": [10000.0],
        "SYN Flag Count": [1],
        "ACK Flag Count": [9],
        "Down/Up Ratio": [1.0],
        "Protocol": [6],
        "Destination Port": [80],
        "Label": ["BENIGN"]
    })

    extracted = extract_features_from_df(dummy_df)
    assert list(extracted.columns) == FEATURE_NAMES, "Extracted DataFrame columns must match FEATURE_NAMES order"

def test_live_flow_extraction_vector():
    live_flow = {
        "duration_sec": 2.5,
        "packet_count": 50,
        "byte_count": 5000,
        "syn_flag_count": 0,
        "ack_flag_count": 50,
        "down_up_ratio": 1.0,
        "protocol": 6,
        "dst_port": 443
    }
    vector = extract_features_from_live_flow(live_flow)
    assert isinstance(vector, np.ndarray)
    assert vector.shape == (1, 14), f"Expected shape (1, 14), got {vector.shape}"
    assert vector[0, 0] == 2.5  # duration
    assert vector[0, 1] == 50.0  # packets
    assert vector[0, 13] == 2  # Port 443 encoded as 2

def test_port_and_protocol_encoders():
    assert encode_port(80) == 1
    assert encode_port(443) == 2
    assert encode_port(53) == 3
    assert encode_port(9999) == 0  # other

    assert encode_protocol("TCP") == 6
    assert encode_protocol("UDP") == 17
    assert encode_protocol("ICMP") == 1
    assert encode_protocol(6) == 6
