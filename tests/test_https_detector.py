"""
Unit Tests for HTTPS Behavioral Detection (Port 443 without payload decryption)
"""
import pytest
from telemetry.https_detector import HTTPSBehavioralAnalyzer

def test_https_analyzer_zero_payload_decryption():
    analyzer = HTTPSBehavioralAnalyzer()
    
    # Benign browsing session
    benign_flow = {
        "src_ip": "10.0.0.50",
        "dst_port": 443,
        "protocol": 6,
        "duration_sec": 3.0,
        "packet_count": 15,
        "byte_count": 12000,
        "syn_flag_count": 1,
        "ack_flag_count": 14
    }
    res_benign = analyzer.analyze_https_flow(benign_flow)
    assert res_benign["payload_decrypted"] is False
    assert res_benign["is_https"] is True
    assert res_benign["is_ddos"] is False

    # SYN flood on port 443
    syn_flood_flow = {
        "src_ip": "10.0.0.99",
        "dst_port": 443,
        "protocol": 6,
        "duration_sec": 1.0,
        "packet_count": 200,
        "byte_count": 12800,
        "syn_flag_count": 200,
        "ack_flag_count": 0
    }
    res_attack = analyzer.analyze_https_flow(syn_flood_flow)
    assert res_attack["payload_decrypted"] is False
    assert res_attack["is_ddos"] is True
    assert "syn_flood" in res_attack["category"]
