"""
Unit Tests for Telemetry Normalizer and Flow Monitoring
"""
import pytest
from telemetry.normalizer import TelemetryNormalizer, NormalizedFlow
from controller.flow_monitor import FlowMonitor

def test_telemetry_normalizer_openflow():
    stat = {
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.100",
        "protocol": 6,
        "dst_port": 80,
        "duration_sec": 2.0,
        "packet_count": 20,
        "byte_count": 2000
    }
    norm = TelemetryNormalizer.from_openflow(stat)
    d = norm.to_dict()
    assert d["src_ip"] == "10.0.0.1"
    assert d["dst_port"] == 80
    assert d["packet_rate"] == 10.0
    assert d["byte_rate"] == 1000.0
    assert d["telemetry_source"] == "OpenFlow_1.3"

def test_telemetry_normalizer_netflow_and_socket():
    netflow_rec = {
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.1",
        "dPkts": 100,
        "dOctets": 6400,
        "first": 1000,
        "last": 3000,
        "src_port": 45000,
        "dst_port": 53,
        "tcp_flags": 0x02,
        "prot": 17
    }
    norm_nf = TelemetryNormalizer.from_netflow_v5(netflow_rec)
    assert norm_nf.protocol == 17
    assert norm_nf.dst_port == 53
    assert norm_nf.telemetry_source == "NetFlow_v5"

def test_flow_monitor_rate_delta():
    monitor = FlowMonitor()
    flow_1 = {
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.100",
        "protocol": 6,
        "dst_port": 80,
        "packet_count": 10,
        "byte_count": 1000,
        "duration_sec": 1.0
    }
    updated_1 = monitor.update_and_calculate_rates(flow_1)
    assert updated_1["packet_rate"] > 0

    flow_2 = {
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.100",
        "protocol": 6,
        "dst_port": 80,
        "packet_count": 30,
        "byte_count": 3000,
        "duration_sec": 2.0
    }
    updated_2 = monitor.update_and_calculate_rates(flow_2)
    assert "packet_rate" in updated_2
    assert "byte_rate" in updated_2
