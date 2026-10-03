"""
Integration Tests for FastAPI Backend Endpoints
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c

def test_api_health(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json()["status"] == "HEALTHY"

def test_api_stats(client):
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_flows" in data
    assert "detection_rate" in data

def test_api_flow_ingestion(client):
    payload = {
        "flow": {
            "src_ip": "10.0.0.99",
            "dst_ip": "10.0.0.100",
            "dst_port": 80,
            "protocol": 6,
            "packet_count": 250,
            "byte_count": 16000,
            "packet_rate": 250.0,
            "byte_rate": 16000.0,
            "telemetry_source": "TestClient"
        },
        "verdict": {
            "is_ddos": True,
            "category": "syn_flood",
            "probability": 0.99
        }
    }
    res = client.post("/api/flows/ingest", json=payload)
    assert res.status_code == 200
    assert res.json()["status"] == "success"

def test_api_detections_and_mitigations(client):
    # Detections query
    det_res = client.get("/api/detections")
    assert det_res.status_code == 200
    assert isinstance(det_res.json(), list)

    # Mitigations query
    mit_res = client.get("/api/mitigations")
    assert mit_res.status_code == 200
    assert isinstance(mit_res.json(), list)

def test_api_models_and_system(client):
    m_res = client.get("/api/models")
    assert m_res.status_code == 200
    assert "current_active_model" in m_res.json()

    sys_res = client.get("/api/system")
    assert sys_res.status_code == 200
    assert sys_res.json()["backend_status"] == "ONLINE"
