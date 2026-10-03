"""
Pydantic Schemas for API Serialization and Request Validation
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class FlowIngestRequest(BaseModel):
    flow: Dict[str, Any]
    verdict: Optional[Dict[str, Any]] = None
    timestamp: Optional[float] = None

class FlowResponse(BaseModel):
    id: int
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: int
    packet_count: int
    byte_count: int
    packet_rate: float
    byte_rate: float
    is_ddos: bool
    category: str
    telemetry_source: str

    class Config:
        from_attributes = True

class DetectionResponse(BaseModel):
    id: int
    timestamp: float
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: int
    is_ddos: bool
    category: str
    confidence: float
    mitigated: bool
    telemetry_source: str

    class Config:
        from_attributes = True

class MitigationResponse(BaseModel):
    id: int
    ip_address: str
    created_at: float
    expires_at: float
    duration: int
    status: str
    reason: str
    category: str
    confidence: float
    remaining_sec: Optional[int] = 0

    class Config:
        from_attributes = True

class MitigationToggleRequest(BaseModel):
    enabled: bool

class ManualBlockRequest(BaseModel):
    ip_address: str
    duration: Optional[int] = 60
    reason: Optional[str] = "Manual Administrator Block"

class SystemStatusResponse(BaseModel):
    backend_status: str
    controller_status: str
    switch_status: str
    database_status: str
    current_model: str
    mitigation_enabled: bool
    active_mitigations_count: int
    cpu_percent: float
    memory_percent: float
    timestamp: float
