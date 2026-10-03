"""
SQLAlchemy ORM Models for Telemetry, Detections, Mitigations, and System Status
"""
import time
from sqlalchemy import Column, Integer, Float, String, Boolean, DateTime
from backend.database import Base

class FlowRecord(Base):
    __tablename__ = "flow_records"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(Float, default=time.time, index=True)
    src_ip = Column(String, index=True)
    dst_ip = Column(String, index=True)
    src_port = Column(Integer, default=0)
    dst_port = Column(Integer, default=80)
    protocol = Column(Integer, default=6)
    duration_sec = Column(Float, default=0.0)
    packet_count = Column(Integer, default=0)
    byte_count = Column(Integer, default=0)
    packet_rate = Column(Float, default=0.0)
    byte_rate = Column(Float, default=0.0)
    is_ddos = Column(Boolean, default=False, index=True)
    category = Column(String, default="benign")
    telemetry_source = Column(String, default="OpenFlow")

class DetectionEvent(Base):
    __tablename__ = "detection_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(Float, default=time.time, index=True)
    src_ip = Column(String, index=True)
    dst_ip = Column(String)
    dst_port = Column(Integer, default=80)
    protocol = Column(Integer, default=6)
    is_ddos = Column(Boolean, default=True)
    category = Column(String, default="general_ddos")
    confidence = Column(Float, default=1.0)
    mitigated = Column(Boolean, default=False)
    telemetry_source = Column(String, default="OpenFlow")

class MitigationEvent(Base):
    __tablename__ = "mitigation_events"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, index=True)
    created_at = Column(Float, default=time.time, index=True)
    expires_at = Column(Float, index=True)
    duration = Column(Integer, default=60)
    status = Column(String, default="ACTIVE", index=True)  # ACTIVE, EXPIRED, REMOVED
    reason = Column(String, default="DDoS Attack")
    category = Column(String, default="general_ddos")
    confidence = Column(Float, default=1.0)
