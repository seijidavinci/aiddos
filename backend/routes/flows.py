"""
Flow Records Route
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.database import get_db
from backend.models import FlowRecord, DetectionEvent, MitigationEvent
from backend.schemas import FlowResponse, FlowIngestRequest
import time

router = APIRouter(prefix="/api/flows", tags=["Flows"])

@router.get("", response_model=List[FlowResponse])
def get_flows(
    limit: int = Query(50, ge=1, le=500),
    is_ddos: Optional[bool] = None,
    protocol: Optional[int] = None,
    telemetry_source: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(FlowRecord)
    if is_ddos is not None:
        query = query.filter(FlowRecord.is_ddos == is_ddos)
    if protocol is not None:
        query = query.filter(FlowRecord.protocol == protocol)
    if telemetry_source is not None:
        query = query.filter(FlowRecord.telemetry_source == telemetry_source)

    flows = query.order_by(FlowRecord.id.desc()).limit(limit).all()
    return flows

@router.post("/ingest")
def ingest_flow(payload: FlowIngestRequest, db: Session = Depends(get_db)):
    flow_data = payload.flow
    verdict = payload.verdict or {}
    ts = payload.timestamp or time.time()

    is_ddos = verdict.get("is_ddos", False)
    category = verdict.get("category", "benign")

    # Record in FlowRecord table
    record = FlowRecord(
        timestamp=ts,
        src_ip=flow_data.get("src_ip", "0.0.0.0"),
        dst_ip=flow_data.get("dst_ip", "10.0.0.100"),
        src_port=flow_data.get("src_port", 0),
        dst_port=flow_data.get("dst_port", 80),
        protocol=flow_data.get("protocol", 6),
        duration_sec=flow_data.get("duration_sec", 1.0),
        packet_count=flow_data.get("packet_count", 1),
        byte_count=flow_data.get("byte_count", 64),
        packet_rate=flow_data.get("packet_rate", 1.0),
        byte_rate=flow_data.get("byte_rate", 64.0),
        is_ddos=is_ddos,
        category=category,
        telemetry_source=flow_data.get("telemetry_source", "OpenFlow")
    )
    db.add(record)

    # If attack, record in DetectionEvent
    if is_ddos:
        det = DetectionEvent(
            timestamp=ts,
            src_ip=record.src_ip,
            dst_ip=record.dst_ip,
            dst_port=record.dst_port,
            protocol=record.protocol,
            is_ddos=True,
            category=category,
            confidence=verdict.get("probability", 1.0),
            mitigated=True,
            telemetry_source=record.telemetry_source
        )
        db.add(det)

        # Check existing active mitigation in DB
        now = time.time()
        existing = db.query(MitigationEvent).filter(
            MitigationEvent.ip_address == record.src_ip,
            MitigationEvent.status == "ACTIVE",
            MitigationEvent.expires_at > now
        ).first()

        if not existing:
            mit = MitigationEvent(
                ip_address=record.src_ip,
                created_at=now,
                expires_at=now + 60,
                duration=60,
                status="ACTIVE",
                reason=f"Automated OpenFlow Mitigation: {category.upper()}",
                category=category,
                confidence=verdict.get("probability", 1.0)
            )
            db.add(mit)

    db.commit()
    return {"status": "success", "is_ddos": is_ddos, "category": category}
