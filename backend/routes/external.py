"""
External Traffic API Route
Aggregates metrics for external authorized traffic, HTTPS behavioral breakdown, and filters.
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional
from backend.database import get_db
from backend.models import FlowRecord, DetectionEvent, MitigationEvent
import time

router = APIRouter(prefix="/api/external", tags=["External Traffic"])

@router.get("/stats")
def get_external_traffic_stats(
    protocol: Optional[str] = None,
    service: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(FlowRecord)

    # Protocol filter
    if protocol:
        p_up = protocol.upper()
        if p_up == "TCP":
            query = query.filter(FlowRecord.protocol == 6)
        elif p_up == "UDP":
            query = query.filter(FlowRecord.protocol == 17)
        elif p_up == "ICMP":
            query = query.filter(FlowRecord.protocol == 1)

    # Service filter
    if service:
        s_up = service.upper()
        if s_up == "HTTPS":
            query = query.filter(FlowRecord.dst_port == 443)
        elif s_up == "HTTP":
            query = query.filter(FlowRecord.dst_port == 80)
        elif s_up == "DNS":
            query = query.filter(FlowRecord.dst_port == 53)

    # Status filter
    if status:
        st_up = status.upper()
        if st_up == "DDOS":
            query = query.filter(FlowRecord.is_ddos == True)
        elif st_up == "NORMAL":
            query = query.filter(FlowRecord.is_ddos == False)

    total_incoming = query.count()
    https_traffic = db.query(FlowRecord).filter(FlowRecord.dst_port == 443).count()
    http_traffic = db.query(FlowRecord).filter(FlowRecord.dst_port == 80).count()
    dns_traffic = db.query(FlowRecord).filter(FlowRecord.dst_port == 53).count()

    tcp_count = db.query(FlowRecord).filter(FlowRecord.protocol == 6).count()
    udp_count = db.query(FlowRecord).filter(FlowRecord.protocol == 17).count()
    icmp_count = db.query(FlowRecord).filter(FlowRecord.protocol == 1).count()

    suspicious_https = db.query(FlowRecord).filter(
        FlowRecord.dst_port == 443,
        FlowRecord.is_ddos == True
    ).count()

    # Top source IPs
    top_sources = (
        db.query(FlowRecord.src_ip, func.count(FlowRecord.id))
        .group_by(FlowRecord.src_ip)
        .order_by(func.count(FlowRecord.id).desc())
        .limit(6)
        .all()
    )

    now = time.time()
    active_mits = db.query(MitigationEvent).filter(
        MitigationEvent.status == "ACTIVE",
        MitigationEvent.expires_at > now
    ).count()

    return {
        "incoming_flow_count": total_incoming,
        "https_traffic": https_traffic,
        "http_traffic": http_traffic,
        "dns_traffic": dns_traffic,
        "protocol_distribution": {
            "TCP": tcp_count,
            "UDP": udp_count,
            "ICMP": icmp_count
        },
        "https_metrics": {
            "total_https_flows": https_traffic,
            "suspicious_https_flows": suspicious_https,
            "average_connection_rate_sec": 12.4,
            "tls_handshake_inspection": "Encrypted Transport Observable Metadata Only (Zero Payload Decryption)"
        },
        "top_source_ips": [{"ip": ip, "flows": count} for ip, count in top_sources],
        "active_mitigations": active_mits
    }
