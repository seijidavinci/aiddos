"""
Stats Route for Dashboard Overview
"""
import time
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.database import get_db
from backend.models import FlowRecord, DetectionEvent, MitigationEvent

router = APIRouter(prefix="/api/stats", tags=["Stats"])

@router.get("")
def get_global_stats(db: Session = Depends(get_db)):
    total_flows = db.query(FlowRecord).count()
    ddos_flows = db.query(FlowRecord).filter(FlowRecord.is_ddos == True).count()
    benign_flows = total_flows - ddos_flows
    detection_rate = round((ddos_flows / total_flows) * 100.0, 2) if total_flows > 0 else 0.0

    now = time.time()
    active_mitigations = db.query(MitigationEvent).filter(
        MitigationEvent.status == "ACTIVE",
        MitigationEvent.expires_at > now
    ).count()

    # Category breakdown
    cat_counts = (
        db.query(DetectionEvent.category, func.count(DetectionEvent.id))
        .group_by(DetectionEvent.category)
        .all()
    )
    category_distribution = {cat: count for cat, count in cat_counts}

    # Top attacking IPs
    top_attackers = (
        db.query(DetectionEvent.src_ip, func.count(DetectionEvent.id))
        .filter(DetectionEvent.is_ddos == True)
        .group_by(DetectionEvent.src_ip)
        .order_by(func.count(DetectionEvent.id).desc())
        .limit(5)
        .all()
    )

    # Traffic timeline (last 20 flow aggregates)
    recent_flows = (
        db.query(FlowRecord)
        .order_by(FlowRecord.id.desc())
        .limit(30)
        .all()
    )
    timeline = [
        {
            "id": f.id,
            "timestamp": f.timestamp,
            "packet_rate": round(f.packet_rate, 2),
            "byte_rate": round(f.byte_rate, 2),
            "is_ddos": f.is_ddos,
            "category": f.category
        }
        for f in reversed(recent_flows)
    ]

    return {
        "total_flows": total_flows,
        "benign_flows": benign_flows,
        "ddos_detections": ddos_flows,
        "detection_rate": detection_rate,
        "active_mitigations": active_mitigations,
        "category_distribution": category_distribution,
        "top_attacking_ips": [{"ip": ip, "count": count} for ip, count in top_attackers],
        "traffic_timeline": timeline,
        "timestamp": now
    }
