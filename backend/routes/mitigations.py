"""
Mitigations Route
"""
import time
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from backend.database import get_db
from backend.models import MitigationEvent
from backend.schemas import MitigationResponse, ManualBlockRequest, MitigationToggleRequest
from src.config import BLOCK_DURATION

router = APIRouter(prefix="/api/mitigations", tags=["Mitigations"])
_MITIGATION_ENABLED_STATE = True

@router.get("", response_model=List[MitigationResponse])
def get_mitigations(active_only: bool = False, db: Session = Depends(get_db)):
    now = time.time()
    query = db.query(MitigationEvent)
    if active_only:
        query = query.filter(MitigationEvent.status == "ACTIVE", MitigationEvent.expires_at > now)
    
    events = query.order_by(MitigationEvent.id.desc()).limit(100).all()
    results = []
    for e in events:
        rem = max(0, int(e.expires_at - now)) if e.status == "ACTIVE" else 0
        r_dict = {
            "id": e.id,
            "ip_address": e.ip_address,
            "created_at": e.created_at,
            "expires_at": e.expires_at,
            "duration": e.duration,
            "status": "ACTIVE" if (e.status == "ACTIVE" and e.expires_at > now) else "EXPIRED",
            "reason": e.reason,
            "category": e.category,
            "confidence": e.confidence,
            "remaining_sec": rem
        }
        results.append(MitigationResponse(**r_dict))
    return results

@router.post("/block")
def manual_block(req: ManualBlockRequest, db: Session = Depends(get_db)):
    now = time.time()
    dur = req.duration or BLOCK_DURATION
    expires_at = now + dur

    existing = db.query(MitigationEvent).filter(
        MitigationEvent.ip_address == req.ip_address,
        MitigationEvent.status == "ACTIVE",
        MitigationEvent.expires_at > now
    ).first()

    if existing:
        return {"status": "already_blocked", "message": f"IP {req.ip_address} is already active until {existing.expires_at}"}

    mit = MitigationEvent(
        ip_address=req.ip_address,
        created_at=now,
        expires_at=expires_at,
        duration=dur,
        status="ACTIVE",
        reason=req.reason or "Manual Admin Block",
        category="manual_mitigation",
        confidence=1.0
    )
    db.add(mit)
    db.commit()
    return {"status": "success", "blocked_ip": req.ip_address, "expires_at": expires_at}

@router.post("/unblock/{ip_address}")
def manual_unblock(ip_address: str, db: Session = Depends(get_db)):
    now = time.time()
    active_rules = db.query(MitigationEvent).filter(
        MitigationEvent.ip_address == ip_address,
        MitigationEvent.status == "ACTIVE"
    ).all()

    if not active_rules:
        return {"status": "not_found", "message": f"No active rule found for {ip_address}"}

    for r in active_rules:
        r.status = "REMOVED"
        r.expires_at = now
    db.commit()
    return {"status": "success", "unblocked_ip": ip_address}

@router.post("/toggle")
def toggle_mitigation(req: MitigationToggleRequest):
    global _MITIGATION_ENABLED_STATE
    _MITIGATION_ENABLED_STATE = req.enabled
    return {"status": "success", "mitigation_enabled": _MITIGATION_ENABLED_STATE}
