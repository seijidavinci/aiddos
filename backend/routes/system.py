"""
System and Health Check Route
"""
import time
import psutil
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models import MitigationEvent
from backend.schemas import SystemStatusResponse

router = APIRouter(tags=["System"])

@router.get("/api/health")
def health_check():
    return {
        "status": "HEALTHY",
        "service": "AI-Driven DDoS SDN Framework Backend",
        "timestamp": time.time()
    }

@router.get("/api/system", response_model=SystemStatusResponse)
def get_system_status(db: Session = Depends(get_db)):
    now = time.time()
    active_mits = db.query(MitigationEvent).filter(
        MitigationEvent.status == "ACTIVE",
        MitigationEvent.expires_at > now
    ).count()

    cpu_usage = psutil.cpu_percent(interval=None)
    mem_usage = psutil.virtual_memory().percent

    return SystemStatusResponse(
        backend_status="ONLINE",
        controller_status="CONNECTED",
        switch_status="ACTIVE_DPID_1",
        database_status="CONNECTED_SQLITE",
        current_model="Random Forest",
        mitigation_enabled=True,
        active_mitigations_count=active_mits,
        cpu_percent=cpu_usage,
        memory_percent=mem_usage,
        timestamp=now
    )
