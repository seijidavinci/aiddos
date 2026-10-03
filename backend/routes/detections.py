"""
Detections Route
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from backend.database import get_db
from backend.models import DetectionEvent
from backend.schemas import DetectionResponse

router = APIRouter(prefix="/api/detections", tags=["Detections"])

@router.get("", response_model=List[DetectionResponse])
def get_detections(
    limit: int = Query(50, ge=1, le=500),
    category: Optional[str] = None,
    src_ip: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(DetectionEvent)
    if category is not None:
        query = query.filter(DetectionEvent.category == category)
    if src_ip is not None:
        query = query.filter(DetectionEvent.src_ip == src_ip)

    detections = query.order_by(DetectionEvent.id.desc()).limit(limit).all()
    return detections

@router.get("/latest", response_model=List[DetectionResponse])
def get_latest_detections(db: Session = Depends(get_db)):
    return db.query(DetectionEvent).order_by(DetectionEvent.id.desc()).limit(10).all()
