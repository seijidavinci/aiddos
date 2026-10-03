"""
FastAPI Backend Main Application
AI-Driven DDoS Detection and Automated Mitigation Framework
"""
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.database import init_db
from backend.routes import stats, flows, detections, mitigations, models_route, system, external
from src.config import BACKEND_HOST, BACKEND_PORT

app = FastAPI(
    title="AI-Driven DDoS Detection and Automated Mitigation Framework API",
    description="REST API for SDN Flow Telemetry, ML Detection, Automated Mitigation, and Live Monitoring",
    version="1.0.0"
)

# Enable CORS for React Dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database tables
@app.on_event("startup")
def startup_event():
    init_db()

# Include all routers
app.include_router(stats.router)
app.include_router(flows.router)
app.include_router(detections.router)
app.include_router(mitigations.router)
app.include_router(models_route.router)
app.include_router(system.router)
app.include_router(external.router)

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host=BACKEND_HOST, port=BACKEND_PORT, reload=False)
