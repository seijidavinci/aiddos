#!/usr/bin/env bash
set -e

echo "======================================================================"
echo "   AI-DRIVEN DDOS DETECTION & AUTOMATED MITIGATION IN SDN"
echo "                DOCKER COMPOSE DEPLOYMENT"
echo "======================================================================"
echo ""

if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker is not installed or not in PATH."
    exit 1
fi

echo "[*] Building and launching containers in detached mode..."
docker compose up --build -d

echo ""
echo "[OK] Containers started successfully!"
echo "  - Dashboard UI:  http://localhost:3000"
echo "  - FastAPI API:   http://localhost:8000"
echo "  - Swagger Docs:  http://localhost:8000/docs"
echo ""
echo "Showing live logs (Press Ctrl+C to stop viewing logs):"
docker compose logs -f
