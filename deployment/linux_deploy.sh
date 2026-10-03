#!/usr/bin/env bash
# =====================================================================
# AI-Driven DDoS Detection & Automated Mitigation Framework in SDN
# Linux & macOS Automated Deployment Script
# =====================================================================

set -e

echo "======================================================================"
echo "   AI-DRIVEN DDOS DETECTION & AUTOMATED MITIGATION IN SDN"
echo "                LINUX / macOS DEPLOYMENT SCRIPT"
echo "======================================================================"
echo ""

# 1. Verify Python 3
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] python3 could not be found. Please install Python 3.10+."
    exit 1
fi
echo "[OK] Python version: $(python3 --version)"

# 2. Verify Node.js & npm
if ! command -v node &> /dev/null; then
    echo "[ERROR] node could not be found. Please install Node.js 18+."
    exit 1
fi
echo "[OK] Node.js version: $(node --version)"
echo "[OK] npm version: $(npm --version)"
echo ""

# 3. Virtual Environment Setup
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment (venv)..."
    python3 -m venv venv
fi
echo "[*] Activating virtual environment..."
source venv/bin/activate

# 4. Install Python dependencies
echo "[*] Installing Python dependencies..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo "[OK] Python dependencies verified."

# 5. Install Dashboard dependencies
if [ ! -d "dashboard/node_modules" ]; then
    echo "[*] Installing Dashboard dependencies (npm install)..."
    cd dashboard
    npm install
    cd ..
fi
echo "[OK] Dashboard dependencies verified."
echo ""

# 6. Run framework
echo "======================================================================"
echo "Launching Full Integrated Framework:"
echo "  - FastAPI Backend (http://127.0.0.1:8000)"
echo "  - React Dashboard (http://localhost:3000)"
echo "  - SDN Switch Simulator & Continuous Engine"
echo "======================================================================"
echo ""
python3 run_system.py
