# 🚀 HOW TO DEPLOY: AI-Driven DDoS Detection & Automated Mitigation Framework in SDN

This document provides **step-by-step instructions** to deploy and run the entire Capstone project from scratch on any system.

---

## 📋 Table of Contents
1. [System Requirements](#1-system-requirements)
2. [Quickstart: 1-Click Automated Deployment](#2-quickstart-1-click-automated-deployment)
3. [Manual Step-by-Step Deployment (Native Windows/Linux/macOS)](#3-manual-step-by-step-deployment-native-windows-linux-macos)
4. [Docker & Docker Compose Deployment](#4-docker--docker-compose-deployment)
5. [Hardware-Accurate Mininet + Ryu SDN Lab (Ubuntu/Linux)](#5-hardware-accurate-mininet--ryu-sdn-lab-ubuntu-linux)
6. [Accessing Services & Dashboards](#6-accessing-services--dashboards)
7. [Verification & Health Check](#7-verification--health-check)
8. [Troubleshooting & Common Questions](#8-troubleshooting--common-questions)

---

## 1. System Requirements

| Requirement | Minimum | Recommended |
| :--- | :--- | :--- |
| **Operating System** | Windows 10/11, Ubuntu 20.04/22.04 LTS, or macOS 12+ | Windows 11 or Ubuntu 22.04 LTS |
| **Python** | Python 3.10+ (tested on Python 3.11 and 3.14) | Python 3.11 / 3.14 (64-bit) |
| **Node.js & npm** | Node.js v18.0.0+ with npm v9+ | Node.js v20+ LTS |
| **RAM** | 4 GB | 8 GB or more |
| **Disk Space** | 2 GB free (excluding raw dataset archive) | 5 GB free |
| **Network Tools (Optional)** | `curl`, `hping3`, `tcpdump` | For active packet generation |

---

## 2. Quickstart: 1-Click Automated Deployment

### For Windows Users (CMD / PowerShell):
Double-click or execute the automated script from project root:
```cmd
deployment\windows_deploy.bat
```
*This checks your Python & Node.js environment, installs any missing packages, and boots the FastAPI backend, the React dashboard, and the continuous SDN telemetry engine.*

### For Linux / macOS / WSL2 Users:
Run the bash deployment script:
```bash
chmod +x deployment/linux_deploy.sh
./deployment/linux_deploy.sh
```

### For Docker Users:
```bash
deployment\docker_deploy.bat       # on Windows
# or
./deployment/docker_deploy.sh      # on Linux/macOS
```

---

## 3. Manual Step-by-Step Deployment (Native Windows / Linux / macOS)

If you prefer to start each service manually or inspect console logs in separate windows:

### Step 3.1: Clone / Navigate to Workspace
```bash
cd c:\CAPSTONE
```

### Step 3.2: Create and Activate Virtual Environment
```bash
# Windows PowerShell:
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS / Git Bash:
python3 -m venv venv
source venv/bin/activate
```

### Step 3.3: Install Backend Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3.4: Install Frontend Dashboard Dependencies
```bash
cd dashboard
npm install
cd ..
```

### Step 3.5: Run Services (in 3 Dedicated Terminals)

#### Terminal 1: FastAPI REST API Backend
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
*Expected output: `Application startup complete. Uvicorn running on http://127.0.0.1:8000`*

#### Terminal 2: React + Vite Dashboard UI
```bash
cd dashboard
npm run dev
```
*Expected output: `VITE ready in 250 ms. Local: http://localhost:3000/`*

#### Terminal 3: Continuous SDN Switch & Telemetry Detection Daemon
```bash
python -m src.live_service
```
*Expected output: `[SDNSimulator] SDN End-to-End Engine & Continuous Detection Loop started.`*
*This streams benign web flows, injects realistic attack bursts, runs 90%-calibrated ML classification, installs OpenFlow 1.3 DROP rules, and triggers 60s auto-expiry.*

---

## 4. Docker & Docker Compose Deployment

The framework includes a multi-stage `Dockerfile` and `docker-compose.yml` for isolated container execution.

### Step 4.1: Build and Launch Containers
```bash
docker compose up --build -d
```

### Step 4.2: Verify Running Containers
```bash
docker compose ps
```

### Step 4.3: Inspect Live Container Logs
```bash
docker compose logs -f ddos-framework
```

### Step 4.4: Stop the Stack
```bash
docker compose down
```

---

## 5. Hardware-Accurate Mininet + Ryu SDN Lab (Ubuntu / Linux)

For hardware-faithful software-defined network emulation using Linux kernel network namespaces and real Open vSwitch (OVS):

### Step 5.1: Install Mininet & Open vSwitch
```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch hping3 iperf tcpdump curl
```

### Step 5.2: Launch the 4 Components

#### Terminal 1: Start Ryu OpenFlow 1.3 Controller
```bash
ryu-manager controller/ddos_controller.py --verbose --ofp-tcp-listen-port 6653
```

#### Terminal 2: Start FastAPI Backend
```bash
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

#### Terminal 3: Serve React Frontend
```bash
cd dashboard
npm install && npm run build
npx serve -s dist -l 3000
```

#### Terminal 4: Launch Mininet Virtual Network Topology
```bash
sudo python3 mininet/topology.py
```
This builds a 7-node virtual SDN network:
- `s1`: OpenFlow 1.3 Switch
- `h1` - `h4`: Attacker hosts (`10.0.0.1` to `10.0.0.4`)
- `h5`, `h6`: Legitimate client hosts (`10.0.0.5`, `10.0.0.6`)
- `h7`: Protected web server (`10.0.0.100`)

### Step 5.3: Test Attack & Mitigation Inside Mininet CLI
```bash
# 1. Verify normal client connectivity:
mininet> h5 curl http://10.0.0.100

# 2. Launch SYN flood attack from attacker h1:
mininet> h1 hping3 -S -p 80 --flood 10.0.0.100 &

# 3. Within 2 seconds, the controller detects attack and installs DROP rule:
# Verify attacker is blocked (100% packet loss):
mininet> h1 ping -c 3 10.0.0.100

# 4. Verify legitimate client h5 continues normal communication unaffected:
mininet> h5 ping -c 3 10.0.0.100

# 5. Inspect Open vSwitch drop rules:
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
```

---

## 6. Accessing Services & Dashboards

Once deployed, access the services via your web browser:

| Interface | URL | Description |
| :--- | :--- | :--- |
| **Interactive Dashboard** | **`http://localhost:3000`** | Real-time traffic graphs, attack alerts, flow tables, active mitigation rules with live countdown timers |
| **FastAPI REST API** | **`http://127.0.0.1:8000`** | Core backend service, flow ingestion endpoint, SQLite ORM database |
| **Interactive Swagger Docs** | **`http://127.0.0.1:8000/docs`** | Live Swagger UI to inspect and test all 14+ REST API endpoints |
| **Live Stats Endpoint** | **`http://127.0.0.1:8000/api/stats`** | Real-time JSON telemetry metrics and category distributions |
| **Active Mitigations API** | **`http://127.0.0.1:8000/api/mitigations`** | JSON list of active/expired OpenFlow 1.3 DROP rules |
| **Model Evaluation Report**| **`http://127.0.0.1:8000/api/models`** | JSON metrics for 90% calibrated models & 9.2M whole dataset |
| **External Sniffer Telemetry** | **`http://127.0.0.1:8000/api/external/stats`**| Encrypted Port 443 HTTPS anomaly telemetry |

---

## 7. Verification & Health Check

### Run Automated Unit & Integration Tests
Run the 21-test automated suite to verify all framework subsystems:
```bash
python -m pytest tests/ -v
```
*Expected: `21 passed in ~6.0s (100% pass rate)`*

### Check Backend Health via cURL
```bash
curl http://127.0.0.1:8000/api/health
```
*Expected JSON response:*
```json
{
  "status": "ok",
  "service": "AI-Driven DDoS SDN Framework",
  "active_model": "KNN",
  "models_loaded": 4
}
```

---

## 8. Troubleshooting & Common Questions

### Q1: "Port 8000 or 3000 is already in use"
Check which process is using the port and terminate it:
- **Windows**:
  ```powershell
  netstat -ano | findstr :8000
  taskkill /PID <PID_NUMBER> /F
  ```
- **Linux / macOS**:
  ```bash
  lsof -ti:8000 | xargs kill -9
  lsof -ti:3000 | xargs kill -9
  ```

### Q2: "Cannot find model artifacts in models/"
If you are deploying on a fresh machine without pre-trained model files:
```bash
# Retrain 90% calibrated models:
python -m src.train_models
# Generate evaluation report & comparison plots:
python -m src.evaluate_models
```

### Q3: "How do I change the mitigation block duration or detection threshold?"
Open [config.yaml](file:///c:/CAPSTONE/config.yaml) and edit:
```yaml
detection:
  detection_threshold: 0.50     # Adjust classification sensitivity (0.10 to 0.90)

mitigation:
  mitigation_enabled: true      # Set to false to run in detection-only mode
  block_duration: 60            # Seconds before drop rule expires
```

---

## 📁 Key File Map

```
c:\CAPSTONE\
├── HOW_TO_DEPLOY.md              <-- This comprehensive deployment guide
├── DEPLOYMENT.md                 <-- Technical deployment specification
├── run_system.py                 <-- One-command Python launcher
├── config.yaml                   <-- Central framework configuration
├── Dockerfile                    <-- Container build definition
├── docker-compose.yml            <-- Multi-container orchestrator
│
├── deployment/                   <-- Helper scripts and templates
│   ├── windows_deploy.bat        <-- Windows 1-click launcher
│   ├── linux_deploy.sh           <-- Linux 1-click launcher
│   ├── docker_deploy.bat         <-- Docker Windows launcher
│   ├── docker_deploy.sh          <-- Docker Linux launcher
│   ├── systemd/                  <-- Linux systemd service unit files
│   └── nginx/                    <-- Production reverse proxy configuration
│
├── backend/                      <-- FastAPI REST API server & database
├── dashboard/                    <-- React 18 + Vite Web UI
├── controller/                   <-- Ryu OpenFlow 1.3 Controller & Switch Simulator
├── telemetry/                    <-- Multi-source normalizer & HTTPS engine
├── mitigation/                   <-- Rule Manager & OpenFlow FlowMod handler
├── traffic_generator/            <-- 8-profile controlled attack generator
├── mininet/                      <-- Mininet virtual SDN network topology
├── models/                       <-- Calibrated ML model artifacts (.joblib)
├── results/                      <-- Evaluation graphs (.png) and reports (.json)
└── tests/                        <-- 21 automated unit/integration tests
```
