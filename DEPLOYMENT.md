# Deployment Guide: AI-Driven DDoS Detection & Mitigation Framework in SDN

This guide provides end-to-end instructions for deploying the framework across three primary environments:
1. **Option A: Quickstart / Local Standalone (Windows, macOS, Linux)** — Ideal for demonstrations, development, and evaluation.
2. **Option B: Containerized Deployment (Docker & Docker Compose)** — Self-contained, multi-port isolated container stack.
3. **Option C: Full Production SDN Lab (Ubuntu / Linux with Mininet & Ryu OpenFlow 1.3)** — Hardware-accurate network namespace emulation with real OpenFlow switches and kernel namespaces.

---

## Architecture & Port Allocation

| Component | Technology | Default Port / Protocol | Purpose |
| :--- | :--- | :--- | :--- |
| **Dashboard UI** | React 18 + Vite | `3000/TCP` | Real-time analytics, mitigation monitor, live attack controls |
| **REST API Backend** | FastAPI + Uvicorn | `8000/TCP` | Telemetry ingestion, prediction API, SQLite ORM database |
| **OpenFlow Controller** | Ryu OpenFlow 1.3 | `6653/TCP` | SDN switch control plane, flow polling & FlowMod DROP rules |
| **Multi-source Telemetry** | Python Socket Server | `2055/UDP` | NetFlow v5/v9 & IPFIX collector |
| **External Sniffer** | Raw Socket / HTTPS | `8443/TCP` & `443/TCP` | Encrypted Port 443 telemetry analyzer (zero payload decryption) |

---

## Option A: Quickstart / Local Standalone (Windows / macOS / Linux)

### 1. Prerequisites
- **Python**: Version 3.10, 3.11, or 3.14 (`python --version`)
- **Node.js**: Version 18+ and npm (`node --version`, `npm --version`)
- **Git**: Installed and available in PATH

### 2. Environment Setup
```bash
# Clone or navigate to the repository
cd c:/CAPSTONE

# Create and activate a Python virtual environment (recommended)
python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install Dashboard dependencies
cd dashboard
npm install
cd ..
```

### 3. Launching the Entire Stack with One Command
Execute the unified orchestrator:
```bash
python run_system.py
```
This single command automatically:
1. Boots the **FastAPI backend** on `http://127.0.0.1:8000`.
2. Initializes the **cross-platform SDN switch & continuous detection engine**.
3. Starts the **React + Vite dashboard** on `http://localhost:3000`.
4. Runs an automated **controlled traffic cycle** (Benign -> SYN Flood -> HTTPS Flood -> UDP Flood) showing live detections and automatic 60-second mitigation countdowns.

### 4. Running Components Independently (Manual Mode)
If you prefer running each service in a dedicated terminal window:

- **Terminal 1: FastAPI Backend**
  ```bash
  python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
  ```
  Swagger Docs available at: `http://127.0.0.1:8000/docs`

- **Terminal 2: React Dashboard**
  ```bash
  cd dashboard
  npm run dev
  ```
  UI accessible at: `http://localhost:3000`

- **Terminal 3: Continuous SDN Simulator & Telemetry Engine**
  ```bash
  python -c "from controller.sdn_simulator import SDNEndToEndEngine; e = SDNEndToEndEngine(); e.start(); import time; time.sleep(3600)"
  ```

---

## Option B: Containerized Deployment (Docker & Docker Compose)

The repository includes a multi-stage `Dockerfile` and `docker-compose.yml`.

### 1. Prerequisites
- Docker Engine 20.10+ and Docker Compose v2+ (`docker --version`, `docker compose version`)

### 2. Build and Launch
```bash
# Build the images and launch the containers in detached mode
docker compose up --build -d

# View real-time container logs
docker compose logs -f
```

### 3. Access the Services
- **Dashboard UI**: `http://localhost:3000`
- **FastAPI REST API**: `http://localhost:8000`
- **Interactive Swagger Docs**: `http://localhost:8000/docs`
- **OpenFlow Controller Port**: `6653`
- **NetFlow / IPFIX Port**: `2055/UDP`

### 4. Stopping the Stack
```bash
docker compose down
```

---

## Option C: Full Production SDN Lab (Ubuntu / Linux with Mininet & Ryu)

This option provides hardware-accurate network namespace emulation using Linux kernel network namespaces and real Open vSwitch instances.

### 1. Host Requirements
- Ubuntu 20.04 LTS or 22.04 LTS (Physical host, VMware/VirtualBox VM, or WSL2 with custom kernel)
- Root/sudo privileges

### 2. Install Mininet and Open vSwitch
```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch hping3 iperf tcpdump curl
```

### 3. Deploy Step-by-Step

#### Step 1: Start Ryu OpenFlow 1.3 Controller
In **Terminal 1**:
```bash
ryu-manager controller/ddos_controller.py --verbose --ofp-tcp-listen-port 6653
```
*The controller will listen on port 6653 and initialize the table-miss flow rules.*

#### Step 2: Start the FastAPI Backend
In **Terminal 2**:
```bash
python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

#### Step 3: Build & Serve the Frontend Dashboard
In **Terminal 3**:
```bash
cd dashboard
npm install
npm run build
npx serve -s dist -l 3000
```

#### Step 4: Launch the Mininet Topology
In **Terminal 4**:
```bash
sudo python3 mininet/topology.py
```
This builds the 7-node network topology:
- `s1`: Open vSwitch (OpenFlow 1.3) connected to remote controller `127.0.0.1:6653`
- `h1` - `h4`: Attacker hosts (`10.0.0.1` – `10.0.0.4`)
- `h5`, `h6`: Legitimate clients (`10.0.0.5`, `10.0.0.6`)
- `h7`: Protected Web Server (`10.0.0.100`)

#### Step 5: Test Normal vs. Attack Traffic in Mininet CLI
Once the Mininet prompt appears (`mininet>`):

1. **Verify Legitimate Client Connectivity**:
   ```bash
   mininet> h5 curl http://10.0.0.100
   ```
   *Expected: HTTP 200 response with latency < 5ms.*

2. **Launch a TCP SYN Flood Attack from Attacker h1**:
   ```bash
   mininet> h1 hping3 -S -p 80 --flood 10.0.0.100 &
   ```
   *Within 2.0 seconds (polling interval), the flow monitor detects high packet-rate anomaly (>1,000 pps).*
   *The AI engine flags `is_ddos: true` with confidence >90%.*
   *The mitigation engine sends an OpenFlow `OFPFC_ADD` FlowMod command dropping all packets matching `ipv4_src=10.0.0.1`.*

3. **Verify Attacker is Blocked While Legitimate Client Retains Access**:
   ```bash
   # Attacker packets are completely dropped at the switch:
   mininet> h1 ping -c 3 10.0.0.100
   # Result: 100% packet loss for attacker!

   # Legitimate client traffic still flows freely:
   mininet> h5 ping -c 3 10.0.0.100
   # Result: 0% packet loss!
   ```

4. **Verify Active Drop Rules on Open vSwitch**:
   ```bash
   sudo ovs-ofctl -O OpenFlow13 dump-flows s1
   ```
   *Notice the high-priority flow rule with `priority=65535,actions=drop,hard_timeout=60`.*

---

## Configuration & Environment Variables

All operational settings can be modified in [config.yaml](file:///c:/CAPSTONE/config.yaml) or via environment variables:

```yaml
sdn_controller:
  host: "0.0.0.0"
  controller_port: 6653
  flow_poll_interval: 2.0           # Flow statistics polling frequency (seconds)

detection:
  detection_threshold: 0.50          # ML classification probability threshold

mitigation:
  mitigation_enabled: true           # Enable/disable automated flow drops
  block_duration: 60                 # Drop rule expiration timeout (seconds)
  duplicate_prevention: true         # Prevent duplicate rule installation
  auto_expiry: true                  # Auto unblock after timeout
```

---

## Verification & Health Check

Run the automated verification test suite to ensure all 21 unit and integration tests pass:
```bash
python -m pytest tests/ -v
```

Check API health endpoint:
```bash
curl http://127.0.0.1:8000/api/health
# Response: {"status": "ok", "service": "AI-Driven DDoS SDN Framework", "active_model": "KNN", "models_loaded": 4}
```
