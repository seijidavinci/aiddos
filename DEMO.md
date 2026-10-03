# End-to-End System Demonstration Guide

This guide walks through the exact procedure for demonstrating the complete **AI-Driven DDoS Detection and Automated Mitigation Framework in SDN** to evaluators, faculty, and technical audiences.

---

## 1. Prerequisites & Environment Check

Verify that the project dependencies are installed and test suite passes:

```bash
# Run the automated test suite (21/21 passing)
python -m pytest tests/ -v
```

---

## 2. Quick-Start (Single Command Demo)

To launch the complete integrated framework (FastAPI Backend + SDN Switch Simulator + React Dashboard + Automated Traffic Generator) on any OS:

```bash
python run_system.py
```

This starts:
- **FastAPI Backend**: `http://127.0.0.1:8000` (API Docs: `http://127.0.0.1:8000/docs`)
- **React + Vite Dashboard**: `http://localhost:3000`
- **SDN Switch & Telemetry Engine**: Continuous 2.0s flow polling loop
- **Automated Traffic Demo**: Simulates benign browsing, TCP SYN floods, Port 443 HTTPS attacks, and UDP floods.

---

## 3. Step-by-Step Manual Demonstration Workflow

### Step 1: Start Backend
In Terminal 1:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
Verify endpoint: `http://127.0.0.1:8000/api/health` returns `{"status": "HEALTHY"}`.

### Step 2: Start React Dashboard
In Terminal 2:
```bash
cd dashboard
npm run dev
```
Open `http://localhost:3000` in your web browser. Observe:
- System status pills show `BACKEND: ONLINE`, `SDN SWITCH: DPID 1`, `MITIGATION: ENABLED`.
- Metric cards display zero active mitigations initially.

### Step 3: Start SDN Controller
- **On Linux / WSL2 with native Mininet**:
  ```bash
  ryu-manager controller/ddos_controller.py --ofp-tcp-listen-port 6653
  ```
  In a separate terminal, launch Mininet:
  ```bash
  sudo python3 mininet/topology.py
  ```
- **On Windows / macOS / Standalone Lab**:
  Run the cross-platform high-fidelity SDN engine:
  ```bash
  python -c "from controller.sdn_simulator import SDNEndToEndEngine; e = SDNEndToEndEngine(); e.start(); import time; time.sleep(3600)"
  ```

### Step 4: Generate Normal (Benign) Traffic
In Terminal 3, run benign traffic:
```bash
python -c "
from traffic_generator.generator import TrafficGenerator
g = TrafficGenerator()
print('Generating normal web and HTTPS browsing traffic...')
g.generate_benign_traffic(client_ip='10.0.0.5', dst_port=80, count=10)
g.generate_benign_traffic(client_ip='10.0.0.6', dst_port=443, count=10)
"
```
**Dashboard Observation**:
- Total flows count increments.
- Status displays **NORMAL** with green pills.
- DDoS Detections and Active Mitigations remain at 0.

### Step 5: Generate Controlled DDoS Attack (TCP SYN Flood)
In Terminal 3, launch a controlled TCP SYN flood from attacker `10.0.0.1`:
```bash
python -c "
from traffic_generator.generator import TrafficGenerator
g = TrafficGenerator()
print('Launching controlled SYN flood from 10.0.0.1...')
g.generate_syn_flood(attacker_ip='10.0.0.1', dst_port=80, duration_sec=5, pps=300)
"
```
**System Reaction**:
1. OpenFlow switch statistics collector captures high packet rate ($> 300\text{ pps}$) and zero payload byte density.
2. The 14 live telemetry features are extracted and scaled via `StandardScaler`.
3. ML model (`RandomForestClassifier`, 98.4% accuracy) detects the anomaly with $>99\%$ confidence.
4. **Automated Mitigation Engine** triggers:
   - Installs an OpenFlow 1.3 `OFPFlowMod` DROP rule matching `ipv4_src=10.0.0.1`.
   - Sets timeout to 60 seconds.
   - Prevents duplicate rule reinstallation.
5. **Dashboard Observation**:
   - Attack card turns **RED** with `DDOS ATTACK DETECTIONS`.
   - Active Mitigations card increments to `1`.
   - The Mitigations Table shows `10.0.0.1` with a real-time countdown timer (`59s left`, `58s left`...).
   - Attacker packets are immediately dropped at the switch.

### Step 6: Verify Duplicate Prevention
Try triggering the attack again immediately:
```bash
python -c "
from traffic_generator.generator import TrafficGenerator
g = TrafficGenerator()
g.generate_syn_flood(attacker_ip='10.0.0.1', duration_sec=2, pps=300)
"
```
Observe the logs:
`[DEBUG] IP 10.0.0.1 is already blocked. Skipping duplicate rule installation.`

### Step 7: Rule Expiration and Traffic Resumption
Watch the countdown in the Mitigations Table:
- When the 60-second timer expires, the mitigation manager removes the rule:
  `[MITIGATION LIFECYCLE] DROP rule for 10.0.0.1 has expired. Normal traffic resumed.`
- Normal traffic from `10.0.0.1` can resume without administrator intervention.
- Administrators can also click the red **Unblock** button at any time for instant unblocking.

---

## 4. HTTPS / TLS Behavioral Anomaly Demonstration

A key capstone requirement is demonstrating attack detection on **Port 443 HTTPS without decrypting TLS payloads**.

### Step 1: Normal HTTPS Traffic
```bash
python -c "
from traffic_generator.generator import TrafficGenerator
g = TrafficGenerator()
g.generate_benign_traffic(client_ip='10.0.0.6', dst_port=443, count=5)
"
```
Navigate to the **External Traffic & HTTPS** tab on the dashboard:
- `HTTPS TRAFFIC (PORT 443)` increments.
- `SUSPICIOUS HTTPS BEHAVIOR` remains 0.
- Protocol distribution shows legitimate TCP (Proto 6).

### Step 2: Encrypted Port 443 DDoS Behavioral Attack
Simulate an abnormal connection exhaustion / TCP SYN flood targeting Port 443:
```bash
python -c "
from traffic_generator.generator import TrafficGenerator
g = TrafficGenerator()
print('Injecting encrypted HTTPS behavioral attack on Port 443...')
g.generate_https_flood(attacker_ip='10.0.0.2', subtype='syn_flood_443', duration_sec=5)
"
```
**System Reaction**:
1. `HTTPSBehavioralAnalyzer` identifies SYN-to-ACK asymmetry and abnormal connection arrival velocity.
2. The ML model predicts DDoS violation targeting port 443.
3. System triggers automated mitigation on `10.0.0.2`.
4. **Dashboard**:
   - `SUSPICIOUS HTTPS BEHAVIOR` increments.
   - Attack category shows `tcp_syn_flood_443`.
   - Mitigation rule appears on switch with DROP action.
   - **Crucial verification**: Zero payload decryption was performed; detection was executed entirely through transport metadata and ML behavioral analysis.

---

## 5. Model Benchmark & Evaluation Demonstration

Click the **ML Models & Benchmark** tab on the dashboard:
1. **Performance Matrix**:
   - Random Forest: **98.06% Accuracy**, **0.9805 F1**, **0.9989 ROC-AUC**, **1.56% FPR**, **0.015 ms Latency**.
   - KNN: **97.72% Accuracy**, **0.9773 F1**, **0.9977 ROC-AUC**, **2.56% FPR**.
   - SVM (RBF): **94.78% Accuracy**, **0.9461 F1**, **0.9935 ROC-AUC**.
   - Logistic Regression: **93.94% Accuracy**, **0.9381 F1**, **0.9805 ROC-AUC**.
2. **Old Baseline Comparison**:
   - Old KNN Baseline: Accuracy = 90.83%, F1 = 0.9077, ROC-AUC = 0.9768, FPR = 8.44%.
   - New KNN Implementation: Accuracy = 97.72%, F1 = 0.9773, ROC-AUC = 0.9977, FPR = 2.56%.
3. **100% Whole Dataset Training (All 9,209,309 Rows)**:
   - Evaluated on holdout set of 40,000 samples across the full dataset: **98.89% Accuracy**, **0.9943 F1-Score**, **0.9995 ROC-AUC**, **0.30% FPR**.
