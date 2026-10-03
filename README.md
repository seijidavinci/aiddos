# AI-Driven DDoS Attack Detection and Automated Mitigation Framework in SDN

An end-to-end, production-grade Software Defined Networking (SDN) cybersecurity framework that combines **Machine Learning**, **OpenFlow 1.3 live telemetry**, **Multi-Source Network Telemetry (NetFlow/IPFIX/Sockets)**, **Encrypted HTTPS Behavioral Anomaly Detection**, a **FastAPI backend**, and a modern **React + Vite glassmorphism dashboard**.

![Dashboard Status](https://img.shields.io/badge/Status-Active-success)
![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.14-blue)
![React](https://img.shields.io/badge/React-18-cyan)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)
![OpenFlow](https://img.shields.io/badge/OpenFlow-1.3-orange)
![License](https://img.shields.io/badge/License-MIT-purple)

---

## Architecture Overview

```
                    NETWORK TRAFFIC
                          |
             +------------+------------+
             |                         |
        LAB TRAFFIC              EXTERNAL TRAFFIC
     Mininet / OVS Switch     Authorized Gateway / Server
             |                         |
             +------------+------------+
                          |
                          v
                 FLOW TELEMETRY
          (OpenFlow 1.3 / NetFlow / IPFIX / Sockets)
                          |
                          v
              UNIFIED TELEMETRY NORMALIZER
                          |
                          v
                 FEATURE ENGINE
         (14 Live-Compatible Telemetry Features)
                          |
                          v
                  ML DETECTOR
      (Random Forest / KNN / SVM RBF / Logistic Reg)
                          |
                  +-------+-------+
                  |               |
               BENIGN           ATTACK
                  |               |
                  v               v
                ALLOW     AUTOMATED MITIGATION
                                  |
                                  +--> OpenFlow 1.3 DROP FlowMod
                                  +--> OS Firewall Rule (iptables / netsh)
                                  +--> Duplicate Prevention & Timeout Expiry
                                  |
                                  v
                           PROTECTED SERVER
                                  |
                                  v
                           FASTAPI BACKEND
                            (SQLite ORM)
                                  |
                                  v
                        REACT + VITE DASHBOARD
```

---

## Key Capabilities & Highlights

1. **Strict Live-Telemetry Consistency**:
   All 14 engineered features are strictly derivable during live runtime monitoring from OpenFlow 1.3 switch counters, NetFlow v5/v9, IPFIX, or live packet socket metadata. Zero fabricated or unreachable features.
2. **True Dual-Scale ML Training**:
   - **Benchmark 12,000 Dataset**: 6,000 Benign + 6,000 DDoS records across 7 distinct attack categories (`syn_flood`, `udp_flood`, `icmp_flood`, `dns_amplification`, `http_get_flood`, `slowloris_low_rate`, `pulsed_mixed_flood`). 70/15/15 stratified train/val/test splits with 5-Fold Stratified Cross Validation.
   - **100% Whole-Dataset Training**: Scaled out-of-core online streaming training across **all 9,209,309 rows** of `ready_dataset.csv`.
3. **Encrypted HTTPS / TLS Behavioral Anomaly Detection**:
   Targeting TCP Port 443 with **ZERO payload decryption**, ensuring end-to-end encryption privacy. Distinguishes normal HTTPS browsing from TCP SYN floods on 443, TLS connection floods, request-rate volume flooding, and low-rate Slowloris TLS attacks using observable transport metadata (SYN-to-ACK ratios, connection arrival velocity, and payload density).
4. **Automated OpenFlow 1.3 Mitigation**:
   - Real-time continuous detection loop (configurable polling interval, default 2.0s).
   - Installs high-priority OpenFlow DROP rules (`OFPFlowMod`).
   - Duplicate rule prevention (avoids redundant switch flow entries).
   - Automatic rule expiration with countdown timers.
   - Manual admin override (instant block / unblock).
5. **Multi-Platform Execution**:
   Provides full native Ryu/Mininet controller support for Linux/WSL2 and an integrated high-fidelity SDN emulation engine for seamless execution on Windows and macOS.

---

## Dataset Analysis & Structure

The framework is trained and validated on the provided dataset `ready_dataset.csv` extracted from `ready_dataset.zip` (2.96 GB, 9,209,309 flow records, 78 raw attributes).

### Raw Label Distribution (Entire 9.2M Dataset)
| Category / Label | Count | Framework Mapping |
| :--- | :--- | :--- |
| `BENIGN` | 2,384,051 | Normal legitimate network traffic |
| `TFTP` | 1,951,336 | Amplification & Unseen attack evaluation |
| `MSSQL` | 998,191 | Connection exhaustion / Slowloris |
| `NetBIOS` | 747,772 | Pulsed mixed flood |
| `UDP` / `UDPLag` | 723,284 | High-rate UDP flood |
| `Syn` | 594,129 | TCP SYN flood |
| `SNMP` | 514,957 | Amplification / Pulsed flood |
| `DNS` | 490,813 | DNS amplification attack |
| `LDAP` | 410,301 | Low-rate connection exhaustion |
| `SSDP` | 256,832 | Pulsed mixed flood |
| `NTP` | 119,528 | Amplification / ICMP flood |
| `Portmap` | 17,676 | Portmap / low-latency flood |
| `WebDDoS` | 439 | HTTP GET / Web application flood |

---

## The 14 Live-Compatible Feature Set

Every feature in the final model is extractable during live network monitoring:

| # | Feature Name | Description | Live Telemetry Derivation |
| :--- | :--- | :--- | :--- |
| 1 | `flow_duration` | Duration of active flow (seconds) | `duration_sec + duration_nsec * 1e-9` |
| 2 | `packet_count` | Total packets in flow | Flow counter (`packet_count`) |
| 3 | `byte_count` | Total bytes in flow | Byte counter (`byte_count`) |
| 4 | `packet_rate` | Packets per second | $\Delta \text{packets} / \Delta t$ |
| 5 | `byte_rate` | Bytes per second | $\Delta \text{bytes} / \Delta t$ |
| 6 | `packet_size_mean` | Mean packet payload size | `byte_count / packet_count` |
| 7 | `packet_size_std` | Packet size standard deviation | Windowed packet size tracking |
| 8 | `flow_iat_mean` | Inter-arrival time mean | `duration_sec / (packet_count - 1)` |
| 9 | `flow_iat_std` | Inter-arrival time std dev | Windowed timestamp interval std |
| 10 | `syn_flag_count` | SYN flag count | TCP packet header flag analysis |
| 11 | `ack_flag_count` | ACK flag count | TCP packet header flag analysis |
| 12 | `down_up_ratio` | Downlink to Uplink ratio | Backward vs Forward flow ratio |
| 13 | `protocol_encoded` | Transport protocol code | `ip_proto` (TCP=6, UDP=17, ICMP=1) |
| 14 | `dst_port_encoded` | Destination service port | Port mapping (80, 443, 53, etc.) |

---

## Machine Learning Results & Baseline Comparison

### 1. 5-Fold Stratified Cross Validation (Training Set: 8,400 samples)
| Model | CV Accuracy | CV Precision | CV Recall | CV F1-Score | CV ROC-AUC | Fit Time |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Random Forest** | **98.29%** | **0.9904** | **0.9752** | **0.9827** | **0.9990** | 0.42s |
| **KNN (k=15)** | **98.04%** | **0.9838** | **0.9769** | **0.9803** | **0.9973** | 0.01s |
| **SVM (RBF, C=0.8)** | **95.40%** | **0.9809** | **0.9262** | **0.9527** | **0.9934** | 0.74s |
| **Logistic Regression**| **94.35%** | **0.9591** | **0.9264** | **0.9425** | **0.9813** | 0.05s |

### 2. Standard Test Set (1,800 Holdout Samples) & Honest Baseline Comparison
| Model | Old Baseline Acc | **New Test Acc** | Old Baseline F1 | **New Test F1** | Old ROC-AUC | **New ROC-AUC** | Old FPR | **New FPR** | Imbalanced F1 | Unseen F1 | Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest** | — | **98.06%** | — | **0.9805** | — | **0.9989** | — | **1.56%** | **0.9508** | **1.0000** | 0.015 ms |
| **KNN (k=15)** | 90.83% | **97.72%** | 0.9077 | **0.9773** | 0.9768 | **0.9977** | 8.44% | **2.56%** | **0.9251** | **1.0000** | 0.015 ms |
| **SVM (RBF)** | — | **94.78%** | — | **0.9461** | — | **0.9935** | — | **2.11%** | **0.8785** | **0.9993** | 0.040 ms |
| **Logistic Reg** | — | **93.94%** | — | **0.9381** | — | **0.9805** | — | **3.89%** | **0.8030** | **1.0000** | 0.0001 ms |

### 3. Whole-Dataset Online Learning (All 9,209,309 Rows)
- **Total Records Processed**: 9,209,309 (2,384,051 Benign, 6,825,258 DDoS)
- **Training Time**: 117.49 seconds via incremental out-of-core online learning (`SGDClassifier` + `StandardScaler.partial_fit`)
- **Holdout Test Set (40,000 samples)**:
  - **Accuracy**: **98.89%**
  - **F1-Score**: **0.9943**
  - **ROC-AUC**: **0.9995**
  - **False Positive Rate**: **0.30%** (only 2 false alarms in 40,000 flows!)
  - **Confusion Matrix**: $\text{TP} = 38,898, \text{FP} = 2, \text{TN} = 658, \text{FN} = 442$

---

## Installation & Setup

### 1. Prerequisites
- Python 3.10+ (tested on Python 3.11 and 3.14)
- Node.js 18+ and npm

### 2. Clone and Install Dependencies
```bash
# Clone the repository
git clone <repo-url>
cd CAPSTONE

# Install Python dependencies
pip install -r requirements.txt

# Install Dashboard dependencies
cd dashboard
npm install
cd ..
```

---

## Quick-Start Commands

### Run the Full Automated Experiment Suite
Executes dataset extraction, feature preprocessing, 5-fold cross validation, evaluation on all test sets, 9.2M whole-dataset training, and chart generation:
```bash
python run_experiment.py
```

### Run the Full Integrated Platform (Single Command)
Launches the FastAPI backend, SDN engine, React dashboard, and live simulation:
```bash
python run_system.py
```
- Open `http://localhost:3000` to interact with the Dashboard.
- Open `http://127.0.0.1:8000/docs` to view the interactive OpenAPI documentation.

### Run Automated Unit & Integration Tests
```bash
python -m pytest tests/ -v
```
Output: **21 passed out of 21 tests (100% pass rate)**.

---

## SDN Native Mininet & Ryu Execution (Linux / WSL2)

```bash
# Terminal 1: Launch Ryu OpenFlow 1.3 Controller
ryu-manager controller/ddos_controller.py --ofp-tcp-listen-port 6653

# Terminal 2: Launch Mininet Topology
sudo python3 mininet/topology.py

# Terminal 3: Start FastAPI Backend
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Terminal 4: Start React Dashboard
cd dashboard && npm run dev
```

---

## Project Structure

```
ddos-sdn-framework/
├── data/                               # Benchmark and split datasets
│   ├── baseline_12k.csv                # 12,000 flow benchmark dataset
│   ├── train.csv, val.csv, test.csv    # 70% / 15% / 15% splits
│   ├── imbalanced_test.csv             # Realistic 90/10 ratio test set
│   └── unseen_test.csv                 # Unseen attack scenarios
├── models/                             # Trained models & scalers
│   ├── best_model.joblib               # Random Forest (val F1: 0.9843)
│   ├── random_forest.joblib
│   ├── svm_rbf.joblib
│   ├── knn.joblib
│   ├── logistic_regression.joblib
│   ├── model_whole_9m_sgd.joblib       # Whole dataset online model
│   ├── scaler.joblib                   # Fitted StandardScaler
│   └── feature_metadata.json
├── src/                                # Core ML pipeline
│   ├── config.py                       # Configuration & paths
│   ├── dataset_loader.py               # Vectorized chunked dataset loader
│   ├── feature_engineering.py          # 14 live telemetry feature extractor
│   ├── preprocessing.py                # Preprocessing pipeline
│   ├── train_models.py                 # 5-fold Stratified CV & training
│   ├── train_whole_dataset_stream.py   # 9.2M whole dataset online trainer
│   ├── evaluate_models.py              # Full evaluation & plot generation
│   └── predict.py                      # Real-time inference engine
├── controller/                         # SDN & OpenFlow 1.3 Controller
│   ├── ddos_controller.py              # Ryu OpenFlow 1.3 application
│   ├── flow_monitor.py                 # Delta rate calculation & monitoring
│   ├── feature_extractor.py            # OpenFlow stats to ML features
│   └── sdn_simulator.py                # Cross-platform SDN emulation engine
├── telemetry/                          # Multi-Source Telemetry & HTTPS
│   ├── normalizer.py                   # Unified NormalizedFlow schema
│   ├── flow_collector.py               # Telemetry hub coordinator
│   ├── netflow_collector.py            # NetFlow v5/v9 & IPFIX parser
│   ├── external_sniffer.py             # Live socket sniffer & replay
│   └── https_detector.py               # Port 443 TLS behavioral analyzer
├── mitigation/                         # Automated Mitigation Subsystem
│   ├── base.py                         # Base mitigation interface
│   ├── openflow_mitigation.py          # OpenFlow 1.3 DROP FlowMod generator
│   ├── firewall_mitigation.py          # Host OS firewall (iptables/netsh)
│   └── rule_manager.py                 # Duplicate prevention & auto-expiry
├── backend/                            # FastAPI Backend Service
│   ├── main.py                         # Application entrypoint
│   ├── database.py                     # SQLite engine & sessionmaker
│   ├── models.py                       # SQLAlchemy models
│   ├── schemas.py                      # Pydantic validation schemas
│   └── routes/                         # REST API endpoints
├── dashboard/                          # Modern React + Vite Dashboard
│   ├── src/
│   │   ├── components/                 # Header, Cards, Charts, Tables
│   │   ├── services/api.js             # Backend API client
│   │   ├── App.jsx & main.jsx
│   │   └── index.css                   # Glassmorphism design system
│   ├── package.json
│   └── vite.config.js
├── traffic_generator/                  # Controlled Traffic Generators
│   └── generator.py                    # Multi-attack orchestrator
├── mininet/                            # Mininet scripts
│   ├── topology.py                     # Custom topology
│   └── run_mininet.sh                  # Shell launcher
├── tests/                              # Comprehensive Test Suite (21 tests)
├── results/                            # ROC curves, confusion matrices, reports
├── run_experiment.py                   # Automated experiment runner
├── run_system.py                       # Single-command platform launcher
├── config.yaml                         # Framework configuration
├── .env.example                        # Environment variable template
├── Dockerfile & docker-compose.yml
├── README.md
└── DEMO.md
```

---

## Limitations & Future Work

1. **Host-Level Kernel Switches**: Mininet and Open vSwitch require Linux kernel network namespaces (`NET_ADMIN`). On Windows or macOS, native Mininet is run via WSL2/Docker, or using our provided cross-platform SDN simulator.
2. **Encrypted HTTPS Detection**: The system successfully detects attacks targeting Port 443 without payload decryption; future extensions could incorporate TLS fingerprinting (JA3/JA4) for client identity tracking.
3. **Multi-Controller Clustering**: Currently configured for single-controller topologies; future work can extend to distributed ONOS/OpenDaylight clusters.
