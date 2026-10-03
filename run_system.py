"""
Unified System Orchestrator
Launches:
1. FastAPI Backend (port 8000)
2. SDN Switch & Telemetry Continuous Detection Engine
3. React + Vite Dashboard Dev Server (port 3000)
4. Interactive traffic generation demonstration
"""
import sys
import time
import subprocess
import threading
import signal
import uvicorn
from controller.sdn_simulator import SDNEndToEndEngine
from traffic_generator.generator import TrafficGenerator

def run_backend():
    print("[1/3] Starting FastAPI Backend on http://127.0.0.1:8000 ...")
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, log_level="warning")

def run_frontend():
    print("[2/3] Starting React + Vite Dashboard on http://localhost:3000 ...")
    try:
        subprocess.run(["npm", "run", "dev"], cwd="dashboard", shell=True)
    except Exception as e:
        print(f"Error starting frontend: {e}")

def run_traffic_demo(sdn_engine: SDNEndToEndEngine):
    print("[3/3] Starting Controlled Traffic Simulation Loop...")
    generator = TrafficGenerator(on_flow_generated=sdn_engine.process_incoming_flow)

    time.sleep(3)  # wait for backend & frontend to boot

    while sdn_engine.running:
        # Phase 1: Benign traffic
        print("\n---> [Simulation Phase 1] Injecting Normal Client Traffic (Ports 80/443)...")
        generator.generate_benign_traffic(client_ip="10.0.0.5", dst_port=80, count=5, interval=0.4)
        generator.generate_benign_traffic(client_ip="10.0.0.6", dst_port=443, count=5, interval=0.4)
        time.sleep(2)

        # Phase 2: SYN flood attack
        print("\n---> [Simulation Phase 2] Injecting TCP SYN Flood from 10.0.0.1...")
        generator.generate_syn_flood(attacker_ip="10.0.0.1", duration_sec=4, pps=300)
        time.sleep(2)

        # Phase 3: HTTPS Behavioral flood attack
        print("\n---> [Simulation Phase 3] Injecting HTTPS Attack targeting Port 443 from 10.0.0.2...")
        generator.generate_https_flood(attacker_ip="10.0.0.2", subtype="syn_flood_443", duration_sec=4)
        time.sleep(2)

        # Phase 4: UDP flood attack
        print("\n---> [Simulation Phase 4] Injecting UDP Flood from 10.0.0.3...")
        generator.generate_udp_flood(attacker_ip="10.0.0.3", duration_sec=4, pps=250)
        time.sleep(4)

def main():
    print("=" * 75)
    print("  AI-DRIVEN DDOS DETECTION & AUTOMATED MITIGATION SDN FRAMEWORK")
    print("  LAUNCHING FULL INTEGRATED PLATFORM (BACKEND + SDN + DASHBOARD)")
    print("=" * 75)

    # 1. Start Backend in separate thread
    b_thread = threading.Thread(target=run_backend, daemon=True)
    b_thread.start()
    time.sleep(1.5)

    # 2. Start SDN Switch & Telemetry Engine
    sdn_engine = SDNEndToEndEngine(backend_url="http://127.0.0.1:8000")
    sdn_engine.start()

    # 3. Start Traffic Demo loop
    t_thread = threading.Thread(target=run_traffic_demo, args=(sdn_engine,), daemon=True)
    t_thread.start()

    # 4. Start Frontend
    try:
        run_frontend()
    except KeyboardInterrupt:
        print("\nShutting down framework...")
    finally:
        sdn_engine.stop()
        print("Framework gracefully stopped.")

if __name__ == "__main__":
    main()
