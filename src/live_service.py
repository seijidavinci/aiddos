"""
Continuous Live SDN Deployment Daemon
Runs:
1. Cross-Platform OpenFlow 1.3 Switch & SDN End-to-End Engine
2. Multi-source Telemetry & Ingestion to FastAPI Backend (http://127.0.0.1:8000)
3. Background Traffic Streamer (Benign + Periodic Attacks)
4. External HTTPS Sniffer Streamer
"""
import time
import random
import logging
import requests
from controller.sdn_simulator import SDNEndToEndEngine
from traffic_generator.generator import TrafficGenerator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("SDNDeploymentDaemon")

def run_daemon():
    logger.info("Starting AI-Driven DDoS SDN Framework Live Daemon...")
    backend_url = "http://127.0.0.1:8000"

    # 1. Initialize and start the SDN End-to-End Engine
    engine = SDNEndToEndEngine(backend_url=backend_url)
    engine.start()

    generator = TrafficGenerator(on_flow_generated=engine.process_incoming_flow)

    logger.info("SDN Engine and Controller active. Streaming traffic continuously...")

    cycle = 0
    try:
        while engine.running:
            cycle += 1
            # Phase A: Benign Web and Cloud Traffic
            for _ in range(4):
                client = random.choice(["10.0.0.5", "10.0.0.6", "192.168.1.10", "192.168.1.25"])
                port = random.choice([80, 443, 8080, 53])
                generator.generate_benign_traffic(client_ip=client, dst_port=port, count=random.randint(3, 8), interval=0.2)
                time.sleep(1.0)

            # Also stream external HTTPS telemetry
            try:
                ext_payload = {
                    "src_ip": random.choice(["172.16.0.4", "198.51.100.22", "203.0.113.88"]),
                    "dst_ip": "10.0.0.100",
                    "src_port": random.randint(30000, 65000),
                    "dst_port": 443,
                    "protocol": 6,
                    "packet_count": random.randint(15, 60),
                    "byte_count": random.randint(2000, 30000),
                    "duration_sec": round(random.uniform(1.0, 3.5), 2),
                    "syn_count": random.randint(1, 2),
                    "ack_count": random.randint(10, 40),
                    "status": "Normal",
                    "telemetry_source": "HTTPS_Analyzer_Port443"
                }
                requests.post(f"{backend_url}/api/external/ingest", json=ext_payload, timeout=0.5)
            except Exception:
                pass

            # Phase B: Periodic Attack Traffic Wave (every 2 cycles)
            if cycle % 2 == 0:
                attack_type = random.choice(["syn_flood", "https_anomaly", "udp_flood", "slowloris"])
                if attack_type == "syn_flood":
                    logger.info("Injecting TCP SYN Flood Attack from 10.0.0.1...")
                    generator.generate_syn_flood(attacker_ip="10.0.0.1", duration_sec=3, pps=250)
                elif attack_type == "https_anomaly":
                    logger.info("Injecting Port 443 HTTPS Asymmetric Flood from 10.0.0.2...")
                    generator.generate_https_flood(attacker_ip="10.0.0.2", subtype="syn_flood_443", duration_sec=3)
                    # Also notify external API
                    try:
                        ext_attack = {
                            "src_ip": "10.0.0.2",
                            "dst_ip": "10.0.0.100",
                            "src_port": 54321,
                            "dst_port": 443,
                            "protocol": 6,
                            "packet_count": 500,
                            "byte_count": 20000,
                            "duration_sec": 1.5,
                            "syn_count": 480,
                            "ack_count": 5,
                            "status": "Attack",
                            "telemetry_source": "HTTPS_Analyzer_Port443"
                        }
                        requests.post(f"{backend_url}/api/external/ingest", json=ext_attack, timeout=0.5)
                    except Exception:
                        pass
                elif attack_type == "udp_flood":
                    logger.info("Injecting UDP Amplification Flood from 10.0.0.3...")
                    generator.generate_udp_flood(attacker_ip="10.0.0.3", duration_sec=3, pps=200)
                elif attack_type == "slowloris":
                    logger.info("Injecting Slowloris Low-Rate Attack from 10.0.0.4...")
                    generator.generate_slowloris(attacker_ip="10.0.0.4", duration_sec=5)

            time.sleep(2.0)

    except KeyboardInterrupt:
        logger.info("Shutting down SDN daemon...")
    finally:
        engine.stop()
        logger.info("SDN daemon stopped.")

if __name__ == "__main__":
    run_daemon()
