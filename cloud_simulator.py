import os
import time

from controller.sdn_simulator import SDNEndToEndEngine
from traffic_generator.generator import TrafficGenerator


BACKEND_URL = os.getenv("BACKEND_URL", "https://aiddos.onrender.com")


def run_simulation():
    print("=" * 70)
    print("AIDDOS CLOUD SIMULATOR")
    print(f"Backend: {BACKEND_URL}")
    print("=" * 70)

    sdn_engine = SDNEndToEndEngine(backend_url=BACKEND_URL)
    sdn_engine.start()

    generator = TrafficGenerator(
        on_flow_generated=sdn_engine.process_incoming_flow
    )

    try:
        time.sleep(3)

        while sdn_engine.running:
            print("\n[1] Generating benign traffic...")
            generator.generate_benign_traffic(
                client_ip="10.0.0.5",
                dst_port=80,
                count=5,
                interval=0.4
            )
            generator.generate_benign_traffic(
                client_ip="10.0.0.6",
                dst_port=443,
                count=5,
                interval=0.4
            )

            time.sleep(2)

            print("[2] Generating SYN flood...")
            generator.generate_syn_flood(
                attacker_ip="10.0.0.1",
                duration_sec=4,
                pps=300
            )

            time.sleep(2)

            print("[3] Generating HTTPS attack...")
            generator.generate_https_flood(
                attacker_ip="10.0.0.2",
                subtype="syn_flood_443",
                duration_sec=4
            )

            time.sleep(2)

            print("[4] Generating UDP flood...")
            generator.generate_udp_flood(
                attacker_ip="10.0.0.3",
                duration_sec=4,
                pps=250
            )

            time.sleep(4)

    except KeyboardInterrupt:
        print("\nStopping cloud simulator...")

    finally:
        sdn_engine.stop()
        print("Cloud simulator stopped.")


if __name__ == "__main__":
    run_simulation()
