#!/bin/bash
# Script to launch Ryu Controller and Mininet Topology in Linux / WSL2 / Docker

echo "=========================================================="
echo "Starting AI-Driven DDoS SDN Framework (Mininet + Ryu)"
echo "=========================================================="

# 1. Start Ryu OpenFlow 1.3 Controller in background
echo "[1/2] Launching Ryu Controller on 0.0.0.0:6653..."
ryu-manager controller/ddos_controller.py --ofp-tcp-listen-port 6653 &
RYU_PID=$!
sleep 2

# 2. Start Mininet Topology
echo "[2/2] Launching Mininet Topology..."
sudo python3 mininet/topology.py

# Cleanup on exit
echo "Cleaning up Ryu Controller..."
kill $RYU_PID
sudo mn -c
echo "Done."
