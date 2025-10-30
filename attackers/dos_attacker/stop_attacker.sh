#!/bin/bash
# Stop attacker and cleanup iptables rules

echo "========================================"
echo "Stopping DoS Attacker"
echo "========================================"
echo ""

echo "[1/2] Cleaning up iptables rules..."
bash cleanup_iptables.sh

echo ""
echo "[2/2] Stopping Docker container..."
docker-compose down

echo ""
echo "========================================"
echo "✅ Attacker stopped and cleaned up!"
echo "========================================"
