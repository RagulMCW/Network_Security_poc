#!/bin/bash
set -e

echo "========================================"
echo "Starting Network Security Monitor"
echo "========================================"

# Capture configuration
CAP_DIR="/captures"
IFACE="${CAPTURE_IFACE:-eth0}"
PCAP_FILE="${CAP_DIR}/capture_$(date +%Y%m%d_%H%M%S).pcap"

mkdir -p "${CAP_DIR}"

echo "Network Interface: ${IFACE}"
echo "Capture File: ${PCAP_FILE}"
echo "Capture Directory: ${CAP_DIR}"

# Check if interface exists
if ! ip link show "${IFACE}" >/dev/null 2>&1; then
    echo "WARNING: Interface ${IFACE} not found. Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/:$//' || echo "No interfaces found"
    echo "Set CAPTURE_IFACE environment variable to change interface"
fi

# Start tcpdump with TIME-based rotation (10 seconds) in promiscuous mode
echo "Starting packet capture with 10-second rotation..."
tcpdump -i "${IFACE}" -s 0 -G 10 -w "${CAP_DIR}/capture_%Y%m%d_%H%M%S.pcap" \
    'not port 22' >/dev/null 2>&1 &
TCPDUMP_PID=$!
echo "tcpdump started (PID: ${TCPDUMP_PID}) - capturing all network traffic"
echo "New PCAP file created every 10 seconds"

# Start automatic PCAP cleanup (keep only 4 most recent files)
echo "Starting automatic PCAP cleanup (keep last 4 files)..."
(
    while true; do
        sleep 60  # Run cleanup every 60 seconds
        
        # Count PCAP files
        PCAP_COUNT=$(ls -1 "${CAP_DIR}"/*.pcap 2>/dev/null | wc -l)
        
        if [ "${PCAP_COUNT}" -gt 4 ]; then
            # Keep only the 4 most recent files
            ls -1t "${CAP_DIR}"/*.pcap | tail -n +5 | xargs -r rm -f
            DELETED=$((PCAP_COUNT - 4))
            echo "[CLEANUP] Deleted ${DELETED} old PCAP files (keeping last 4)"
        fi
    done
) &
CLEANUP_PID=$!
echo "PCAP cleanup started (PID: ${CLEANUP_PID})"

# Start HAProxy
echo "Starting HAProxy load balancer..."
haproxy -f /app/src/config/haproxy.cfg &
HAPROXY_PID=$!
echo "HAProxy started (PID: ${HAPROXY_PID})"
# Start Flask application
echo "Starting Flask web server..."
python3 /app/src/app/server.py &
FLASK_PID=$!
echo "Flask started (PID: ${FLASK_PID})"

echo "========================================"
echo "All services running!"
echo "   Web interface: http://localhost:8080"
echo "   Direct Flask: http://localhost:5000"
echo "   Packet captures: ${CAP_DIR}"
echo "========================================"

# Graceful shutdown handler
cleanup() {
    echo ""
    echo "Shutting down services..."
    kill ${TCPDUMP_PID} ${HAPROXY_PID} ${FLASK_PID} ${CLEANUP_PID} 2>/dev/null || true
    echo "Cleanup complete"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Keep container running
wait