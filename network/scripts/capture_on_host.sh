#!/bin/bash
# Host-based Packet Capture for custom_net
# Runs on WSL host to capture ALL traffic on the Docker bridge

NETWORK_NAME="custom_net"
CAPTURE_DIR="/mnt/e/nos/Network_Security_poc/network/captures"
ROTATION_SECONDS=10
KEEP_FILES=4

echo "========================================"
echo "HOST-BASED PACKET CAPTURE"
echo "========================================"
echo ""

# Get Docker bridge interface for custom_net
BRIDGE_ID=$(docker network inspect ${NETWORK_NAME} -f '{{.Id}}' | cut -c1-12)
BRIDGE_IFACE="br-${BRIDGE_ID}"

echo "Network: ${NETWORK_NAME}"
echo "Bridge Interface: ${BRIDGE_IFACE}"
echo "Capture Directory: ${CAPTURE_DIR}"
echo "Rotation: Every ${ROTATION_SECONDS} seconds"
echo "Keep: Last ${KEEP_FILES} files"
echo ""

# Check if bridge exists
if ! ip link show "${BRIDGE_IFACE}" >/dev/null 2>&1; then
    echo "ERROR: Bridge interface ${BRIDGE_IFACE} not found!"
    echo "Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/:$//'
    exit 1
fi

# Create capture directory
mkdir -p "${CAPTURE_DIR}"

# Check if tcpdump is installed
if ! command -v tcpdump >/dev/null 2>&1; then
    echo "ERROR: tcpdump not installed!"
    echo "Install with: sudo apt-get install tcpdump"
    exit 1
fi

echo "Starting packet capture..."
echo "Press Ctrl+C to stop"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Stopping packet capture..."
    if [ ! -z "${TCPDUMP_PID}" ]; then
        sudo kill ${TCPDUMP_PID} 2>/dev/null
    fi
    if [ ! -z "${CLEANUP_PID}" ]; then
        kill ${CLEANUP_PID} 2>/dev/null
    fi
    echo "Capture stopped"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start tcpdump on the Docker bridge with time-based rotation
# This captures ALL traffic on custom_net including:
# - DoS attacks, SYN floods
# - Device traffic
# - Attacker traffic
# - Everything!
sudo tcpdump -i "${BRIDGE_IFACE}" -s 0 -G ${ROTATION_SECONDS} \
    -w "${CAPTURE_DIR}/capture_%Y%m%d_%H%M%S.pcap" \
    -Z $(whoami) \
    -B 8192 \
    'not port 22' >/dev/null 2>&1 &
TCPDUMP_PID=$!

echo "✓ tcpdump started (PID: ${TCPDUMP_PID})"
echo "✓ Capturing on ${BRIDGE_IFACE}"
echo "✓ Saving to ${CAPTURE_DIR}/capture_*.pcap"
echo ""

# Start cleanup loop (keep only last N files)
(
    while true; do
        sleep 60
        
        # Count PCAP files
        PCAP_COUNT=$(ls -1 "${CAPTURE_DIR}"/*.pcap 2>/dev/null | wc -l)
        
        if [ "${PCAP_COUNT}" -gt ${KEEP_FILES} ]; then
            # Keep only the N most recent files
            ls -1t "${CAPTURE_DIR}"/*.pcap | tail -n +$((KEEP_FILES + 1)) | xargs -r rm -f
            DELETED=$((PCAP_COUNT - KEEP_FILES))
            echo "[$(date +%H:%M:%S)] Deleted ${DELETED} old PCAP files (keeping last ${KEEP_FILES})"
        fi
    done
) &
CLEANUP_PID=$!

echo "✓ Auto-cleanup started (PID: ${CLEANUP_PID})"
echo ""
echo "Capture is running. Files will appear in:"
echo "  ${CAPTURE_DIR}/"
echo ""

# Show live packet count every 10 seconds
while true; do
    sleep 10
    LATEST_FILE=$(ls -t "${CAPTURE_DIR}"/*.pcap 2>/dev/null | head -1)
    if [ -f "${LATEST_FILE}" ]; then
        SIZE=$(du -h "${LATEST_FILE}" | cut -f1)
        echo "[$(date +%H:%M:%S)] Latest: $(basename ${LATEST_FILE}) (${SIZE})"
    fi
done

wait
