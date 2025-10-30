#!/bin/bash
# Packet Capture for Beelzebub Honeypot Network
# Captures ALL traffic on honeypot_net to verify redirected attacks

NETWORK_NAME="honeypot_net"
CAPTURE_DIR="/mnt/e/nos/Network_Security_poc/honey_pot/pcap_captures"
ROTATION_SECONDS=10
KEEP_FILES=10

echo "========================================"
echo "BEELZEBUB HONEYPOT PACKET CAPTURE"
echo "========================================"
echo ""

# Get Docker bridge interface for honeypot_net
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
    echo "Make sure honeypot_net network exists:"
    echo "  docker network create --subnet=192.168.7.0/24 honeypot_net"
    echo ""
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

echo "Starting honeypot packet capture..."
echo "This will capture:"
echo "  - All traffic to/from Beelzebub (192.168.7.2)"
echo "  - Redirected attacker traffic"
echo "  - SSH brute-force attempts"
echo "  - MySQL/PostgreSQL connections"
echo "  - Port scans"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Stopping honeypot packet capture..."
    if [ ! -z "${TCPDUMP_PID}" ]; then
        sudo kill ${TCPDUMP_PID} 2>/dev/null
    fi
    if [ ! -z "${CLEANUP_PID}" ]; then
        kill ${CLEANUP_PID} 2>/dev/null
    fi
    echo "Capture stopped"
    echo ""
    echo "Captured files in: ${CAPTURE_DIR}/"
    ls -lh "${CAPTURE_DIR}/" 2>/dev/null | tail -5
    exit 0
}

trap cleanup SIGINT SIGTERM

# Start tcpdump on the honeypot bridge with time-based rotation
# Captures ALL traffic on honeypot_net including:
# - Redirected DoS attacks
# - SSH brute-force attempts
# - Database connection attempts
# - Port scans
# - Any malicious activity
sudo tcpdump -i "${BRIDGE_IFACE}" -s 0 -G ${ROTATION_SECONDS} \
    -w "${CAPTURE_DIR}/honeypot_%Y%m%d_%H%M%S.pcap" \
    -Z $(whoami) \
    -B 8192 \
    'not port 22 or (port 22 and not host 192.168.7.1)' >/dev/null 2>&1 &
TCPDUMP_PID=$!

echo "✓ tcpdump started (PID: ${TCPDUMP_PID})"
echo "✓ Capturing on ${BRIDGE_IFACE}"
echo "✓ Saving to ${CAPTURE_DIR}/honeypot_*.pcap"
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

# Show live packet count and traffic summary every 10 seconds
while true; do
    sleep 10
    LATEST_FILE=$(ls -t "${CAPTURE_DIR}"/*.pcap 2>/dev/null | head -1)
    if [ -f "${LATEST_FILE}" ]; then
        SIZE=$(du -h "${LATEST_FILE}" | cut -f1)
        PACKETS=$(tcpdump -r "${LATEST_FILE}" 2>/dev/null | wc -l)
        
        # Check for specific traffic types
        SYN_PACKETS=$(tcpdump -r "${LATEST_FILE}" 'tcp[tcpflags] & tcp-syn != 0' 2>/dev/null | wc -l)
        SSH_PACKETS=$(tcpdump -r "${LATEST_FILE}" 'port 22' 2>/dev/null | wc -l)
        
        echo "[$(date +%H:%M:%S)] Latest: $(basename ${LATEST_FILE}) (${SIZE}, ${PACKETS} pkts, ${SYN_PACKETS} SYN, ${SSH_PACKETS} SSH)"
    fi
done

wait
