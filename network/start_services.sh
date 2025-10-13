#!/bin/bash
set -e

echo "========================================"
echo "🚀 Starting Network Security Monitor"
echo "========================================"

# Capture configuration
CAP_DIR="/captures"
IFACE="${CAPTURE_IFACE:-eth0}"
PCAP_FILE="${CAP_DIR}/capture_$(date +%Y%m%d_%H%M%S).pcap"

mkdir -p "${CAP_DIR}"

echo "📡 Network Interface: ${IFACE}"
echo "💾 Capture File: ${PCAP_FILE}"
echo "📁 Capture Directory: ${CAP_DIR}"

# Check if interface exists
if ! ip link show "${IFACE}" >/dev/null 2>&1; then
    echo "⚠️  Interface ${IFACE} not found. Available interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/:$//' || echo "No interfaces found"
    echo "📝 Set CAPTURE_IFACE environment variable to change interface"
    # Don't exit, continue with eth0 anyway
fi

# Start tcpdump with rotation (10MB files, keep 5 files)
echo "🔍 Starting packet capture..."
tcpdump -i "${IFACE}" -s 0 -w "${PCAP_FILE}" -C 10 -W 5 \
    'not port 22' >/dev/null 2>&1 &
TCPDUMP_PID=$!
echo "✅ tcpdump started (PID: ${TCPDUMP_PID})"

# Start HAProxy
echo "🔄 Starting HAProxy load balancer..."
haproxy -f /app/haproxy.cfg &
HAPROXY_PID=$!
echo "✅ HAProxy started (PID: ${HAPROXY_PID})"

# Start Flask application
echo "🌐 Starting Flask web server..."
python3 /app/flask_server.py &
FLASK_PID=$!
echo "✅ Flask started (PID: ${FLASK_PID})"

echo "========================================"
echo "🟢 All services running!"
echo "   📊 Web interface: http://localhost:8080"
echo "   🔧 Direct Flask: http://localhost:5000"
echo "   📦 Packet captures: ${CAP_DIR}"
echo "========================================"

# Graceful shutdown handler
cleanup() {
    echo ""
    echo "🛑 Shutting down services..."
    kill ${TCPDUMP_PID} ${HAPROXY_PID} ${FLASK_PID} 2>/dev/null || true
    echo "✅ Cleanup complete"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Keep container running
wait
