#!/bin/bash
# Stop host-based packet capture

echo "Stopping packet capture on custom_net bridge..."

# Find tcpdump processes capturing on br-* interfaces
TCPDUMP_PIDS=$(ps aux | grep 'tcpdump.*br-' | grep -v grep | awk '{print $2}')

if [ -z "${TCPDUMP_PIDS}" ]; then
    echo "No active tcpdump processes found"
else
    for PID in ${TCPDUMP_PIDS}; do
        echo "Stopping tcpdump (PID: ${PID})..."
        sudo kill ${PID}
    done
    echo "✓ Packet capture stopped"
fi
