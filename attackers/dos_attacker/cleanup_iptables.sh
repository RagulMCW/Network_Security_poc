#!/bin/bash
# Cleanup iptables rules for attacker when container is stopped/removed
# This ensures fresh testing without lingering redirection rules

ATTACKER_IP="${1:-192.168.6.132}"

echo "🧹 Cleaning up iptables rules for ${ATTACKER_IP}..."

# Get all possible Beelzebub IPs (current and old)
BEELZEBUB_IPS=("172.18.0.2" "192.168.7.2" "192.168.7.3")

# Remove all DNAT rules for this attacker IP regardless of destination
for DEST_IP in "${BEELZEBUB_IPS[@]}"; do
    sudo iptables -t nat -D PREROUTING -s ${ATTACKER_IP} -p tcp -j DNAT --to-destination ${DEST_IP} 2>/dev/null && \
        echo "  ✅ Removed TCP DNAT rule → ${DEST_IP}" || true
    
    sudo iptables -t nat -D PREROUTING -s ${ATTACKER_IP} -p udp -j DNAT --to-destination ${DEST_IP} 2>/dev/null && \
        echo "  ✅ Removed UDP DNAT rule → ${DEST_IP}" || true
done

# Remove mangle rules if any
sudo iptables -t mangle -D PREROUTING -s ${ATTACKER_IP} -j MARK --set-mark 100 2>/dev/null && \
    echo "  ✅ Removed mangle rule" || true

# Remove from reroutes.log
REROUTES_LOG="/mnt/e/nos/Network_Security_poc/honey_pot/logs/reroutes.log"
if [ -f "$REROUTES_LOG" ]; then
    grep -v "${ATTACKER_IP}" "$REROUTES_LOG" > "${REROUTES_LOG}.tmp" 2>/dev/null || true
    mv "${REROUTES_LOG}.tmp" "$REROUTES_LOG" 2>/dev/null || true
    echo "  ✅ Cleaned reroutes.log"
fi

echo ""
echo "✅ Cleanup complete! Attacker can now access network normally."
echo ""
echo "Verify no rules remain:"
sudo iptables -t nat -L PREROUTING -n | grep ${ATTACKER_IP} || echo "  ✅ No iptables rules found for ${ATTACKER_IP}"
