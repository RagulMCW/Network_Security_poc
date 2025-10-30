#!/bin/bash

echo "========================================"
echo "HONEYPOT MONITORING STATUS"
echo "========================================"
echo ""

# Check if Beelzebub is running
if docker ps | grep -q beelzebub-honeypot; then
    echo "[OK] Beelzebub honeypot is RUNNING"
    
    # Get Beelzebub IP on honeypot_net
    BEELZEBUB_IP=$(docker inspect beelzebub-honeypot --format '{{.NetworkSettings.Networks.honeypot_net.IPAddress}}' 2>/dev/null)
    
    if [ -z "$BEELZEBUB_IP" ]; then
        echo "[WARNING] Beelzebub not connected to honeypot_net"
        echo "          Run: docker network connect honeypot_net beelzebub-honeypot"
    else
        echo "[OK] Beelzebub IP: $BEELZEBUB_IP"
    fi
else
    echo "[ERROR] Beelzebub honeypot is NOT RUNNING"
    echo "        Run: cd honey_pot && docker-compose -f docker-compose-simple.yml up -d"
    exit 1
fi

echo ""
echo "----------------------------------------"
echo "DEVICES ON HONEYPOT NETWORK"
echo "----------------------------------------"

# Get all containers on honeypot_net
HONEYPOT_CONTAINERS=$(docker network inspect honeypot_net --format '{{range $id,$v := .Containers}}{{$v.Name}} {{$v.IPv4Address}} {{end}}' 2>/dev/null | grep -v '^$')

if [ -z "$HONEYPOT_CONTAINERS" ]; then
    echo "[INFO] No devices rerouted yet"
else
    echo "$HONEYPOT_CONTAINERS" | while read name ip; do
        if [ -n "$name" ]; then
            ip_only=$(echo $ip | cut -d'/' -f1)
            if [ "$name" != "beelzebub-honeypot" ]; then
                echo "[REROUTED] $name → $ip_only"
            fi
        fi
    done
fi

echo ""
echo "----------------------------------------"
echo "IPTABLES RULES (Traffic Redirection)"
echo "----------------------------------------"

# Check for DNAT rules
DNAT_RULES=$(sudo iptables -t nat -L PREROUTING -n | grep -c DNAT 2>/dev/null)
if [ "$DNAT_RULES" -gt 0 ]; then
    echo "[OK] $DNAT_RULES iptables DNAT rules active"
    echo ""
    sudo iptables -t nat -L PREROUTING -n --line-numbers | grep DNAT | head -5
    if [ "$DNAT_RULES" -gt 5 ]; then
        echo "... and $((DNAT_RULES - 5)) more rules"
    fi
else
    echo "[WARNING] No iptables DNAT rules found"
    echo "          Traffic may not be redirected to honeypot"
fi

echo ""
echo "----------------------------------------"
echo "BEELZEBUB LOGS"
echo "----------------------------------------"

LOG_FILE="/mnt/e/nos/Network_Security_poc/honey_pot/logs/beelzebub.log"

if [ -f "$LOG_FILE" ]; then
    LOG_SIZE=$(wc -l < "$LOG_FILE" 2>/dev/null || echo "0")
    echo "[OK] Log file exists: $LOG_SIZE lines"
    
    if [ "$LOG_SIZE" -gt 0 ]; then
        echo ""
        echo "Last 5 log entries:"
        echo "---"
        tail -5 "$LOG_FILE"
        echo "---"
    else
        echo "[INFO] No logs yet - waiting for rerouted traffic"
    fi
else
    echo "[WARNING] Log file not found: $LOG_FILE"
    echo "          Check Beelzebub configuration"
fi

echo ""
echo "----------------------------------------"
echo "ATTACK DATA (JSON Logs)"
echo "----------------------------------------"

ATTACK_LOG="/mnt/e/nos/Network_Security_poc/honey_pot/logs/attacks.jsonl"

if [ -f "$ATTACK_LOG" ]; then
    ATTACK_COUNT=$(wc -l < "$ATTACK_LOG" 2>/dev/null || echo "0")
    echo "[OK] Attack log exists: $ATTACK_COUNT attacks recorded"
    
    if [ "$ATTACK_COUNT" -gt 0 ]; then
        echo ""
        echo "Latest attack:"
        echo "---"
        tail -1 "$ATTACK_LOG" | jq '.' 2>/dev/null || tail -1 "$ATTACK_LOG"
        echo "---"
    fi
else
    echo "[INFO] No attack log yet: $ATTACK_LOG"
fi

echo ""
echo "========================================"
echo "QUICK COMMANDS"
echo "========================================"
echo ""
echo "View live Beelzebub logs:"
echo "  tail -f $LOG_FILE"
echo ""
echo "View live attack data:"
echo "  tail -f $ATTACK_LOG | jq '.'"
echo ""
echo "Check all rerouted devices:"
echo "  docker network inspect honeypot_net"
echo ""
echo "Remove all iptables rules:"
echo "  sudo iptables -t nat -F PREROUTING"
echo ""
echo "========================================"
