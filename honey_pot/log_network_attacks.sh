#!/bin/bash
# Simple network attack logger for rerouted devices
# Logs when devices are on honeypot_net (indicating they're isolated attackers)

LOG_FILE="/mnt/e/nos/Network_Security_poc/honey_pot/logs/network_attacks.jsonl"
INTERVAL=10

echo "[$(date)] Starting network attack logger..."

mkdir -p "$(dirname "$LOG_FILE")"

while true; do
    # Get containers on honeypot_net (excluding honeypot itself)
    containers=$(docker ps --filter "network=honeypot_net" --format "{{.Names}}" | grep -v beelzebub)
    
    for container in $containers; do
        # Get container IP on honeypot_net
        ip=$(docker inspect "$container" --format '{{.NetworkSettings.Networks.honeypot_net.IPAddress}}' 2>/dev/null)
        
        if [ -n "$ip" ] && [ "$ip" != "" ]; then
            # Determine attack type based on container name
            attack_type="Unknown"
            if echo "$container" | grep -q "hping"; then
                attack_type="DoS_Flood"
            elif echo "$container" | grep -q "curl"; then
                attack_type="HTTP_Flood"
            elif echo "$container" | grep -q "attacker"; then
                attack_type="Malicious_Activity"
            fi
            
            # Log the attack
            timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            echo "{\"timestamp\":\"$timestamp\",\"source_container\":\"$container\",\"source_ip\":\"$ip\",\"attack_type\":\"$attack_type\",\"packet_count\":0,\"protocol\":\"network_flood\",\"port\":\"all\"}" >> "$LOG_FILE"
            
            echo "[$(date)] Logged $attack_type from $container ($ip)"
        fi
    done
    
    sleep "$INTERVAL"
done
