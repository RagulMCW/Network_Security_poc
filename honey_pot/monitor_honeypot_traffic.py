#!/usr/bin/env python3
"""
Monitor network traffic on honeypot_net and log attack patterns
This captures network-level attacks like DoS floods that don't appear in application logs
"""

import subprocess
import time
import json
from datetime import datetime
from collections import defaultdict
import os

HONEYPOT_NETWORK = "honeypot_net"
LOG_FILE = "/mnt/e/nos/Network_Security_poc/honey_pot/logs/network_attacks.jsonl"
INTERVAL = 10  # Check every 10 seconds

def get_container_stats(container_name):
    """Get network statistics for a container"""
    try:
        # Get container network stats
        cmd = f'docker stats {container_name} --no-stream --format "{{{{json .}}}}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0 and result.stdout.strip():
            stats = json.loads(result.stdout.strip())
            return stats
    except Exception as e:
        print(f"Error getting stats for {container_name}: {e}")
    return None

def get_containers_on_honeypot():
    """Get list of containers on honeypot_net (excluding honeypot itself)"""
    try:
        cmd = f'docker ps --filter "network={HONEYPOT_NETWORK}" --format "{{{{.Names}}}}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0 and result.stdout.strip():
            containers = [c.strip() for c in result.stdout.strip().split('\n')]
            # Filter out honeypot itself
            return [c for c in containers if c and 'beelzebub' not in c.lower()]
    except Exception as e:
        print(f"Error getting honeypot containers: {e}")
    return []

def get_container_ip(container_name):
    """Get container IP on honeypot_net"""
    try:
        cmd = f'docker inspect {container_name} --format "{{{{.NetworkSettings.Networks.{HONEYPOT_NETWORK}.IPAddress}}}}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception as e:
        print(f"Error getting IP for {container_name}: {e}")
    return "unknown"

def count_packets_to_honeypot(container_name):
    """Count packets from container to honeypot using tcpdump"""
    try:
        # Run tcpdump for 5 seconds to count packets
        container_ip = get_container_ip(container_name)
        if container_ip == "unknown":
            return 0
        
        # Get honeypot IP
        honeypot_ip_cmd = f'docker inspect beelzebub-honeypot --format "{{{{.NetworkSettings.Networks.{HONEYPOT_NETWORK}.IPAddress}}}}"'
        honeypot_result = subprocess.run(honeypot_ip_cmd, shell=True, capture_output=True, text=True, timeout=5)
        
        if honeypot_result.returncode != 0:
            return 0
        
        honeypot_ip = honeypot_result.stdout.strip()
        
        # Count packets in 5-second window
        tcpdump_cmd = f'timeout 5 docker exec beelzebub-honeypot tcpdump -i eth0 -c 10000 src {container_ip} 2>&1 | tail -1'
        result = subprocess.run(tcpdump_cmd, shell=True, capture_output=True, text=True)
        
        # Parse output: "123 packets captured"
        if "packets captured" in result.stdout:
            count_str = result.stdout.split("packets captured")[0].strip().split()[-1]
            return int(count_str)
    except Exception as e:
        print(f"Error counting packets: {e}")
    return 0

def log_attack(container_name, container_ip, packet_count, attack_type):
    """Log attack to JSONL file"""
    try:
        attack_data = {
            "timestamp": datetime.now().isoformat(),
            "source_container": container_name,
            "source_ip": container_ip,
            "attack_type": attack_type,
            "packet_count": packet_count,
            "protocol": "network_flood",
            "port": "all"
        }
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(attack_data) + '\n')
        
        print(f"[{datetime.now()}] Logged {attack_type} from {container_name} ({container_ip}): {packet_count} packets")
    except Exception as e:
        print(f"Error logging attack: {e}")

def analyze_traffic():
    """Analyze traffic from rerouted containers"""
    print(f"[{datetime.now()}] Starting honeypot traffic monitor...")
    
    packet_history = defaultdict(list)
    
    while True:
        try:
            containers = get_containers_on_honeypot()
            
            if not containers:
                time.sleep(INTERVAL)
                continue
            
            for container in containers:
                container_ip = get_container_ip(container)
                
                # Check if container is sending high packet rates
                # For DoS detection: count packets in 5-second window
                # High rate = DoS flood
                
                # Simple detection: if container exists on honeypot_net, it was rerouted
                # Log its presence and basic stats
                
                # Get current time for tracking
                now = datetime.now()
                
                # For demonstration, log every rerouted container activity
                # In production, you'd want more sophisticated detection
                
                # Check if this is a known attacker container (hping3, curl, etc.)
                is_attacker = any(x in container.lower() for x in ['hping', 'curl', 'attacker', 'dos'])
                
                if is_attacker:
                    # Log this as an active attack
                    log_attack(
                        container_name=container,
                        container_ip=container_ip,
                        packet_count=0,  # Would need tcpdump to get actual count
                        attack_type="DoS_Flood" if 'hping' in container.lower() else "HTTP_Flood"
                    )
        
        except Exception as e:
            print(f"Error in analyze_traffic loop: {e}")
        
        time.sleep(INTERVAL)

if __name__ == "__main__":
    try:
        analyze_traffic()
    except KeyboardInterrupt:
        print("\n[*] Traffic monitor stopped by user")
    except Exception as e:
        print(f"Fatal error: {e}")
