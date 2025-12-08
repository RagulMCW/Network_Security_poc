#!/usr/bin/env python3
"""
Apply DNAT iptables rules for endpoint_behavior_attacker
Reroutes ALL traffic to Beelzebub honeypot
"""

import subprocess
import sys

ATTACKER_IP = "192.168.6.201"
HONEYPOT_IP = "172.18.0.2"

def run_command(cmd):
    """Run WSL command and return result"""
    try:
        result = subprocess.run(
            ['wsl', 'bash', '-c', cmd],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Timeout"
    except Exception as e:
        return False, "", str(e)

def main():
    print("=" * 80)
    print("Applying DNAT iptables rules for endpoint_behavior_attacker")
    print("=" * 80)
    print(f"  Source IP: {ATTACKER_IP}")
    print(f"  Honeypot IP: {HONEYPOT_IP}")
    print("=" * 80)
    print()
    
    # DNAT rules for ALL traffic - 9 ports
    dnat_rules = [
        f"sudo iptables -t nat -A PREROUTING -s {ATTACKER_IP} -p tcp --dport 80 -j DNAT --to-destination {HONEYPOT_IP}:8080",
        f"sudo iptables -t nat -A PREROUTING -s {ATTACKER_IP} -p tcp --dport 443 -j DNAT --to-destination {HONEYPOT_IP}:8080",
        f"sudo iptables -t nat -A PREROUTING -s {ATTACKER_IP} -p tcp --dport 8080 -j DNAT --to-destination {HONEYPOT_IP}:8080",
        f"sudo iptables -t nat -A PREROUTING -s {ATTACKER_IP} -p tcp --dport 5000 -j DNAT --to-destination {HONEYPOT_IP}:8080",
        f"sudo iptables -t nat -A PREROUTING -s {ATTACKER_IP} -p tcp --dport 22 -j DNAT --to-destination {HONEYPOT_IP}:22",
        f"sudo iptables -t nat -A PREROUTING -s {ATTACKER_IP} -p tcp --dport 3306 -j DNAT --to-destination {HONEYPOT_IP}:3306",
        f"sudo iptables -t nat -A PREROUTING -s {ATTACKER_IP} -p tcp --dport 5432 -j DNAT --to-destination {HONEYPOT_IP}:5432",
        f"sudo iptables -t nat -A PREROUTING -s {ATTACKER_IP} -p tcp --dport 21 -j DNAT --to-destination {HONEYPOT_IP}:21",
        f"sudo iptables -t nat -A PREROUTING -s {ATTACKER_IP} -p tcp --dport 23 -j DNAT --to-destination {HONEYPOT_IP}:23"
    ]
    
    # FORWARD rules
    forward_rules = [
        f"sudo iptables -A FORWARD -s {ATTACKER_IP} -d {HONEYPOT_IP} -j ACCEPT",
        f"sudo iptables -A FORWARD -s {HONEYPOT_IP} -d {ATTACKER_IP} -j ACCEPT"
    ]
    
    # MASQUERADE rule
    masquerade_rule = f"sudo iptables -t nat -A POSTROUTING -s {ATTACKER_IP} -d {HONEYPOT_IP} -j MASQUERADE"
    
    all_rules = dnat_rules + forward_rules + [masquerade_rule]
    
    applied = 0
    failed = 0
    
    port_names = ["HTTP (80)", "HTTPS (443)", "HTTP-ALT (8080)", "Flask (5000)", "SSH (22)", "MySQL (3306)", "PostgreSQL (5432)", "FTP (21)", "Telnet (23)", "FORWARD (1/2)", "FORWARD (2/2)", "MASQUERADE"]
    
    for i, rule in enumerate(all_rules):
        port_name = port_names[i] if i < len(port_names) else f"Rule {i+1}"
        print(f"[{i+1}/{len(all_rules)}] Applying {port_name}...", end=" ")
        
        success, stdout, stderr = run_command(rule)
        
        if success:
            print("✅")
            applied += 1
        else:
            print(f"❌ {stderr}")
            failed += 1
    
    print()
    print("=" * 80)
    print("VERIFICATION: Current DNAT rules")
    print("=" * 80)
    
    verify_cmd = f"sudo iptables -t nat -L PREROUTING -n -v --line-numbers | grep {ATTACKER_IP}"
    success, stdout, stderr = run_command(verify_cmd)
    
    if success and stdout:
        print(stdout)
    else:
        print("No rules found or verification failed")
    
    print()
    print("=" * 80)
    print(f"RESULT: {applied} rules applied successfully, {failed} failed")
    print("=" * 80)
    print(f"  Device: endpoint_behavior_attacker ({ATTACKER_IP})")
    print(f"  Honeypot: Beelzebub ({HONEYPOT_IP})")
    print(f"  Method: Traffic rerouting only - device stays on custom_net")
    print("=" * 80)
    print()
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
