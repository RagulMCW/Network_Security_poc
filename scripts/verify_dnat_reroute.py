#!/usr/bin/env python3
"""
Verify DNAT traffic rerouting and test SSH connection
"""

import subprocess
import json
import time

def run_command(cmd):
    """Run WSL command and return result"""
    try:
        result = subprocess.run(
            ['wsl', 'bash', '-c', cmd],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "Timeout"
    except Exception as e:
        return False, "", str(e)

def main():
    print("=" * 80)
    print("DNAT Traffic Rerouting Verification")
    print("=" * 80)
    print()
    
    # 1. Check endpoint_behavior_attacker networks
    print("[1/6] Checking endpoint_behavior_attacker networks...")
    cmd = 'docker inspect endpoint_behavior_attacker --format \'{{json .NetworkSettings.Networks}}\''
    success, stdout, stderr = run_command(cmd)
    
    if success:
        networks = json.loads(stdout)
        print(f"  ✅ Container is on {len(networks)} network(s):")
        for net_name, net_info in networks.items():
            ip = net_info.get('IPAddress', 'N/A')
            print(f"     - {net_name}: {ip}")
    else:
        print(f"  ❌ Failed: {stderr}")
        return 1
    
    print()
    
    # 2. Check if on both custom_net and honeypot_net
    print("[2/6] Verifying network connections...")
    has_custom_net = 'custom_net' in networks
    has_honeypot_net = 'honey_pot_honeypot_net' in networks
    
    custom_net_ip = networks.get('custom_net', {}).get('IPAddress', 'N/A')
    honeypot_net_ip = networks.get('honey_pot_honeypot_net', {}).get('IPAddress', 'N/A')
    
    if has_custom_net:
        print(f"  ✅ Connected to custom_net: {custom_net_ip}")
    else:
        print("  ❌ NOT on custom_net")
    
    if has_honeypot_net:
        print(f"  ✅ Connected to honeypot_net: {honeypot_net_ip}")
    else:
        print("  ❌ NOT on honeypot_net")
    
    print()
    
    # 3. Check Beelzebub honeypot IP
    print("[3/6] Getting Beelzebub honeypot IP...")
    cmd = 'docker inspect beelzebub-honeypot --format \'{{.NetworkSettings.Networks.honey_pot_honeypot_net.IPAddress}}\''
    success, honeypot_ip, stderr = run_command(cmd)
    
    if success and honeypot_ip:
        print(f"  ✅ Beelzebub IP: {honeypot_ip}")
    else:
        print(f"  ❌ Failed to get Beelzebub IP: {stderr}")
        honeypot_ip = "172.18.0.2"
        print(f"  ⚠️  Using default: {honeypot_ip}")
    
    print()
    
    # 4. Test ping connectivity
    print("[4/6] Testing ping connectivity to honeypot...")
    cmd = f'docker exec endpoint_behavior_attacker ping -c 3 {honeypot_ip}'
    success, stdout, stderr = run_command(cmd)
    
    if success and 'packets transmitted' in stdout:
        # Extract packet stats
        lines = stdout.split('\n')
        for line in lines:
            if 'packets transmitted' in line:
                print(f"  ✅ {line.strip()}")
                break
    else:
        print(f"  ❌ Ping failed: {stderr if stderr else 'No response'}")
    
    print()
    
    # 5. Check active DNAT rules
    print("[5/6] Verifying DNAT iptables rules...")
    cmd = 'sudo iptables -t nat -L PREROUTING -n -v --line-numbers | grep 192.168.6.201 | wc -l'
    success, rule_count, stderr = run_command(cmd)
    
    if success and rule_count:
        print(f"  ✅ {rule_count} DNAT rules active for 192.168.6.201")
    else:
        print("  ❌ No DNAT rules found")
    
    print()
    
    # 6. Test SSH connection (with DNAT - should be rerouted to honeypot)
    print("[6/6] Testing SSH connection to trigger DNAT...")
    print("  Attempting SSH to 192.168.6.131:22 (should be rerouted to honeypot)...")
    
    # Use sshpass if available
    cmd = 'docker exec endpoint_behavior_attacker sshpass -p "admin" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 root@192.168.6.131 "whoami" 2>&1'
    success, stdout, stderr = run_command(cmd)
    
    if success and 'root' in stdout:
        print(f"  ✅ SSH connection successful!")
        print(f"     Response: {stdout[:100]}")
    else:
        print(f"  ⚠️  SSH response: {stdout[:200] if stdout else stderr[:200]}")
    
    print()
    
    # 7. Check Beelzebub logs for recent connections
    print("[7/6] Checking Beelzebub logs for recent activity...")
    cmd = 'tail -20 /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/honey_pot/logs/beelzebub.log | grep -i "192.168.6.201\\|SSH\\|Login" | tail -5'
    success, stdout, stderr = run_command(cmd)
    
    if success and stdout:
        print("  ✅ Recent Beelzebub activity:")
        for line in stdout.split('\n')[:5]:
            if line.strip():
                print(f"     {line[:150]}")
    else:
        print("  ⚠️  No recent activity in Beelzebub logs")
    
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"  • endpoint_behavior_attacker: {custom_net_ip} (custom_net)")
    print(f"  • Also connected to: {honeypot_net_ip} (honeypot_net)")
    print(f"  • Beelzebub honeypot: {honeypot_ip}")
    print(f"  • DNAT rules active: {rule_count}")
    print(f"  • Next: Monitor Beelzebub logs for SSH connections")
    print("=" * 80)
    print()
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
