# SSH Brute Force Attacker

## Overview
Simulates SSH brute force attacks against the target server (192.168.6.131:22) for security testing and honeypot validation.

## Features
- **Brute Force Attack**: Attempts login with common username/password combinations
- **Continuous Testing**: Runs indefinitely with configurable intervals
- **Detailed Logging**: Dumps SSH attack logs every 5 seconds
- **Real-time Monitoring**: Color-coded output for success/failure

## Configuration

### Environment Variables
- `TARGET_IP`: Target SSH server IP (default: 192.168.6.131)
- `TARGET_PORT`: SSH port (default: 22)
- `ATTACK_INTERVAL`: Seconds between login attempts (default: 5)
- `LOG_INTERVAL`: Seconds between log dumps (default: 5)

### Network
- **Attacker IP**: 192.168.6.133
- **Network**: custom_net (192.168.6.0/24)

## Usage

### Start SSH Attacker
```bash
cd E:\nos\Network_Security_poc\attackers\ssh_attacker
docker-compose up -d
```

### View Live Logs
```bash
docker logs -f ssh-attacker
```

### Stop Attacker
```bash
docker-compose down
```

## Log Files

### Location
`E:\nos\Network_Security_poc\attackers\ssh_attacker\logs\`

### Files
1. **ssh_attacks_YYYYMMDD_HHMMSS.log**: Detailed attack log with timestamps
2. **ssh_summary.log**: Summary statistics dumped every 5 seconds

### View Logs
```bash
# View detailed logs
type logs\ssh_attacks_*.log

# View summary
type logs\ssh_summary.log

# Real-time monitoring (WSL)
wsl tail -f /mnt/e/nos/Network_Security_poc/attackers/ssh_attacker/logs/ssh_summary.log
```

## Attack Credentials

### Usernames Tested
- root
- admin
- user
- test
- ubuntu
- debian
- pi
- administrator
- guest

### Passwords Tested
- password
- 123456
- admin
- root
- toor
- test
- 12345678
- qwerty
- password123
- letmein

## Expected Behavior

1. **Normal Operation** (No Honeypot Redirect):
   - Attacker tries SSH login to 192.168.6.131:22
   - All attempts fail (no valid credentials)
   - Logs show failed attempts every 5 seconds

2. **When MCP Detects Attack**:
   - MCP creates iptables DNAT rules
   - Traffic redirects to Beelzebub honeypot (172.18.0.2:22)
   - Beelzebub SSH honeypot captures attempts
   - PCAP files show redirected SSH traffic

3. **Honeypot Detection**:
   - High frequency of SSH connection attempts
   - Multiple failed login attempts
   - Pattern matches brute force behavior

## Verification

### Check Attacker is Running
```bash
docker ps | findstr ssh-attacker
```

### Check Target Server SSH
```bash
wsl bash -c "nc -zv 192.168.6.131 22"
```

### Check iptables Redirect (After MCP Detection)
```bash
wsl bash -c "sudo iptables -t nat -L PREROUTING -n -v | grep 192.168.6.133"
```

### Check PCAP for SSH Traffic
```bash
wsl bash -c "tcpdump -r /mnt/e/nos/Network_Security_poc/honey_pot/pcap_captures/[latest].pcap -n 'port 22'"
```

## Integration with System

### Dashboard Control
The SSH attacker will be integrated with the dashboard for easy start/stop control.

### MCP Detection
When SSH brute force is detected (high connection rate), MCP will:
1. Identify malicious behavior
2. Create iptables DNAT rules
3. Redirect traffic to Beelzebub honeypot
4. Log the isolation event

### Cleanup
When stopped via dashboard:
```bash
wsl bash /mnt/e/nos/Network_Security_poc/attackers/dos_attacker/cleanup_iptables.sh 192.168.6.133
```

## Security Notes
- **Testing Only**: This tool is for security testing in controlled environments
- **Do Not Use**: Against systems you don't own or have permission to test
- **Legal Compliance**: Ensure all testing complies with local laws and regulations
