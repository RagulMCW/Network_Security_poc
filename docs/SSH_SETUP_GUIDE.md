# SSH Honeypot Setup - Complete Guide

## 🎯 What Was Created

### 1. SSH Server on 192.168.6.131
- **Container**: network-monitor (updated)
- **SSH Port**: 22 (exposed as 2222 on host)
- **Purpose**: Target for SSH brute force attacks

#### Test Accounts Created:
| Username | Password | Description |
|----------|----------|-------------|
| root | rootpassword | Root access |
| admin | admin123 | Admin account |
| test | test123 | Test user |
| user | password | Regular user |

### 2. SSH Brute Force Attacker on 192.168.6.133
- **Container**: ssh-attacker
- **Target**: 192.168.6.131:22
- **Attack Interval**: 5 seconds between attempts
- **Log Dump Interval**: 5 seconds

#### Attack Strategy:
- Tests 9 common usernames (root, admin, user, test, ubuntu, debian, pi, administrator, guest)
- Tests 10 common passwords (password, 123456, admin, root, toor, test, 12345678, qwerty, password123, letmein)
- Runs continuously in rounds (90 attempts per round)
- Logs all attempts with timestamp

### 3. Dashboard Integration
- New SSH attacker control panel
- Start/Stop buttons for SSH attacker
- View logs directly from dashboard
- Real-time status monitoring

---

## 📁 Files Created/Modified

### New Files:
```
attackers/ssh_attacker/
├── docker-compose.yml           # SSH attacker configuration
├── Dockerfile                   # Container build instructions
├── ssh_bruteforce.sh           # Main attack script
├── START_SSH_ATTACKER.bat      # Quick start script
├── STOP_SSH_ATTACKER.bat       # Quick stop script
├── VIEW_LOGS.bat               # Log viewer utility
├── README.md                   # Documentation
├── logs/                       # Log output directory
└── wordlists/                  # Username/password lists
    ├── usernames.txt
    └── passwords.txt

SETUP_SSH.bat                   # Main setup script
```

### Modified Files:
```
network/docker/Dockerfile       # Added SSH server
network/docker-compose.yml      # Exposed port 22
network/scripts/start_services.sh # Start SSH on boot
dashboard/app.py                # Added SSH attacker API endpoints
dashboard/templates/control_panel.html # Added SSH controls
dashboard/static/dashboard.js   # Added SSH JavaScript functions
```

---

## 🚀 Quick Start

### Step 1: Setup SSH Server and Attacker
```batch
cd E:\nos\Network_Security_poc
SETUP_SSH.bat
```

This will:
1. Rebuild network monitor with SSH server
2. Build SSH attacker container
3. Start network monitor (SSH server will be running)

### Step 2: Start SSH Attacker

**Option A: From Dashboard**
1. Open dashboard: http://localhost:5100
2. Go to "Attack Simulators" page
3. Click "Start SSH Attacker"

**Option B: From Command Line**
```batch
cd E:\nos\Network_Security_poc\attackers\ssh_attacker
START_SSH_ATTACKER.bat
```

### Step 3: Monitor Attacks

**View Live Container Logs:**
```batch
wsl docker logs -f ssh-attacker
```

**View From Dashboard:**
1. Open dashboard: http://localhost:5100
2. Go to "Attack Simulators" page
3. Click "View Logs" under SSH Attacker

**View Log Files:**
```batch
cd E:\nos\Network_Security_poc\attackers\ssh_attacker\logs
type ssh_summary.log
```

---

## 🧪 Testing & Verification

### Test SSH Server is Running
```bash
# From Windows
wsl ssh -p 2222 admin@localhost
# Password: admin123

# From inside Docker network
wsl docker exec ssh-attacker ssh admin@192.168.6.131
```

### Check SSH Server Logs
```bash
wsl docker exec network-monitor tail -f /var/log/auth.log
```

### Verify Attack Traffic
```bash
# Check if SSH attacker is running
wsl docker ps | grep ssh-attacker

# Watch live attacks
wsl docker logs -f ssh-attacker

# Check iptables rules (after MCP detection)
wsl bash -c "sudo iptables -t nat -L PREROUTING -n -v | grep 192.168.6.133"
```

### Check PCAP for SSH Traffic
```bash
# View captured SSH packets
wsl bash -c "tcpdump -r /mnt/e/nos/Network_Security_poc/honey_pot/pcap_captures/[latest].pcap -n 'port 22' | head -20"
```

---

## 📊 Expected Behavior

### Phase 1: Normal Operation
1. SSH attacker sends login attempts to 192.168.6.131:22
2. Network monitor SSH server receives attempts
3. All attempts fail (wrong passwords)
4. Logs show failed authentication attempts every 5 seconds

**Sample Log Output:**
```
[2025-10-30 10:15:23] Attempting login: root:password
[2025-10-30 10:15:23] ✗ FAILED: root:password
[2025-10-30 10:15:28] Attempting login: root:123456
[2025-10-30 10:15:28] ✗ FAILED: root:123456
```

### Phase 2: MCP Detection & Isolation
When MCP agent detects SSH brute force pattern:

1. **Detection Triggers:**
   - High frequency of SSH connection attempts
   - Multiple failed login attempts
   - Matches brute force behavior signature

2. **MCP Actions:**
   - Creates iptables DNAT rules
   - Redirects 192.168.6.133 traffic to Beelzebub honeypot (172.18.0.2)
   - Logs isolation event in reroutes.log

3. **Traffic Flow Changes:**
   ```
   BEFORE: SSH Attacker → Network Monitor SSH Server
   AFTER:  SSH Attacker → iptables DNAT → Beelzebub Honeypot (172.18.0.2:22)
   ```

4. **Beelzebub Captures:**
   - SSH connection attempts logged
   - Brute force pattern recorded
   - All traffic captured in PCAP files

### Phase 3: Cleanup & Reset
When stopped via dashboard:

1. Dashboard calls cleanup script for 192.168.6.133
2. iptables rules removed
3. SSH attacker container stopped
4. Traffic returns to normal flow

---

## 🔍 Verification Checklist

### SSH Server (192.168.6.131)
- [ ] Container running: `wsl docker ps | grep network-monitor`
- [ ] SSH port listening: `wsl docker exec network-monitor netstat -tlnp | grep :22`
- [ ] Can connect: `wsl ssh -p 2222 admin@localhost`
- [ ] Test accounts work: Try admin:admin123

### SSH Attacker (192.168.6.133)
- [ ] Container running: `wsl docker ps | grep ssh-attacker`
- [ ] Logs generating: `wsl docker logs ssh-attacker`
- [ ] Log files created: Check `attackers/ssh_attacker/logs/`
- [ ] Summary updates every 5 seconds

### Dashboard Integration
- [ ] SSH attacker controls visible on "Attack Simulators" page
- [ ] Start button works
- [ ] Stop button works
- [ ] View logs button shows output
- [ ] Status badge updates

### MCP Agent Detection
- [ ] MCP agent running: Check dashboard
- [ ] Detects SSH brute force after ~30+ attempts
- [ ] Creates iptables rules: `sudo iptables -t nat -L PREROUTING`
- [ ] Logs isolation in reroutes.log

### Honeypot Capture
- [ ] Beelzebub running: `wsl docker ps | grep beelzebub`
- [ ] PCAP capture running: `wsl docker ps | grep pcap-capture`
- [ ] PCAP files have SSH traffic: Check pcap_captures/
- [ ] Beelzebub logs show SSH attempts

---

## 📈 Log Locations

| Component | Log Location | Description |
|-----------|-------------|-------------|
| SSH Attacker Container | `wsl docker logs ssh-attacker` | Live container output |
| SSH Attack Details | `attackers/ssh_attacker/logs/ssh_attacks_*.log` | Detailed attempt logs |
| SSH Attack Summary | `attackers/ssh_attacker/logs/ssh_summary.log` | Statistics every 5 seconds |
| SSH Server Auth | Network monitor: `/var/log/auth.log` | SSH server authentication logs |
| MCP Isolation | `honey_pot/logs/reroutes.log` | Isolation events |
| Beelzebub Honeypot | `honey_pot/logs/beelzebub.log` | Honeypot interactions |
| PCAP Captures | `honey_pot/pcap_captures/*.pcap` | Network traffic captures |

---

## 🛠️ Troubleshooting

### SSH Server Won't Start
```bash
# Check if SSH service started
wsl docker exec network-monitor service ssh status

# Manually start SSH
wsl docker exec network-monitor service ssh start

# Check SSH logs
wsl docker exec network-monitor cat /var/log/auth.log
```

### SSH Attacker Can't Connect
```bash
# Check connectivity
wsl docker exec ssh-attacker ping 192.168.6.131

# Test SSH port
wsl docker exec ssh-attacker nc -zv 192.168.6.131 22

# Check if server is listening
wsl docker exec network-monitor netstat -tlnp | grep :22
```

### Logs Not Generating
```bash
# Check if attacker is running
wsl docker ps | grep ssh-attacker

# Check container logs
wsl docker logs ssh-attacker

# Restart attacker
cd E:\nos\Network_Security_poc\attackers\ssh_attacker
STOP_SSH_ATTACKER.bat
START_SSH_ATTACKER.bat
```

### iptables Rules Not Cleaning Up
```bash
# Manually run cleanup for SSH attacker
wsl bash /mnt/e/nos/Network_Security_poc/attackers/dos_attacker/cleanup_iptables.sh 192.168.6.133

# Verify rules removed
wsl bash -c "sudo iptables -t nat -L PREROUTING -n -v | grep 192.168.6.133"
```

---

## 🎓 Understanding the System

### Why Two Different IPs?
- **192.168.6.131**: Legitimate SSH server (network monitor)
- **192.168.6.133**: Malicious SSH attacker
- **172.18.0.2**: Beelzebub honeypot (redirect target after detection)

### Attack Flow Diagram
```
┌─────────────────┐     SSH Brute Force     ┌──────────────────┐
│  SSH Attacker   │ ───────────────────────> │  SSH Server      │
│  192.168.6.133  │                          │  192.168.6.131   │
└─────────────────┘                          └──────────────────┘
        │                                             │
        │                                             │
        │                                             ▼
        │                                    ┌──────────────────┐
        │                                    │  Auth Logs       │
        │                                    │  /var/log/auth   │
        │                                    └──────────────────┘
        │
        │ (After MCP Detection)
        │
        ▼
┌─────────────────┐     iptables DNAT       ┌──────────────────┐
│  iptables NAT   │ ───────────────────────> │  Beelzebub       │
│  PREROUTING     │                          │  172.18.0.2:22   │
└─────────────────┘                          └──────────────────┘
                                                      │
                                                      ▼
                                             ┌──────────────────┐
                                             │  PCAP Capture    │
                                             │  + Honeypot Logs │
                                             └──────────────────┘
```

### Log Dump Mechanism
Every 5 seconds, the SSH attacker dumps statistics:
- Total attempts made
- Failed attempts
- Successful attempts (if any weak credentials found)
- Timestamp of dump

This provides real-time visibility into attack progression.

---

## 📝 Configuration Variables

### SSH Attacker Environment Variables
Edit `attackers/ssh_attacker/docker-compose.yml`:
```yaml
environment:
  - TARGET_IP=192.168.6.131      # SSH server to attack
  - TARGET_PORT=22                # SSH port
  - ATTACK_INTERVAL=5             # Seconds between login attempts
  - LOG_INTERVAL=5                # Seconds between log dumps
```

### Customize Credentials
Edit wordlist files:
- `attackers/ssh_attacker/wordlists/usernames.txt`
- `attackers/ssh_attacker/wordlists/passwords.txt`

Then rebuild:
```batch
cd E:\nos\Network_Security_poc\attackers\ssh_attacker
wsl bash -c "docker-compose down && docker-compose up -d --build"
```

---

## ✅ Success Criteria

Your SSH honeypot system is working correctly when:

1. ✅ SSH server responds on 192.168.6.131:22
2. ✅ Test accounts can login successfully
3. ✅ SSH attacker generates logs every 5 seconds
4. ✅ Dashboard shows SSH attacker controls
5. ✅ MCP detects brute force pattern
6. ✅ iptables rules redirect attacker to honeypot
7. ✅ PCAP files capture SSH traffic
8. ✅ Beelzebub logs show SSH attempts
9. ✅ Cleanup script removes iptables rules
10. ✅ System resets for next test

---

## 🎯 Next Steps

1. Run `SETUP_SSH.bat` to build everything
2. Start SSH attacker from dashboard
3. Watch logs for attack attempts
4. Wait for MCP to detect and isolate
5. Verify traffic redirected to honeypot
6. Stop attacker and verify cleanup
7. Review PCAP files for captured SSH traffic

**Enjoy your SSH honeypot testing! 🎉**
