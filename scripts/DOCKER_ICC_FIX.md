# Docker Inter-Container Communication Fix

## Problem
Devices (vdevice_001, vdevice_002) were unable to connect to network-monitor (192.168.6.131:5000) with connection timeout errors, even though they were on the same Docker network (custom_net).

## Root Cause
The iptables FORWARD chain had a **DROP policy** which was blocking all inter-container communication on the custom_net bridge network.

## Solution

### Critical iptables Rule
```bash
sudo iptables -I FORWARD 1 -i br-b1ac5d1cbe59 -o br-b1ac5d1cbe59 -j ACCEPT
sudo iptables -I FORWARD 1 -s 192.168.6.0/24 -d 192.168.6.0/24 -j ACCEPT
```

Where `br-b1ac5d1cbe59` is the bridge interface for custom_net (get it via `docker network inspect custom_net`).

### Automated Enforcement
1. **ensure_docker_icc.bat** - Script to ensure ICC rule exists
   - Located: `scripts/ensure_docker_icc.bat`
   - Run anytime to verify/restore the rule

2. **Network START.bat** - Automatically runs ICC check on startup
   - Located: `network/START.bat`
   - Calls ensure_docker_icc.bat after starting network-monitor

3. **Dashboard Protection** - Clear iptables button preserves ICC rule
   - Modified: `dashboard/app.py` - `/api/beelzebub/clear_all_dnat` endpoint
   - Changed from `iptables -F FORWARD` (flushes ALL) to selective rule removal
   - Automatically restores ICC rule after clearing DNAT rules

## Why This Rule is Critical
Without this rule:
- ❌ Devices cannot send data to network-monitor
- ❌ Devices cannot check status with network-monitor  
- ❌ All HTTP requests timeout after 5 seconds
- ❌ Network topology appears broken despite correct configuration

With this rule:
- ✅ Devices can communicate within custom_net (192.168.6.0/24)
- ✅ HTTP requests to network-monitor:5000 succeed
- ✅ Device data flows normally
- ✅ Network monitoring functions properly

## Verification

Check if rule exists:
```bash
wsl bash -c "sudo iptables -L FORWARD -n -v --line-numbers | head -10"
```

Expected output should show:
```
1    0     0 ACCEPT     0    --  br-b1ac5d1cbe59 br-b1ac5d1cbe59  0.0.0.0/0  0.0.0.0/0
2    0     0 ACCEPT     0    --  *      *       192.168.6.0/24   192.168.6.0/24
```

Test connectivity:
```bash
wsl bash -c "docker exec vdevice_002 python3 -c 'import requests; print(requests.get(\"http://192.168.6.131:5000/\", timeout=2).status_code)'"
```

Should return `404` (server responds) instead of timeout.

## Additional Fixes Applied
- **Port correction**: Changed device_simulator.py from port 5002 → 5000
  - `devices/device_simulator.py` line 20: `SERVER_URL = 'http://192.168.6.131:5000'`

## Related Files
- `/scripts/ensure_docker_icc.bat` - ICC rule enforcement script
- `/network/START.bat` - Network startup with ICC check
- `/dashboard/app.py` - Protected clear_all_dnat endpoint
- `/devices/device_simulator.py` - Fixed port configuration
