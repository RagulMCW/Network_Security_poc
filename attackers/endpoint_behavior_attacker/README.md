# Endpoint Behavior-Based Malware Attacker

## Overview
This attacker simulates **malicious endpoint behaviors** WITHOUT using real malware files. It focuses on **behavioral anomalies** that should be detected by **anomaly-based detection systems** (Case 2).

## Detection Strategy: Case 2 - Anomaly/Behavior Detection

Unlike the signature-based attacker which uploads real malware files, this attacker:
- ✅ Uses **DUMMY files** (no real malware)
- ✅ Exhibits **malicious behavior patterns**
- ✅ Should be caught by **anomaly detection**, not signature matching
- ✅ Simulates **6 different attack behaviors**

## Malicious Behaviors Simulated

### 1. **Port Scanning** (Reconnaissance)
- Rapidly scans multiple ports (21, 22, 23, 25, 80, 443, 445, 3389, 5000, 8080, 8443, 9000)
- Attempts to identify open services
- **Anomaly**: Unusual network scanning pattern from endpoint

### 2. **Suspicious API Abuse**
- High-frequency API calls (every 5 seconds)
- Multiple endpoints targeted
- Automated user-agent strings
- **Anomaly**: Rate limiting violations, suspicious automation patterns

### 3. **Credential Harvesting**
- Attempts to access sensitive files:
  - `/etc/passwd`, `/etc/shadow`
  - SSH keys (`/root/.ssh/id_rsa`)
  - AWS credentials (`~/.aws/credentials`)
  - Windows SAM files
- **Anomaly**: Repeated access to credential storage locations

### 4. **Privilege Escalation Attempts**
- Repeated privilege elevation requests
- Commands like `sudo su -`, `runas /user:administrator`
- Multiple failed authentication attempts
- **Anomaly**: Unusual permission request patterns

### 5. **Lateral Movement**
- Attempts to connect to other network devices
- SMB/network share access attempts
- Scanning adjacent IP ranges
- **Anomaly**: Unauthorized network connection attempts

### 6. **Data Staging**
- Collects files in temporary locations
- Creates hidden staging directories
- Batches multiple files together
- **Anomaly**: Unusual file collection patterns

## Comparison with Malware File Attacker

| Feature | Malware Attacker (Case 1) | Endpoint Behavior Attacker (Case 2) |
|---------|---------------------------|-------------------------------------|
| **Detection Method** | Signature-based (hash matching) | Anomaly/Behavior-based |
| **File Type** | Real malware APK | Dummy files only |
| **Primary Activity** | File upload | Multiple behavioral patterns |
| **IP Address** | 192.168.6.200 | 192.168.6.201 |
| **Should be blocked by** | Hash database, YARA rules | Behavioral analysis, anomaly detection |

## Quick Start

### 1. Start the Attacker
```cmd
START.bat
```

### 2. View Live Logs
```cmd
LOGS.bat
```

### 3. Stop the Attacker
```cmd
STOP.bat
```

### 4. Rebuild (after code changes)
```cmd
REBUILD.bat
```

## Configuration

Edit `docker-compose.yml` to adjust behavior intervals:

```yaml
environment:
  - TARGET_IP=192.168.6.131          # Network monitor IP
  - TARGET_PORT=5000                  # Monitor port
  - SCAN_INTERVAL=10                  # Port scan interval (seconds)
  - API_ABUSE_INTERVAL=5              # API abuse interval (seconds)
  - CREDENTIAL_ACCESS_INTERVAL=8      # Credential access interval (seconds)
```

## Network Configuration

- **Container Name**: `endpoint_behavior_attacker`
- **IP Address**: `192.168.6.201`
- **Network**: `custom_net` (external)
- **Target**: Network Monitor at `192.168.6.131:5000`

## Logs

Logs are stored in two locations:
1. **Container logs**: View with `docker logs -f endpoint_behavior_attacker`
2. **File logs**: `./logs/behavior_simulator.log`

## Expected Detection

This attacker should trigger:
- ✅ **Anomaly alerts** for suspicious behavior patterns
- ✅ **Rate limiting** violations
- ✅ **Behavioral analysis** flags
- ✅ **Network anomaly** detection
- ❌ **NOT signature-based** detection (uses dummy files, not real malware)

## Testing Detection

1. Start this attacker alongside the malware file attacker
2. Monitor which detection system catches which attacker:
   - **Case 1 (Signature)**: Should catch malware file attacker
   - **Case 2 (Behavior)**: Should catch this endpoint behavior attacker
3. Verify that both detection methods work independently

## Troubleshooting

### Container won't start
```cmd
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Check if running
```cmd
docker ps | findstr endpoint_behavior
```

### Network connectivity
```cmd
docker exec endpoint_behavior_attacker ping 192.168.6.131
```

### View detailed logs
```cmd
docker logs endpoint_behavior_attacker --tail 100
```

## Architecture

```
Endpoint Behavior Attacker (192.168.6.201)
    ↓
6 Malicious Behavior Threads:
  1. Port Scanning (every 10s)
  2. API Abuse (every 5s)
  3. Credential Harvesting (every 8s)
  4. Privilege Escalation (every 12s)
  5. Lateral Movement (every 15s)
  6. Data Staging (every 18s)
    ↓
Target: Network Monitor (192.168.6.131:5000)
    ↓
Detection: Behavioral Anomaly Analysis
    ↓
Action: Device should be marked malicious & blocked
```

## Key Differences from Malware Attacker

1. **No Real Malware**: Uses dummy files only
2. **Behavioral Focus**: Emphasizes attack patterns, not file signatures
3. **Multiple Attack Vectors**: 6 different malicious behaviors
4. **Continuous Operation**: All behaviors run simultaneously
5. **Detection Method**: Should trigger anomaly detection, not signature matching

## Security Note

⚠️ **This is a testing tool for security systems**
- Does NOT contain real malware
- Uses only dummy/benign files
- Simulates malicious behaviors for testing purposes
- Should only be used in controlled lab environments

## Integration with Detection System

Your detection system should:
1. **Monitor** this endpoint for behavioral anomalies
2. **Detect** suspicious patterns (port scanning, credential access, etc.)
3. **Flag** the device as malicious based on behavior
4. **Block** the endpoint (192.168.6.201) automatically
5. **Differentiate** this from signature-based detection of the other attacker
