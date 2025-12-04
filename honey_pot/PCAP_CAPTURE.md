# PCAP Auto-Capture System

## Overview
The honeypot automatically captures all TCP network traffic and maintains only the 5 most recent capture files.

## Features

### ✅ Automatic Start
- PCAP capture starts **automatically** when you run `START.bat`
- No manual intervention needed
- Runs in background via `honeypot-pcap` container

### 📦 What Gets Captured
- **TCP traffic only** on honeypot ports:
  - SSH: Port 22
  - HTTP: Port 80
  - HTTPS: Port 443
  - MySQL: Port 3306
  - PostgreSQL: Port 5432
  - FTP: Port 21
  - Telnet: Port 23

### ♻️ Auto-Rotation
- Creates new PCAP file every **10 minutes**
- Filename format: `honeypot_YYYYMMDD_HHMMSS.pcap`
- Example: `honeypot_20251204_044601.pcap`

### 🗂️ Auto-Cleanup
- Keeps only **last 5 PCAP files**
- Automatically deletes older files
- Cleanup runs:
  - On honeypot startup
  - After each rotation (every 10 minutes)

## File Locations

```
honey_pot/
├── pcap_captures/              ← All PCAP files here
│   ├── honeypot_*.pcap         ← Capture files (max 5)
│   └── capture.log             ← Capture process log
└── logs/
    └── pcap_capture.log        ← Detailed capture log
```

## Usage

### View PCAP Files
```batch
# Interactive viewer
VIEW_PCAPS.bat

# Manual check
cd pcap_captures
dir honeypot_*.pcap
```

### Analyze with Wireshark
1. Navigate to `pcap_captures` folder
2. Double-click any `honeypot_*.pcap` file
3. Wireshark will open (if installed)

### Manual Cleanup
```batch
# Run cleanup script
cleanup_old_pcaps.bat

# Delete all PCAP files
cd pcap_captures
del honeypot_*.pcap
```

## Technical Details

### Container Configuration
- Image: `nicolaka/netshoot:latest`
- Container: `honeypot-pcap`
- Network Mode: Shares network with `beelzebub` container
- Capabilities: `NET_ADMIN`, `NET_RAW` (required for packet capture)

### Rotation Logic
1. Capture runs for 600 seconds (10 minutes)
2. Timeout triggers file rotation
3. New file created with current timestamp
4. Old files cleaned up (keep last 5)
5. Process repeats indefinitely

### Storage Management
- Each PCAP file size varies (typically 1-50 MB depending on traffic)
- Maximum storage: ~250 MB (5 files × ~50 MB average)
- Auto-cleanup prevents disk space issues

## Troubleshooting

### No PCAP Files Generated
**Check container status:**
```bash
docker ps --filter "name=honeypot-pcap"
```

**Check capture logs:**
```bash
docker logs honeypot-pcap
# or
type logs\pcap_capture.log
```

### PCAP Files Not Rotating
**Verify capture is running:**
```bash
docker exec honeypot-pcap ps aux | findstr tcpdump
```

**Restart capture:**
```batch
STOP.bat
START.bat
```

### Too Many Files (More than 5)
**Run manual cleanup:**
```batch
cleanup_old_pcaps.bat
```

## Benefits

### 🔍 Complete Network Visibility
- See exactly what attackers are doing at the packet level
- Analyze protocols, payloads, and attack patterns
- Forensic evidence for security incidents

### 📊 Complement to Logs
- Beelzebub logs: High-level events (commands, logins)
- PCAP files: Low-level network packets
- Together: Complete attack picture

### 💾 Storage Efficient
- Only 5 files = manageable size
- Old data automatically deleted
- No manual maintenance needed

### ⚡ Always Ready
- Starts automatically with honeypot
- No configuration needed
- Works out of the box

## Example Workflow

1. **Start Honeypot**: `START.bat`
   - Honeypot starts
   - PCAP capture starts automatically
   - Files saved to `pcap_captures/`

2. **Attack Occurs**:
   - Attacker connects to SSH/HTTP/MySQL
   - Traffic captured in current PCAP file
   - Every 10 minutes: new file created

3. **View Results**: `VIEW_PCAPS.bat`
   - See list of capture files
   - Open in Wireshark for analysis
   - Cross-reference with `beelzebub.log`

4. **Automatic Maintenance**:
   - Old files deleted automatically
   - Only 5 most recent kept
   - No manual cleanup needed

## Integration with Dashboard

The PCAP system works alongside the dashboard:
- Dashboard shows high-level attack logs
- PCAP files provide detailed packet analysis
- Use both for complete security monitoring

---

**Last Updated**: December 4, 2025
**Status**: ✅ Fully Automated
