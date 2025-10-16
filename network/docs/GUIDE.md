# Network Security Monitor - User Guide

Complete guide for the Network Security Monitoring system.

## Quick Start

### Start System
```bash
cd E:\nos\Network_Security_poc\network
wsl bash wsl-manager.sh start
```

### Stop System
```bash
wsl bash wsl-manager.sh stop
```

### Check Status
```bash
wsl bash wsl-manager.sh status
```

### Access Dashboard
Open in browser: http://localhost:8080

## Complete Setup

### First Time Setup
```bash
# Full setup (build + start)
wsl bash wsl-manager.sh setup

# Or step by step
wsl bash wsl-manager.sh build    # Build Docker image
wsl bash wsl-manager.sh start    # Start container
wsl bash wsl-manager.sh health   # Check health
```

### Access Points
- Dashboard: http://localhost:8080
- HAProxy Stats: http://localhost:8082
- Flask API: http://192.168.6.131:5000

## How It Works

### System Components

1. **Docker Container** (192.168.6.131)
   - Runs on custom network (192.168.6.0/24)
   - Contains all monitoring services

2. **tcpdump**
   - Captures all network packets
   - Saves to `/captures` folder
   - New file every 30 seconds

3. **Flask API** (Port 5000)
   - Provides REST API for devices
   - Serves monitoring data
   - Tracks registered devices

4. **HAProxy** (Port 8082)
   - Load balancer
   - High availability support

5. **Web Dashboard**
   - Real-time device monitoring
   - Shows network activity
   - Displays packet statistics

### Data Flow

```
Network Traffic → tcpdump → Capture Files
       ↓
Virtual Devices → Flask API → Dashboard
       ↓
  Packet Analysis
```

## Commands

### Container Management
```bash
# Start container
wsl bash wsl-manager.sh start

# Stop container
wsl bash wsl-manager.sh stop

# Restart container
wsl bash wsl-manager.sh restart

# Remove container
wsl bash wsl-manager.sh clean

# Check status
wsl bash wsl-manager.sh status
```

### View Logs
```bash
# Container logs
wsl docker logs network-monitor

# Follow logs
wsl docker logs -f network-monitor

# tcpdump logs
wsl docker exec network-monitor ps aux | grep tcpdump
```

### Packet Captures
```bash
# List captures
dir E:\nos\Network_Security_poc\network\captures

# Analyze capture (from WSL)
wsl tcpdump -r captures/capture_*.pcap

# Count packets
wsl tcpdump -r captures/capture_*.pcap | wc -l
```

## API Endpoints

### Device Management
```bash
# List all devices
curl http://192.168.6.131:5000/api/devices/list

# Device summary
curl http://192.168.6.131:5000/api/devices/summary

# Device status
curl http://192.168.6.131:5000/api/device/status?device_id=device_001
```

### Network Information
```bash
# Network info
curl http://192.168.6.131:5000/network/info

# Capture files
curl http://192.168.6.131:5000/capture/files

# Health check
curl http://192.168.6.131:5000/health
```

## Virtual Devices

See `../devices/README.md` for virtual device management.

### Quick Commands
```batch
# Create devices
cd ..\devices
manage_devices.bat create 10 iot_sensor

# List devices
manage_devices.bat list

# View logs
manage_devices.bat logs 001
```

## Troubleshooting

### Container Won't Start
```bash
# Check Docker
wsl docker ps -a

# Check network
wsl docker network ls

# Remove old container and network
wsl docker rm network-monitor
wsl docker network rm custom_net

# Rebuild
wsl bash wsl-manager.sh setup
```

### No Packet Captures
```bash
# Check tcpdump is running
wsl docker exec network-monitor ps aux | grep tcpdump

# Check captures directory
wsl docker exec network-monitor ls -lh /captures

# Restart container
wsl bash wsl-manager.sh restart
```

### Dashboard Not Loading
```bash
# Check ports
wsl docker port network-monitor

# Test API
curl http://192.168.6.131:5000/health

# Check browser console for errors
# Open http://localhost:8080 and press F12
```

### Devices Not Appearing
```bash
# Check if devices are running
cd ..\devices
manage_devices.bat list

# Check device logs
manage_devices.bat logs 001

# Test API connection
curl http://192.168.6.131:5000/api/devices/list
```

## File Structure

```
network/
├── wsl-manager.sh          # Main control script
├── network-monitor.html    # Web dashboard
├── requirements.txt        # Python dependencies
│
├── docker/
│   └── Dockerfile          # Container image
│
├── src/
│   ├── app/
│   │   └── server.py       # Flask API
│   └── config/
│       └── haproxy.cfg     # Load balancer config
│
├── scripts/
│   ├── start_services.sh   # Service startup
│   └── analyze_capture.py  # Packet analysis
│
├── captures/               # Packet capture files
│
└── docs/
    ├── API.md             # API documentation
    ├── HOW_IT_WORKS.md    # Technical details
    └── TESTING.md         # Test procedures
```

## Configuration

### Network Settings
- Network: custom_net (192.168.6.0/24)
- Server IP: 192.168.6.131
- Device Range: 192.168.6.10-254

### Ports
- 5000: Flask API
- 8080: Web Dashboard (mapped to HAProxy)
- 8082: HAProxy Stats
- 8404: HAProxy Admin

### Capture Settings
- Rotation: 30 seconds
- Location: /captures (inside container)
- Format: PCAP

## Best Practices

1. **Start server before creating devices**
   ```bash
   wsl bash wsl-manager.sh start
   cd ..\devices
   manage_devices.bat create 5
   ```

2. **Monitor resources**
   ```bash
   wsl docker stats network-monitor
   ```

3. **Regular cleanup**
   ```bash
   # Remove old captures (keep last 100)
   # Do this manually or create cleanup script
   ```

4. **Check logs regularly**
   ```bash
   wsl docker logs network-monitor --tail 50
   ```

## Common Tasks

### View Active Devices
```bash
curl http://192.168.6.131:5000/api/devices/list | python -m json.tool
```

### Analyze Latest Capture
```bash
wsl tcpdump -n -r captures/capture_$(ls -t captures/ | head -1)
```

### Export Device Data
```bash
curl http://192.168.6.131:5000/api/devices/summary > devices.json
```

### Monitor Live Traffic
```bash
wsl docker exec network-monitor tcpdump -i eth0 -n
```

## Summary

**Start**: `wsl bash wsl-manager.sh start`  
**Stop**: `wsl bash wsl-manager.sh stop`  
**Dashboard**: http://localhost:8080  
**Create Devices**: `cd ..\devices && manage_devices.bat create 10`  
**View Devices**: `manage_devices.bat list`  

That's all you need!
