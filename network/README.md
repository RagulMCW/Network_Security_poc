# Network Security Monitor# Network Security Monitor



Containerized network monitoring system with packet capture, device tracking, and web dashboard.A containerized network monitoring system for packet capture, device detection, and traffic analysis.



## Quick StartVersion 1.0 | October 2025



### Start System## Overview

```bash

cd E:\nos\Network_Security_poc\networkThe Network Security Monitor provides:

wsl bash wsl-manager.sh start

```- Real-time packet capture using tcpdump

- Automatic device detection and tracking

### Access Dashboard- Web-based dashboard for visualization

Open in browser: **http://localhost:8080**- Command-line analysis tools

- REST API for programmatic access

### Stop System

```bash## Quick Start

wsl bash wsl-manager.sh stop

```**Step 1: Start the monitoring system**

```bash

## What It Doescd /mnt/e/nos/Network_Security_poc/network

./wsl-manager.sh setup

- Captures all network packets```

- Tracks connected devices

- Provides web dashboard**Step 2: Access the web interface**

- Stores packet data for analysis```

- Supports virtual devicesOpen file: network-monitor.html

Click: Refresh button

## Complete Setup (First Time)```



```bash**Step 3: Analyze packets (optional)**

# Build and start everything```cmd

wsl bash wsl-manager.sh setupcd E:\nos\Network_Security_poc\network

analyze.bat

# Check it's working```

wsl bash wsl-manager.sh health

```**Step 4: Stop the system**

```bash

## Common Commands./wsl-manager.sh stop

```

```bash

# Start monitoring## Features

wsl bash wsl-manager.sh start

**Packet Capture**

# Stop monitoring- 30-second rotation for fresh data

wsl bash wsl-manager.sh stop- PCAP format compatible with Wireshark

- Automatic file management

# Check status

wsl bash wsl-manager.sh status**Device Detection**

- Real-time device discovery

# View logs- IP address tracking

wsl docker logs network-monitor- Traffic volume monitoring

- Connection status

# Restart

wsl bash wsl-manager.sh restart**Web Dashboard**

- Modern, responsive interface

# Complete cleanup- Auto-refresh every 10 seconds

wsl bash wsl-manager.sh clean- Device cards with detailed information

```- Network statistics



## System Components**Analysis Tools**

- Protocol distribution

| Component | Purpose | Access |- Top talkers identification

|-----------|---------|--------|- Packet conversation tracking

| tcpdump | Packet capture | Inside container |- Anomaly detection

| Flask API | Device management | http://192.168.6.131:5000 |

| HAProxy | Load balancer | http://localhost:8082 |## System Requirements

| Dashboard | Web interface | http://localhost:8080 |

- Windows 10/11 with WSL2

## Network Configuration- Docker Desktop for Windows

- Python 3.8+ with virtual environment

- Network: `custom_net` (192.168.6.0/24)- 4GB RAM minimum

- Server: 192.168.6.131- 2GB free disk space

- Devices: 192.168.6.10-254

- Capture rotation: 30 seconds## Documentation



## Virtual DevicesThe project includes comprehensive documentation:



Create test devices to populate the network:1. **GETTING_STARTED.md** - Installation and initial setup

2. **USER_GUIDE.md** - Detailed usage instructions and workflows

```batch3. **TECHNICAL_REFERENCE.md** - Architecture, API, and configuration

cd ..\devices4. **COMMAND_REFERENCE.md** - Complete command listing

manage_devices.bat create 10 iot_sensor

manage_devices.bat listAll documentation is located in the `docs/` directory.

```

## Command Summary

See `devices/README.md` for details.

**Container Management**

## API Endpoints```bash

./wsl-manager.sh setup    # Start monitoring

```bash./wsl-manager.sh stop     # Stop monitoring

# List all devices./wsl-manager.sh health   # Check status

curl http://192.168.6.131:5000/api/devices/list./wsl-manager.sh logs     # View logs

```

# Device summary

curl http://192.168.6.131:5000/api/devices/summary**Packet Analysis**

```cmd

# Network infoanalyze.bat               # Interactive analysis tool

curl http://192.168.6.131:5000/network/info```



# Health check**API Access**

curl http://192.168.6.131:5000/health```bash

```curl http://localhost:5002/health          # Health check

curl http://localhost:5002/network/info    # Device information

## Packet Capturescurl http://localhost:8082/stats           # HAProxy statistics

```

Captures are stored in: `E:\nos\Network_Security_poc\network\captures\`

## Project Structure

```bash

# List captures```

dir capturesnetwork/

├── README.md                # This file

# Analyze with tcpdump├── network-monitor.html     # Web dashboard

wsl tcpdump -r captures/capture_*.pcap├── wsl-manager.sh          # Container management

├── analyze.bat             # Packet analysis tool

# Open in Wireshark├── requirements.txt        # Python dependencies

# Copy file to Windows and open with Wireshark│

```├── docs/                   # Documentation

│   ├── GETTING_STARTED.md  # Setup and installation

## Project Structure│   ├── USER_GUIDE.md       # Usage and workflows

│   ├── TECHNICAL_REFERENCE.md  # Architecture and API

```│   ├── COMMAND_REFERENCE.md    # Complete command list

network/│   ├── API.md              # API specifications

├── README.md              # This file│   ├── TESTING.md          # Test procedures

├── wsl-manager.sh         # Main control script│   └── HOW_IT_WORKS.md     # Technical deep-dive

├── network-monitor.html   # Web dashboard│

├── requirements.txt       # Python dependencies├── captures/               # Packet capture files

├── captures/              # Packet capture files├── docker/                 # Container configuration

├── docker/│   └── Dockerfile

│   └── Dockerfile├── scripts/                # Analysis scripts

├── src/│   ├── analyze_capture.py

│   ├── app/server.py      # Flask API│   └── start_services.sh

│   └── config/haproxy.cfg├── src/                    # Application code

├── scripts/│   ├── app/

│   └── analyze_capture.py│   │   └── server.py       # Flask API

└── docs/│   └── config/

    ├── GUIDE.md           # Complete user guide│       └── haproxy.cfg     # Load balancer config

    ├── API.md             # API documentation└── tests/                  # Test files

    ├── HOW_IT_WORKS.md    # Technical details    ├── test_integration.py

    └── TESTING.md         # Test procedures    └── test_monitor.py

``````



## Troubleshooting## Architecture



**Container won't start:****Components:**

```bash- Docker container running Ubuntu 22.04

wsl docker ps -a- tcpdump for packet capture (30-second rotation)

wsl bash wsl-manager.sh clean- Flask REST API for data access

wsl bash wsl-manager.sh setup- HAProxy for load balancing

```- HTML/JavaScript web interface



**Dashboard shows no devices:****Network:**

```bash- Custom Docker network: 192.168.6.0/24

# Make sure server is running- Container IP: 192.168.6.131

wsl bash wsl-manager.sh status- Port mappings: 5002 (API), 8082 (HAProxy)

# Check API
curl http://192.168.6.131:5000/health

# Create test devices
cd ..\devices
manage_devices.bat create 5
```

**No packet captures:**
```bash
# Check tcpdump is running
wsl docker exec network-monitor ps aux | grep tcpdump

# Restart container
wsl bash wsl-manager.sh restart
```

## Documentation

- **GUIDE.md** - Complete usage guide
- **API.md** - API reference
- **HOW_IT_WORKS.md** - Technical architecture
- **TESTING.md** - Testing procedures
- **devices/README.md** - Virtual device management

## Requirements

- Windows 10/11 with WSL2
- Docker Desktop
- Python 3.8+ (in WSL)
- Web browser

## Summary

**Start**: `wsl bash wsl-manager.sh start`  
**Dashboard**: http://localhost:8080  
**Stop**: `wsl bash wsl-manager.sh stop`  

For detailed instructions, see `docs/GUIDE.md`
