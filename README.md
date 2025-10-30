# Network Security POC

A comprehensive network security monitoring and testing system built with Docker containers, featuring real-time packet capture, device simulation, attack testing, Beelzebub honeypot, and a **professional web dashboard** for complete system control.

**Version 2.0** | October 2025

---

## 🎮 NEW: Web Dashboard!

**Control everything from a beautiful web interface!**

```bash
cd dashboard
start_dashboard.bat
# Open: http://localhost:5000
```

**Features:**
- 📊 Multi-page dashboard (Overview, Devices, Honeypot, Attackers, Logs)
- 📱 Create/delete devices with one click
- 🌐 Network control (create/delete Docker network)
- 🍯 Honeypot management
- 💀 DOS attacker simulation
- 📡 Live device data streaming
- 📋 Real-time attack logs

**[See Full Dashboard Documentation →](dashboard/README.md)**

---

## Table of Contents

- [Overview](#overview)
- [Dashboard](#dashboard-new)
- [System Architecture](#system-architecture)
- [Quick Start](#quick-start)
- [Core Components](#core-components)
- [Usage Workflows](#usage-workflows)
- [Documentation](#documentation)
- [Requirements](#requirements)
- [Troubleshooting](#troubleshooting)

---

## Overview

The Network Security POC provides a complete environment for network security testing, monitoring, and analysis. The system creates an isolated Docker network where you can:

- **Control everything from web dashboard** (NEW!)
- Capture and analyze all network traffic in real-time
- Simulate legitimate devices generating network traffic
- Launch controlled attacks to test security detection
- Deploy Beelzebub honeypot to capture and analyze attacker behavior
- Automatically detect anomalies and security threats
- Visualize network activity through dashboards

### Key Features

- **🎮 Web Dashboard**: Professional UI to control entire system
- **📡 Device Management**: Create IoT sensors, cameras, laptops with one click
- **🍯 Beelzebub Honeypot**: Intelligent trap with real-time monitoring
- **Real-time Packet Capture**: Continuous network traffic monitoring with tcpdump
- **Device Simulation**: Create virtual devices that generate realistic network traffic
- **Attack Simulation**: Test DoS, DDoS, and SYN flood detection capabilities
- **Automated Analysis**: Intelligent packet analysis with anomaly detection
- **Live Data Streaming**: See device communications in real-time
- **REST API**: Programmatic access to system data and controls

---

## Dashboard (NEW!)

### Quick Start
```bash
cd E:\nos\Network_Security_poc\dashboard
start_dashboard.bat
```
Open browser: **http://localhost:5000**

### Pages

#### 📊 Overview
- System statistics (containers, devices, attacks, network status)
- Network control (create/delete)
- Quick actions

#### 📱 Devices  
- Create devices (IoT Sensor, Smartphone, Laptop, Camera, Generic)
- View all devices in grid layout
- Delete devices individually
- View device logs
- Cleanup stopped containers

#### 🍯 Beelzebub
- Start/stop Beelzebub honeypot
- View live attack logs
- See attacker IPs and protocols
- Attack counter

#### 💀 Attackers
- Start/stop DOS attackers
- Test network defenses

#### 📋 Logs
- Live device data table
- Sensor readings from all devices
- Real-time updates

### Features
✅ Beautiful multi-page UI
✅ One-click device creation
✅ Live device data streaming
✅ Real-time status updates (auto-refresh)
✅ Toast notifications
✅ Professional design

---

## System Architecture

```
Docker Network: custom_net (192.168.6.0/24)
├─────────────────────────────────────────────────────────┐
│                                                          │
│  Monitor Container (192.168.6.131)                      │
│  ├── Flask API Server (Port 5000)                       │
│  ├── HAProxy Load Balancer (Port 8080)                  │
│  ├── tcpdump Packet Capture                             │
│  └── Web Dashboard                                       │
│          ▲                                               │
│          │                                               │
│          ├── Virtual Device Containers (192.168.6.10+)  │
│          │   └── Simulate IoT sensors, phones, laptops  │
│          │                                               │
│          └── Attacker Containers (192.168.6.132+)       │
│              └── Generate DoS/DDoS traffic              │
│                                                          │
└─────────────────────────────────────────────────────────┘
          │
          └─► Windows Host Access
              ├── http://localhost:8082 (Dashboard)
              ├── http://localhost:5002 (API)
              └── http://localhost:8415 (HAProxy Stats)
```

### Network Isolation

All components operate within an isolated Docker network (192.168.6.0/24). The monitor container captures all traffic between containers, creating a controlled environment for security testing without affecting external networks.

---

## Quick Start

### Step 1: Start the Network Monitor

```bash
cd E:\nos\Network_Security_poc\network
wsl bash wsl-manager.sh start
```

This creates the Docker network and starts the monitoring container with Flask API, HAProxy, and tcpdump.

### Step 2: Access the Dashboard

Open your web browser and navigate to:
```
http://localhost:8082
```

### Step 3: Create Virtual Devices (Optional)

```cmd
cd E:\nos\Network_Security_poc\devices
manage_devices.bat create 10 iot_sensor
```

### Step 4: Run Security Tests (Optional)

```cmd
cd E:\nos\Network_Security_poc\attackers\dos_attacker
docker-compose up --build
```

### Step 5: Analyze Traffic

```cmd
cd E:\nos\Network_Security_poc\network
analyze_auto.bat
```

### Step 6: Stop the System

```bash
cd E:\nos\Network_Security_poc\network
wsl bash wsl-manager.sh stop
```

---

## Core Components

### 1. Network Monitor (`network/`)

The central monitoring system that captures and analyzes network traffic.

**Key Files:**
- `wsl-manager.sh` - Container management script
- `analyze.bat` / `analyze_auto.bat` - Packet analysis tools
- `network-monitor.html` - Web dashboard
- `scripts/analyze_capture.py` - Analysis engine

**Features:**
- Captures packets every 30 seconds to PCAP files
- Automatically cleans up old captures (keeps last 5)
- Detects high packet rates (DoS/DDoS indicators)
- Identifies SYN flood attacks
- Detects ARP spoofing attempts
- Tracks protocol distribution and top talkers

### 2. Virtual Devices (`devices/`)

Simulates legitimate network devices for testing purposes.

**Supported Device Types:**
- `iot_sensor` - IoT sensors (temperature, humidity, pressure)
- `smartphone` - Mobile devices (location, battery, network)
- `laptop` - Computers (CPU, memory, disk)
- `camera` - Security cameras (motion, recording)
- `generic` - Basic status devices

**Usage:**
```cmd
manage_devices.bat create 10 iot_sensor
manage_devices.bat list
manage_devices.bat stop
```

### 3. Attack Simulators (`attackers/dos_attacker/`)

Tools for testing security detection capabilities.

**Available Attackers:**
- **hping3**: Low-level packet flooding (TCP SYN floods)
- **curl**: HTTP-layer attacks (application DoS)

**Usage:**
```bash
# Using Docker Compose
docker-compose up --build

# Using Docker Run (hping3)
docker run --rm --cap-add=NET_RAW --network custom_net --ip 192.168.6.132 \
  -e TARGET_IP=192.168.6.131 -e PACKET_RATE=1000 hping3-attacker

# Using Docker Run (curl)
docker run --rm --network custom_net --ip 192.168.6.133 \
  -e TARGET_URL=http://192.168.6.131:5000/health -e REQUESTS=1000 \
  hping3-attacker /app/curl_sender.sh
```

---

## Usage Workflows

### Workflow 1: Basic Monitoring

1. Start the monitor: `wsl bash wsl-manager.sh start`
2. Access dashboard: http://localhost:8082
3. Monitor real-time traffic
4. Stop monitor: `wsl bash wsl-manager.sh stop`

### Workflow 2: Device Simulation

1. Start monitor
2. Create devices: `manage_devices.bat create 20 iot_sensor`
3. View devices in dashboard
4. Analyze traffic: `analyze_auto.bat`
5. Stop devices: `manage_devices.bat stop`

### Workflow 3: Security Testing

1. Start monitor
2. Launch attack: `docker-compose up` (in attackers/ directory)
3. Analyze results: `analyze_auto.bat`
4. Review anomaly detection output
5. Check for flagged attacker IPs

### Workflow 4: Traffic Analysis

1. Collect traffic (monitor must be running)
2. Run interactive analysis: `analyze.bat`
3. Select capture file to analyze
4. Review:
   - Protocol distribution
   - Top source/destination IPs
   - Network conversations
   - Security anomalies

---

## Documentation

Detailed documentation is organized by component:

### Main Documentation
- `README.md` (this file) - System overview and quick start
- `HOW_IT_WORKS_NOW.md` - Detailed architecture explanation
- `SYSTEM_FLOWCHART.md` - System component diagrams

### Component Documentation
- `network/README.md` - Network monitor detailed guide
- `network/docs/GUIDE.md` - Complete network usage guide
- `network/docs/API.md` - REST API reference
- `network/docs/HOW_IT_WORKS.md` - Technical deep dive
- `network/docs/TESTING.md` - Testing procedures
- `devices/README.md` - Virtual device management
- `attackers/dos_attacker/README.md` - Attack tool guide

---

## Requirements

### System Requirements
- Windows 10/11 with WSL2 installed
- Docker Desktop for Windows
- 4GB RAM minimum (8GB recommended)
- 10GB free disk space

### Software Dependencies
- Python 3.8+ with virtual environment
- scapy library for packet analysis
- Git for version control

### Network Requirements
- Docker network capability
- No special firewall configurations needed
- System operates in isolated Docker network

---

## Troubleshooting

### Monitor Container Won't Start

```bash
# Check Docker status
wsl docker ps -a

# Clean and restart
wsl bash wsl-manager.sh clean
wsl bash wsl-manager.sh setup
```

### Dashboard Shows No Data

```bash
# Verify container is running
wsl bash wsl-manager.sh status

# Check API health
curl http://localhost:5002/health

# Restart services
wsl bash wsl-manager.sh restart
```

### No Packet Captures Generated

```bash
# Verify tcpdump is running
wsl docker exec net-monitor-wan ps aux | grep tcpdump

# Check captures directory
dir network\captures

# Restart if needed
wsl bash wsl-manager.sh restart
```

### Virtual Devices Not Connecting

```bash
# Ensure monitor is running first
cd network
wsl bash wsl-manager.sh start

# Verify network exists
wsl docker network ls | findstr custom_net

# Check device logs
manage_devices.bat logs 001
```

### Attack Not Detected

```bash
# Verify attacker container started
docker ps | findstr attacker

# Check attacker output for IP confirmation
# IP should be displayed: "Attacker container IP: 192.168.6.132"

# Wait for capture rotation (30 seconds)
# Then analyze: analyze_auto.bat
```

---

## Command Reference

### Network Monitor

```bash
wsl bash wsl-manager.sh setup      # Initial setup and start
wsl bash wsl-manager.sh start      # Start monitoring
wsl bash wsl-manager.sh stop       # Stop monitoring
wsl bash wsl-manager.sh restart    # Restart services
wsl bash wsl-manager.sh status     # Check status
wsl bash wsl-manager.sh health     # Health check
wsl bash wsl-manager.sh logs       # View logs
wsl bash wsl-manager.sh clean      # Complete cleanup
```

### Virtual Devices

```cmd
manage_devices.bat build           # Build device image
manage_devices.bat create N TYPE   # Create N devices of TYPE
manage_devices.bat list            # List all devices
manage_devices.bat stats           # Show statistics
manage_devices.bat logs ID         # View device logs
manage_devices.bat start           # Start all devices
manage_devices.bat stop            # Stop all devices
manage_devices.bat remove          # Remove all devices
```

### Analysis Tools

```cmd
analyze.bat                        # Interactive analysis
analyze_auto.bat                   # Analyze latest capture
cleanup_captures.bat              # Manual cleanup (keeps last 5)
```

### API Endpoints

```bash
curl http://localhost:5002/health
curl http://localhost:5002/network/info
curl http://localhost:5002/api/devices/list
curl http://localhost:5002/api/devices/summary
curl http://localhost:8082/stats
```

---

## Project Structure

```
Network_Security_poc/
├── README.md                    # This file
├── HOW_IT_WORKS_NOW.md          # Detailed architecture
├── SYSTEM_FLOWCHART.md          # Component diagrams
│
├── network/                     # Network monitor system
│   ├── README.md
│   ├── wsl-manager.sh           # Container management
│   ├── analyze.bat              # Interactive analysis
│   ├── analyze_auto.bat         # Automated analysis
│   ├── cleanup_captures.bat     # Cleanup utility
│   ├── network-monitor.html     # Web dashboard
│   ├── requirements.txt
│   ├── captures/                # PCAP files storage
│   ├── docker/
│   │   └── Dockerfile
│   ├── scripts/
│   │   ├── analyze_capture.py   # Analysis engine
│   │   └── start_services.sh
│   ├── src/
│   │   ├── app/server.py        # Flask API
│   │   └── config/haproxy.cfg
│   ├── docs/
│   │   ├── GUIDE.md
│   │   ├── API.md
│   │   ├── HOW_IT_WORKS.md
│   │   └── TESTING.md
│   └── tests/
│
├── devices/                     # Virtual device simulator
│   ├── README.md
│   ├── device_simulator.py
│   ├── Dockerfile
│   ├── manage_devices.bat
│   └── manage_devices.sh
│
└── attackers/
    └── dos_attacker/            # Attack simulation tools
        ├── README.md
        ├── Dockerfile
        ├── docker-compose.yml
        ├── hping3_sender.sh     # Low-level attack
        └── curl_sender.sh       # HTTP attack
```

---

## License

This is a proof-of-concept system for educational and security testing purposes only. Use responsibly and only on networks you own or have explicit permission to test.

---

## Support

For issues, questions, or contributions:

1. Check the documentation in the `docs/` directories
2. Review the troubleshooting section above
3. Examine the log files for error messages
4. Refer to component-specific README files

---

**Note**: This system is designed for controlled testing environments. Always ensure you have proper authorization before conducting security testing on any network.
