# Network Security POC - AI-Powered Malware Detection

A complete network security testing and monitoring platform using Zeek IDS, containerized simulations, and AI-powered threat analysis.

## System Architecture

```
Docker Network (custom_net: 192.168.6.0/24)
├── Devices (192.168.6.10-15) ────────┐
├── Malware (192.168.6.200) ──────────┤
└── Monitor (192.168.6.131) ←─────────┘
         │
         ↓
    WSL Host (Zeek Monitor)
    Captures bridge traffic
         │
         ↓
    Windows (zeek_logs/)
    Stores session logs
         │
         ↓
    MCP Agent (AI Analysis)
    Detects threats
```

## Components

### 1. Zeek Network Monitor
**Location:** `network/zeek/`
- START.bat - Start monitoring
- STOP.bat - Stop monitoring  
- zeek_monitor.sh - Main script
- README.md - Documentation

**Features:** Real-time packet capture, generates logs every 2-3 seconds, auto-copies to Windows

### 2. Device Simulators
**Location:** `devices/`
- manage_devices.bat - Fleet management
- device_simulator.py - Clean code
- 6 virtual devices sending traffic every 1-2 seconds

### 3. Malware Simulator
**Location:** `attackers/malware_attacker/`
- START.bat, STOP.bat, LOGS.bat
- malware_simulator.sh - All behaviors
- C2 Beacon, Data Exfil, EICAR, DNS attacks

### 4. MCP Agent
**Location:** `mcp_agent/`
- RUN_AGENT.bat - Start AI analysis
- Reads Zeek logs, detects threats

## Quick Start

```cmd
REM 1. Start devices
cd devices
manage_devices.bat create 6

REM 2. Start Zeek monitor
cd network\zeek
START.bat

REM 3. Start malware simulator
cd attackers\malware_attacker
START.bat

REM 4. Run AI analysis
cd mcp_agent
RUN_AGENT.bat
```

## System Workflow

```
Traffic Generation → Network Capture → Log Generation → AI Analysis

Devices send requests (1-2s) ──┐
Malware sends attacks (15-40s) ─┤
                                │
                                ↓
                    Zeek captures bridge traffic
                    tcpdump rotates every 2 seconds
                                │
                                ↓
                    Zeek analyzes PCAP files
                    Generates protocol logs
                                │
                                ↓
                    Auto-copy to Windows
                    zeek_logs/session_TIMESTAMP/
                                │
                                ↓
                    MCP Agent reads logs
                    Claude AI detects threats
```

## Current Status

Running Components:
- net-monitor-wan (192.168.6.131:5002, 8082, 8415)
- vdevice_001-006 (192.168.6.10-15)
- malware_attacker (192.168.6.200)
- zeek_monitor (WSL Host)

## File Structure

```
Network_Security_poc/
├── README.md                    (This file)
├── attackers/
│   └── malware_attacker/        (7 files - Clean)
├── devices/                     (Fleet management)
├── network/
│   ├── zeek/                    (4 files - Clean)
│   └── zeek_logs/               (Auto-generated)
├── mcp_agent/                   (AI analysis)
├── dashboard/                   (Port 8082)
└── scripts/                     (Utilities)
```

## Professional Code Standards

Improvements Made:
- Zeek: 8 files → 4 files (50% reduction)
- Malware: 14 files → 7 files (50% reduction)  
- Consolidated scripts
- Clean documentation
- Simple commands
- Error handling

## Testing

```cmd
REM Check traffic
wsl docker logs vdevice_001 --tail 10

REM View Zeek logs
cd network\zeek_logs
dir /od

REM Check malware activity
cd attackers\malware_attacker
LOGS.bat

REM AI analysis
cd mcp_agent
RUN_AGENT.bat
```

## Performance

- CPU: ~10% total
- RAM: ~500 MB total
- Network: ~10 requests/second
- Logs: ~3 MB per session

## Troubleshooting

```cmd
REM Restart Zeek
cd network\zeek
STOP.bat && START.bat

REM Recreate devices
cd devices
manage_devices.bat delete all
manage_devices.bat create 6

REM Check containers
wsl docker ps
```

## Quick Reference

Essential Commands:
- Start: See Quick Start section
- Status: `wsl docker ps`
- Logs: `network/zeek_logs/`
- Dashboard: http://localhost:8082
- API: http://localhost:5002

---

Status: OPERATIONAL | Components: 4 | Containers: 8 | Clean Code: YES
