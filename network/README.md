# Network Security Monitor

Capture and analyze network traffic using Docker and Python.

## Quick Start

### 1. Start Container (WSL)
```bash
cd /mnt/e/nos/Network_Security_poc/network
./wsl-manager.sh setup
```

### 2. Analyze Packets (Windows)
```cmd
cd E:\nos\Network_Security_poc\network
analyze.bat
```

### 3. Stop Container (WSL)
```bash
./wsl-manager.sh stop
```

## What You Get

**Analysis Results:**
- Total packets captured
- Protocol distribution (TCP, UDP, ARP, etc.)
- Top source/destination IPs
- Network conversations
- Security anomaly detection

**Example Output:**
```
Total Packets: 348
TCP: 333 packets (95.7%)
ARP: 4 packets (1.1%)
Top IPs: 192.168.6.129, 192.168.6.131
```

## Web Access
- Health Check: http://localhost:5002/health
- Statistics: http://localhost:8082/stats

## All Commands

### WSL Commands
```bash
./wsl-manager.sh          # Interactive menu
./wsl-manager.sh setup    # Build + Start
./wsl-manager.sh stop     # Stop
./wsl-manager.sh health   # Check health
./wsl-manager.sh logs     # View logs
```

### Windows Commands
```cmd
analyze.bat               # Analyze packets
```

## Files

```
network/
├── wsl-manager.sh       # WSL manager (Docker)
├── analyze.bat          # Windows analyzer
├── START_HERE.md        # Quick overview
├── QUICK_REF.md         # Command reference
│
├── captures/            # Captured packet files
├── docker/              # Dockerfile
├── scripts/             # Analysis scripts (Python)
├── src/                 # Flask app + HAProxy config
└── docs/                # API + Testing docs
```

## Requirements

- Docker (WSL2)
- Python 3.8+ with scapy
- Virtual environment at `E:\nos\.venv`

## Documentation

- **START_HERE.md** - Quick start (1 page)
- **QUICK_REF.md** - Command reference
- **HOW_IT_WORKS.md** - Detailed explanation ⭐
- **DIAGRAMS.md** - Visual diagrams ⭐
- **PROJECT_SUMMARY.md** - Project overview
- **docs/API.md** - API documentation
- **docs/TESTING.md** - Testing guide

⭐ = Perfect for team presentations!