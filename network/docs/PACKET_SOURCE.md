# Where Do Packets Come From? 

## Understanding Your Current Setup

### Question: "I didn't connect any devices, so where are these packets coming from?"

---

## Answer: Internal Docker Traffic!

### Current Packet Sources (Without External Devices):

```
┌──────────────────────────────────────────────────────┐
│              Your Current Setup                       │
│                                                      │
│  ┌────────────────────────────────────────────┐    │
│  │  Docker Network (192.168.6.0/24)           │    │
│  │                                            │    │
│  │  ┌─────────────────────────────────────┐  │    │
│  │  │  Container: net-monitor-wan         │  │    │
│  │  │  IP: 192.168.6.131                  │  │    │
│  │  │                                     │  │    │
│  │  │  Services running:                  │  │    │
│  │  │  - Flask (port 5000)                │  │    │
│  │  │  - HAProxy (port 8080)              │  │    │
│  │  │  - tcpdump (capturing)              │  │    │
│  │  └──────────┬──────────────────────────┘  │    │
│  │             │                              │    │
│  │             │ Internal traffic             │    │
│  │             │                              │    │
│  │  ┌──────────▼──────────────────────────┐  │    │
│  │  │  Docker Gateway                     │  │    │
│  │  │  IP: 192.168.6.1                    │  │    │
│  │  └─────────────────────────────────────┘  │    │
│  └────────────────────────────────────────────┘    │
│                       ▲                             │
│                       │                             │
│           Port forwarding (5002, 8082, 8415)        │
│                       │                             │
│  ┌────────────────────┴───────────────────────┐    │
│  │  Windows Host                              │    │
│  │  - Your browser accessing localhost:5002   │    │
│  │  - curl commands                           │    │
│  │  - Docker commands                         │    │
│  └────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────┘
```

---

## Current Packet Sources (348 packets captured):

### 1. **Your Browser/curl Requests** (Most packets)
Every time you access:
```
http://localhost:5002/health
http://localhost:8082/stats
```

This creates TCP packets:
- Your computer → Docker → Container
- Container → Docker → Your computer
- **Result:** TCP conversations between 192.168.6.129 and 192.168.6.131

### 2. **Docker Internal Communication**
- Health checks (every 30 seconds)
- Container to gateway communication
- Network keep-alive packets

### 3. **ARP Packets**
- Containers discovering each other
- MAC address resolution
- Network layer 2 communication

### 4. **Service Communication**
- Flask ↔ HAProxy internal traffic
- Health monitoring
- Load balancer checks

---

## Breakdown of Your 348 Packets:

```
Total: 348 packets
├── TCP: 333 packets (95.7%)  ← Your browser requests!
│   └── Conversations:
│       ├── 192.168.6.129 → 192.168.6.131: 185 packets (requests)
│       └── 192.168.6.131 → 192.168.6.129: 148 packets (responses)
│
└── ARP: 4 packets (1.1%)     ← Network discovery
    └── Docker containers finding each other

└── Other: 11 packets (3.2%)  ← Internal Docker traffic
```

---

## IP Address Explanation:

### 192.168.6.131 (Container)
- Your network monitor container
- Running Flask, HAProxy, tcpdump

### 192.168.6.129 (Docker Host)
- The Docker engine on your computer
- Acts as bridge between Windows and container

### Traffic Flow:
```
Windows (You)
    ↓
Docker Host (192.168.6.129)
    ↓
Container (192.168.6.131)
    ↓
tcpdump captures everything!
```

---

## Why You See Traffic (Without External Devices):

### Every time you run:
```cmd
# In Windows
curl http://localhost:5002/health
```

**What happens:**
1. Windows sends request to localhost:5002
2. Docker forwards to container 192.168.6.131:5000
3. Flask responds
4. Response goes back through Docker
5. **tcpdump captures all of this!**

### This creates packets:
```
Request:  192.168.6.129 → 192.168.6.131 (TCP SYN)
Response: 192.168.6.131 → 192.168.6.129 (TCP SYN-ACK)
Request:  192.168.6.129 → 192.168.6.131 (TCP ACK)
Request:  192.168.6.129 → 192.168.6.131 (HTTP GET /health)
Response: 192.168.6.131 → 192.168.6.129 (HTTP 200 OK + JSON)
Close:    192.168.6.129 → 192.168.6.131 (TCP FIN)
```

**Result: ~10-15 packets per request!**

---

## How to Add External Devices:

### Method 1: Add Another Container (Simulated Device)
```bash
# Create a "client" container
docker run -it --name client \
  --net custom_net --ip 192.168.6.140 \
  ubuntu:22.04 /bin/bash

# Inside client container
apt-get update && apt-get install -y curl
curl http://192.168.6.131:5000/health

# Monitor will capture this!
```

### Method 2: Add Attacker Container
```bash
# Create attacker container
docker run -it --name attacker \
  --net custom_net --ip 192.168.6.150 \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  ubuntu:22.04 /bin/bash

# Inside attacker
apt-get install -y nmap arpspoof
nmap 192.168.6.131
# Monitor captures the scan!
```

### Method 3: Use Host Network (Real Devices)
```bash
# Stop current container
docker stop net-monitor-wan
docker rm net-monitor-wan

# Rebuild with host network
docker run -d --name net-monitor-wan \
  --network host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$(pwd)/captures:/captures" \
  network-security-monitor

# Now captures ALL network traffic:
# - Your WiFi devices
# - Internet traffic
# - Everything on your network!
```

---

## Updated Rotation: Every 30 Seconds

### Old Behavior:
- New file created when size reaches 10MB
- Could take hours for large file

### New Behavior (Fixed!):
```bash
# New file every 30 seconds
capture_20251013_143000.pcap  (14:30:00 - 14:30:30)
capture_20251013_143030.pcap  (14:30:30 - 14:31:00)
capture_20251013_143100.pcap  (14:31:00 - 14:31:30)
```

### analyze.bat Now:
```
Option 1: Analyze LATEST capture only ← Recommended!
Option 2: Analyze all captures
Option 3: Analyze specific file
```

**Choose Option 1** to see the most recent 30 seconds of traffic!

---

## Summary for Your Team:

### Current Packets Come From:
1. ✅ Your browser requests (localhost:5002)
2. ✅ curl commands you run
3. ✅ Docker health checks
4. ✅ Container internal communication
5. ✅ ARP network discovery

### To Add More Traffic:
1. 🔧 Add client containers (simulated devices)
2. 🔧 Add attacker containers (for testing)
3. 🔧 Use host network (real devices)

### New Features:
1. ⭐ PCAP files rotate every 30 seconds
2. ⭐ analyze.bat can analyze just the latest file
3. ⭐ See real-time traffic (not old data)

### Recommendation:
```cmd
# Wait 30 seconds after starting container
# Then analyze latest capture
analyze.bat
# Choose option 1 (latest only)
```

**Now you have fresh, recent data every time!** 🎉