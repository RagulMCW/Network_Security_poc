# How Network Security Monitor Works
## Simple Explanation for Team Presentation

---

## 1. How PCAP Data is Captured from Container

### Simple Flow:
```
Container → tcpdump → Captures packets → Saves to file → Shared with Windows
```

### Detailed Steps:

**Step 1: Container Starts**
```bash
# Inside container, tcpdump runs automatically
tcpdump -i eth0 -w /captures/capture.pcap
```

**Step 2: Network Traffic Flows**
```
Your Computer → Docker Network → Container (captures everything)
```

**Step 3: Data is Saved**
```
Container: /captures/capture.pcap
    ↓ (Docker volume mount)
Windows: E:\nos\Network_Security_poc\network\captures\capture.pcap
```

**Key Point:** The container and Windows share the same folder!

---

## 2. Does Container Have Static IP? YES!

### Your Container IP Configuration:

```bash
Container Name: net-monitor-wan
Static IP: 192.168.6.131
Network: custom_net (192.168.6.0/24)
```

### Network Diagram:
```
┌─────────────────────────────────────┐
│  Docker Network: custom_net         │
│  Subnet: 192.168.6.0/24             │
│                                     │
│  ┌──────────────────────────────┐  │
│  │  Container: net-monitor-wan  │  │
│  │  Static IP: 192.168.6.131    │  │
│  │  - Port 5000 (Flask)         │  │
│  │  - Port 8080 (HAProxy)       │  │
│  │  - Port 8404 (Stats)         │  │
│  └──────────────────────────────┘  │
│                                     │
│  ┌──────────────────────────────┐  │
│  │  Docker Gateway              │  │
│  │  IP: 192.168.6.1             │  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
           ↕
    Windows Host
    Access via: localhost:5002, 8082, 8415
```

---

## 3. Can You Connect Real Devices? YES!

### Option A: Connect Device to Same Docker Network

**Scenario:** Simulate attacks from another container

```bash
# Create attacker container on same network
docker run -it --name attacker \
  --net custom_net --ip 192.168.6.132 \
  ubuntu:22.04 /bin/bash

# Inside attacker container
apt-get update && apt-get install -y curl netcat nmap

# Attack the monitor container
curl http://192.168.6.131:5000
nmap 192.168.6.131
```

**Your monitor will capture all this traffic!**

### Option B: Use Host Network Mode (Real Network)

```bash
# Stop current container
docker stop net-monitor-wan
docker rm net-monitor-wan

# Run with host network (captures REAL network traffic)
docker run -d --name net-monitor-wan \
  --network host \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$(pwd)/captures:/captures" \
  network-security-monitor
```

**Now it captures traffic from:**
- Your computer
- All devices on your WiFi/network
- Real internet traffic

---

## 4. How analyze.bat Works (Step by Step)

### What Happens When You Run analyze.bat:

```cmd
analyze.bat
```

**Step 1: Activate Virtual Environment**
```cmd
E:\nos\.venv\Scripts\activate.bat
```
- Loads Python with scapy library

**Step 2: Find Capture Files**
```cmd
dir captures\*.pcap*
```
- Lists all packet capture files

**Step 3: Show Menu**
```
1. Analyze all captures
2. Analyze specific file
3. Just list files
4. Exit
```

**Step 4: Run Python Analysis**
```cmd
python scripts\analyze_capture.py captures\capture.pcap
```

**Step 5: Python Script Reads PCAP**
```python
# Inside analyze_capture.py
packets = rdpcap("capture.pcap")  # Read all packets

# Count protocols
for packet in packets:
    if TCP in packet: tcp_count += 1
    if UDP in packet: udp_count += 1
    if ARP in packet: arp_count += 1

# Find top IPs
source_ips[packet.src] += 1
dest_ips[packet.dst] += 1

# Print report
print("Total Packets:", len(packets))
print("TCP:", tcp_count)
print("Top IPs:", source_ips)
```

**Step 6: Display Results**
```
Total Packets: 348
TCP: 333 packets (95.7%)
Top IPs: 192.168.6.129 -> 192.168.6.131
```

**Step 7: Cleanup**
```cmd
deactivate  # Exit virtual environment
```

---

## 5. How to Simulate ARP Attack

### Setup Attack Simulation:

**Terminal 1: Start Monitor (WSL)**
```bash
./wsl-manager.sh setup
```

**Terminal 2: Create Attacker Container (WSL)**
```bash
# Create attacker on same network
docker run -it --name attacker \
  --net custom_net --ip 192.168.6.132 \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  ubuntu:22.04 /bin/bash
```

**Inside Attacker Container:**
```bash
# Install tools
apt-get update
apt-get install -y dsniff arpspoof nmap

# Perform ARP spoofing attack
arpspoof -i eth0 -t 192.168.6.131 192.168.6.1
# This tells monitor (131) that attacker is the gateway

# Or use scapy for ARP attack
python3
>>> from scapy.all import *
>>> send(ARP(op=2, pdst="192.168.6.131", hwdst="ff:ff:ff:ff:ff:ff"))
```

**Terminal 3: Analyze Results (Windows)**
```cmd
analyze.bat
# You'll see the ARP spoofing in the results!
```

---

## 6. Complete Attack Simulation Workflow

### Diagram:
```
┌────────────────────────────────────────────────┐
│         Docker Network (192.168.6.0/24)        │
│                                                │
│  ┌──────────────┐         ┌──────────────┐   │
│  │  Attacker    │ ──ARP─→ │  Monitor     │   │
│  │  .132        │  Spoof  │  .131        │   │
│  │              │         │  (Captures!) │   │
│  └──────────────┘         └──────────────┘   │
│         │                        │            │
│         └────── Traffic ─────────┘            │
└────────────────────────────────────────────────┘
                    ↓
          Windows Analysis (analyze.bat)
                    ↓
          "ARP Attack Detected!"
```

---

## 7. Key Points for Your Team

### ✅ **PCAP Capture:**
- Container runs `tcpdump` continuously
- Saves to shared folder (Docker volume)
- Windows can access files immediately

### ✅ **Static IP:**
- Yes! Container has 192.168.6.131
- Always same IP (predictable for testing)
- Easy to target in attacks

### ✅ **Real Device Connection:**
- Option 1: Add containers to same network
- Option 2: Use host network mode (real traffic)
- Both work for attack simulation

### ✅ **analyze.bat Process:**
1. Activates Python environment
2. Reads PCAP files with scapy
3. Counts protocols (TCP, UDP, ARP)
4. Finds top IPs and conversations
5. Detects anomalies (ARP spoofing, etc.)
6. Shows results in terminal

### ✅ **Attack Simulation:**
- Create attacker container on same network
- Use tools: arpspoof, nmap, scapy
- Monitor captures everything
- Analyze to see attack patterns

---

## 8. Demo Script for Presentation

```bash
# 1. Show container IP
docker inspect net-monitor-wan | grep IPAddress

# 2. Show tcpdump running
docker exec net-monitor-wan ps aux | grep tcpdump

# 3. Show real-time capture
docker exec net-monitor-wan ls -la /captures/

# 4. Generate traffic
curl http://localhost:5002/health

# 5. Show capture grew
docker exec net-monitor-wan ls -lh /captures/

# 6. Analyze in Windows
cd E:\nos\Network_Security_poc\network
analyze.bat
```

---

## 9. Summary Slide for Team

**Question:** How does it work?

**Answer:**
1. Container captures network packets with tcpdump
2. Saves to shared folder (visible in Windows)
3. Container has static IP (192.168.6.131)
4. Can connect devices/containers to same network
5. analyze.bat reads packets and shows statistics
6. Perfect for simulating ARP attacks and testing

**Use Case:** Network security testing and attack simulation

---

## Need More Details?

- **Technical docs:** docs/API.md, docs/TESTING.md
- **Architecture:** See docker/Dockerfile and src/
- **Analysis code:** scripts/analyze_capture.py

Simple, clean, and ready for your team presentation!