# Network Security Monitor - Visual Diagrams

## 1. Complete System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Your Computer                        │
│                                                             │
│  ┌─────────────────┐              ┌─────────────────┐       │
│  │   Windows       │              │      WSL2       │       │
│  │                 │              │                 │       │
│  │  Virtual Env    │              │  Docker Engine  │       │
│  │  E:\nos\.venv   │              │                 │       │
│  │                 │              │                 │       │
│  │  analyze.bat ───┼──reads───────┤                 │       │
│  │                 │              │                 │       │
│  └─────────────────┘              └────────┬────────┘       │
│           │                                │                │
│           │                                │                │
│           ▼                                ▼                │
│  ┌─────────────────────────────────────────────────────┐    │
│  │            Shared Folder                            │    │
│  │  Windows: E:\nos\..\network\captures\               │    │
│  │  WSL: /mnt/e/nos/.../network/captures/              │    │
│  │  Container: /captures/                              │    │
│  │                                                     │    │
│  │  📄 capture_20251013_091236.pcap0                   │    │
│  │  📄 capture_20251013_092345.pcap0                   │    │
│  └─────────────────────────────────────────────────────┘    │
│                           ▲                                 │
│                           │                                 │
│                           │ writes                          │
│                           │                                 │
│  ┌────────────────────────┴──────────────────────────┐      │
│  │         Docker Container: net-monitor-wan         │      │
│  │         Static IP: 192.168.6.131                  │      │
│  │                                                   │      │
│  │  ┌─────────────┐  ┌──────────┐  ┌────────────┐  │        │
│  │  │   tcpdump   │  │  Flask   │  │  HAProxy   │  │        │
│  │  │  (capture)  │  │  :5000   │  │  :8080     │  │        │
│  │  └─────────────┘  └──────────┘  └────────────┘  │        │
│  └───────────────────────────────────────────────────┘      │
│                           │                                 │
│                           │ Port Forwarding                 │
│                           ▼                                 │
│           Windows Browser: localhost:5002, :8082            │
└─────────────────────────────────────────────────────────────┘
```

## 2. Network Topology

```
┌──────────────────────────────────────────────────────────┐
│           Docker Network: custom_net                     │
│           Subnet: 192.168.6.0/24                         │
│                                                          │
│                                                          │
│   ┌─────────────────────────────────────────┐            │
│   │  Gateway                                │            │
│   │  IP: 192.168.6.1                        │            │
│   └────────────┬────────────────────────────┘            │
│                │                                         │
│                │                                         │
│         ┌──────┴──────┐                                  │
│         │             │                                  │
│         ▼             ▼                                  │
│   ┌──────────┐   ┌──────────┐                            │
│   │ Monitor  │   │ Attacker │ (optional)                 │ 
│   │ .131     │   │ .132     │                            │
│   │          │◄──│          │  ARP Spoof                 │
│   │ Captures │   │ Attack   │                            │
│   │ Traffic  │   │ Tools    │                            │
│   └──────────┘   └──────────┘                            │
│        │                                                 │
│        │ Port Mapping                                    │
│        ▼                                                 │
│   Windows Host                                           │
│   localhost:5002 → 192.168.6.131:5000                    │
│   localhost:8082 → 192.168.6.131:8080                    │
└──────────────────────────────────────────────────────────┘
```

## 3. Data Flow: Capture to Analysis

```
Step 1: Traffic Generation
    ↓
┌─────────────────┐
│ Network Traffic │  (Your browsing, app usage, attacks)
└────────┬────────┘
         │
         ▼
Step 2: Capture
┌─────────────────────────────┐
│ Container (192.168.6.131)   │
│                             │
│  tcpdump -i eth0            │
│  Captures every packet      │
└─────────┬───────────────────┘
          │
          ▼
Step 3: Save to Disk
┌─────────────────────────────┐
│ /captures/capture.pcap      │
│                             │
│ Binary packet data          │
│ (Raw network packets)       │
└─────────┬───────────────────┘
          │
          │ Docker volume mount
          ▼
Step 4: Shared with Windows
┌─────────────────────────────┐
│ E:\nos\..\captures\         │
│                             │
│ Same file, different path   │
└─────────┬───────────────────┘
          │
          ▼
Step 5: Analysis
┌─────────────────────────────┐
│ analyze.bat                 │
│  ↓                          │
│ Python + scapy              │
│  ↓                          │
│ Read PCAP file              │
│  ↓                          │
│ Parse packets               │
│  ↓                          │
│ Generate statistics         │
└─────────┬───────────────────┘
          │
          ▼
Step 6: Results
┌─────────────────────────────┐
│ Report on Screen            │
│                             │
│ - Total packets: 348        │
│ - TCP: 95.7%                │
│ - Top IPs                   │
│ - Conversations             │
│ - Anomalies                 │
└─────────────────────────────┘
```

## 4. Attack Simulation Flow

```
┌────────────────────────────────────────────────────┐
│             Attack Simulation Setup                │
└────────────────────────────────────────────────────┘
                        │
         ┌──────────────┼──────────────┐
         │              │              │
         ▼              ▼              ▼
    ┌────────┐    ┌─────────┐    ┌─────────┐
    │ Target │    │ Monitor │    │Attacker │
    │(victim)│    │ (.131)  │    │ (.132)  │
    │  .130  │    │Captures │    │  Tools  │
    └────┬───┘    └────┬────┘    └────┬────┘
         │             │              │
         │◄────────────┼──────────────┘
         │   ARP Spoof │    Step 1: Attacker sends
         │             │    fake ARP to victim
         │             │
         │             │◄────────────  Step 2: Monitor
         │             │    captures the ARP packets
         │             │
         └─────────────┼────────────►  Step 3: Traffic
                       │    flows through attacker
                       │
                       ▼
                  Analyze.bat
                       │
                       ▼
              "ARP Attack Detected!"
```

## 5. analyze.bat Processing Flow

```
┌─────────────────────────────────────┐
│  User runs: analyze.bat             │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│  Activate Python Virtual Env        │
│  E:\nos\.venv\Scripts\activate.bat  │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│  Find all .pcap files               │
│  dir captures\*.pcap*               │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│  Show Interactive Menu              │
│  1. Analyze all                     │
│  2. Analyze specific                │
│  3. List files                      │
│  4. Exit                            │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│  User selects option                │
└───────────────┬─────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│  For each selected file:            │
│  python scripts\analyze_capture.py  │
└───────────────┬─────────────────────┘
                │
     ┌──────────┴──────────┐
     │                     │
     ▼                     ▼
┌──────────┐      ┌──────────────────┐
│Read PCAP │      │ Parse Packets    │
│with      │  →   │ - Count protocols│
│scapy     │      │ - Find IPs       │
└──────────┘      │ - Detect attacks │
                  └─────────┬────────┘
                            │
                            ▼
                  ┌──────────────────┐
                  │ Generate Report  │
                  │ - Statistics     │
                  │ - Top IPs        │
                  │ - Conversations  │
                  │ - Anomalies      │
                  └─────────┬────────┘
                            │
                            ▼
                  ┌──────────────────┐
                  │ Display on Screen│
                  └─────────┬────────┘
                            │
                            ▼
                  ┌──────────────────┐
                  │ Deactivate venv  │
                  │ Done!            │
                  └──────────────────┘
```

## 6. Real-World Attack Scenario

```
Scenario: ARP Poisoning Attack

Before Attack:
┌──────────┐         ┌──────────┐
│  Victim  │────────►│ Gateway  │
│  .130    │         │  .1      │
└──────────┘         └──────────┘
     Normal traffic flows directly

During Attack:
┌──────────┐         ┌──────────┐         ┌──────────┐
│  Victim  │────────►│ Attacker │────────►│ Gateway  │
│  .130    │  thinks │  .132    │  passes │  .1      │
└──────────┘  .132   └────┬─────┘  along  └──────────┘
              is              │
              gateway         │ intercepts
                             │
                             ▼
                      ┌──────────┐
                      │ Monitor  │
                      │  .131    │
                      │ CAPTURES │
                      │   ALL!   │
                      └──────────┘

Analysis Shows:
✓ ARP packets from .132 claiming to be .1
✓ Traffic pattern changed
✓ Suspicious ARP responses
✓ ANOMALY DETECTED!
```

## 7. Port Mapping Diagram

```
Windows Browser                Docker Container
(Your Computer)                (net-monitor-wan)
                              IP: 192.168.6.131

localhost:5002  ─────────────► :5000 (Flask API)
                Port Forward

localhost:8082  ─────────────► :8080 (HAProxy)
                Port Forward

localhost:8415  ─────────────► :8404 (Statistics)
                Port Forward

Why this works:
- Docker forwards ports from host to container
- You access localhost (easy to remember)
- Container uses real network interface
- Both see same services!
```

## Summary for Presentation

**Key Points:**
1. Container has static IP (192.168.6.131)
2. tcpdump captures ALL traffic passing through
3. Files saved to shared folder (Windows + Container)
4. analyze.bat processes with Python/scapy
5. Can add more containers for attack simulation
6. Perfect for network security testing

**Use Cases:**
- ARP spoofing detection
- Network traffic analysis
- Attack simulation
- Security training
- Packet forensics