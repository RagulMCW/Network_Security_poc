# Network Security System - Simple Flow Diagram

## 🎯 **MAIN SYSTEM FLOW**

```
┌─────────────────────────────────────────────────────────────┐
│                    🖥️  WINDOWS HOST                         │
│                                                             │
│  • Dashboard (Flask) - Port 5001                           │
│  • User controls everything via web browser                │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                    🐧 WSL2 UBUNTU                           │
│                                                             │
│  • Docker Engine running                                   │
│  • Two networks: Production + Honeypot                     │
└──────────────────────────┬──────────────────────────────────┘
                           │
        ┌──────────────────┴──────────────────┐
        ↓                                     ↓
┌───────────────────┐              ┌──────────────────┐
│ PRODUCTION NET    │              │ HONEYPOT NET     │
│ 192.168.6.0/24   │              │ 172.18.0.0/16   │
│                   │              │                  │
│ • Devices         │              │ • Beelzebub     │
│ • Attackers       │              │   Honeypot      │
│ • Monitor         │              │   (172.18.0.2)  │
└─────────┬─────────┘              └──────────────────┘
          │
          ↓
┌─────────────────────────────────────────────────────────────┐
│              📊 TRAFFIC CAPTURE & ANALYSIS                  │
│                                                             │
│  tcpdump → PCAP files → Zeek Monitor → Logs → Dashboard   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔄 **COMPLETE SYSTEM WORKFLOW**

### **Step 1: Network Setup**
```
User clicks "Create Network"
       ↓
Dashboard sends WSL command
       ↓
Docker creates custom_net (192.168.6.0/24)
       ↓
Network ready ✅
```

### **Step 2: Start Monitor Container**
```
User clicks "Start Monitor"
       ↓
Docker starts network-monitor container
       ↓
Monitor container starts 3 services:
  1. tcpdump (captures packets → /captures/)
  2. Zeek monitor (analyzes PCAPs → /app/zeek_logs/)
  3. Flask API (port 5000)
       ↓
All services running ✅
```

### **Step 3: Automatic Traffic Capture**
```
┌──────────────────────────────────────────┐
│  tcpdump Running Inside Monitor         │
│                                          │
│  • Listens on eth0                      │
│  • Captures ALL network traffic         │
│  • Saves to /captures/                  │
│  • Rotates every 60 seconds             │
│  • Keeps last 100 files                 │
└──────────────────────────────────────────┘
                  │
                  ↓
         Files Created:
   capture_20251114_065520.pcap
   capture_20251114_065620.pcap
   capture_20251114_065720.pcap
```

### **Step 4: Automatic Zeek Analysis**
```
┌──────────────────────────────────────────┐
│  Zeek Monitor (monitor.sh)               │
│                                          │
│  WHILE TRUE:                            │
│    • Scan /captures/ every 5 seconds    │
│    • Find new *.pcap files              │
│    • Run: zeek -C -r file.pcap          │
│    • Output logs to session directory   │
│    • Mark file as processed             │
│    • Sleep 5 seconds                    │
│  END WHILE                              │
└──────────────────────────────────────────┘
                  │
                  ↓
    Zeek Logs Created:
    /app/zeek_logs/session_20251114_070027/
      ├── conn.log (network connections)
      ├── http.log (HTTP requests)
      ├── dns.log (DNS queries)
      ├── files.log (file transfers)
      └── packet_filter.log (stats)
```

### **Step 5: Device/Attacker Activity**
```
User creates device containers
       ↓
Device_1, Device_2, Device_3... running
       ↓
Devices send HTTP requests to monitor
       ↓
Traffic flows through bridge ✅
       ↓
tcpdump captures everything
       ↓
Zeek analyzes and logs

─────────────────────────────────

User starts DOS attacker
       ↓
hping3-attacker container starts
       ↓
Sends SYN flood to monitor:5000
       ↓
~100 packets/second flooding
       ↓
tcpdump captures attack traffic
       ↓
Zeek logs show HIGH packet count
```

### **Step 6: Dashboard Monitoring**
```
Dashboard polls /api/status every 10 seconds
       ↓
Shows:
  • Network status
  • Running containers
  • Device count
  • Attacker status
  • Monitor health

User can view Zeek logs:
  • Click "View Zeek Logs"
  • Dashboard reads /app/zeek_logs/
  • Shows latest session data
  • Displays connections, HTTP, DNS
```

---

## 📊 **DATA FLOW DIAGRAM**

```
┌────────────┐
│  DEVICES   │ (device_1, device_2, device_3...)
└──────┬─────┘
       │ Normal HTTP traffic
       │
       ↓
┌─────────────────────────┐
│   PRODUCTION BRIDGE     │
│   br-3b9ea2fd6f9c      │
│   (192.168.6.0/24)     │
└──────┬──────────┬───────┘
       │          │
       ↓          ↓
┌──────────┐  ┌────────────────┐
│ MONITOR  │  │ tcpdump        │
│ :5000    │  │ (capture)      │
└──────────┘  └────────┬───────┘
                       │
                       ↓
              ┌─────────────────┐
              │ PCAP Files      │
              │ /captures/      │
              │ *.pcap          │
              └────────┬────────┘
                       │
                       ↓
              ┌─────────────────┐
              │ Zeek Monitor    │
              │ monitor.sh      │
              │ (every 5s)      │
              └────────┬────────┘
                       │
                       ↓
              ┌─────────────────┐
              │ Zeek Logs       │
              │ /app/zeek_logs/ │
              │ session_*/      │
              └────────┬────────┘
                       │
                       ↓
              ┌─────────────────┐
              │ Dashboard       │
              │ (Read & Display)│
              └─────────────────┘
```

---

## 🔴 **ATTACK DETECTION & ISOLATION FLOW**

```
┌──────────────────────────────────────────────────────────┐
│  STEP 1: Normal Operation                                │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Attacker (192.168.6.132)  ──────→  Monitor (131)      │
│       │                                  │               │
│       └──→ tcpdump captures              │               │
│                  ↓                       │               │
│            Zeek analyzes                 │               │
│                  ↓                       │               │
│            conn.log shows traffic        │               │
│                                                          │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│  STEP 2: DoS Attack Started                              │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  User clicks "Start Attacker"                           │
│       ↓                                                  │
│  hping3-attacker starts                                 │
│       ↓                                                  │
│  Sends 100+ SYN packets/sec                             │
│       ↓                                                  │
│  Monitor overwhelmed! 🔥                                 │
│       ↓                                                  │
│  tcpdump captures flood                                 │
│       ↓                                                  │
│  PCAP file grows rapidly                                │
│                                                          │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│  STEP 3: AI Detection (Dashboard Analysis)               │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Dashboard reads Zeek conn.log                          │
│       ↓                                                  │
│  Counts packets per IP:                                 │
│    192.168.6.132 = 3,817 packets                       │
│       ↓                                                  │
│  THRESHOLD CHECK:                                       │
│    < 1500   → Normal                                    │
│    1500-3000 → Warning ⚠️                               │
│    > 3000   → CRITICAL! 🚨                              │
│       ↓                                                  │
│  ATTACK DETECTED!                                       │
│                                                          │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│  STEP 4: Auto-Isolation (iptables Redirect)             │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Dashboard identifies attacker:                         │
│    Container: hping3-attacker                           │
│    IP: 192.168.6.132                                    │
│       ↓                                                  │
│  Get Beelzebub honeypot IP:                            │
│    docker inspect beelzebub-honeypot                   │
│    → 172.18.0.2                                         │
│       ↓                                                  │
│  Create iptables rules:                                 │
│    iptables -t nat -A PREROUTING \                     │
│      -s 192.168.6.132 -p tcp \                         │
│      -j DNAT --to-destination 172.18.0.2               │
│       ↓                                                  │
│  Log to reroutes.log                                    │
│       ↓                                                  │
│  ✅ TRAFFIC REDIRECTED!                                 │
│                                                          │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│  STEP 5: Redirected Traffic Flow                         │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Attacker (192.168.6.132)                              │
│       │                                                  │
│       ↓ SYN Flood                                       │
│  iptables NAT (intercepts)                             │
│       │                                                  │
│       ↓ Redirected                                      │
│  Beelzebub Honeypot (172.18.0.2)                       │
│       │                                                  │
│       ↓ Logs attack                                     │
│  beelzebub.log                                          │
│                                                          │
│  Monitor (192.168.6.131) ← No traffic ✅ Protected!     │
│                                                          │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│  STEP 6: User Cleanup                                    │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  User clicks "Stop Attacker"                            │
│       ↓                                                  │
│  Dashboard runs cleanup_iptables.sh                     │
│       ↓                                                  │
│  Delete iptables DNAT rules                             │
│       ↓                                                  │
│  Clear reroutes.log                                     │
│       ↓                                                  │
│  docker compose down (stop attacker)                    │
│       ↓                                                  │
│  ✅ System reset to normal                              │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

---

## 🗂️ **FILE STRUCTURE**

```
Network_Security_poc/
├── dashboard/
│   ├── app.py                    (Flask web server)
│   ├── templates/
│   │   └── control_panel.html   (Web UI)
│   └── static/
│       └── dashboard.js          (Frontend logic)
│
├── network/
│   ├── docker-compose.yml        (Monitor container config)
│   ├── captures/                 (tcpdump PCAP files)
│   │   └── capture_*.pcap
│   ├── zeek_logs/                (Zeek analysis output)
│   │   ├── session_20251114_070027/
│   │   │   ├── conn.log          (Connections)
│   │   │   ├── http.log          (HTTP requests)
│   │   │   ├── dns.log           (DNS queries)
│   │   │   └── files.log         (File transfers)
│   │   └── zeek_monitor.log      (Monitor script log)
│   └── zeek/
│       ├── monitor.sh            (Zeek automation script)
│       └── README.md             (Documentation)
│
├── honey_pot/
│   ├── docker-compose-simple.yml (Beelzebub config)
│   ├── logs/
│   │   ├── reroutes.log          (Isolation tracking)
│   │   ├── attacks.jsonl         (Attack data)
│   │   └── beelzebub.log         (Honeypot logs)
│   └── pcap_captures/            (Honeypot traffic)
│       └── honeypot_*.pcap
│
├── attackers/
│   └── dos_attacker/
│       ├── docker-compose.yml    (Attacker config)
│       ├── hping3_sender.sh      (Attack script)
│       └── cleanup_iptables.sh   (Cleanup script)
│
└── devices/
    ├── device_simulator.py       (IoT device simulator)
    └── Dockerfile                (Device container)
```

---

## 🔑 **KEY COMPONENTS EXPLAINED**

### **1. tcpdump (Packet Capture)**
```bash
# Running inside network-monitor container
tcpdump -i eth0 -w /captures/capture_%Y%m%d_%H%M%S.pcap -G 60
```
- Captures ALL network traffic
- Rotates files every 60 seconds
- Keeps last 100 files

### **2. Zeek Monitor (monitor.sh)**
```bash
#!/bin/bash
while true; do
  find /captures -name "*.pcap" | while read pcap; do
    zeek -C -r "$pcap" "Log::default_logdir=$session_dir"
    echo "$pcap" >> /tmp/zeek_processed.txt
  done
  sleep 5
done
```
- Runs continuously (24/7)
- Scans for new PCAPs every 5 seconds
- Analyzes with Zeek
- Creates session directories with logs

### **3. Zeek Logs (TSV Format)**
```
conn.log fields:
  ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
  proto, service, duration, orig_bytes, resp_bytes, conn_state

Example entry:
  1731574887.042847  CHhAvVGS1DHFjwGMf  192.168.6.3  51112
  192.168.6.131  5000  tcp  http  0.000682  187  318  S1
```

### **4. Dashboard (Flask API)**
```python
# Key endpoints:
/api/status              → Get system status
/api/network/create      → Create Docker network
/api/monitor/start       → Start monitor container
/api/attackers/start     → Start DOS attacker
/api/beelzebub/start     → Start honeypot
/api/beelzebub/reroute   → Isolate IP to honeypot
```

---

## 📊 **MONITORING & ALERTS**

```
┌─────────────────────────────────────────┐
│  Dashboard Auto-Refresh (10s)           │
├─────────────────────────────────────────┤
│                                         │
│  Check:                                 │
│    ✅ Network status                    │
│    ✅ Container health                  │
│    ✅ Device count                      │
│    ✅ Attacker status                   │
│    ✅ Zeek log size                     │
│                                         │
│  If attack detected:                    │
│    🚨 Show alert                        │
│    🛡️ Auto-isolate button              │
│    📊 Show attack stats                 │
│                                         │
└─────────────────────────────────────────┘
```

---

## 🎯 **SUMMARY**

**System Purpose:**
- Monitor network traffic automatically
- Detect DoS attacks using Zeek logs
- Isolate malicious IPs to honeypot
- Log all activity for analysis

**Automatic Operations:**
1. tcpdump captures traffic → PCAPs
2. Zeek analyzes PCAPs → Logs
3. Dashboard reads logs → Detects attacks
4. iptables redirects traffic → Honeypot

**User Actions:**
- Start/stop containers via web UI
- View Zeek logs in real-time
- Manually isolate IPs
- Cleanup and reset system

**Key Innovation:**
- Fully automated monitoring (no manual intervention)
- Zeek analyzes ALL traffic automatically
- Traffic redirection via iptables (instant, transparent)
- Web-based control panel (easy to use)
