# Network Security & Malware Detection System

A comprehensive Proof of Concept (POC) for detecting malware, analyzing network traffic, and automating responses using Zeek, Docker, and AI agents.

---

## 🎯 **How It Works (Simple Explanation)**

Think of this as a **smart security camera system** for your network:

1. **📱 Devices Send Traffic** → IoT devices, laptops, and containers communicate normally
2. **🎥 Monitor Watches Everything** → Network monitor captures all traffic (like a CCTV camera)
3. **🧠 AI Analyzes Behavior** → Zeek + AI Agent detect suspicious patterns (malware, attacks, anomalies)
4. **🚨 Alerts & Response** → Dashboard shows threats + Auto-isolates bad actors to honeypot

---

## 🔄 **System Architecture & Workflow**

### **1. Current Architecture - Visual Overview**

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                 Docker Network: custom_net                              │
│                                    (192.168.6.0/24)                                     │
│                                                                                         │
│  ┌──────────────────────┐         ┌──────────────────────┐   ┌──────────────────────┐   │
│  │    Monitor Server    │◄────────┤    Normal Devices    │   │      Attackers       │   │
│  │   (network-monitor)  │         │   (IoT Simulators)   │   │   (Malware/DoS/SSH)  │   │
│  │                      │         │                      │   │                      │   │
│  │ IP: 192.168.6.131    │         │ IP: 192.168.6.10-16  │   │ IP: 192.168.6.200+   │   │
│  │                      │         │                      │   │                      │   │
│  │ Services:            │         │ Behavior:            │   │ Behavior:            │   │
│  │ • Zeek (Traffic Log) │         │ • Send Sensor Data   │   │ • Upload Malware     │   │
│  │ • tcpdump (Capture)  │         │ • Regular Heartbeat  │   │ • Brute Force SSH    │   │
│  │ • Flask API (:5000)  │         │ • Valid Requests     │   │ • DoS Flooding       │   │
│  └──────────┬───────────┘         └──────────────────────┘   └──────────────────────┘   │
│             │                                                                           │
└─────────────┼───────────────────────────────────────────────────────────────────────────┘
              │
              │ Traffic Logs (conn.log, files.log)
              ▼
┌─────────────────────────────┐       ┌───────────────────────────────────────────────────┐
│      Host Machine (Windows) │       │           Docker Network: honeypot_net            │
│                             │       │                (172.18.0.0/16)                    │
│  ┌───────────────────────┐  │       │                                                   │
│  │       MCP Agent       │  │       │  ┌──────────────────────┐                         │
│  │   (Python/Claude AI)  │  │       │  │  Beelzebub Honeypot  │                         │
│  │                       │  │       │  │                      │                         │
│  │ Actions:              │  │       │  │ IP: 172.18.0.2       │                         │
│  │ 1. Read Zeek Logs     │──┼──────►│  │                      │                         │
│  │ 2. Check File Hashes  │  │ DNAT  │  │ Services:            │                         │
│  │ 3. Reroute Traffic    │  │ Rule  │  │ • SSH (LLM Powered)  │                         │
│  └───────────────────────┘  │       │  │ • HTTP / FTP / SQL   │                         │
│                             │       │  └──────────▲───────────┘                         │
│  ┌───────────────────────┐  │       │             │                                     │
│  │      Dashboard        │  │       └─────────────┼─────────────────────────────────────┘
│  │    (Flask Web UI)     │  │                     │                                      
│  │                       │  │                     │                                      
│  │ • http://localhost:5000  │                     │                                      
│  └───────────────────────┘  │                     │                                      
└─────────────────────────────┘                     │                                      
                                                    │                                      
         Attacker Traffic Redirected (DNAT) ────────┘                                      
```

### **2. Step-by-Step: How It Works**

#### **Step 1: Start the System**
```bash
scripts/start_all.sh
```
**What happens:**
- ✅ Creates `custom_net` (192.168.6.0/24) and `honeypot_net`
- ✅ Starts **Network Monitor** (192.168.6.131) with Zeek & tcpdump
- ✅ Starts **Honeypot** (172.18.0.2) with LLM integration
- ✅ Starts **Dashboard** on host (localhost:5000)

#### **Step 2: Traffic Generation (Normal vs Attack)**

**Scenario A: Normal IoT Device**
```
IoT Device (192.168.6.10)                   Monitor (192.168.6.131)
     │                                            │
     │ 1. Send Sensor Data (JSON)                 │
     ├──────────────────────────────────────────►│
     │   POST /api/device/data                    │
     │                                            │
     │◄──────────────────────────────────────────┤
     │   200 OK                                   │
```
*Result: Zeek logs "Normal" traffic. Agent sees no threat.*

**Scenario B: Malware Attack**
```
Malware Attacker (192.168.6.200)            Monitor (192.168.6.131)
     │                                            │
     │ 1. Upload Malicious File (APK/EXE)         │
     ├──────────────────────────────────────────►│
     │   POST /api/firmware/update                │
     │   [Malicious Payload]                      │
     │                                            │
     │◄──────────────────────────────────────────┤
     │   200 OK (File received)                   │
```
*Result: Zeek extracts file hash. Agent detects threat.*

#### **Step 3: Detection & Analysis (The AI Brain)**

**Automatic Process (Every 30s):**
1. **Zeek** rotates logs (`conn.log`, `files.log`) to `network/zeek_logs/`
2. **MCP Agent** reads the new logs
3. **Agent** sees file upload from `192.168.6.200`
4. **Agent** checks hash against **MalwareBazaar Database**
5. **Agent** confirms: "⚠️ MALWARE DETECTED (Trojan.AndroidOS)"

#### **Step 4: Automated Response (Isolation)**

**Action Taken:**
1. Agent triggers **Isolation Protocol**
2. Applies **iptables DNAT Rule** on the Host/Router:
   ```bash
   iptables -t nat -A PREROUTING -s 192.168.6.200 -j DNAT --to-destination 172.18.0.2
   ```
3. **Attacker is now silently rerouted to Honeypot**

#### **Step 5: Honeypot Interaction (AI vs Attacker)**

The honeypot uses **Ollama (LLM)** to generate realistic responses, fooling the attacker into thinking they have breached a real system.

```
┌──────────────────────┐                    ┌──────────────────────┐
│   Malware Attacker   │                    │  Beelzebub Honeypot  │
│   (192.168.6.200)    │                    │    (172.18.0.2)      │
└──────────┬───────────┘                    └──────────┬───────────┘
           │                                           │
           │ 1. SSH Login Attempt                      │
           │    "ssh root@192.168.6.201"               │
           ├──────────────────────────────────────────►│
           │                                           │
           │                                           │ 2. Honeypot asks LLM:
           │                                           │    "User ran 'ssh root'. Generate a
           │                                           │     realistic Ubuntu login prompt."
           │                                           │
           │ 3. LLM Generates Response                 │◄────────────────────────┐
           │    "Welcome to Ubuntu 22.04 LTS..."       │                         │
           │◄──────────────────────────────────────────┤                         │
           │                                           │                         │
           │ 4. Attacker runs command                  │                         │
           │    "cat /etc/passwd"                      │                         │
           ├──────────────────────────────────────────►│                         │
           │                                           │                         │
           │                                           │ 5. Honeypot asks LLM:   │
           │                                           │    "User ran 'cat /etc/passwd'. │
           │                                           │     Generate fake file content."│
           │                                           │                         │
           │ 6. LLM Generates Fake File                │◄────────────────────────┘
           │    "root:x:0:0:root:/root:/bin/bash..."   │
           │◄──────────────────────────────────────────┤
           │                                           │
           ▼                                           ▼
    Attacker is fooled!                   Interaction Logged
```
*Result: Attacker wastes time attacking a decoy while you collect evidence.*

---

## 🔄 **Full Working Flow**

### **Step 1: Normal Traffic Flow**
```
📱 Device → 🌐 Network → 🖥️ Monitor → ✅ Allowed
```
- IoT devices send sensor data every 10 seconds
- Monitor server receives and logs the data
- Everything operates normally

### **Step 2: Attack Simulation**
```
💀 Attacker → 🌐 Network → 🖥️ Monitor → 🎥 Captured
```
- **Malware Attacker**: Uploads suspicious files (APK, EXE)
- **DoS Attacker**: Floods network with packets
- **SSH Attacker**: Tries brute force login
- **All traffic is captured by tcpdump**

### **Step 3: Traffic Analysis**
```
📦 PCAP File → 🧪 Zeek → 📋 Logs (conn.log, files.log, http.log)
```
- Zeek processes captured packets
- Extracts connection details, file hashes, HTTP requests
- Logs stored in `network/zeek_logs/session_TIMESTAMP/`

### **Step 4: AI Detection**
```
📋 Zeek Logs → 🤖 AI Agent → 🔍 Analysis
```
AI Agent analyzes using **MCP Tools**:
1. **🔧 read_zeek_logs** → Reads network traffic logs
2. **🔧 check_malware_hash** → Verifies file signatures against MalwareBazaar
3. **🔧 docker_command** → Checks container status
4. **🔧 move_device_to_honeypot** → Isolates threats

**Detection Methods:**
- **Behavioral Anomalies**: Regular intervals, high frequency, unusual endpoints
- **Signature Matching**: File hash verification (SHA256)
- **Traffic Patterns**: Data exfiltration, C2 beacons, port scanning

### **Step 5: Automated Response**
```
🚨 Threat Detected → 🚫 iptables Rules → 🍯 Honeypot Isolation
```
When threat is confirmed:
1. Dashboard shows alert with evidence
2. User clicks "Reroute to Honeypot"
3. System applies iptables DNAT rules
4. Attacker's traffic redirected to isolated network
5. Honeypot logs all attacker behavior safely

---

## 📂 **Project Structure**

```
Network_Security_poc/
├── attackers/              # Attack simulation containers
│   ├── dos_attacker/       # Denial of Service simulator
│   ├── endpoint_behavior/  # Endpoint behavior simulator
│   ├── malware_attacker/   # Malware upload simulator
│   └── ssh_attacker/       # SSH brute force simulator
├── dashboard/              # Web interface (Flask)
│   ├── app.py              # Main application
│   ├── static/             # JS, CSS
│   └── templates/          # HTML templates
├── devices/                # IoT device simulators
├── honey_pot/              # Beelzebub Honeypot
│   ├── docker-compose.yml  # Honeypot configuration
│   └── logs/               # Honeypot interaction logs
├── malware_db/             # Malware hash database & YARA rules
├── mcp_agent/              # AI Agent (MCP Server & Client)
│   ├── client/             # Agent logic
│   └── server/             # MCP server implementation
├── network/                # Network monitoring (Zeek)
│   ├── zeek/               # Zeek scripts
│   └── zeek_logs/          # Traffic logs
├── scripts/                # Utility scripts
└── tests/                  # Test scripts
```

---

## 🚀 **Quick Start**

### 1. **Initial Setup**
Run the setup script to initialize the environment:
```bash
scripts/initial_setup.bat
```

### 2. **Start the System**
Launch all containers and services:
```bash
scripts/start_all.sh
```

### 3. **Access Dashboard**
Open your browser and navigate to:
`http://localhost:5000`

### 4. **Run AI Agent**
Start the AI agent to monitor traffic:
```bash
mcp_agent/RUN_AGENT.bat
```

---

## 🛠️ **Key Components**

### 1. 🖥️ **Network Monitor (Zeek Engine)**
**What it does:** Acts as the "security camera" recording all network traffic
- Runs on Docker container at `192.168.6.131:5000`
- Uses `tcpdump` to capture all packets on the network
- Zeek processes PCAP files every 30 seconds
- Generates detailed logs: `conn.log`, `http.log`, `files.log`, `dns.log`

### 2. 💀 **Attack Simulators**
- **Malware Attacker (192.168.6.200)**: Uploads real malware APK files
- **DoS Attacker (192.168.6.132)**: Simulates high-volume packet flooding
- **SSH Attacker**: Attempts brute force login

### 3. 🍯 **Honeypot (Beelzebub)**
- **Role**: Decoy system to trap attackers
- **Features**: AI-powered responses (LLM), SSH emulation, HTTP emulation
- **Integration**: Connected to dashboard for real-time monitoring

### 4. 🤖 **MCP Agent**
- **Role**: Intelligent analysis and response
- **Capabilities**:
    - Reads Zeek logs
    - Checks file hashes against malware database
    - Executes Docker commands
    - Manages iptables rules for isolation

---

## 📊 **Dashboard Features**

- **Real-time Traffic Map**: Visualizes network flow
- **Threat Alerts**: Instant notifications of detected attacks
- **Honeypot Logs**: View attacker interactions
- **LLM Responses**: See how the AI honeypot responds to attackers
- **Control Panel**: Start/Stop simulators, Reroute IPs

---

## 📝 **Scripts & Utilities**

All utility scripts are located in the `scripts/` directory:
- `start_all.sh`: Start the entire system
- `apply_dnat_reroute.bat`: Manually reroute an IP to the honeypot
- `initial_setup.bat`: First-time setup
- `diagnose.bat`: Troubleshoot issues

---

## 🧪 **Testing**

Run tests located in the `tests/` directory:
- `test_gemini.py`: Test LLM connection
- `test_ssh_llm_connection.py`: Test SSH honeypot connectivity

---

**Developed for Network Security Research**
- Hash: `a864d996cb...` (known malware signature)

**Detection Method:** File hash matching against MalwareBazaar database

#### **DoS Attacker (192.168.6.132)**
**Purpose:** Tests network flooding detection

**Behavior:**
- Sends 100+ packets per second using `hping3`
- SYN flood attack on port 5000
- Overwhelms network monitor

**Detection Method:** High connection frequency in `conn.log`

#### **SSH Brute Force Attacker (192.168.6.133)**
**Purpose:** Tests authentication attack detection

**Behavior:**
- Attempts SSH login with common passwords
- Uses wordlist of 100+ credentials
- Targets monitor server (192.168.6.131:22)

**Detection Method:** Repeated failed connection attempts

#### **Endpoint Behavior Attacker (192.168.6.201)**
**Purpose:** Tests behavioral anomaly detection (no real malware)

**Simulates 9 malicious behaviors:**
1. **C2 Beacon** → Regular callbacks every 2s
2. **Data Exfiltration** → Large uploads to cloud
3. **DNS DGA** → Random domain queries
4. **Port Scanning** → Sequential port probing
5. **API Abuse** → High-frequency API calls
6. **Credential Harvesting** → /etc/passwd reads
7. **Privilege Escalation** → Sudo attempts
8. **Lateral Movement** → Internal network scans
9. **Data Staging** → File compression

**Detection Method:** Behavioral pattern analysis (timing, frequency, endpoints)

---

### 3. 🎨 **Dashboard (Control Center)**
**URL:** `http://localhost:5100`

**Pages:**
1. **Overview** → System status, container counts, network health
2. **Network Map** → Visual topology with all devices and IPs
3. **Monitor** → Start/stop Zeek monitor, view logs
4. **Devices** → Create/delete IoT simulators
5. **Honeypot** → Beelzebub control, reroute threats, attacker analytics
6. **Attackers** → Start/stop attack simulations
7. **AI Agent** → Chat with AI for threat analysis
8. **Logs** → Device data, monitor logs, honeypot attacks

**Key Features:**
- Real-time status updates every 5 seconds
- One-click threat isolation
- AI-powered security analysis
- Network topology visualization
- Tool execution tracking

---

### 4. 🤖 **AI Security Agent**
**Model:** glm-4.5 (Claude 3.5 Sonnet via Anthropic API)  
**Framework:** MCP (Model Context Protocol) with FastMCP

**Capabilities:**
- Reads Zeek logs and analyzes traffic patterns
- Detects behavioral anomalies without signatures
- Verifies file hashes against MalwareBazaar
- Executes Docker commands via WSL
- Provides evidence-based threat reports

**20 MCP Tools Available:**
```
📁 File System: read_file, write_file, list_directory
💻 System: run_command, run_powershell, run_batch_file
🐧 WSL/Linux: wsl_command, wsl_bash_script, wsl_read_file
🐳 Docker: docker_command
🛡️ Security: read_zeek_logs, check_malware_hash, move_device_to_honeypot
```

**Workflow:**
1. User asks: *"Analyze latest logs for threats"*
2. AI uses `🔧 read_zeek_logs` → Gets latest session data
3. AI analyzes behavior → Detects anomalies
4. AI uses `🔧 check_malware_hash` → Verifies suspicious files
5. AI uses `🔧 docker_command` → Checks container status
6. AI generates report with evidence and recommendations

---

### 5. 🍯 **Beelzebub Honeypot**
**Network:** Isolated `honeypot_net (192.168.7.0/24)`

**Purpose:** Safely trap and study attackers

**How Isolation Works:**
1. AI detects threat on main network (192.168.6.x)
2. User clicks "Reroute to Honeypot" on dashboard
3. System applies `iptables DNAT` rules:
   ```bash
   iptables -t nat -A PREROUTING -s 192.168.6.132 -j DNAT --to-destination 192.168.7.3
   ```
4. All attacker traffic redirected to honeypot
5. Attacker thinks they're still on main network
6. Honeypot logs all actions (commands, credentials, HTTP requests)

**Honeypot Services:**
- SSH (port 2223)
- HTTP (ports 8080, 8081, 8443)
- FTP (port 2121)
- MySQL (port 3306)
- PostgreSQL (port 5432)

**Attacker Analytics:**
- Unique IPs detected
- Credentials attempted
- Commands executed
- HTTP paths accessed
- Protocols used

##  Project Structure

``nNetwork_Security_poc/
 attackers/              # Docker containers for attack simulation
    malware_attacker/   # Sends malware samples
    dos_attacker/       # Performs DoS attacks
 dashboard/              # Flask-based web UI
 network/                # Zeek monitor configuration
    zeek/               # Zeek scripts (local.zeek, monitor.sh)
    zeek_logs/          # Generated logs
 honey_pot/              # Beelzebub honeypot setup
 docs/                   # Documentation
 scripts/                # Utility scripts for setup/maintenance
``n
##  Usage

### Prerequisites
- Docker & Docker Compose
- WSL2 (if on Windows)

### Quick Start
1. **Start the System:**
   `Bash
   cd Network_Security_poc
   ./scripts/start_all.sh
   ` 

2. **Access Dashboard:**
   Open http://localhost:5001 in your browser.

3. **Simulate Attack:**
   - Go to the Dashboard.
   - Click **'Start Malware Attacker'**.
   - Watch the **Zeek Logs** panel for files.log entries showing the detected hashes.

##  Log Analysis
Zeek logs are stored in network/zeek_logs/.
- **files.log:** Details of transferred files (MD5, SHA1, SHA256).
- **http.log:** Web traffic details.
- **conn.log:** All TCP/UDP connections.

##  Security Features
- **Hash Extraction:** The system extracts X-Original-Hash headers to verify file integrity even if the transfer is incomplete.
- **Automated Isolation:** Capable of rewriting iptables rules to quarantine attackers.
