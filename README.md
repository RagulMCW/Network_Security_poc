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

## 🔄 **Step-by-Step Process**

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
- Malware attacker uploads suspicious files
- DoS attacker floods network with packets
- SSH attacker tries brute force login
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
## 🏗️ **Key Components**

### 1. 🖥️ **Network Monitor (Zeek Engine)**
**What it does:** Acts as the "security camera" recording all network traffic

**How it works:**
- Runs on Docker container at `192.168.6.131:5000`
- Uses `tcpdump` to capture all packets on the network
- Zeek processes PCAP files every 30 seconds
- Generates detailed logs: `conn.log`, `http.log`, `files.log`, `dns.log`
- Custom `local.zeek` script extracts file hashes (SHA256) from HTTP headers

**Key Features:**
- Real-time packet capture
- File transfer detection with hash extraction
- Protocol analysis (HTTP, DNS, TCP, UDP)
- Automated log rotation by session

---

### 2. 💀 **Attack Simulators**

#### **Malware Attacker (192.168.6.200)**
**Purpose:** Tests signature-based malware detection

**Behavior:**
- Uploads real malware APK files (5.5 MB) every 5 seconds
- Sends files to `/api/firmware/update` endpoint
- Uses Python `requests` library with custom headers
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
   `ash
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
