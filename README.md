# Network Security & Malware Detection System

A comprehensive Proof of Concept (POC) for detecting malware, analyzing network traffic, and automating responses using Zeek, Docker, and AI agents.

##  System Architecture

The system simulates a production network where devices and attackers interact. Traffic is captured, analyzed by Zeek, and visualized on a dashboard.

`mermaid
graph TD
    subgraph 'Attacker Network'
        A[Malware Attacker] -->|Sends Malware/EICAR| B(Network Monitor)
        C[DoS Attacker] -->|SYN Flood| B
    end

    subgraph 'Production Network'
        D[IoT Devices] -->|Normal Traffic| B
    end

    subgraph 'Detection System'
        B -->|Captures Traffic| E[tcpdump]
        E -->|PCAP Files| F[Zeek Monitor]
        F -->|Analyzes| G[Zeek Logs]
        G -->|Parses| H[Dashboard / AI Agent]
    end

    subgraph 'Response'
        H -->|Detects Threat| I[Firewall / IPTables]
        I -->|Redirects| J[Honeypot]
    end
``n
##  Key Components

### 1. Network Monitor (Zeek)
- **Role:** The core analysis engine.
- **Function:** Captures all traffic on the bridge network using tcpdump.
- **Analysis:** Processes PCAP files with Zeek to generate logs (conn.log, http.log, files.log).
- **Customization:** Uses a custom local.zeek script to extract file hashes (X-Original-Hash) and detect EICAR signatures.

### 2. Malware Attacker
- **Role:** Simulates a compromised host or external attacker.
- **Behavior:** 
    - Sends malware samples (e.g., EICAR, dummy binaries) every 3 seconds.
    - Simulates C2 (Command & Control) beacons.
    - Simulates Data Exfiltration.
- **Mechanism:** Uses send_malware_sample.py to inject custom headers for tracking.

### 3. Dashboard
- **Role:** Visualization and Control Center.
- **Features:**
    - Real-time traffic monitoring.
    - Attack detection alerts.
    - Controls to start/stop attackers and the honeypot.
    - View raw Zeek logs.

### 4. Honeypot (Beelzebub)
- **Role:** Trap for malicious actors.
- **Function:** When an attack is detected, the system can redirect the attacker's traffic to this isolated container to study their behavior without risking the production network.

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
