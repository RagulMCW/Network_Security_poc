# Beelzebub Honeypot - AI-Powered Network Security System# Beelzebub Honeypot - AI-Powered Network Security System



> AI-Powered Deception System for Network Security Research> AI-Powered Deception System for Network Security Research



An intelligent honeypot that simulates vulnerable production servers to attract, trap, and study attackers. Built on the official [Beelzebub framework](https://github.com/mariocandela/beelzebub) with full dashboard integration.An intelligent honeypot that simulates vulnerable production servers to attract, trap, and study attackers. Built on the official [Beelzebub framework](https://github.com/mariocandela/beelzebub) with full dashboard integration.



------



## Table of Contents## Table of Contents



- [Overview](#overview)- [Overview](#overview)

- [System Architecture](#system-architecture)- [System Architecture](#system-architecture)

- [How It Works](#how-it-works)- [How It Works](#how-it-works)

- [Quick Start](#quick-start)- [Quick Start](#quick-start)

- [Features](#features)- [Features](#features)

- [Testing & Monitoring](#testing--monitoring)- [Testing & Monitoring](#testing--monitoring)

- [IP Rerouting](#ip-rerouting)- [IP Rerouting](#ip-rerouting)

- [Logs & Analytics](#logs--analytics)- [Logs & Analytics](#logs--analytics)

- [Configuration](#configuration)- [Configuration](#configuration)

- [Troubleshooting](#troubleshooting)- [Troubleshooting](#troubleshooting)



------



## Overview## Overview



**Beelzebub** is an advanced honeypot framework that simulates vulnerable services to attract and study attacker behavior. This deployment includes:**Beelzebub** is an advanced honeypot framework that simulates vulnerable services to attract and study attacker behavior. This deployment uses:



- **AI Model**: GLM-4.5 via Anthropic API for realistic shell interactions

- **Protocols**: SSH, HTTP, MySQL, PostgreSQL, FTP, Telnet

- **Logging**: Comprehensive attack logging with JSONL format- **AI Model**: GLM-4.5 via Anthropic API for realistic shell interactions---

- **Deployment**: Docker-based for easy setup and isolation

- **Protocols**: SSH, HTTP, MySQL, PostgreSQL, FTP, Telnet

### Key Features

- **Logging**: Comprehensive attack logging with JSONL format## 🎯 What Is This?

- AI-powered realistic responses to attacker commands

- Multiple protocol support (SSH, HTTP, Database, FTP, Telnet)- **Deployment**: Docker-based for easy setup and isolation

- Automatic credential capture and logging

- Web-based log viewer for real-time monitoringBeelzebub is a **deception honeypot** that pretends to be a vulnerable server to:

- Isolated Docker network for security

- Integration with security dashboard### Key Features



### Deployment Status✅ AI-powered realistic responses to attacker commands  - ✅ **Attract attackers** - Looks like an easy target with open services



- **Status**: Fully Operational✅ Multiple protocol support (SSH, HTTP, Database, FTP, Telnet)  - ✅ **Trap & isolate** - Contains malicious activity in a safe environment

- **Integration**: Dashboard control panel enabled

- **AI Engine**: GPT-4 optional with fallback system✅ Automatic credential capture and logging  - ✅ **Log everything** - Records all attacker actions and commands

- **Protocols**: SSH, HTTP, MySQL, PostgreSQL

- **Monitoring**: Professional logging and analytics✅ Web-based log viewer  - ✅ **Learn patterns** - Analyze attack methods, tools, and behavior



---✅ Isolated Docker network for security  - ✅ **Protect real systems** - Diverts attention from actual infrastructure



## System Architecture✅ Integration with security dashboard  



### Network Flow### Current Status



```---

INTERNET / ATTACKERS

         |- ✅ **Fully Operational** - Integrated with dashboard control panel

         v

EXPOSED HONEYPOT PORTS## 🏗️ Architecture- ✅ **AI-Powered** - Intelligent responses (GPT-4 optional, fallback included)

SSH:2222 | HTTP:8080 | MySQL:3306 | PostgreSQL:5432

         |- ✅ **Multi-Protocol** - SSH, HTTP, MySQL, PostgreSQL support

         v

BEELZEBUB HONEYPOT CONTAINER### System Architecture Flowchart- ✅ **Production-Ready** - Professional logging and monitoring

  - Protocol Handlers

  - AI Response Engine (GLM-4.5)

  - Logger

         |```---

         v

PERSISTENT STORAGE┌─────────────────────────────────────────────────────────────────┐

  - logs/beelzebub.log (JSONL)

  - logs/attacks.jsonl│                        INTERNET / ATTACKERS                      │## 🧠 How It Works

         |

         v└────────────────────────────┬────────────────────────────────────┘

ANALYTICS & MONITORING

  - Log Viewer (Port 8888)                             │### Passive Monitoring (Automatic)

  - Security Dashboard (Port 5000)

```                             ▼



### Component Architecture┌─────────────────────────────────────────────────────────────────┐The honeypot **does NOT scan your network**. Instead, it:



- **Protocol Handlers**: SSH, HTTP, MySQL, PostgreSQL, FTP, Telnet│                    EXPOSED HONEYPOT PORTS                        │

- **AI Response Engine**: GLM-4.5 for intelligent attacker interaction

- **Logger**: Captures all interactions to JSONL format│  SSH:2222 │ HTTP:8080 │ MySQL:3306 │ PostgreSQL:5432 │ FTP:2121 │1. **Sits on network** with visible IP `192.168.6.200`

- **Storage**: Persistent logs for analysis

- **Monitoring**: Web-based log viewer and dashboard integration└────────────────────────────┬────────────────────────────────────┘2. **Opens fake services** (SSH, HTTP, databases)



---                             │3. **Waits for attackers** to discover and connect



## How It Works                             ▼4. **Logs automatically** when someone attacks



### Passive Monitoring (Automatic)┌─────────────────────────────────────────────────────────────────┐5. **You review logs** in Analytics dashboard



The honeypot operates in passive mode by default:│                  BEELZEBUB HONEYPOT CONTAINER                    │



1. **Network Presence**: Honeypot sits on network at IP `192.168.6.200`│  ┌──────────────────────────────────────────────────────────┐   │```

2. **Service Exposure**: Opens fake services (SSH, HTTP, databases)

3. **Attacker Discovery**: Waits for attackers to discover and connect│  │  Protocol Handlers                                       │   │┌─────────────────────────────┐

4. **Automatic Logging**: Records all interactions automatically

5. **Analytics Review**: Review captured data in Analytics dashboard│  │  ├─ SSH Service (AI-Powered with GLM-4.5)               │   ││     Beelzebub Honeypot      │



**Important**: The honeypot does NOT actively scan your network. It only logs connections made to it.│  │  ├─ HTTP Service (Fake phpMyAdmin)                      │   ││   IP: 192.168.6.200         │



### Active Rerouting (Manual Control)│  │  ├─ MySQL Service (Banner: 8.0.29)                      │   ││                              │



For targeted monitoring, you can manually reroute suspicious devices:│  │  ├─ PostgreSQL Service (Banner: 9.6.0)                  │   ││   Services:                  │



1. **Identify Threat**: Detect suspicious IP (e.g., `192.168.6.132`)│  │  ├─ FTP Service                                          │   ││   • SSH (Port 2222)          │

2. **Initiate Reroute**: Dashboard → Honeypot page → Enter IP → Click "Reroute"

3. **Network Isolation**: Container moved to `honeypot_net` (192.168.7.0/24)│  │  └─ Telnet Service                                       │   ││   • HTTP (Port 8080)         │

4. **Traffic Capture**: All device traffic logged and analyzed

5. **Behavior Analysis**: Review attacker methods and tools used│  └──────────────────────────────────────────────────────────┘   ││   • MySQL (Port 3306)        │



**Network Transition**:│                             │                                    ││   • PostgreSQL (Port 5432)   │

```

Before Reroute:│                             ▼                                    ││                              │

Device (192.168.6.132) → Access to all network resources

│  ┌──────────────────────────────────────────────────────────┐   ││   Status: WAITING...         │

After Reroute:

Device (192.168.7.2) → Isolated in honeypot network│  │  AI Response Engine (GLM-4.5)                           │   │└──────────▲──────────────────┘

                    → Can only communicate with honeypot

                    → Cannot reach production systems│  │  • Analyzes attacker commands                           │   │           │

                    → All actions logged

```│  │  • Generates realistic shell responses                  │   │           │ Attacker finds it



---│  │  • Simulates compromised server behavior                │   │           │ and tries to hack



## Quick Start│  └──────────────────────────────────────────────────────────┘   │           │



### Prerequisites│                             │                                    │      👤 Attacker



- Windows 10/11 with WSL2│                             ▼                                    │```

- Docker Desktop installed and running

- API Keys (optional): GLM-4.5 via Anthropic for AI responses│  ┌──────────────────────────────────────────────────────────┐   │



### Installation│  │  Logger                                                  │   │**Key Point**: Attackers must **come to the honeypot**. It doesn't search for them.



#### Method 1: Dashboard Control (Recommended)│  │  • Captures all interactions                            │   │



**Starting the honeypot:**│  │  • Records credentials, commands, payloads              │   │### Active Rerouting (Manual Control)



1. Open Dashboard: `http://localhost:5000`│  │  • Outputs to /logs/beelzebub.log                       │   │

2. Navigate: Click "Honeypot" in sidebar

3. Start: Click "Start Honeypot" button│  └──────────────────────────────────────────────────────────┘   │You can **force suspicious devices** into the honeypot:

4. Monitor: View stats, logs, and interactions in real-time

└────────────────────────────┬────────────────────────────────────┘

**Stopping the honeypot:**

                             │1. **Identify suspicious IP** (e.g., `192.168.6.132`)

1. Go to Honeypot page

2. Click "Stop Honeypot" button                             ▼2. **Reroute via dashboard**: Honeypot page → Enter IP → Click "🎯 Reroute"



#### Method 2: Batch Scripts┌─────────────────────────────────────────────────────────────────┐3. **Device gets isolated** - Moved to `honeypot_net` (192.168.7.0/24)



```batch│                      PERSISTENT STORAGE                          │4. **All traffic logged** - Everything the device does is recorded

# Start

cd e:\nos\Network_Security_poc\honey_pot│  ┌──────────────────────────────────────────────────────────┐   │5. **Analyze behavior** - Review what it tried to do

start_beelzebub.bat

│  │  ./logs/beelzebub.log (JSONL format)                    │   │

# Stop

stop_beelzebub.bat│  │  ./logs/attacks.jsonl (parsed attacks)                  │   │```

```

│  └──────────────────────────────────────────────────────────┘   │Before Reroute:

#### Method 3: Docker Compose

└────────────────────────────┬────────────────────────────────────┘Device (192.168.6.132) → Can access everything

```batch

cd e:\nos\Network_Security_poc\honey_pot                             │



# Start                   ┌─────────┴─────────┐After Reroute:

wsl docker compose -f docker-compose-beelzebub.yml up -d

                   │                   │Device (192.168.7.2) → TRAPPED in honeypot network

# Stop

wsl docker compose -f docker-compose-beelzebub.yml down                   ▼                   ▼                     → Can ONLY talk to honeypot

```

┌──────────────────────────┐ ┌────────────────────────┐                     → Cannot reach real systems

---

│   LOG VIEWER (Web UI)    │ │  SECURITY DASHBOARD    │                     → All actions logged

## Features

│   http://localhost:8888  │ │  http://localhost:5000 │```

### Simulated Services

│   • Browse attack logs   │ │  • Analytics           │

| Service | Port | Simulation Details |

|---------|------|-------------------|│   • Real-time viewing    │ │  • Attack visualization│**Key Point**: You must **manually reroute** suspicious IPs. Honeypot won't do it automatically.

| **SSH** | 2222 | Fake Linux shell with root access |

| **HTTP Admin** | 8080 | Fake phpMyAdmin database panel |└──────────────────────────┘ └────────────────────────┘

| **HTTP Alt** | 8081 | Fake web server |

| **MySQL** | 3306 | Database server (Banner: 8.0.29) |```---

| **PostgreSQL** | 5432 | Database server (Banner: 9.6.0) |

| **Log Viewer** | 8888 | Real-time log web interface |



### Data Capture---## 🚀 Quick Start



**Logged Information**:

- All SSH commands entered by attackers

- HTTP requests (URLs, methods, headers, body)## 🔄 How It Works### Method 1: Dashboard Control (Recommended)

- Login attempts (usernames and passwords)

- Connection metadata (IP addresses, timestamps, protocols)

- Attack patterns and tool signatures

### Attack Flow Diagram**Start the honeypot:**

**Intelligence Features**:

- AI-powered responses (optional GPT-4 integration)

- Automatic pattern analysis

- Threat scoring (High/Medium/Low)```1. **Open Dashboard**: `http://localhost:5000`

- Attack rate statistics

- Protocol distribution analysis┌─────────────┐2. **Navigate**: Click "🍯 Honeypot" in sidebar

- Export capabilities (JSON format)

│  Attacker   │3. **Start**: Click "▶️ Start Honeypot" button

---

│  Scanning   │4. **Monitor**: View stats, logs, and interactions in real-time

## Testing & Monitoring

│  Network    │

### Test SSH Honeypot

└──────┬──────┘**Stop the honeypot:**

```bash

# Connect       │

ssh root@localhost -p 2222

       │ 1. Port Scan discovers open ports1. Go to Honeypot page

# Weak passwords that will work:

# - root       │    (SSH:2222, HTTP:8080, etc.)2. Click "⏹️ Stop Honeypot" button

# - admin

# - password       │

# - 123456

       ▼### Method 2: Batch Scripts

# Once connected, try commands:

ls┌─────────────────────────────┐

pwd

whoami│  Attacker Connects to Port  │```batch

cat .env          # Shows fake database credentials

docker ps         # Shows fake containers│  (e.g., SSH on port 2222)   │# Start

netstat -tuln     # Shows fake network connections

```└──────────┬──────────────────┘cd e:\nos\Network_Security_poc\honey_pot



**Attacker View**:           │start_beelzebub.bat

```bash

root@prod-db-server-03:~$ ls           │ 2. Honeypot accepts connection

Documents  Images  .ssh  .docker  mysql_backups

           │    and presents fake service# Stop

root@prod-db-server-03:~$ cat .env

DB_HOST=localhost           │stop_beelzebub.bat

DB_USER=admin

DB_PASS=P@ssw0rd123!     # FAKE credentials           ▼```

API_KEY=sk-proj-fake12345

```┌─────────────────────────────────┐



### Test HTTP Honeypot│  Service Handler Activated      │### Method 3: Docker Compose



**Browser Access**:│  • SSH: Shows OpenSSH banner    │

- URL: `http://localhost:8080`

- Displays: Fake phpMyAdmin login page│  • HTTP: Shows phpMyAdmin login │```batch

- Features: Fake database management interface

- Content: Fake tables with "customer_data", "payment_info"│  • MySQL/PostgreSQL: Shows DB   │cd e:\nos\Network_Security_poc\honey_pot

- Logging: All interactions recorded

└──────────┬──────────────────────┘

**Command Line**:

```bash           │# Start

curl http://localhost:8080

curl http://localhost:8080/admin           │ 3. Attacker attempts authenticationwsl docker compose -f docker-compose-beelzebub.yml up -d

curl -X POST http://localhost:8080/login -d "user=admin&pass=test"

```           │    (username/password, exploits)



### Test Database Honeypots           │# Stop



```bash           ▼wsl docker compose -f docker-compose-beelzebub.yml down

# MySQL

mysql -h localhost -P 3306 -u root -p┌─────────────────────────────────┐```



# PostgreSQL│  Credentials Captured & Logged  │

psql -h localhost -p 5432 -U postgres

```│  • Username: admin              │---



### View Logs│  • Password: password123        │



**Dashboard (Recommended)**:│  • IP: 192.168.1.50             │## ✨ Features

1. Navigate to "Honeypot" page

2. Click service buttons (SSH, HTTP, etc.)│  • Timestamp: 2025-10-27T05:30  │

3. View formatted, searchable logs

└──────────┬──────────────────────┘### Fake Services (What Attackers See)

**Web Interface**:

- URL: `http://localhost:8888/logs`           │

- Features: Real-time updates, all services visible

           │ 4. Attacker granted fake access| Service | Port | Simulation |

**Raw Files**:

- Location: `honey_pot/logs/`           │|---------|------|------------|

- Files: `ssh-22.log`, `http-8080.log`, `attacks.jsonl`

           ▼| **SSH** | 2222 | Fake Linux shell with root access |

---

┌─────────────────────────────────┐| **HTTP Admin** | 8080 | Fake phpMyAdmin database panel |

## IP Rerouting

│  AI-Powered Interaction Begins  │| **HTTP Alt** | 8081 | Fake web server |

### When to Use Rerouting

│  Attacker: ls -la               │| **MySQL** | 3306 | Fake database server |

Reroute suspicious IPs when you need to:

- Monitor specific device behavior in detail│  GLM-4.5: Generates response    │| **PostgreSQL** | 5432 | Fake database server |

- Contain potential threats in isolated environment

- Gather detailed intelligence on specific attacker│  showing fake files/directories │| **Log Viewer** | 8888 | Real-time log web interface |

- Protect production systems from suspicious activity

└──────────┬──────────────────────┘

### Rerouting Process

           │### What Gets Logged

**Via Dashboard**:

           │ 5. Every command logged

1. Open Dashboard: `http://localhost:5000`

2. Navigate: Go to "Honeypot" page           │✅ **All SSH commands** - Every command attackers type  

3. Locate Section: "Reroute Device/Attacker to Honeypot"

4. Enter IP: Input address (e.g., `192.168.6.132`)           ▼✅ **HTTP requests** - URLs, methods, headers, body  

5. Execute: Click "Reroute to Honeypot"

6. Verify: Container moved to isolated network┌─────────────────────────────────┐✅ **Login attempts** - Usernames and passwords tried  

7. Monitor: View rerouted IPs in "Currently Rerouted IPs" section

│  Attacker Tries Commands        │✅ **Connection data** - IP addresses, timestamps, protocols  

**Rerouting Steps**:

│  • cat .env (shows fake creds)  │✅ **Attack patterns** - Tools used, attack sequences  

```

Step 1: Container on custom_net (192.168.6.0/24)│  • docker ps (shows containers) │

        Access: Dashboard, monitor, other devices

│  • cat id_rsa (shows fake key)  │### Intelligence Features

Step 2: Reroute executed

        Commands:└──────────┬──────────────────────┘

        - docker network disconnect custom_net container_name

        - docker network connect honeypot_net container_name           │- **🤖 AI Responses** (Optional): GPT-4 powered realistic interactions



Step 3: Container on honeypot_net (192.168.7.0/24)           │ 6. All data captured- **📊 Pattern Analysis**: Automatic detection of attack methods

        Access: Only honeypot (192.168.7.100)

        Isolated from: All other resources           │- **🎯 Threat Scoring**: High/Medium/Low threat classification

        Logging: All actions recorded

           ▼- **📈 Statistics**: Attack rates, top attackers, protocol distribution

Step 4: Analytics review

        Data: Commands tried, services accessed, data theft attempts┌─────────────────────────────────┐- **💾 Export**: Download analytics reports as JSON

```

│  Log Entry Created (JSONL)      │

### Remove Reroute

│  {                              │---

1. Go to "Currently Rerouted IPs" section

2. Click "Remove" next to the IP address│    "timestamp": "...",          │

3. Container returns to main network

│    "source_ip": "192.168.1.50", │## 🧪 Testing & Monitoring

---

│    "protocol": "ssh",           │

## Logs & Analytics

│    "command": "cat .env",       │### Test SSH Honeypot

### Analytics Dashboard

│    "response": "DB_PASS=..."    │

**Access**: Dashboard → "Analytics" page

│  }                              │```bash

**Available Metrics**:

└──────────┬──────────────────────┘# Connect

- **Summary Statistics**

  - Total attacks recorded           │ssh root@localhost -p 2222

  - Unique attacker count

  - Attack rate (attacks/minute)           │ 7. Security team analyzes

  - Most targeted service port

           │# Try weak passwords (all work!):

- **Top Attackers**

  - Ranked list by IP address           ▼# - root

  - Attack count and percentage

  - Threat level classification (High/Medium/Low)┌─────────────────────────────────┐# - admin



- **Protocol Distribution**│  Dashboard Shows Analytics      │# - password

  - Visual representation of attack types

  - HTTP, SSH, MySQL breakdown│  • Attack patterns              │# - 123456

  - Percentage distribution

│  • Common credentials tried     │

- **Most Targeted URLs**

  - Paths attackers attempted│  • Attacker IPs/geolocations    │# Once "logged in", try commands:

  - Common targets: /admin, /login, /api

│  • Exploit attempts             │ls

- **User Agents**

  - Tools used by attackers└─────────────────────────────────┘pwd

  - curl, Python scripts, browsers

```whoami

- **Detailed Profiles**

  - Per-attacker analysiscat .env          # Shows fake database credentials

  - Command history

  - Service targets### Service Interaction Detailsdocker ps         # Shows fake containers

  - URL access patterns

netstat -tuln     # Shows fake network connections

- **Raw Logs**

  - Recent attack records#### SSH Honeypot Flow```

  - Full request/response data

```

### Example Analytics Output

Attacker → ssh root@honeypot -p 2222**What attackers see:**

```

TOTAL ATTACKS: 31          ↓```bash

UNIQUE ATTACKERS: 2

ATTACK RATE: 40.10 attacks/minuteHoneypot → Password prompt appearsroot@prod-db-server-03:~$ ls



TOP ATTACKERS:          ↓Documents  Images  .ssh  .docker  mysql_backups

   #1 192.168.6.133: 20 attacks (64.5%) - High Threat

   #2 192.168.6.1: 11 attacks (35.5%) - Medium ThreatAttacker → Enters password (root, admin, 123456)



MOST TARGETED URLs:          ↓root@prod-db-server-03:~$ cat .env

   /admin: 10 requests

   /: 21 requestsHoneypot → ✅ LOGGED + Grants access to fake shellDB_HOST=localhost



TIMELINE:          ↓DB_USER=admin

   First Attack: 2025-10-23 11:37:22

   Last Attack: 2025-10-23 11:38:08Attacker → whoamiDB_PASS=P@ssw0rd123!     # FAKE! But looks real

   Duration: 46 seconds

```          ↓API_KEY=sk-proj-fake12345



### Log File FormatsGLM-4.5  → Analyzes command context```



**attacks.jsonl** (Structured):          → Generates: "root"

```json

{          ↓### Test HTTP Honeypot

  "timestamp": "2025-10-24T13:50:00.000Z",

  "protocol": "SSH",Honeypot → Returns realistic output

  "attacker_ip": "192.168.6.133",

  "port": 2222,          → ✅ LOGGED command & response**Browser**: Open `http://localhost:8080`

  "request": "cat /etc/passwd"

}          ↓

```

Attacker → cat /etc/passwdYou'll see:

**ssh-22.log** (Human-readable):

```          ↓- Fake phpMyAdmin login page

2025-10-24 13:50:00 - INFO - SSH connection from 192.168.6.133

2025-10-24 13:50:05 - INFO - Login attempt: root / password123GLM-4.5  → Generates fake passwd file- Fake database management interface

2025-10-24 13:50:06 - INFO - Command: ls -la

2025-10-24 13:50:08 - INFO - Command: cat .env          → Shows realistic user accounts- Fake tables with "customer_data", "payment_info"

```

          ↓- Everything looks real but logs all interactions

---

Honeypot → ✅ LOGGED entire interaction

## Configuration

```**Command line**:

### OpenAI Integration (Optional)

```bash

**Without OpenAI** (Default):

- Uses regex-based response patterns#### HTTP Honeypot Flowcurl http://localhost:8080

- Pre-configured realistic responses

- No API costs```curl http://localhost:8080/admin

- Functional and effective

Attacker → Opens http://honeypot:8080curl -X POST http://localhost:8080/login -d "user=admin&pass=test"

**With OpenAI** (Enhanced):

- GPT-4 powered intelligent responses          ↓```

- Contextual conversation capability

- Extremely realistic interactionsHoneypot → Displays fake phpMyAdmin login page

- Per-API-call costs apply

          ↓### Test Database Honeypots

**To Enable**:

Attacker → Enters credentials (admin/password)

1. Obtain API key: https://platform.openai.com/api-keys

2. Set environment variable:          ↓```bash

   ```batch

   set OPENAI_API_KEY=sk-proj-your-key-hereHoneypot → ✅ LOGGED credentials# MySQL

   ```

3. Restart honeypot          → Redirects to fake dashboardmysql -h localhost -P 3306 -u root -p



### Customize Services          ↓



**Edit SSH Responses**:Honeypot → Shows fake databases:# PostgreSQL

- File: `beelzebub-example/configurations/services/ssh-22-enhanced.yaml`

- Modify: Commands and response patterns          • production_dbpsql -h localhost -p 5432 -U postgres



**Edit HTTP Pages**:          • customer_data```

- File: `beelzebub-example/configurations/services/http-8080-admin.yaml`

- Customize: HTML content, endpoints          • payment_info



### Add New Services          ↓### View Logs



1. Create YAML file in `beelzebub-example/configurations/services/`Attacker → Clicks on databases (captured)

2. Define protocol, port, and handlers

3. Add port mapping to `docker-compose-beelzebub.yml`          ↓**Dashboard** (Easiest):

4. Restart honeypot

Honeypot → ✅ LOGGED all interactions1. Go to "🍯 Honeypot" page

**Example FTP Service**:

```yaml```2. Click service buttons (SSH, HTTP, etc.)

apiVersion: "v1"

protocol: "tcp"3. See formatted logs

address: ":21"

description: "FTP Honeypot"---



handlers:**Web Interface**:

  - pattern: "^USER (.+)$"

    response: "331 Password required for $1"## 🚀 Quick Start- URL: `http://localhost:8888/logs`

  - pattern: "^PASS (.+)$"

    response: "230 Login successful"- Real-time updates

```

### Prerequisites- All services visible

---

- **Windows 10/11** with WSL2

## Troubleshooting

- **Docker Desktop** installed and running**Raw Files**:

### Honeypot Won't Start

- **API Keys**: GLM-4.5 via Anthropic (optional, falls back to regex)- Location: `honey_pot/logs/`

**Diagnostics**:

```batch- Files: `ssh-22.log`, `http-8080.log`, `attacks.jsonl`

# Check if networks exist

wsl docker network ls | findstr "honeypot_net custom_net"### Installation Steps



# Create networks if missing---

wsl docker network create --subnet=192.168.7.0/24 honeypot_net

1. **Navigate to honeypot directory**

# Check container status

wsl docker ps -a | findstr beelzebub   ```bash## 🎯 IP Rerouting



# View container logs   cd e:\nos\Network_Security_poc\honey_pot

wsl docker logs beelzebub-honeypot

```   ```### When to Use



### No Attacks Showing



**Reason**: Honeypot operates in passive mode - it waits for attackers to connect.2. **Configure API keys** (Optional - for AI responses)Reroute suspicious IPs when you want to:



**Solutions**:   - 🔍 **Monitor specific device** behavior

1. Test manually (see Testing section)

2. Manually reroute a suspicious device IP   Edit `.env` file:- 🚨 **Contain potential threat** in isolated environment

3. Wait for real attackers to discover it

4. Verify logs exist: `dir honey_pot\logs`   ```env- 📊 **Gather detailed intelligence** on specific attacker



### Reroute Not Working   GLM_KEY=your_glm_key_here- 🛡️ **Protect real systems** from suspicious activity



**Diagnostics**:   ANTHROPIC_API_KEY=your_anthropic_key_here

```batch

# Check container exists   ANTHROPIC_BASE_URL=https://api.z.ai/api/anthropic### How to Reroute

wsl docker ps | findstr <container_name>

   ```

# Check network connectivity

wsl docker network inspect honeypot_net**Via Dashboard**:

wsl docker network inspect custom_net

   > **Note**: If you don't have API keys, the honeypot will use fallback regex-based responses (still functional!)

# View dashboard logs

# Look for: "Found container: ...", "Rerouting..."1. Open Dashboard: `http://localhost:5000`

```

3. **Start the honeypot**2. Go to "🍯 Honeypot" page

### Port Already in Use

   3. Scroll to "🔄 Reroute Device/Attacker to Honeypot"

**Identify Process**:

```batch   **Option A: Using Quick Start Script (Recommended)**4. Enter IP address (e.g., `192.168.6.132`)

# Check what's using ports

netstat -ano | findstr "2222 8080 8888"   ```bash5. Click "🎯 Reroute to Honeypot"



# Kill the process   start_beelzebub_simple.bat6. Container is moved to isolated network

taskkill /PID <process_id> /F

   ```7. View rerouted IPs in "Currently Rerouted IPs" section

# Or change ports in docker-compose-beelzebub.yml

```



### Logs Not Appearing   **Option B: Manual Docker Compose****What Happens**:



**Solutions**:   ```bash

- Wait 30 seconds after starting

- Try connecting to a service (SSH, HTTP)   wsl bash -c "docker compose -f docker-compose-simple.yml up -d"```

- Check `logs/` directory exists

- Verify container has write permissions   ```Step 1: Container is on custom_net (192.168.6.0/24)



---        Can access: dashboard, monitor, other devices



## File Structure4. **Verify services are running**



```   ```bashStep 2: You reroute the IP

honey_pot/

├── README.md                          # Documentation   wsl bash -c "docker ps | grep beelzebub"        Dashboard executes:

├── docker-compose-beelzebub.yml       # Deployment configuration

├── start_beelzebub.bat                # Quick start script   ```        - docker network disconnect custom_net container_name

├── stop_beelzebub.bat                 # Quick stop script

│        - docker network connect honeypot_net container_name

├── beelzebub-example/                 # Service configurations

│   └── configurations/   Expected output:

│       └── services/

│           ├── ssh-22-enhanced.yaml   # AI-powered SSH   ```Step 3: Container now on honeypot_net (192.168.7.0/24)

│           ├── http-8080-admin.yaml   # Fake admin panel

│           └── *.yaml                 # Additional services   beelzebub-honeypot    Up    0.0.0.0:2222->22/tcp, 0.0.0.0:8080->80/tcp, ...        Can ONLY access: honeypot (192.168.7.100)

│

├── logs/                              # Attack logs   beelzebub-log-viewer  Up    0.0.0.0:8888->80/tcp        Isolated from: everything else

│   ├── attacks.jsonl                  # Structured attack data

│   ├── ssh-22.log                     # SSH interactions   ```        All actions: logged in honeypot

│   ├── http-8080.log                  # HTTP requests

│   └── reroutes.log                   # Reroute history

│

└── beelzebub/                         # Official framework source---Step 4: Review Analytics page

    └── ...

```        See: what commands they tried



---## ⚙️ Configuration             what services they accessed



## Additional Resources             what data they attempted to steal



### Service Endpoints### File Structure```



| Service | Host Port | Container Port | Purpose |```

|---------|-----------|----------------|---------|

| SSH | 2222 | 22 | AI-powered shell honeypot |honey_pot/### Remove Reroute

| HTTP | 8080 | 80 | Fake phpMyAdmin interface |

| HTTPS | 8443 | 443 | Secure HTTP (future use) |├── docker-compose-simple.yml    # Main deployment configuration

| FTP | 2121 | 21 | FTP honeypot |

| Telnet | 2323 | 23 | Telnet honeypot |├── .env                         # API keys and environment variables1. Go to "Currently Rerouted IPs" section

| MySQL | 3306 | 3306 | Database honeypot |

| PostgreSQL | 5432 | 5432 | Database honeypot |├── .env.example                 # Template for environment setup2. Click "❌ Remove" next to the IP

| Log Viewer | 8888 | 80 | Web-based log browser |

├── start_beelzebub_simple.bat  # Quick start script3. Container returns to main network

### Useful Commands

├── stop_beelzebub_simple.bat   # Quick stop script

**View Running Containers**:

```bash├── beelzebub-example/---

wsl bash -c "docker ps"

```│   └── configurations/



**Monitor Resource Usage**:│       ├── beelzebub.yaml      # Core honeypot config## 📊 Logs & Analytics

```bash

wsl bash -c "docker stats beelzebub-honeypot"│       └── services/

```

│           ├── ssh-22-enhanced.yaml      # SSH service + AI config### Analytics Dashboard

**Execute Container Command**:

```bash│           ├── http-8080-admin.yaml      # HTTP/phpMyAdmin service

wsl bash -c "docker exec beelzebub-honeypot [command]"

```│           ├── tcp-3306.yaml             # MySQL service**Access**: Dashboard → "📈 Analytics" page



**View Container Configuration**:│           └── tcp-5432.yaml             # PostgreSQL service

```bash

wsl bash -c "docker inspect beelzebub-honeypot"└── logs/**What You See**:

```

    ├── beelzebub.log           # Main log file (JSONL)

**Export Logs for Analysis**:

```bash    └── attacks.jsonl           # Parsed attack data- **📈 Summary Stats**

copy logs\beelzebub.log E:\analysis\honeypot_logs_%date%.jsonl

``````  - Total attacks



---  - Unique attackers



## Security Warnings### Service Configuration  - Attack rate (attacks/minute)



1. **Network Isolation**: Honeypot runs in isolated Docker network. Ensure proper firewall rules before internet exposure.  - Most targeted port



2. **Resource Limits**: Monitor system resources - aggressive attacks can consume CPU/memory.#### SSH Service (`ssh-22-enhanced.yaml`)



3. **Legal Compliance**: Ensure deployment complies with organizational security policies and legal requirements.- **Protocol**: SSH- **🎯 Top Attackers**



4. **API Key Security**: Keep `.env` file secure. Never commit to version control.- **Port**: 22 (mapped to 2222 on host)  - Ranked list of IPs



5. **Regular Monitoring**: Review logs regularly to detect sophisticated attacks that might escape containment.- **AI Model**: GLM-4.5 via Anthropic  - Attack count and percentage



---- **Features**:  - Threat level (High/Medium/Low)



## Summary  - Realistic shell simulation



### Honeypot Capabilities  - Weak password honeypot (root, admin, password, 123456)- **🌐 Protocol Distribution**



**Automatic Functions**:  - Command logging and AI-generated responses  - Visual bars showing attack types

- Passively waits for attackers on network

- Logs all interactions automatically  - Fake system files (.env, id_rsa, docker configs)  - HTTP, SSH, MySQL breakdown

- Does NOT scan your network

- Does NOT reroute IPs automatically



**Manual Operations Required**:#### HTTP Service (`http-8080-admin.yaml`)- **📍 Most Targeted URLs**

- Start honeypot via dashboard or script

- Monitor Analytics page for attack data- **Protocol**: HTTP  - What paths attackers tried

- Manually reroute suspicious IPs when needed

- Review logs regularly for security insights- **Port**: 80 (mapped to 8080 on host)  - `/admin`, `/login`, `/api`, etc.



### Benefits- **Simulation**: Fake phpMyAdmin interface



- Safe environment for studying attacker behavior- **Features**:- **🖥️ User Agents**

- Rich data collection on attack patterns and tools

- Protection of real systems from malicious activity  - Login page with credential capture  - Tools attackers used

- Educational insights into threat actor tactics

  - Fake database dashboard  - curl, Python scripts, browsers

---

  - Realistic database structure display

## Support

- **🔍 Detailed Profiles**

For issues, questions, or contributions:

- Check logs: `docker logs beelzebub-honeypot`#### Database Services  - Per-attacker analysis

- Review configuration: `beelzebub-example/configurations/`

- Security dashboard: `http://localhost:5000`- **MySQL** (`tcp-3306.yaml`): Port 3306, Banner: "8.0.29"  - Commands they tried

- Official Beelzebub: https://github.com/mariocandela/beelzebub

- **PostgreSQL** (`tcp-5432.yaml`): Port 5432, Banner: "9.6.0"  - Services they targeted

---

  - URLs they accessed

**Version**: 1.0  

**Last Updated**: October 2025  ### Environment Variables

**Status**: Production Ready

- **📋 Raw Logs**

| Variable | Description | Required |  - Recent attack records

|----------|-------------|----------|  - Full request/response data

| `GLM_KEY` | GLM API key | Optional* |

| `ANTHROPIC_API_KEY` | Anthropic API key for GLM-4.5 | Optional* |### Example Analytics Output

| `ANTHROPIC_BASE_URL` | API endpoint URL | Optional* |

| `BZ_LOG_LEVEL` | Logging level (info, debug) | No |```

| `HONEYPOT_HOSTNAME` | Simulated hostname | No |📈 TOTAL ATTACKS: 31

👤 UNIQUE ATTACKERS: 2

\* Without API keys, honeypot uses fallback regex-based responses⚡ ATTACK RATE: 40.10 attacks/minute



---🎯 TOP ATTACKERS:

   #1 192.168.6.133: 20 attacks (64.5%) - 🔴 High Threat

## 🧪 Testing   #2 192.168.6.1: 11 attacks (35.5%) - 🟡 Medium Threat



### Test SSH Honeypot📍 MOST TARGETED URLs:

   /admin: 10 requests

1. **Connect via SSH**   /: 21 requests

   ```bash

   ssh root@localhost -p 2222⏰ TIMELINE:

   ```   First Attack: 2025-10-23 11:37:22

   Last Attack: 2025-10-23 11:38:08

2. **Try weak passwords**   Duration: 46 seconds

   - `root````

   - `admin`

   - `password`### Log File Formats

   - `123456`

   - `ubuntu`**attacks.jsonl** (Structured logs):

```json

3. **Test commands** (with AI enabled){

   ```bash  "timestamp": "2025-10-24T13:50:00.000Z",

   whoami              # Returns: root  "protocol": "SSH",

   pwd                 # Returns: /home/ubuntu  "attacker_ip": "192.168.6.133",

   ls -la              # Shows fake files/directories  "port": 2222,

   cat .env            # Shows fake database credentials  "request": "cat /etc/passwd"

   docker ps           # Shows fake containers}

   cat ~/.ssh/id_rsa   # Shows fake SSH private key```

   netstat -tuln       # Shows fake network connections

   ```**ssh-22.log** (Human-readable):

```

### Test HTTP Honeypot2025-10-24 13:50:00 - INFO - SSH connection from 192.168.6.133

2025-10-24 13:50:05 - INFO - Login attempt: root / password123

1. **Open browser**2025-10-24 13:50:06 - INFO - Command: ls -la

   ```2025-10-24 13:50:08 - INFO - Command: cat .env

   http://localhost:8080```

   ```

---

2. **Login with any credentials**

   - Username: `admin`## ⚙️ Configuration

   - Password: `password123`

### OpenAI Integration (Optional)

3. **Explore fake dashboard**

   - View fake databases**Without OpenAI** (Default):

   - Click on database tables- Uses regex patterns

   - All interactions are logged!- Pre-configured responses

- Still very realistic

### Test Database Honeypots- **FREE**



**MySQL:****With OpenAI** (Enhanced):

```bash- GPT-4 powered responses

mysql -h localhost -P 3306 -u root -p- Contextual conversations

# Enter any password - connection will be captured- Extremely realistic

```- Costs per API call



**PostgreSQL:****To Enable**:

```bash

psql -h localhost -p 5432 -U postgres1. Get API key: https://platform.openai.com/api-keys

# Connection attempt will be logged2. Set environment variable:

```   ```batch

   set OPENAI_API_KEY=sk-proj-your-key-here

### Monitor Logs in Real-Time   ```

3. Restart honeypot

**Option 1: Docker Logs**

```bash### Customize Services

wsl bash -c "docker logs -f beelzebub-honeypot"

```**Edit SSH responses**:

- File: `beelzebub-example/configurations/services/ssh-22-enhanced.yaml`

**Option 2: Log File**- Modify commands and responses

```bash

wsl bash -c "tail -f /mnt/e/nos/Network_Security_poc/honey_pot/logs/beelzebub.log"**Edit HTTP pages**:

```- File: `beelzebub-example/configurations/services/http-8080-admin.yaml`

- Customize HTML, endpoints

**Option 3: Web-based Log Viewer**

```### Add New Services

http://localhost:8888/logs/beelzebub.log

```1. Create YAML file in `beelzebub-example/configurations/services/`

2. Define protocol, port, handlers

---3. Add port mapping to `docker-compose-beelzebub.yml`

4. Restart honeypot

## 📊 Log Analysis

**Example FTP honeypot**:

### Log Format (JSONL)```yaml

apiVersion: "v1"

Each interaction is logged in JSON Lines format:protocol: "tcp"

address: ":21"

```jsondescription: "FTP Honeypot"

{

  "timestamp": "2025-10-27T05:30:15Z",handlers:

  "level": "info",  - pattern: "^USER (.+)$"

  "protocol": "ssh",    response: "331 Password required for $1"

  "source_ip": "192.168.1.50",  - pattern: "^PASS (.+)$"

  "source_port": 54321,    response: "230 Login successful"

  "destination_port": 22,```

  "username": "root",

  "password": "password123",---

  "command": "cat .env",

  "response": "DB_HOST=localhost\nDB_PASS=P@ssw0rd123!",## 🔧 Troubleshooting

  "session_id": "abc123"

}### Honeypot Won't Start

```

```batch

### Analyzing Attack Patterns# Check if networks exist

wsl docker network ls | findstr "honeypot_net custom_net"

**View all SSH login attempts:**

```bash# Create networks if missing

wsl bash -c "cat logs/beelzebub.log | grep 'password' | jq ."wsl docker network create --subnet=192.168.7.0/24 honeypot_net

```

# Check container status

**Count unique attacker IPs:**wsl docker ps -a | findstr beelzebub

```bash

wsl bash -c "cat logs/beelzebub.log | jq -r '.source_ip' | sort | uniq -c"# View logs

```wsl docker logs beelzebub-honeypot

```

**Most common passwords tried:**

```bash### No Attacks Showing

wsl bash -c "cat logs/beelzebub.log | jq -r '.password' | sort | uniq -c | sort -rn"

```**Reason**: Honeypot is **passive** - it waits for attackers.



### Integration with Security Dashboard**Solutions**:

1. ✅ Test it yourself (see Testing section)

Logs are automatically available to the security dashboard at `http://localhost:5000`:2. ✅ Manually reroute a device IP

3. ✅ Wait for real attackers to find it

- **Attack Analytics**: Visualizations of attack patterns4. ✅ Check logs exist: `dir honey_pot\logs`

- **Geolocation**: Map showing attacker origins

- **Threat Intelligence**: Common exploits and TTPs### Reroute Not Working

- **Timeline**: Attack sequence and progression

```batch

---# Check container exists

wsl docker ps | findstr <container_name>

## 🛑 Stopping the Honeypot

# Check networks

**Option 1: Quick Stop Script**wsl docker network inspect honeypot_net

```bashwsl docker network inspect custom_net

stop_beelzebub_simple.bat

```# View dashboard logs (shows reroute attempts)

# In terminal running dashboard, look for:

**Option 2: Docker Compose**# "📦 Found container: ..."

```bash# "🔄 Rerouting..."

wsl bash -c "docker compose -f docker-compose-simple.yml down"```

```

### Port Already in Use

**Remove all data and reset:**

```bash```batch

wsl bash -c "docker compose -f docker-compose-simple.yml down -v"# Check what's using ports

del logs\beelzebub.lognetstat -ano | findstr "2222 8080 8888"

```

# Kill the process

---taskkill /PID <process_id> /F



## 🔧 Troubleshooting# Or change ports in docker-compose-beelzebub.yml

```

### Issue: Containers won't start

### Logs Not Appearing

**Check Docker is running:**

```bash- Wait 30 seconds after starting

wsl bash -c "docker ps"- Try connecting to a service (SSH, HTTP)

```- Check `logs/` directory exists

- Verify container has write permissions

**Check logs for errors:**

```bash---

wsl bash -c "docker logs beelzebub-honeypot"

```## 📁 File Structure



**Common fix:**```

```bashhoney_pot/

wsl bash -c "docker compose -f docker-compose-simple.yml down"├── README.md                          # This file

wsl bash -c "docker compose -f docker-compose-simple.yml up -d"├── docker-compose-beelzebub.yml       # Main deployment config

```├── start_beelzebub.bat                # Quick start script

├── stop_beelzebub.bat                 # Quick stop script

### Issue: Port already in use│

├── beelzebub-example/                 # Service configurations

**Find what's using the port:**│   └── configurations/

```bash│       └── services/

netstat -ano | findstr :2222│           ├── ssh-22-enhanced.yaml   # AI-powered SSH

netstat -ano | findstr :8080│           ├── http-8080-admin.yaml   # Fake admin panel

```│           └── *.yaml                 # Other services

│

**Kill the process or change port in `docker-compose-simple.yml`:**├── logs/                              # Attack logs

```yaml│   ├── attacks.jsonl                  # Structured attack data

ports:│   ├── ssh-22.log                     # SSH interactions

  - "2223:22"  # Changed from 2222│   ├── http-8080.log                  # HTTP requests

```│   └── reroutes.log                   # Reroute history

│

### Issue: AI responses not working└── beelzebub/                         # Official Beelzebub source

    └── ...

**Verify API keys are set:**```

```bash

wsl bash -c "docker inspect beelzebub-honeypot | grep -A 3 ANTHROPIC"---

```

## 📚 Additional Resources

**Check API key in .env file:**

```bash- **Official Beelzebub**: https://github.com/mariocandela/beelzebub

type .env | findstr ANTHROPIC- **OpenAI API**: https://platform.openai.com/

```- **Dashboard**: http://localhost:5000

- **Log Viewer**: http://localhost:8888/logs

**Without API keys:** Honeypot automatically falls back to regex-based responses (still functional!)

---

### Issue: No logs appearing

## 🎓 Summary

**Check log file exists:**

```bash### What Honeypot Does

dir logs

```✅ **Passively waits** for attackers on network  

✅ **Logs everything** attackers try automatically  

**Check permissions:**❌ **Does NOT scan** your network  

```bash❌ **Does NOT reroute** IPs automatically  

wsl bash -c "ls -la /mnt/e/nos/Network_Security_poc/honey_pot/logs/"

```### You Must Do



**Restart with fresh logs:**✅ **Start honeypot** via dashboard or script  

```bash✅ **Monitor Analytics** page to see attacks  

del logs\beelzebub.log✅ **Manually reroute** suspicious IPs if needed  

wsl bash -c "docker compose -f docker-compose-simple.yml restart"✅ **Review logs** regularly for insights  

```

### Result

### Issue: Can't access log viewer

🛡️ Safe environment to study attackers  

**Check log viewer container:**📊 Rich data on attack patterns  

```bash🎯 Protects real systems from harm  

wsl bash -c "docker ps | grep log-viewer"🧠 Learn attacker tactics and tools  

```

---

**Check browser URL:**

```**🍯 Happy Honeypotting!**

http://localhost:8888/logs/beelzebub.log
```

**Restart log viewer:**
```bash
wsl bash -c "docker restart beelzebub-log-viewer"
```

---

## 📚 Additional Resources

### Service Endpoints

| Service | Host Port | Container Port | Purpose |
|---------|-----------|----------------|---------|
| SSH | 2222 | 22 | AI-powered shell honeypot |
| HTTP | 8080 | 80 | Fake phpMyAdmin interface |
| HTTPS | 8443 | 443 | Secure HTTP (future use) |
| FTP | 2121 | 21 | FTP honeypot |
| Telnet | 2323 | 23 | Telnet honeypot |
| MySQL | 3306 | 3306 | Database honeypot |
| PostgreSQL | 5432 | 5432 | Database honeypot |
| Log Viewer | 8888 | 80 | Web-based log browser |

### Useful Commands

**View running containers:**
```bash
wsl bash -c "docker ps"
```

**View container resource usage:**
```bash
wsl bash -c "docker stats beelzebub-honeypot"
```

**Execute command in container:**
```bash
wsl bash -c "docker exec beelzebub-honeypot [command]"
```

**View container configuration:**
```bash
wsl bash -c "docker inspect beelzebub-honeypot"
```

**Export logs for analysis:**
```bash
copy logs\beelzebub.log E:\analysis\honeypot_logs_%date%.jsonl
```

---

## ⚠️ Security Warnings

1. **Network Isolation**: The honeypot runs in an isolated Docker network, but ensure it's not directly exposed to the internet without proper firewall rules.

2. **Resource Limits**: Monitor system resources - aggressive attacks can consume CPU/memory.

3. **Legal Considerations**: Ensure honeypot deployment complies with your organization's security policies and legal requirements.

4. **API Key Security**: Keep your `.env` file secure and never commit it to version control.

5. **Regular Monitoring**: Review logs regularly to detect sophisticated attacks that might escape the honeypot.

---

## 📞 Support

For issues, questions, or contributions:
- Check logs: `docker logs beelzebub-honeypot`
- Review configuration: `beelzebub-example/configurations/`
- Security dashboard: `http://localhost:5000`

---

**Happy Hunting! 🍯🐝**



Beelzebub Honeypot - Simple Summary
What Is It?
A fake vulnerable server that tricks hackers into attacking it instead of your real systems. It records everything they do.
How It Works
The honeypot is PASSIVE:

Sits on your network with IP 192.168.6.200
Opens fake services (SSH, databases, web pages)
Waits for attackers to find it
Logs everything when they connect
You review what they tried in the dashboard

Key Point: It does NOT scan your network. Attackers must come to it.
What Attackers See
ServiceWhat It Looks LikeSSH (Port 2222)Fake Linux server with root accessHTTP (Port 8080)Fake phpMyAdmin admin panelMySQL (Port 3306)Fake database serverPostgreSQL (Port 5432)Fake database server
Everything looks real but is completely fake and isolated.
What Gets Logged
✅ Every command attackers type
✅ Passwords they try
✅ Their IP addresses
✅ What tools they use
✅ What files they try to access
Quick Start
Easiest way:

Open dashboard: http://localhost:5000
Click "🍯 Honeypot" in sidebar
Click "▶️ Start Honeypot"
Done! It's now waiting for attacks

View attacks:

Dashboard → "📈 Analytics" page
See who attacked, when, and what they tried

Optional: Trap Specific Devices
If you spot a suspicious IP (like 192.168.6.132):

Go to Honeypot page
Enter the IP address
Click "🎯 Reroute"
That device is now trapped and can only talk to the honeypot
Everything it does is logged

The Point
Instead of attackers hitting your real systems, they hit the honeypot:

🛡️ Your real systems stay safe
📊 You learn what attackers are trying
🎯 You can study their methods
🚨 You get early warning of threats

It's like a security camera, but for hackers.