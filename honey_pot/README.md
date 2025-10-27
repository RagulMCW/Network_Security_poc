# 🍯 Beelzebub Honeypot - AI-Powered Network Security Trap# 🍯 Beelzebub AI Honeypot



A sophisticated honeypot system powered by GLM-4.5 AI to detect, analyze, and log attacker activities in your network.> **AI-Powered Deception System for Network Security Research**



## 📋 Table of ContentsAn intelligent honeypot that simulates vulnerable production servers to attract, trap, and study attackers. Built on the official [Beelzebub framework](https://github.com/mariocandela/beelzebub) with full dashboard integration.

- [Overview](#overview)

- [Architecture](#architecture)---

- [How It Works](#how-it-works)

- [Quick Start](#quick-start)## 📋 Table of Contents

- [Configuration](#configuration)

- [Testing](#testing)- [What Is This?](#-what-is-this)

- [Log Analysis](#log-analysis)- [How It Works](#-how-it-works)

- [Troubleshooting](#troubleshooting)- [Quick Start](#-quick-start)

- [Features](#-features)

---- [Testing & Monitoring](#-testing--monitoring)

- [IP Rerouting](#-ip-rerouting)

## 🎯 Overview- [Logs & Analytics](#-logs--analytics)

- [Configuration](#-configuration)

**Beelzebub** is an advanced honeypot framework that simulates vulnerable services to attract and study attacker behavior. This deployment uses:- [Troubleshooting](#-troubleshooting)



- **AI Model**: GLM-4.5 via Anthropic API for realistic shell interactions---

- **Protocols**: SSH, HTTP, MySQL, PostgreSQL, FTP, Telnet

- **Logging**: Comprehensive attack logging with JSONL format## 🎯 What Is This?

- **Deployment**: Docker-based for easy setup and isolation

Beelzebub is a **deception honeypot** that pretends to be a vulnerable server to:

### Key Features

✅ AI-powered realistic responses to attacker commands  - ✅ **Attract attackers** - Looks like an easy target with open services

✅ Multiple protocol support (SSH, HTTP, Database, FTP, Telnet)  - ✅ **Trap & isolate** - Contains malicious activity in a safe environment

✅ Automatic credential capture and logging  - ✅ **Log everything** - Records all attacker actions and commands

✅ Web-based log viewer  - ✅ **Learn patterns** - Analyze attack methods, tools, and behavior

✅ Isolated Docker network for security  - ✅ **Protect real systems** - Diverts attention from actual infrastructure

✅ Integration with security dashboard  

### Current Status

---

- ✅ **Fully Operational** - Integrated with dashboard control panel

## 🏗️ Architecture- ✅ **AI-Powered** - Intelligent responses (GPT-4 optional, fallback included)

- ✅ **Multi-Protocol** - SSH, HTTP, MySQL, PostgreSQL support

### System Architecture Flowchart- ✅ **Production-Ready** - Professional logging and monitoring



```---

┌─────────────────────────────────────────────────────────────────┐

│                        INTERNET / ATTACKERS                      │## 🧠 How It Works

└────────────────────────────┬────────────────────────────────────┘

                             │### Passive Monitoring (Automatic)

                             ▼

┌─────────────────────────────────────────────────────────────────┐The honeypot **does NOT scan your network**. Instead, it:

│                    EXPOSED HONEYPOT PORTS                        │

│  SSH:2222 │ HTTP:8080 │ MySQL:3306 │ PostgreSQL:5432 │ FTP:2121 │1. **Sits on network** with visible IP `192.168.6.200`

└────────────────────────────┬────────────────────────────────────┘2. **Opens fake services** (SSH, HTTP, databases)

                             │3. **Waits for attackers** to discover and connect

                             ▼4. **Logs automatically** when someone attacks

┌─────────────────────────────────────────────────────────────────┐5. **You review logs** in Analytics dashboard

│                  BEELZEBUB HONEYPOT CONTAINER                    │

│  ┌──────────────────────────────────────────────────────────┐   │```

│  │  Protocol Handlers                                       │   │┌─────────────────────────────┐

│  │  ├─ SSH Service (AI-Powered with GLM-4.5)               │   ││     Beelzebub Honeypot      │

│  │  ├─ HTTP Service (Fake phpMyAdmin)                      │   ││   IP: 192.168.6.200         │

│  │  ├─ MySQL Service (Banner: 8.0.29)                      │   ││                              │

│  │  ├─ PostgreSQL Service (Banner: 9.6.0)                  │   ││   Services:                  │

│  │  ├─ FTP Service                                          │   ││   • SSH (Port 2222)          │

│  │  └─ Telnet Service                                       │   ││   • HTTP (Port 8080)         │

│  └──────────────────────────────────────────────────────────┘   ││   • MySQL (Port 3306)        │

│                             │                                    ││   • PostgreSQL (Port 5432)   │

│                             ▼                                    ││                              │

│  ┌──────────────────────────────────────────────────────────┐   ││   Status: WAITING...         │

│  │  AI Response Engine (GLM-4.5)                           │   │└──────────▲──────────────────┘

│  │  • Analyzes attacker commands                           │   │           │

│  │  • Generates realistic shell responses                  │   │           │ Attacker finds it

│  │  • Simulates compromised server behavior                │   │           │ and tries to hack

│  └──────────────────────────────────────────────────────────┘   │           │

│                             │                                    │      👤 Attacker

│                             ▼                                    │```

│  ┌──────────────────────────────────────────────────────────┐   │

│  │  Logger                                                  │   │**Key Point**: Attackers must **come to the honeypot**. It doesn't search for them.

│  │  • Captures all interactions                            │   │

│  │  • Records credentials, commands, payloads              │   │### Active Rerouting (Manual Control)

│  │  • Outputs to /logs/beelzebub.log                       │   │

│  └──────────────────────────────────────────────────────────┘   │You can **force suspicious devices** into the honeypot:

└────────────────────────────┬────────────────────────────────────┘

                             │1. **Identify suspicious IP** (e.g., `192.168.6.132`)

                             ▼2. **Reroute via dashboard**: Honeypot page → Enter IP → Click "🎯 Reroute"

┌─────────────────────────────────────────────────────────────────┐3. **Device gets isolated** - Moved to `honeypot_net` (192.168.7.0/24)

│                      PERSISTENT STORAGE                          │4. **All traffic logged** - Everything the device does is recorded

│  ┌──────────────────────────────────────────────────────────┐   │5. **Analyze behavior** - Review what it tried to do

│  │  ./logs/beelzebub.log (JSONL format)                    │   │

│  │  ./logs/attacks.jsonl (parsed attacks)                  │   │```

│  └──────────────────────────────────────────────────────────┘   │Before Reroute:

└────────────────────────────┬────────────────────────────────────┘Device (192.168.6.132) → Can access everything

                             │

                   ┌─────────┴─────────┐After Reroute:

                   │                   │Device (192.168.7.2) → TRAPPED in honeypot network

                   ▼                   ▼                     → Can ONLY talk to honeypot

┌──────────────────────────┐ ┌────────────────────────┐                     → Cannot reach real systems

│   LOG VIEWER (Web UI)    │ │  SECURITY DASHBOARD    │                     → All actions logged

│   http://localhost:8888  │ │  http://localhost:5000 │```

│   • Browse attack logs   │ │  • Analytics           │

│   • Real-time viewing    │ │  • Attack visualization│**Key Point**: You must **manually reroute** suspicious IPs. Honeypot won't do it automatically.

└──────────────────────────┘ └────────────────────────┘

```---



---## 🚀 Quick Start



## 🔄 How It Works### Method 1: Dashboard Control (Recommended)



### Attack Flow Diagram**Start the honeypot:**



```1. **Open Dashboard**: `http://localhost:5000`

┌─────────────┐2. **Navigate**: Click "🍯 Honeypot" in sidebar

│  Attacker   │3. **Start**: Click "▶️ Start Honeypot" button

│  Scanning   │4. **Monitor**: View stats, logs, and interactions in real-time

│  Network    │

└──────┬──────┘**Stop the honeypot:**

       │

       │ 1. Port Scan discovers open ports1. Go to Honeypot page

       │    (SSH:2222, HTTP:8080, etc.)2. Click "⏹️ Stop Honeypot" button

       │

       ▼### Method 2: Batch Scripts

┌─────────────────────────────┐

│  Attacker Connects to Port  │```batch

│  (e.g., SSH on port 2222)   │# Start

└──────────┬──────────────────┘cd e:\nos\Network_Security_poc\honey_pot

           │start_beelzebub.bat

           │ 2. Honeypot accepts connection

           │    and presents fake service# Stop

           │stop_beelzebub.bat

           ▼```

┌─────────────────────────────────┐

│  Service Handler Activated      │### Method 3: Docker Compose

│  • SSH: Shows OpenSSH banner    │

│  • HTTP: Shows phpMyAdmin login │```batch

│  • MySQL/PostgreSQL: Shows DB   │cd e:\nos\Network_Security_poc\honey_pot

└──────────┬──────────────────────┘

           │# Start

           │ 3. Attacker attempts authenticationwsl docker compose -f docker-compose-beelzebub.yml up -d

           │    (username/password, exploits)

           │# Stop

           ▼wsl docker compose -f docker-compose-beelzebub.yml down

┌─────────────────────────────────┐```

│  Credentials Captured & Logged  │

│  • Username: admin              │---

│  • Password: password123        │

│  • IP: 192.168.1.50             │## ✨ Features

│  • Timestamp: 2025-10-27T05:30  │

└──────────┬──────────────────────┘### Fake Services (What Attackers See)

           │

           │ 4. Attacker granted fake access| Service | Port | Simulation |

           │|---------|------|------------|

           ▼| **SSH** | 2222 | Fake Linux shell with root access |

┌─────────────────────────────────┐| **HTTP Admin** | 8080 | Fake phpMyAdmin database panel |

│  AI-Powered Interaction Begins  │| **HTTP Alt** | 8081 | Fake web server |

│  Attacker: ls -la               │| **MySQL** | 3306 | Fake database server |

│  GLM-4.5: Generates response    │| **PostgreSQL** | 5432 | Fake database server |

│  showing fake files/directories │| **Log Viewer** | 8888 | Real-time log web interface |

└──────────┬──────────────────────┘

           │### What Gets Logged

           │ 5. Every command logged

           │✅ **All SSH commands** - Every command attackers type  

           ▼✅ **HTTP requests** - URLs, methods, headers, body  

┌─────────────────────────────────┐✅ **Login attempts** - Usernames and passwords tried  

│  Attacker Tries Commands        │✅ **Connection data** - IP addresses, timestamps, protocols  

│  • cat .env (shows fake creds)  │✅ **Attack patterns** - Tools used, attack sequences  

│  • docker ps (shows containers) │

│  • cat id_rsa (shows fake key)  │### Intelligence Features

└──────────┬──────────────────────┘

           │- **🤖 AI Responses** (Optional): GPT-4 powered realistic interactions

           │ 6. All data captured- **📊 Pattern Analysis**: Automatic detection of attack methods

           │- **🎯 Threat Scoring**: High/Medium/Low threat classification

           ▼- **📈 Statistics**: Attack rates, top attackers, protocol distribution

┌─────────────────────────────────┐- **💾 Export**: Download analytics reports as JSON

│  Log Entry Created (JSONL)      │

│  {                              │---

│    "timestamp": "...",          │

│    "source_ip": "192.168.1.50", │## 🧪 Testing & Monitoring

│    "protocol": "ssh",           │

│    "command": "cat .env",       │### Test SSH Honeypot

│    "response": "DB_PASS=..."    │

│  }                              │```bash

└──────────┬──────────────────────┘# Connect

           │ssh root@localhost -p 2222

           │ 7. Security team analyzes

           │# Try weak passwords (all work!):

           ▼# - root

┌─────────────────────────────────┐# - admin

│  Dashboard Shows Analytics      │# - password

│  • Attack patterns              │# - 123456

│  • Common credentials tried     │

│  • Attacker IPs/geolocations    │# Once "logged in", try commands:

│  • Exploit attempts             │ls

└─────────────────────────────────┘pwd

```whoami

cat .env          # Shows fake database credentials

### Service Interaction Detailsdocker ps         # Shows fake containers

netstat -tuln     # Shows fake network connections

#### SSH Honeypot Flow```

```

Attacker → ssh root@honeypot -p 2222**What attackers see:**

          ↓```bash

Honeypot → Password prompt appearsroot@prod-db-server-03:~$ ls

          ↓Documents  Images  .ssh  .docker  mysql_backups

Attacker → Enters password (root, admin, 123456)

          ↓root@prod-db-server-03:~$ cat .env

Honeypot → ✅ LOGGED + Grants access to fake shellDB_HOST=localhost

          ↓DB_USER=admin

Attacker → whoamiDB_PASS=P@ssw0rd123!     # FAKE! But looks real

          ↓API_KEY=sk-proj-fake12345

GLM-4.5  → Analyzes command context```

          → Generates: "root"

          ↓### Test HTTP Honeypot

Honeypot → Returns realistic output

          → ✅ LOGGED command & response**Browser**: Open `http://localhost:8080`

          ↓

Attacker → cat /etc/passwdYou'll see:

          ↓- Fake phpMyAdmin login page

GLM-4.5  → Generates fake passwd file- Fake database management interface

          → Shows realistic user accounts- Fake tables with "customer_data", "payment_info"

          ↓- Everything looks real but logs all interactions

Honeypot → ✅ LOGGED entire interaction

```**Command line**:

```bash

#### HTTP Honeypot Flowcurl http://localhost:8080

```curl http://localhost:8080/admin

Attacker → Opens http://honeypot:8080curl -X POST http://localhost:8080/login -d "user=admin&pass=test"

          ↓```

Honeypot → Displays fake phpMyAdmin login page

          ↓### Test Database Honeypots

Attacker → Enters credentials (admin/password)

          ↓```bash

Honeypot → ✅ LOGGED credentials# MySQL

          → Redirects to fake dashboardmysql -h localhost -P 3306 -u root -p

          ↓

Honeypot → Shows fake databases:# PostgreSQL

          • production_dbpsql -h localhost -p 5432 -U postgres

          • customer_data```

          • payment_info

          ↓### View Logs

Attacker → Clicks on databases (captured)

          ↓**Dashboard** (Easiest):

Honeypot → ✅ LOGGED all interactions1. Go to "🍯 Honeypot" page

```2. Click service buttons (SSH, HTTP, etc.)

3. See formatted logs

---

**Web Interface**:

## 🚀 Quick Start- URL: `http://localhost:8888/logs`

- Real-time updates

### Prerequisites- All services visible

- **Windows 10/11** with WSL2

- **Docker Desktop** installed and running**Raw Files**:

- **API Keys**: GLM-4.5 via Anthropic (optional, falls back to regex)- Location: `honey_pot/logs/`

- Files: `ssh-22.log`, `http-8080.log`, `attacks.jsonl`

### Installation Steps

---

1. **Navigate to honeypot directory**

   ```bash## 🎯 IP Rerouting

   cd e:\nos\Network_Security_poc\honey_pot

   ```### When to Use



2. **Configure API keys** (Optional - for AI responses)Reroute suspicious IPs when you want to:

   - 🔍 **Monitor specific device** behavior

   Edit `.env` file:- 🚨 **Contain potential threat** in isolated environment

   ```env- 📊 **Gather detailed intelligence** on specific attacker

   GLM_KEY=your_glm_key_here- 🛡️ **Protect real systems** from suspicious activity

   ANTHROPIC_API_KEY=your_anthropic_key_here

   ANTHROPIC_BASE_URL=https://api.z.ai/api/anthropic### How to Reroute

   ```

**Via Dashboard**:

   > **Note**: If you don't have API keys, the honeypot will use fallback regex-based responses (still functional!)

1. Open Dashboard: `http://localhost:5000`

3. **Start the honeypot**2. Go to "🍯 Honeypot" page

   3. Scroll to "🔄 Reroute Device/Attacker to Honeypot"

   **Option A: Using Quick Start Script (Recommended)**4. Enter IP address (e.g., `192.168.6.132`)

   ```bash5. Click "🎯 Reroute to Honeypot"

   start_beelzebub_simple.bat6. Container is moved to isolated network

   ```7. View rerouted IPs in "Currently Rerouted IPs" section



   **Option B: Manual Docker Compose****What Happens**:

   ```bash

   wsl bash -c "docker compose -f docker-compose-simple.yml up -d"```

   ```Step 1: Container is on custom_net (192.168.6.0/24)

        Can access: dashboard, monitor, other devices

4. **Verify services are running**

   ```bashStep 2: You reroute the IP

   wsl bash -c "docker ps | grep beelzebub"        Dashboard executes:

   ```        - docker network disconnect custom_net container_name

        - docker network connect honeypot_net container_name

   Expected output:

   ```Step 3: Container now on honeypot_net (192.168.7.0/24)

   beelzebub-honeypot    Up    0.0.0.0:2222->22/tcp, 0.0.0.0:8080->80/tcp, ...        Can ONLY access: honeypot (192.168.7.100)

   beelzebub-log-viewer  Up    0.0.0.0:8888->80/tcp        Isolated from: everything else

   ```        All actions: logged in honeypot



---Step 4: Review Analytics page

        See: what commands they tried

## ⚙️ Configuration             what services they accessed

             what data they attempted to steal

### File Structure```

```

honey_pot/### Remove Reroute

├── docker-compose-simple.yml    # Main deployment configuration

├── .env                         # API keys and environment variables1. Go to "Currently Rerouted IPs" section

├── .env.example                 # Template for environment setup2. Click "❌ Remove" next to the IP

├── start_beelzebub_simple.bat  # Quick start script3. Container returns to main network

├── stop_beelzebub_simple.bat   # Quick stop script

├── beelzebub-example/---

│   └── configurations/

│       ├── beelzebub.yaml      # Core honeypot config## 📊 Logs & Analytics

│       └── services/

│           ├── ssh-22-enhanced.yaml      # SSH service + AI config### Analytics Dashboard

│           ├── http-8080-admin.yaml      # HTTP/phpMyAdmin service

│           ├── tcp-3306.yaml             # MySQL service**Access**: Dashboard → "📈 Analytics" page

│           └── tcp-5432.yaml             # PostgreSQL service

└── logs/**What You See**:

    ├── beelzebub.log           # Main log file (JSONL)

    └── attacks.jsonl           # Parsed attack data- **📈 Summary Stats**

```  - Total attacks

  - Unique attackers

### Service Configuration  - Attack rate (attacks/minute)

  - Most targeted port

#### SSH Service (`ssh-22-enhanced.yaml`)

- **Protocol**: SSH- **🎯 Top Attackers**

- **Port**: 22 (mapped to 2222 on host)  - Ranked list of IPs

- **AI Model**: GLM-4.5 via Anthropic  - Attack count and percentage

- **Features**:  - Threat level (High/Medium/Low)

  - Realistic shell simulation

  - Weak password honeypot (root, admin, password, 123456)- **🌐 Protocol Distribution**

  - Command logging and AI-generated responses  - Visual bars showing attack types

  - Fake system files (.env, id_rsa, docker configs)  - HTTP, SSH, MySQL breakdown



#### HTTP Service (`http-8080-admin.yaml`)- **📍 Most Targeted URLs**

- **Protocol**: HTTP  - What paths attackers tried

- **Port**: 80 (mapped to 8080 on host)  - `/admin`, `/login`, `/api`, etc.

- **Simulation**: Fake phpMyAdmin interface

- **Features**:- **🖥️ User Agents**

  - Login page with credential capture  - Tools attackers used

  - Fake database dashboard  - curl, Python scripts, browsers

  - Realistic database structure display

- **🔍 Detailed Profiles**

#### Database Services  - Per-attacker analysis

- **MySQL** (`tcp-3306.yaml`): Port 3306, Banner: "8.0.29"  - Commands they tried

- **PostgreSQL** (`tcp-5432.yaml`): Port 5432, Banner: "9.6.0"  - Services they targeted

  - URLs they accessed

### Environment Variables

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
