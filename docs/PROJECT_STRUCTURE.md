# Project Structure

## 📁 Directory Layout

```
Network_Security_poc/
│
├── 📊 dashboard/                      # Web Dashboard & Control Center
│   ├── app.py                         # Flask application (main)
│   ├── requirements.txt               # Python dependencies
│   ├── start_dashboard.bat            # Start dashboard
│   ├── restart_dashboard.bat          # Restart dashboard
│   ├── static/                        # Static assets
│   │   └── dashboard.js               # Frontend JavaScript
│   └── templates/                     # HTML templates
│       ├── dashboard.html             # Main dashboard UI
│       └── control_panel.html         # Control panel UI
│
├── 🎯 attackers/                      # Attack Simulation Tools
│   ├── dos_attacker/                  # DOS/SYN Flood Attacker
│   │   ├── docker-compose.yml         # Docker configuration
│   │   ├── Dockerfile                 # Container build
│   │   ├── hping3_sender.sh           # Attack script
│   │   ├── curl_sender.sh             # HTTP flood script
│   │   ├── cleanup_iptables.sh        # Cleanup script
│   │   ├── stop_attacker.bat          # Stop script
│   │   └── README.md                  # Documentation
│   │
│   └── ssh_attacker/                  # SSH Brute Force Attacker
│       ├── docker-compose.yml         # Docker configuration
│       ├── Dockerfile                 # Container build
│       ├── ssh_bruteforce.sh          # Attack script
│       ├── START_SSH_ATTACKER.bat     # Start script
│       ├── STOP_SSH_ATTACKER.bat      # Stop script
│       ├── VIEW_LOGS.bat              # Log viewer
│       ├── wordlists/                 # Credential lists
│       │   ├── usernames.txt          # Username wordlist
│       │   └── passwords.txt          # Password wordlist
│       ├── logs/                      # Attack logs (gitignored)
│       └── README.md                  # Documentation
│
├── 🍯 honey_pot/                      # Beelzebub Honeypot
│   ├── docker-compose-simple.yml      # Honeypot + PCAP capture
│   ├── .env.example                   # Environment template
│   ├── start_beelzebub_simple.bat     # Start honeypot
│   ├── stop_beelzebub_simple.bat      # Stop honeypot
│   ├── view_live_logs.bat             # Live log viewer
│   ├── start_honeypot_capture.bat     # Start PCAP capture
│   ├── stop_honeypot_capture.bat      # Stop PCAP capture
│   ├── start_network_logger.bat       # Start network logger
│   ├── pcap_captures/                 # Packet captures (gitignored)
│   ├── logs/                          # Honeypot logs
│   │   ├── beelzebub.log              # Main honeypot log
│   │   ├── reroutes.log               # Traffic reroute log
│   │   └── attacks.jsonl              # Attack JSON logs
│   ├── beelzebub-example/             # Example configurations
│   │   └── configurations/            # Config templates
│   └── README.md                      # Documentation
│
├── 🌐 network/                        # Network Monitoring
│   ├── docker-compose.yml             # Network monitor service
│   ├── wsl-manager.sh                 # Service manager
│   ├── start_monitor.bat              # Start monitor
│   ├── stop_monitor.bat               # Stop monitor
│   ├── start_capture.bat              # Start packet capture
│   ├── stop_capture.bat               # Stop packet capture
│   ├── cleanup_captures.bat           # Clean old PCAPs
│   ├── cleanup_old_pcaps.sh           # PCAP cleanup script
│   ├── requirements.txt               # Python dependencies
│   ├── docker/                        # Docker build files
│   │   └── Dockerfile                 # Network monitor image
│   ├── scripts/                       # Utility scripts
│   │   ├── start_services.sh          # Service startup
│   │   ├── stop_capture.sh            # Stop capture
│   │   ├── capture_on_host.sh         # Host-based capture
│   │   └── analyze_capture.py         # PCAP analyzer
│   ├── src/                           # Source code
│   │   ├── app/                       # Flask application
│   │   │   └── server.py              # API server
│   │   └── config/                    # Configuration
│   │       └── haproxy.cfg            # HAProxy config
│   ├── captures/                      # PCAP files (gitignored)
│   ├── docs/                          # Documentation
│   │   ├── API.md                     # API documentation
│   │   ├── GUIDE.md                   # Usage guide
│   │   ├── HOW_IT_WORKS.md            # Architecture
│   │   └── TESTING.md                 # Testing guide
│   ├── tests/                         # Unit tests
│   └── README.md                      # Documentation
│
├── 🤖 mcp_agent/                      # AI Threat Detection Agent
│   ├── start_agent.bat                # Start MCP agent
│   ├── run_agent.py                   # Agent runner
│   ├── query_agent.py                 # Query interface
│   ├── install_dependencies.bat       # Dependency installer
│   ├── client/                        # MCP client
│   │   └── agent.py                   # Agent logic
│   ├── server/                        # MCP server
│   │   └── server.py                  # Server logic
│   ├── config/                        # Configuration
│   │   └── .env.example               # Config template
│   ├── STATUS.md                      # Agent status
│   └── README.md                      # Documentation
│
├── 🖥️ devices/                        # Virtual Device Simulator
│   ├── device_simulator.py            # Device simulation
│   ├── Dockerfile                     # Container build
│   ├── manage_devices.bat             # Device manager (Windows)
│   ├── manage_devices.sh              # Device manager (Linux)
│   └── README.md                      # Documentation
│
├── 📚 docs/                           # Documentation Hub
│   ├── SSH_SETUP_GUIDE.md             # SSH setup instructions
│   ├── SYSTEM_SUMMARY.md              # System overview
│   ├── TROUBLESHOOTING.md             # Troubleshooting guide
│   ├── HONEYPOT_REFERENCE.md          # Honeypot quick reference
│   ├── flow.md                        # System flow diagrams
│   └── PROJECT_STRUCTURE.md           # This file
│
├── 🛠️ scripts/                        # Utility Scripts
│   ├── test_system.bat                # System test suite
│   ├── test_system.sh                 # System test (Linux)
│   ├── start_all.sh                   # Start all services
│   ├── organize_project.bat           # Project organizer
│   ├── clean_project.bat              # Cleanup script
│   ├── initial_setup.bat              # First-time setup
│   ├── setup_passwordless_iptables.bat # iptables setup
│   ├── apply_iptables_reroute.bat     # Apply reroutes
│   ├── fix_firewall.bat               # Firewall fixes
│   ├── fix_port_conflict.bat          # Port conflict fixes
│   └── diagnose.bat                   # System diagnostics
│
├── 📄 Root Files
│   ├── README.md                      # Main project README
│   ├── START_ALL.bat                  # Quick start (all services)
│   ├── SETUP_SSH.bat                  # SSH setup wizard
│   ├── .gitignore                     # Git ignore rules
│   └── REORGANIZE.bat                 # One-time reorganization
│
└── 📦 Git Repository
    └── .git/                          # Git version control

```

---

## 🎯 Key Directories Explained

### `/dashboard` - Control Center
The web-based dashboard for monitoring and controlling all system components.
- **Technologies**: Flask, HTML, JavaScript
- **Port**: 5100
- **Purpose**: Centralized management interface

### `/attackers` - Attack Simulation
Tools for testing network security through controlled attacks.
- **DOS Attacker**: High-volume packet floods (SYN, HTTP)
- **SSH Attacker**: Brute-force login attempts
- **Purpose**: Security testing and validation

### `/honey_pot` - Beelzebub Honeypot
Decoy system that attracts and logs malicious activity.
- **Services**: SSH, HTTP, MySQL, PostgreSQL
- **Network**: 172.18.0.0/16
- **Purpose**: Trap and analyze attacks

### `/network` - Monitoring Infrastructure
Core network monitoring and packet capture system.
- **IP**: 192.168.6.131
- **Capabilities**: PCAP capture, traffic analysis, API
- **Purpose**: Network visibility

### `/mcp_agent` - AI Detection
Autonomous threat detection and response agent.
- **Technology**: Model Context Protocol (MCP)
- **Capabilities**: Behavioral analysis, auto-isolation
- **Purpose**: Intelligent security automation

### `/devices` - Device Simulation
Creates virtual devices for testing network behavior.
- **Types**: IoT sensors, servers, workstations
- **Purpose**: Realistic network simulation

### `/docs` - Documentation
All project documentation in one place.
- **Guides**: Setup, troubleshooting, architecture
- **References**: API docs, quick references
- **Purpose**: Knowledge base

### `/scripts` - Utilities
Helper scripts for maintenance and diagnostics.
- **Testing**: System validation scripts
- **Cleanup**: File and resource management
- **Setup**: Configuration helpers
- **Purpose**: Operational efficiency

---

## 📊 File Naming Conventions

### Scripts
- **Start scripts**: `start_*.bat` or `START_*.bat`
- **Stop scripts**: `stop_*.bat` or `STOP_*.bat`
- **Utility scripts**: `*_*.bat` (lowercase with underscores)
- **Major commands**: `UPPERCASE.bat` (e.g., `START_ALL.bat`)

### Documentation
- **Main docs**: `UPPERCASE.md` (e.g., `README.md`)
- **Guides**: `*_GUIDE.md` (e.g., `SSH_SETUP_GUIDE.md`)
- **References**: `*_REFERENCE.md`
- **Technical**: `lowercase.md` (e.g., `flow.md`)

### Configuration
- **Docker**: `docker-compose.yml`, `Dockerfile`
- **Environment**: `.env`, `.env.example`
- **Requirements**: `requirements.txt`
- **Config files**: Lowercase with extension

---

## 🔒 Security Notes

### Sensitive Files (in `.gitignore`)
- `*.env` - Environment variables and secrets
- `*.log` - Log files with sensitive data
- `*.pcap` - Packet captures (may contain sensitive traffic)
- `logs/` - All log directories
- `**/logs/*.log` - All nested log files

### Safe to Commit
- `.env.example` - Template without secrets
- `*.md` - Documentation
- `*.bat`, `*.sh` - Scripts
- `*.yml`, `*.cfg` - Configuration templates
- Source code files

---

## 📈 Growth & Maintenance

### Adding New Components
1. Create directory under appropriate parent (`attackers/`, `devices/`, etc.)
2. Include `README.md` in new directory
3. Add `.gitkeep` to empty subdirectories
4. Update this file with new structure
5. Add scripts to `/scripts` if needed

### Cleanup Schedule
- **Daily**: Temp files (automatic)
- **Weekly**: Old PCAP files (keep last 5)
- **Monthly**: Old logs (keep last month)
- **Never**: Configuration, source code, docs

### Backup Strategy
- **Critical**: `/mcp_agent/config`, `honey_pot/.env`
- **Important**: All `*.py`, `*.sh`, `*.yml` files
- **Optional**: Recent PCAP files, logs

---

## ✅ Organization Checklist

- [x] Root-level clutter removed
- [x] Documentation centralized in `/docs`
- [x] Utility scripts in `/scripts`
- [x] Consistent naming conventions
- [x] Professional .gitignore
- [x] Clear README
- [x] Organized subdirectories
- [x] Removed redundant files
- [x] Added .gitkeep for empty dirs
- [x] Updated all documentation

---

**Last Updated:** October 30, 2025
**Maintained By:** Network Security POC Team
