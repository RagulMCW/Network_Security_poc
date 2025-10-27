# 🍯 Beelzebub Honeypot - Quick Reference Card

## 🚀 Quick Commands

### Start/Stop
```bash
# Start honeypot
start_beelzebub_simple.bat

# Stop honeypot
stop_beelzebub_simple.bat

# Restart honeypot
wsl bash -c "docker compose -f docker-compose-simple.yml restart"
```

### Monitor
```bash
# View logs (real-time)
wsl bash -c "docker logs -f beelzebub-honeypot"

# Check status
wsl bash -c "docker ps | grep beelzebub"

# View log file
type logs\beelzebub.log
```

## 🎯 Service Endpoints

| Service | URL/Command | Description |
|---------|-------------|-------------|
| SSH | `ssh root@localhost -p 2222` | AI-powered shell |
| HTTP | `http://localhost:8080` | Fake phpMyAdmin |
| MySQL | `mysql -h localhost -P 3306 -u root -p` | DB honeypot |
| PostgreSQL | `psql -h localhost -p 5432 -U postgres` | DB honeypot |
| Logs | `http://localhost:8888/logs/beelzebub.log` | Web log viewer |
| Dashboard | `http://localhost:5000` | Security analytics |

## 🧪 Quick Tests

### Test SSH (AI-Powered)
```bash
ssh root@localhost -p 2222
# Password: root, admin, password, or 123456

# Try these commands:
whoami
ls -la
cat .env
docker ps
cat ~/.ssh/id_rsa
```

### Test HTTP
```
1. Open: http://localhost:8080
2. Login: admin / password123
3. Browse fake databases
```

## 📊 Log Analysis

```bash
# View all login attempts
wsl bash -c "cat logs/beelzebub.log | jq -r 'select(.password) | {time:.timestamp, ip:.source_ip, user:.username, pass:.password}'"

# Count unique IPs
wsl bash -c "cat logs/beelzebub.log | jq -r '.source_ip' | sort | uniq -c"

# Most common passwords
wsl bash -c "cat logs/beelzebub.log | jq -r '.password' | grep -v null | sort | uniq -c | sort -rn"
```

## 🔧 Troubleshooting

```bash
# Container won't start
wsl bash -c "docker logs beelzebub-honeypot"

# Port conflict
netstat -ano | findstr :2222

# Restart everything
stop_beelzebub_simple.bat
start_beelzebub_simple.bat

# Check environment variables
wsl bash -c "docker inspect beelzebub-honeypot | grep -A 5 Env"
```

## 📂 Directory Structure

```
honey_pot/
├── docker-compose-simple.yml    # Main config
├── .env                         # API keys (KEEP SECRET!)
├── start_beelzebub_simple.bat  # Start script
├── stop_beelzebub_simple.bat   # Stop script
├── README.md                    # Full documentation
├── beelzebub-example/
│   └── configurations/
│       ├── beelzebub.yaml      # Core config
│       └── services/           # Service definitions
└── logs/
    └── beelzebub.log           # Attack logs (JSONL)
```

## ⚙️ Configuration Files

| File | Purpose |
|------|---------|
| `.env` | API keys & environment variables |
| `docker-compose-simple.yml` | Container orchestration |
| `beelzebub.yaml` | Core honeypot settings |
| `ssh-22-enhanced.yaml` | SSH service + GLM-4.5 config |
| `http-8080-admin.yaml` | HTTP/phpMyAdmin service |
| `tcp-3306.yaml` | MySQL service |
| `tcp-5432.yaml` | PostgreSQL service |

## 🔑 Default Credentials (Honeypot Accepts)

**SSH:**
- Username: `root` | Password: `root`, `admin`, `password`, `123456`, `ubuntu`

**HTTP:**
- Any username/password combination is accepted and logged!

## 📈 Integration

**Dashboard Integration:**
- Logs auto-sync to `http://localhost:5000`
- View analytics, attack patterns, geolocation
- Real-time attack monitoring

## ⚠️ Important Notes

1. **API Keys**: GLM-4.5 requires valid API keys in `.env`
2. **Fallback**: Without API keys, uses regex-based responses
3. **Isolation**: Runs in isolated Docker network
4. **Logging**: All interactions logged to JSONL format
5. **Security**: Never expose directly to internet without firewall!

## 📞 Need Help?

```bash
# Full documentation
type README.md

# View this guide
type QUICK_REFERENCE.md

# Check logs
wsl bash -c "docker logs beelzebub-honeypot"

# Dashboard
http://localhost:5000
```

---
**Last Updated:** October 27, 2025  
**Version:** 1.0 (GLM-4.5 Powered)
