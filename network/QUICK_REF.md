# Quick Reference

## Start
```bash
# WSL
./wsl-manager.sh setup
```

## Analyze
```cmd
# Windows
analyze.bat
```

## Stop
```bash
# WSL
./wsl-manager.sh stop
```

## Access
- Health: http://localhost:5002/health
- Stats: http://localhost:8082/stats

## All WSL Commands
```bash
./wsl-manager.sh          # Menu
./wsl-manager.sh setup    # Build + Start
./wsl-manager.sh stop     # Stop
./wsl-manager.sh health   # Check
./wsl-manager.sh logs     # View logs
```

## All Windows Commands
```cmd
analyze.bat               # Analyze packets
```

## Daily Workflow
1. WSL: `./wsl-manager.sh setup`
2. Wait 15-30 minutes
3. Windows: `analyze.bat`
4. WSL: `./wsl-manager.sh stop`

## Troubleshooting
```bash
# Clean and restart
./wsl-manager.sh clean
./wsl-manager.sh setup

# Fix permissions
chmod 777 /mnt/e/nos/Network_Security_poc/network/captures
```