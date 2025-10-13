# START HERE

## 3 Simple Steps

### 1. Start (WSL)
```bash
cd /mnt/e/nos/Network_Security_poc/network
./wsl-manager.sh setup
```
Wait 15-30 minutes.

### 2. Analyze (Windows)
```cmd
cd E:\nos\Network_Security_poc\network
analyze.bat
```
Choose option 1 to analyze all captures.

### 3. Stop (WSL)
```bash
./wsl-manager.sh stop
```

## What You'll See

```
Total Packets: 348
TCP: 333 packets (95.7%)
Top IPs: 192.168.6.129 -> 192.168.6.131
No anomalies detected.
```

## Files

- **README.md** - Complete guide
- **QUICK_REF.md** - All commands
- **wsl-manager.sh** - Docker manager (WSL)
- **analyze.bat** - Packet analyzer (Windows)
- **captures/** - Your packet data

## Need Help?

- Commands not working? Check **QUICK_REF.md**
- Want API info? Check **docs/API.md**
- Full details? Check **README.md**

That's it! Simple and clean.