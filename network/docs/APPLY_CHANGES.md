# Apply 30-Second Rotation Updates

## 🎯 What Was Changed:

### 1. start_services.sh
```bash
# OLD (10MB rotation):
tcpdump -C 10 -W 5 -i any -w capture.pcap

# NEW (30-second rotation):
tcpdump -G 30 -w capture_%Y%m%d_%H%M%S.pcap
```

### 2. analyze.bat
```
NEW MENU OPTION:
[1] Analyze LATEST capture only (recommended)
[2] Analyze all captures in directory
[3] Analyze specific capture file
[4] View detailed help
[5] Exit
```

---

## 📋 Step-by-Step: Apply Changes

### Step 1: Rebuild Docker Image
```cmd
cd E:\nos\Network_Security_poc\network

wsl bash wsl-manager.sh
# Choose: [3] Stop Container

# Rebuild image
docker build -t network-security-monitor ./docker

# Restart container
wsl bash wsl-manager.sh
# Choose: [1] Setup Network and Start Container
```

### Step 2: Wait 90 Seconds
```cmd
# Let the container run for 90 seconds
# This will create at least 3 new PCAP files:
# - capture_20251013_143000.pcap (30 seconds)
# - capture_20251013_143030.pcap (30 seconds)
# - capture_20251013_143100.pcap (30 seconds)
```

### Step 3: Test Latest File Analysis
```cmd
cd E:\nos\Network_Security_poc\network

# Run analyzer
analyze.bat

# Choose option: 1 (Analyze LATEST capture only)

# You should see:
# "Analyzing: capture_20251013_143100.pcap"
#  ↑ The newest file!
```

---

## 🧪 Test the 30-Second Rotation

### Verification:
```cmd
# Check captures directory
dir captures\*.pcap0 /o-d /tc

# You should see files like:
# capture_20251013_143100.pcap0  ← Newest (30 seconds ago)
# capture_20251013_143030.pcap0  ← 60 seconds ago
# capture_20251013_143000.pcap0  ← 90 seconds ago
```

### Generate Traffic:
```cmd
# Open another terminal
cd E:\nos\Network_Security_poc\network

# Make 5 requests
curl http://localhost:5002/health
curl http://localhost:5002/health
curl http://localhost:5002/health
curl http://localhost:8082/stats
curl http://localhost:8082/stats

# Wait 35 seconds
timeout /t 35

# Analyze latest capture
analyze.bat
# Choose: 1 (Latest only)

# You should see your 5 requests in the output!
```

---

## 🔍 Expected Results:

### After 90 seconds of running:
```
captures/
├── capture_20251013_143000.pcap0  (30 seconds of traffic)
├── capture_20251013_143030.pcap0  (30 seconds of traffic)
└── capture_20251013_143100.pcap0  (30 seconds of traffic) ← LATEST
```

### analyze.bat option 1 output:
```
======================================
Analyzing LATEST capture only
======================================

Latest capture file: capture_20251013_143100.pcap0

=== Network Capture Analysis ===
Total packets: 42
Time range: 30 seconds

Protocol Distribution:
- TCP: 38 packets (90.5%)
- ARP: 2 packets (4.8%)
- Other: 2 packets (4.7%)

Top Talkers:
192.168.6.129 → 192.168.6.131: 20 packets
192.168.6.131 → 192.168.6.129: 18 packets
```

---

## ✅ Success Checklist:

- [ ] Container rebuilt with new start_services.sh
- [ ] Multiple PCAP files created (every 30 seconds)
- [ ] analyze.bat shows "Analyze LATEST capture only" as option 1
- [ ] Option 1 analyzes only the newest file
- [ ] File timestamps show 30-second intervals

---

## 🐛 Troubleshooting:

### Problem: Only one PCAP file created
**Solution:** Container using old image
```cmd
# Force rebuild
docker build --no-cache -t network-security-monitor ./docker
wsl bash wsl-manager.sh
# Choose [3] Stop, then [1] Start
```

### Problem: Files not showing in captures/
**Solution:** Volume mount issue
```cmd
# Check volume mapping
docker inspect net-monitor-wan | grep -A 10 Mounts

# Should show:
# "Source": "/e/nos/Network_Security_poc/network/captures"
# "Destination": "/captures"
```

### Problem: analyze.bat still shows old menu
**Solution:** File not saved
```cmd
# Re-run analyze.bat
analyze.bat

# Should show 5 options (not 4)
```

---

## 🎓 For Your Team Presentation:

### Key Points:
1. **30-second rotation** = fresh data every time
2. **Analyze latest only** = see recent activity
3. **Timestamped filenames** = easy to identify when traffic occurred
4. **No more huge files** = manageable file sizes

### Demo Script:
```cmd
# 1. Show rotation
dir captures\*.pcap0 /o-d

# 2. Generate traffic
curl http://localhost:5002/health

# 3. Wait 35 seconds
timeout /t 35

# 4. Analyze latest
analyze.bat → option 1

# 5. Show results
# Point out: "This is only the last 30 seconds!"
```

---

## 📊 Next Steps:

1. **Apply changes** (rebuild container)
2. **Test 30-second rotation** (wait 90 seconds)
3. **Test analyze.bat option 1** (should work perfectly)
4. **Add simulated devices** (see PACKET_SOURCE.md)
5. **Generate attack traffic** (see HOW_IT_WORKS.md)

---

## 💡 Pro Tip:

**For continuous monitoring:**
```cmd
# PowerShell loop
while ($true) {
    Clear-Host
    Write-Host "Latest 30-second capture:"
    .\analyze.bat # Option 1
    Start-Sleep -Seconds 35
}
```

This shows real-time analysis every 35 seconds! 🚀