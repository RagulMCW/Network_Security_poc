# Attacker Tracking Implementation

## Overview
Comprehensive attacker tracking and visualization system integrated into the Network Security Dashboard for monitoring Beelzebub honeypot activity.

## Features Implemented

### 1. Backend API Endpoint
**Endpoint:** `GET /api/honeypot/attackers`

**Returns:**
```json
{
  "success": true,
  "attackers": [
    {
      "ip": "192.168.1.100",
      "first_seen": "2024-10-27T10:30:45Z",
      "last_seen": "2024-10-27T10:45:30Z",
      "total_interactions": 15,
      "protocols": ["SSH", "HTTP"],
      "ports": [2222, 8080],
      "credentials": [...],
      "commands": [...],
      "http_requests": [...]
    }
  ],
  "total_attacks": 150,
  "unique_ips": 5,
  "credentials_tried": [
    {
      "username": "admin",
      "password": "123456",
      "protocol": "ssh",
      "timestamp": "2024-10-27T10:30:45Z",
      "count": 3
    }
  ],
  "commands_executed": [
    {
      "command": "ls -la",
      "timestamp": "2024-10-27T10:31:20Z",
      "count": 2
    }
  ],
  "http_requests": [
    {
      "method": "GET",
      "url": "/admin/login",
      "user_agent": "Mozilla/5.0...",
      "timestamp": "2024-10-27T10:32:10Z",
      "count": 1
    }
  ],
  "rerouted_devices": [
    {
      "name": "device_192.168.1.100",
      "ip": "192.168.7.10",
      "status": "active",
      "rerouted_at": "2024-10-27T10:25:00Z"
    }
  ]
}
```

**Location:** `dashboard/app.py` lines 497-598

### 2. Frontend Dashboard Sections

#### A. Attacker Statistics (4 Counters)
- **Total Attacks:** Real-time count of all attack attempts
- **Unique IPs:** Number of distinct attacker IP addresses
- **Credentials Tried:** Total credential combinations attempted
- **Commands Executed:** Total SSH commands run by attackers

**Element IDs:**
- `attacker-total-attacks`
- `attacker-unique-ips`
- `attacker-credentials`
- `attacker-commands`

#### B. Detected Attackers List
Displays comprehensive information for each attacking IP:
- IP address with skull icon
- Interaction count badge
- Protocols used (SSH, HTTP, MySQL, etc.)
- Ports targeted
- First seen timestamp
- Last seen timestamp
- Credential attempt count
- Command execution count
- HTTP request count

**Element ID:** `attacker-list`

**Features:**
- Color-coded by threat level (red for attackers)
- Expandable cards showing all details
- Icons for each data type

#### C. Captured Credentials
Shows all authentication attempts captured by honeypot:
- Username attempted
- Password attempted
- Protocol (SSH, HTTP, MySQL, PostgreSQL)
- Timestamp
- Retry count (how many times same credential was tried)

**Element ID:** `credentials-list`

**Features:**
- Color-coded with yellow/orange theme
- Code-style formatting for credentials
- Retry indicators for repeated attempts

#### D. SSH Commands Executed
Displays all SSH commands attackers ran:
- Full command text
- Timestamp
- Execution count
- Smart color coding:
  - **Red:** Destructive commands (rm, delete)
  - **Orange:** Download commands (wget, curl)
  - **Green:** Reconnaissance (cat, ls)
  - **Purple:** Privilege escalation (chmod, sudo)
  - **Blue:** General commands

**Element ID:** `commands-list`

**Features:**
- Terminal-style code blocks
- Icon indicators based on command type
- Monospace font for command readability

#### E. HTTP Requests
Shows all HTTP traffic to honeypot web services:
- HTTP method (GET, POST, PUT, DELETE, PATCH)
- Request URL/path
- User-Agent string
- Timestamp
- Request count

**Element ID:** `http-requests-list`

**Features:**
- Method badges with color coding:
  - **Blue:** GET
  - **Green:** POST
  - **Orange:** PUT
  - **Red:** DELETE
  - **Purple:** PATCH
- Full User-Agent display for fingerprinting
- Monospace formatting for technical data

### 3. JavaScript Functions

#### Main Function
**`refreshAttackerDetails()`**
- Fetches data from `/api/honeypot/attackers`
- Updates all 4 stat counters
- Calls all display functions
- Handles errors gracefully with fallback UI
- **Location:** `dashboard/static/dashboard.js` lines 420-447

#### Display Functions

**`displayAttackersList(attackers)`**
- Creates detailed cards for each attacker IP
- Shows all metrics and interaction history
- Empty state: "No attackers detected yet"
- **Location:** Lines 449-530

**`displayCredentialsList(credentials)`**
- Formats credential attempts with icons
- Groups repeated attempts
- Empty state: "No credential attempts captured"
- **Location:** Lines 532-590

**`displayCommandsList(commands)`**
- Color-codes commands by threat level
- Shows execution frequency
- Terminal-style formatting
- Empty state: "No SSH commands executed yet"
- **Location:** Lines 592-656

**`displayHttpRequestsList(requests)`**
- HTTP method badges
- Full request details
- User-Agent analysis
- Empty state: "No HTTP requests captured"
- **Location:** Lines 658-728

### 4. Auto-Refresh Integration

#### Page Load
When user clicks "Honeypot" page:
```javascript
showPage('honeypot') → refreshHoneypotStats() → refreshAttackerDetails()
```
**Location:** `dashboard.js` line 42

#### Periodic Updates
Every 5 seconds when on honeypot page:
```javascript
setInterval → if (currentPage === 'honeypot') → refreshHoneypotStats() → refreshAttackerDetails()
```
**Location:** `dashboard.js` line 1439

### 5. Empty State Handling

All sections display helpful messages when no data is available:
- **No Attackers:** Info icon with "No attackers detected yet" + explanation
- **No Credentials:** Shield icon with "No credential attempts captured" + explanation
- **No Commands:** Terminal icon with "No SSH commands executed yet" + explanation
- **No HTTP Requests:** Globe icon with "No HTTP requests captured" + explanation

## UI/UX Features

### Visual Design
- **Color Scheme:** Dark theme with accent colors
- **Card Layout:** Border-left accent bars for visual hierarchy
- **Icons:** Font Awesome icons for all data types
- **Typography:** Monospace for code/technical data, sans-serif for labels

### Interactive Elements
- **Refresh Buttons:** Manual refresh for each section
- **Scrollable Lists:** Vertical scroll for long data sets
- **Hover States:** Visual feedback on interactive elements
- **Status Badges:** Color-coded status indicators

### Responsive Design
- **Flexible Grids:** Adapts to container width
- **Scrolling:** Prevents overflow with max-height constraints
- **Readable Text:** Optimized font sizes for long data

## Data Flow

```
[Beelzebub Honeypot]
         ↓
   beelzebub.log (JSONL)
         ↓
[Flask Backend Parser]
    (/api/honeypot/attackers)
         ↓
[JavaScript Frontend]
    (refreshAttackerDetails)
         ↓
[Dashboard UI Sections]
    - Attackers List
    - Credentials List
    - Commands List
    - HTTP Requests List
```

## Testing

### Manual Testing
1. **Start Dashboard:** `start_dashboard.bat`
2. **Navigate to Honeypot Page:** Click "Honeypot" in nav
3. **Verify Empty State:** All sections show "No data" messages
4. **Start Honeypot:** Click "Start Honeypot" button
5. **Generate Traffic:** 
   - SSH: `ssh -p 2222 admin@localhost` (password: anything)
   - HTTP: Open `http://localhost:8080/admin`
6. **Verify Data Appears:** Check all 4 sections populate with data
7. **Test Auto-Refresh:** Wait 5 seconds, verify updates

### Expected Behavior
- ✅ All sections display empty state initially
- ✅ Stats counters show 0 when no data
- ✅ Data appears after honeypot receives traffic
- ✅ Auto-refresh updates every 5 seconds
- ✅ Manual refresh buttons work
- ✅ Color coding applies correctly
- ✅ No JavaScript errors in browser console

### Log Format Requirements
Beelzebub logs must be in JSONL format with these fields:
```json
{
  "msg": "SSH connection from 192.168.1.100",
  "level": "info",
  "time": "2024-10-27T10:30:45Z",
  "port": ":2222",
  "protocol": "ssh",
  "commands": ["ls", "cat /etc/passwd"],
  "credentials": {"username": "admin", "password": "123456"}
}
```

## Future Enhancements

### Planned Features
- [ ] Real-time attack map with geolocation
- [ ] Attack pattern analysis with AI
- [ ] Automated threat scoring
- [ ] Export attacker data to CSV/JSON
- [ ] Integration with threat intelligence feeds
- [ ] Attacker session replay
- [ ] Detailed packet analysis
- [ ] Malware sample capture and analysis

### Backend Improvements
- [ ] Enhanced log parsing for more fields
- [ ] Database storage for historical data
- [ ] API rate limiting and caching
- [ ] Pagination for large datasets
- [ ] Search and filter capabilities

### Frontend Improvements
- [ ] Charts and graphs for attack trends
- [ ] Sortable/filterable tables
- [ ] Drill-down into individual sessions
- [ ] Real-time notifications for new attacks
- [ ] Custom alert rules

## Troubleshooting

### No Data Showing
1. Check honeypot is running: `docker ps | findstr beelzebub`
2. Verify logs exist: `dir honey_pot\logs\beelzebub.log`
3. Check browser console for JavaScript errors (F12)
4. Test API endpoint: `http://localhost:5000/api/honeypot/attackers`

### Empty State Not Showing
1. Check element IDs in HTML match JavaScript
2. Verify display functions are being called
3. Check for CSS conflicts hiding elements

### Auto-Refresh Not Working
1. Verify `currentPage === 'honeypot'` in console
2. Check `setInterval` is running (line 1439)
3. Test manual refresh button works

### Styling Issues
1. Clear browser cache (Ctrl+F5)
2. Check CSS loaded in Network tab (F12)
3. Verify element IDs and class names

## Files Modified

### Backend
- `dashboard/app.py` - Added `/api/honeypot/attackers` endpoint (147 lines)

### Frontend
- `dashboard/templates/control_panel.html` - Added 4 attacker sections (~80 lines)
- `dashboard/static/dashboard.js` - Added 5 functions (~300 lines)

### Documentation
- `dashboard/ATTACKER_TRACKING_IMPLEMENTATION.md` - This file

## Version History

### v1.0.0 (2024-10-27)
- Initial implementation
- 4 attacker tracking sections
- Backend API endpoint
- Auto-refresh integration
- Empty state handling
- Comprehensive documentation

---

**Last Updated:** 2024-10-27  
**Status:** ✅ Implemented and ready for testing  
**Tested:** ⏳ Pending user testing with live traffic
