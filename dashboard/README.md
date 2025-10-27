# 🎮 Network Security Dashboard

**Professional Multi-Page Web UI to Control Your Entire Docker Network Security Setup**

## 🌟 Features

### 📊 Overview Page
- **Real-time statistics**: Running containers, active devices, registered devices, attacks
- **Network control**: Create/delete Docker network with one click
- **Quick actions**: Fast navigation to any section
- **Live status indicators**: Green/Red badges for all components

### 📱 Devices Page (NEW!)
- **Create devices**: Select type (IoT Sensor, Smartphone, Laptop, Camera, Generic)
- **Beautiful card layout**: Each device in its own card with status
- **Device details**: Name, type, container ID, running status
- **Individual controls**: View logs or delete each device
- **Auto-refresh**: Updates every 5 seconds
- **Cleanup tool**: Remove stopped containers

### 🍯 Honeypot Page
- **Control panel**: Start/stop honeypot with one click
- **Live attack logs**: See attacker IPs, protocols, and data in real-time
- **Attack counter**: Total attacks logged
- **Dashboard link**: Quick access to honeypot monitoring (localhost:5001)

### 💀 Attackers Page
- **DOS simulation**: Start/stop attack containers
- **Testing mode**: Safely test your defenses

### 📋 Logs Page (NEW!)
- **Device data stream**: Live table showing all device communications
- **Detailed info**: Timestamp, device ID, type, IP, sensor data
- **Real-time updates**: See device data as it arrives
- **Scrollable table**: View latest 50 entries

## 🚀 Quick Start

### 1. Start Dashboard
```bash
cd E:\nos\Network_Security_poc\dashboard
start_dashboard.bat
```

### 2. Open Browser
```
http://localhost:5000
```

### 3. Use the Dashboard!

#### Create Network First:
1. Go to **Overview** page
2. Click **"Create Network"**
3. Wait for success message ✅

#### Add Devices:
1. Go to **Devices** page
2. Select device type (IoT Sensor, Smartphone, etc.)
3. Click **"Create Device"**
4. Device appears in grid with status
5. Repeat to add more devices!

#### View Device Data:
1. Go to **Logs** page
2. See live device communications
3. Watch sensor data stream in

#### Control Honeypot:
1. Go to **Honeypot** page
2. Click **"Start Honeypot"**
3. View live attacks

## 🎯 Dashboard Pages

### 📊 Overview
```
┌─────────────────────────────────────┐
│  Statistics (5 boxes)               │
│  - Running Containers               │
│  - Active Devices                   │
│  - Registered Devices               │
│  - Attacks Logged                   │
│  - Network Status                   │
├─────────────────────────────────────┤
│  Network Control Card               │
│  Quick Actions Card                 │
└─────────────────────────────────────┘
```

### 📱 Devices
```
┌─────────────────────────────────────┐
│  Device Creation Form               │
│  [Select Type] [Create] [Refresh]   │
├─────────────────────────────────────┤
│  Device Grid (Cards)                │
│  ┌──────┐ ┌──────┐ ┌──────┐        │
│  │Dev 1 │ │Dev 2 │ │Dev 3 │        │
│  │ ✅   │ │ ✅   │ │ ⏸️   │        │
│  │[Logs]│ │[Logs]│ │[Logs]│        │
│  │[Del] │ │[Del] │ │[Del] │        │
│  └──────┘ └──────┘ └──────┘        │
└─────────────────────────────────────┘
```

### 📋 Logs
```
┌─────────────────────────────────────┐
│  Device Data Table                  │
│  ┌──────────────────────────────┐  │
│  │Time│Device│Type│IP│Data     │  │
│  ├────┼──────┼────┼──┼─────────┤  │
│  │10:30│dev_1│IoT │..│{temp:..}│  │
│  │10:31│dev_2│Cam │..│{motion}│  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
```

## 🔧 How It Works

### Device Creation Flow:
```
1. User clicks "Create Device" in UI
   ↓
2. Dashboard sends POST to /api/devices/create
   ↓
3. Backend:
   - Finds next device number (device_1, device_2, etc.)
   - Builds Docker image if needed
   - Runs container with custom_net network
   - Sets environment variables (DEVICE_ID, DEVICE_TYPE, SERVER_URL)
   ↓
4. Device container starts:
   - Runs device_simulator.py
   - Registers with dashboard at http://192.168.6.1:5000
   - Sends data every 10 seconds
   ↓
5. Dashboard receives device data:
   - Logs to device_registry
   - Stores in device_data_log
   - Displays in Logs page
   ↓
6. UI updates automatically (5-second refresh)
```

### Device Communication:
```
Device Container (192.168.6.x)
    ↓ HTTP POST /api/device/register
Dashboard Server (192.168.6.1:5000)
    ↓ Response: "Registered!"
Device Container
    ↓ HTTP POST /api/device/data (every 10s)
Dashboard Server
    ↓ Logs data
Logs Page (Browser)
    ↓ Shows in table
```

## 🎨 UI Features

✨ **Beautiful Design**
- Purple gradient background
- White cards with shadows
- Smooth hover effects
- Professional typography

🎯 **Smart Navigation**
- Top navigation bar
- Active page indicator
- One-click page switching

📊 **Live Updates**
- Auto-refresh every 5 seconds
- Toast notifications
- Real-time status badges

🎭 **Responsive**
- Adapts to screen size
- Grid layouts
- Mobile-friendly

## 📡 API Endpoints

### Network
- `POST /api/network/create` - Create Docker network
- `POST /api/network/delete` - Delete network

### Devices
- `GET /api/devices/list` - List containers
- `POST /api/devices/create` - Create device container
- `DELETE /api/devices/delete/<id>` - Delete device
- `POST /api/devices/cleanup` - Remove stopped containers
- `GET /api/devices/registry` - Get registered devices (from device data)
- `GET /api/devices/data/latest` - Get latest device sensor data

### Device Communication (Devices use these)
- `POST /api/device/register` - Device registers itself
- `POST /api/device/data` - Device sends sensor data
- `GET /api/device/status` - Check device status

### Honeypot
- `POST /api/honeypot/start` - Start honeypot
- `POST /api/honeypot/stop` - Stop honeypot
- `GET /api/honeypot/logs` - Get attack logs

### Attackers
- `POST /api/attackers/start` - Start DOS attackers
- `POST /api/attackers/stop` - Stop attackers

### Status
- `GET /api/status` - System overview
- `GET /api/containers/logs/<name>` - Container logs

## 🛠️ Device Types

### 🔧 Generic
- Basic status, uptime, health
- 5-15 second intervals

### 📡 IoT Sensor
- Temperature, humidity, pressure
- 3-10 second intervals
- Small payloads

### 📱 Smartphone  
- Location, battery, network status
- 5-15 second intervals
- Medium payloads

### 💻 Laptop
- CPU, memory, disk, network usage
- 10-30 second intervals
- Large payloads

### 📷 Camera
- Motion detection, recording status, storage
- 2-8 second intervals
- Medium payloads

## 📝 Complete Workflow Example

### Scenario: Set Up Full Environment with Devices

1. **Open Dashboard** → http://localhost:5000

2. **Create Network** (Overview Page)
   - Click "Create Network"
   - Status → ON ✅

3. **Add Devices** (Devices Page)
   - Select "IoT Sensor" → Click "Create Device"
   - Select "Camera" → Click "Create Device"  
   - Select "Laptop" → Click "Create Device"
   - Wait 10 seconds for devices to build/start
   - **Result**: 3 devices appear in grid ✅

4. **Check Device Data** (Logs Page)
   - After 10-20 seconds, device data appears
   - Table shows: device_001, device_002, device_003
   - Sensor data updates every 10 seconds
   - See temperature, humidity, motion detection, CPU usage, etc.

5. **Start Honeypot** (Honeypot Page)
   - Click "Start Honeypot"
   - Status → RUNNING ✅

6. **Start Attackers** (Attackers Page)
   - Click "Start Attackers"
   - Status → ACTIVE ✅
   - Attacks logged in Honeypot page

7. **Monitor Everything** (Overview Page)
   - See all statistics
   - 8 running containers (3 devices + honeypot + monitor + attackers)
   - 3 active devices
   - 3 registered devices
   - Attacks accumulating

8. **Delete a Device** (Devices Page)
   - Find device_2
   - Click "Delete"
   - Confirm → Device removed ✅
   - Container stopped and deleted

9. **Cleanup** (Devices Page)
   - Click "Cleanup Stopped"
   - Removes any exited containers

10. **Shutdown** (Overview Page)
    - Click "Delete Network"
    - All containers stopped
    - Network removed

## � Troubleshooting

### Devices Not Appearing?
1. Check network is created (Overview page - should be ON)
2. Wait 30 seconds after creating device (building image takes time)
3. Check "Refresh" button on Devices page
4. Look at browser console (F12) for errors

### No Device Data in Logs?
1. Devices need network to be ON
2. Devices take 10 seconds to send first data
3. Dashboard must be running on port 5000
4. Device SERVER_URL points to http://192.168.6.1:5000

### Device Won't Delete?
1. Click "Cleanup Stopped" to remove exited containers
2. Check Docker Desktop to see if container exists
3. Manually stop: `wsl docker stop device_X`

### Dashboard Not Loading?
1. Check port 5000 is not in use
2. Restart: `restart_dashboard.bat`
3. Check Flask is installed: `pip install flask flask-cors`

## � What You Get

✅ **Beautiful multi-page dashboard** with navigation
✅ **Complete device management** - create, view, delete
✅ **Live device data streaming** - see sensor readings
✅ **Device registry** - tracks all registered devices
✅ **Honeypot control** - start/stop and monitor attacks
✅ **Attacker simulation** - DOS testing
✅ **Real-time updates** - auto-refresh every 5 seconds
✅ **Professional UI** - cards, grids, badges, toasts
✅ **Full Docker integration** - WSL commands
✅ **Device communication server** - receives device data

## 🚀 You Now Have

A **PROFESSIONAL NETWORK SECURITY COMMAND CENTER**! 🎮

- Create devices with ONE CLICK
- See LIVE device data streaming
- Monitor ALL network activity
- Control EVERYTHING from beautiful web UI
- No more command line needed!

**This is a complete, production-ready dashboard!** �
