0.
# How Your System Works Now

## Current Architecture - Simple Explanation

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Docker Network: custom_net                        │
│                       (192.168.6.0/24)                              │
│                                                                      │
│  ┌──────────────────┐         ┌──────────────────┐                │
│  │  Monitor Server  │         │  Virtual Device  │                │
│  │  Container       │◄────────┤  Container 1     │                │
│  │                  │         │                  │                │
│  │ IP: 192.168.6.131│         │ IP: 192.168.6.10 │                │
│  │                  │         │                  │                │
│  │ Services:        │         │ Runs:            │                │
│  │ • Flask API      │         │ device_simulator │                │
│  │ • HAProxy        │         │     .py          │                │
│  │ • tcpdump        │         │                  │                │
│  └────────┬─────────┘         └──────────────────┘                │
│           │                                                        │
│           │                   ┌──────────────────┐                │
│           │                   │  Virtual Device  │                │
│           └───────────────────┤  Container 2     │                │
│                               │                  │                │
│                               │ IP: 192.168.6.11 │                │
│                               │                  │                │
│                               │ Runs:            │                │
│                               │ device_simulator │                │
│                               │     .py          │                │
│                               └──────────────────┘                │
│                                                                      │
│                               ... (up to 7 devices)                 │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
         │
         │ Port Mappings to Windows Host
         │
         ├─► Port 8082 → Access Dashboard (http://localhost:8082)
         ├─► Port 5002 → Access Flask API
         └─► Port 8415 → HAProxy Stats
```

## Step-by-Step: What Happens When You Run It

### 1. Start Monitor Container
```bash
cd Network_Security_poc\network
wsl bash wsl-manager.sh start
```

**What happens:**
- ✅ Creates Docker network `custom_net` (192.168.6.0/24)
- ✅ Creates container `net-monitor-wan`
- ✅ Assigns IP: **192.168.6.131**
- ✅ Starts 3 services inside:
  - **tcpdump** - Captures ALL network packets
  - **Flask API** (port 5000) - Receives device data
  - **HAProxy** (port 8080) - Serves dashboard

### 2. Create Virtual Devices
```bash
cd ..\devices
manage_devices.bat create 7 iot_sensor
```

**What happens:**
- ✅ Creates 7 Docker containers
- ✅ Each container:
  - Connects to **same network** (`custom_net`)
  - Gets unique IP (192.168.6.10, .11, .12, etc.)
  - Runs `device_simulator.py` script
  - Configured with: `SERVER_URL=http://192.168.6.131:5000`

### 3. Devices Connect and Communicate

**Automatic Process (happens continuously):**

```
Virtual Device Container                    Monitor Container
(192.168.6.10)                             (192.168.6.131)
     │                                            │
     │ 1. Register on startup                     │
     ├──────────────────────────────────────────►│
     │   POST /api/device/register                │
     │   {device_id, type, ip, mac}               │
     │                                            │
     │◄──────────────────────────────────────────┤
     │   {status: "success"}                      │
     │                                            │
     │                                            │
     │ 2. Send sensor data (every 3-10s)          │
     ├──────────────────────────────────────────►│
     │   POST /api/device/data                    │
     │   {temp, humidity, pressure, etc}          │
     │                                            │
     │◄──────────────────────────────────────────┤
     │   {status: "success"}                      │
     │                                            │
     │                                            │
     │ 3. Check status (every 3rd request)        │
     ├──────────────────────────────────────────►│
     │   GET /api/device/status                   │
     │                                            │
     │◄──────────────────────────────────────────┤
     │   {status: "online"}                       │
     │                                            │
     └─── Repeat forever ───                      │
```

**Meanwhile:**
- ✅ **tcpdump** captures ALL this traffic
- ✅ Saves to files: `/captures/capture_YYYYMMDD_HHMMSS.pcap`
- ✅ New file every 30 seconds

### 4. View Dashboard

**Open browser:** http://localhost:8082

```
Browser                         HAProxy (8080)           Flask API (5000)
   │                                │                         │
   │ GET /                          │                         │
   ├───────────────────────────────►│                         │
   │                                │                         │
   │                                │ GET /                   │
   │                                ├────────────────────────►│
   │                                │                         │
   │                                │  dashboard HTML         │
   │                                │◄────────────────────────┤
   │                                │                         │
   │  dashboard HTML                │                         │
   │◄───────────────────────────────┤                         │
   │                                │                         │
   │ JavaScript loads...            │                         │
   │                                │                         │
   │ GET /api/devices/list          │                         │
   ├───────────────────────────────►│                         │
   │                                │                         │
   │                                │ Forward request         │
   │                                ├────────────────────────►│
   │                                │                         │
   │                                │  {devices: [...]}       │
   │                                │◄────────────────────────┤
   │                                │                         │
   │  {devices: [...]}              │                         │
   │◄───────────────────────────────┤                         │
   │                                │                         │
   │ Display devices!               │                         │
```

## Key Points - Yes, This Is What You Wanted!

✅ **ONE NETWORK** - All containers on `custom_net` (192.168.6.0/24)

✅ **MONITOR CONTAINER** - Has your server (Flask API, tcpdump, HAProxy)

✅ **DEVICE CONTAINERS** - Connect to the SAME network

✅ **COMMUNICATION** - Devices talk to server using HTTP over Docker network

✅ **PACKET CAPTURE** - tcpdump captures ALL traffic between containers

✅ **NO EXTERNAL NETWORK NEEDED** - Everything happens inside Docker network

## Network Isolation

```
Windows Host (Your Computer)
       │
       │ (Port mapping only)
       │
       ├─► localhost:8082 → View Dashboard
       ├─► localhost:5002 → API (if needed)
       │
       │
       ▼
┌─────────────────────────────────────┐
│   Docker Network (custom_net)       │
│   192.168.6.0/24                    │
│                                     │
│   All containers talk to each       │
│   other using internal IPs          │
│                                     │
│   ┌─────────┐      ┌─────────┐    │
│   │ Monitor │◄────►│ Device  │    │
│   │  .131   │      │  .10    │    │
│   └─────────┘      └─────────┘    │
│                                     │
│   Traffic NEVER leaves this network │
│   (unless you explicitly route it)  │
└─────────────────────────────────────┘
```

## What Gets Captured

The **tcpdump** inside monitor container captures:

1. ✅ Device registration requests
2. ✅ Device sensor data submissions
3. ✅ Device status checks
4. ✅ Server responses
5. ✅ Any ARP/DNS requests
6. ✅ ALL packets between containers

**Files saved to:** `Network_Security_poc/network/captures/*.pcap`

## Summary

**Your Question:** "I have my network container right, when I create device it should be connect to that network and do actions in that server inside the network right?"

**Answer:** **YES! That's EXACTLY how it works!**

1. You start monitor container → Creates network + server
2. You create devices → They join SAME network
3. Devices automatically connect to server on that network
4. Devices send data to server
5. Server captures all traffic
6. You view everything on dashboard

**It's all self-contained in one Docker network!** 🎯
