# Network Map Visual Example

## What You'll See

```
                    Network Map: custom_net (192.168.6.0/24)
                    ========================================

                              device_2 (iot_sensor)
                                  192.168.6.11
                                      🔵
                                       |
                                       |
     device_1 (smartphone)             |           honeypot
        192.168.6.10                   |          192.168.6.200
            🔵 ----------------------- 🟢 ----------------------- 🟠
                                       |
                                       |     Dashboard Server
                                       |       192.168.6.1
                                       |
                                       |
                                      🟣
                                       |
                                  Monitor Server
                                  192.168.6.131


Legend:
🟢 = Gateway/Dashboard Server (center)
🔵 = Devices (blue circles)
🟠 = Honeypot (orange circle)
🟣 = Monitor (purple circle)
🔴 = Attacker (red circle)
```

## How It Updates

### Scenario 1: Adding a Device

**Before:**
```
        device_1 --- 🟢 --- honeypot
```

**After 5 seconds:**
```
        device_1 --- 🟢 --- honeypot
                      |
                   device_2  ← NEW!
```

### Scenario 2: Removing a Device

**Before:**
```
        device_1 --- 🟢 --- device_2
```

*User clicks "Delete device_2"*

**After 5 seconds:**
```
        device_1 --- 🟢
```

### Scenario 3: Full Network

```
              device_1 (iot_sensor)
                      🔵
                       |
       device_2 -------|------- honeypot
       🔵              |           🟠
                       |
                      🟢
                 Dashboard Server
                       |
                       |
       monitor --------|------- attacker
         🟣            |           🔴
                       |
                    device_3
                      🔵
```

## Interactive Features

### Click on a Node:

**Example: Click device_1**

```
Node Details Panel:
┌────────────────────────────────┐
│ device_1 (iot_sensor)         │
├────────────────────────────────┤
│ ID: device_1                   │
│ Type: device                   │
│ IP Address: 192.168.6.10       │
│ Status: RUNNING                │
│ Container ID: a1b2c3d4         │
│ Last Seen: 2025-10-24T06:52:10 │
└────────────────────────────────┘
```

**Example: Click Gateway**

```
Node Details Panel:
┌────────────────────────────────┐
│ Dashboard Server               │
├────────────────────────────────┤
│ ID: gateway                    │
│ Type: gateway                  │
│ IP Address: 192.168.6.1        │
│ Status: RUNNING                │
└────────────────────────────────┘
```

## Layout Behavior

### With 1 Device:
```
      🔵 device_1
       |
      🟢 gateway
```

### With 2 Devices:
```
  device_1 🔵 ------ 🟢 ------ 🔵 device_2
```

### With 4 Devices:
```
           device_1
              🔵
               |
    device_2   |   device_3
       🔵 ---- 🟢 ---- 🔵
               |
              🔵
           device_4
```

### With 8+ Devices:
```
    🔵        🔵       🔵
        \      |      /
    🔵 --- \   |   / --- 🔵
            \  |  /
             \ | /
    🔵 ------- 🟢 ------- 🔵
             / | \
            /  |  \
    🔵 --- /   |   \ --- 🔵
        /      |      \
    🔵        🔵       🔵
```

## Connection Types

### Solid Lines (Network):
```
device_1 ═══════ gateway
```
- Docker network connections
- Container-to-container

### Dashed Lines (Data):
```
device_1 ─ ─ ─ ─ gateway
```
- HTTP data connections
- Sensor readings
- API calls

## Color Meanings

| Color  | Type     | Example                    |
|--------|----------|----------------------------|
| 🟢 Green | Gateway  | Dashboard Server (center)  |
| 🔵 Blue  | Device   | IoT sensors, smartphones   |
| 🟠 Orange| Honeypot | Beelzebub honeypot         |
| 🟣 Purple| Monitor  | Network monitor server     |
| 🔴 Red   | Attacker | DOS attacker containers    |
| ⚫ Gray  | Other    | Unknown containers         |

## Real-Time Updates

### Auto-Refresh Every 5 Seconds:

```
Second 0:  device_1 --- 🟢 --- honeypot

Second 5:  device_1 --- 🟢 --- honeypot
                         |
                      device_2  ← Added!

Second 10: device_1 --- 🟢 --- honeypot
                         |
                      device_2

Second 15: device_1 --- 🟢 --- honeypot  ← Still there
                         |
                      device_2
                         |
                      monitor ← Added!
```

## Hover Effects

**Before Hover:**
```
  🔵 (normal size - 30px)
```

**On Hover:**
```
  🔵 (grows - 35px)
```

**Cursor Changes:**
- Default → Pointer when hovering over nodes
- Click to see details

## Node Labels

Each node shows:
```
┌────────────────────┐
│   device_1         │ ← Name
│  (iot_sensor)      │ ← Type (if device)
└────────────────────┘
         🔵          ← Circle
┌────────────────────┐
│  192.168.6.10      │ ← IP Address
└────────────────────┘
```

## Status Indicator (Top Bar)

```
Network: custom_net (192.168.6.0/24) | Nodes: 5 | Auto-refresh: ON
```

## Page Layout

```
┌─────────────────────────────────────────────────────────────┐
│ 🗺️ Network Topology Map                                     │
│ Live visualization (auto-refresh every 5s)                  │
├─────────────────────────────────────────────────────────────┤
│ Network: custom_net | Nodes: 5 | Auto-refresh: ON          │
│ [🔄 Refresh Map]                                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│                    [SVG Canvas Here]                         │
│                 Network visualization                        │
│                                                              │
├──────────────────────────┬──────────────────────────────────┤
│ Legend:                  │ Node Details:                    │
│ 🟢 Gateway               │                                  │
│ 🔵 Device                │ (Click a node to see details)    │
│ 🟠 Honeypot              │                                  │
│ 🟣 Monitor               │                                  │
│ 🔴 Attacker              │                                  │
└──────────────────────────┴──────────────────────────────────┘
```

## Mobile Responsive

On smaller screens:
- Canvas scales to fit
- Nodes adjust positions
- Labels may truncate
- Details panel moves below map

## Animation

**Smooth Transitions:**
- Nodes fade in when added
- Nodes fade out when removed
- Size changes on hover are smooth
- No jarring updates

## Performance

- SVG rendering (fast, scalable)
- Efficient 5-second polling
- No lag with 10+ nodes
- Smooth on modern browsers

## Browser Compatibility

✅ Chrome/Edge (recommended)
✅ Firefox
✅ Safari
⚠️ IE11 (basic support, no animations)

## Example Usage Flow

1. **Open Network Map page**
   - See gateway in center
   - Empty if no devices

2. **Create a device**
   - Go to Devices page
   - Click "Create Device"
   - Return to Network Map
   - Device appears within 5 seconds

3. **Click device node**
   - Details panel updates
   - Shows IP, status, etc.

4. **Add more devices**
   - They arrange in circle automatically
   - All update in real-time

5. **Delete a device**
   - Device disappears from map
   - Layout reorganizes
   - Node count updates

## Tips

- Keep Network Map page open to monitor changes
- Click nodes to inspect details
- Use legend to identify node types
- Watch node count in header
- Refresh manually if needed (button available)

---

This visual guide shows exactly what you'll see when you use the Network Map feature!
