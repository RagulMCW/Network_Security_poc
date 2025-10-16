# Virtual Device System

Simple tool to create virtual network devices for testing and monitoring.

## Quick Start

### 1. Build Device Image (First Time Only)
```batch
manage_devices.bat build
```

### 2. Create Devices
```batch
# Create 5 generic devices
manage_devices.bat create 5

# Create specific device types
manage_devices.bat create 10 iot_sensor
manage_devices.bat create 5 smartphone
manage_devices.bat create 3 laptop
manage_devices.bat create 2 camera
```

### 3. Manage Devices
```batch
# List all devices
manage_devices.bat list

# View device logs
manage_devices.bat logs 001

# Check statistics
manage_devices.bat stats

# Stop devices
manage_devices.bat stop

# Start devices
manage_devices.bat start

# Remove all devices
manage_devices.bat remove
```

## Device Types

| Type | Description | Data Generated |
|------|-------------|----------------|
| `iot_sensor` | IoT sensors | Temperature, humidity, pressure |
| `smartphone` | Mobile devices | Location, battery, network |
| `laptop` | Computers | CPU, memory, disk usage |
| `camera` | Security cameras | Motion, recording status |
| `generic` | Basic device | Status, uptime |

## How It Works

1. Each device runs in a Docker container
2. Gets unique IP address (192.168.6.10, .11, .12, etc.)
3. Sends data to server every 5-10 seconds
4. All traffic captured by tcpdump
5. Visible in dashboard at http://localhost:8080

## Network Layout

```
Server:     192.168.6.131  (Flask API + tcpdump)
Device 1:   192.168.6.10
Device 2:   192.168.6.11
Device 3:   192.168.6.12
...
```

## Troubleshooting

**Issue: Network not found**
```batch
cd ..\network
wsl bash wsl-manager.sh start
```

**Issue: Can't create devices**
```batch
# Rebuild image
manage_devices.bat build

# Check Docker
wsl docker ps
wsl docker network ls
```

**Issue: Devices not sending data**
```batch
# Check logs
manage_devices.bat logs 001

# Restart devices
manage_devices.bat stop
manage_devices.bat start
```

## Examples

```batch
# Create 20 IoT sensors
manage_devices.bat create 20 iot_sensor

# Create mixed devices
manage_devices.bat create 5 iot_sensor
manage_devices.bat create 3 smartphone
manage_devices.bat create 2 laptop

# Monitor activity
manage_devices.bat list
manage_devices.bat stats

# View specific device
manage_devices.bat logs 001

# Clean up
manage_devices.bat remove
```

## Requirements

- Docker with WSL2
- Main server running (network/wsl-manager.sh)
- Custom network: custom_net (192.168.6.0/24)

## Files

- `Dockerfile` - Device container image
- `device_simulator.py` - Device behavior script
- `manage_devices.bat` - Windows management tool
- `manage_devices.sh` - Linux management tool
