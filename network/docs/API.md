# Network Security Monitor - API Documentation

## Overview
REST API for network security monitoring and packet capture management.

## Base URL
- Local: `http://localhost:5000`
- WSL: `http://localhost:5000` (with port forwarding)

## Authentication
No authentication required for local development environment.

## Endpoints

### Health Check
**GET** `/health`

Returns service health status.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-10T10:30:00Z",
  "services": {
    "flask": "running",
    "capture": "active",
    "haproxy": "healthy"
  }
}
```

### Network Information
**GET** `/network/info`

Returns current network interface information.

**Response:**
```json
{
  "interfaces": [
    {
      "name": "eth0",
      "ip": "172.20.0.2",
      "netmask": "255.255.0.0",
      "status": "up"
    }
  ],
  "hostname": "network-monitor",
  "timestamp": "2024-01-10T10:30:00Z"
}
```

### Capture Files
**GET** `/capture/files`

Lists all available packet capture files.

**Response:**
```json
{
  "files": [
    {
      "filename": "capture_20240110_103000.pcap",
      "size": 1048576,
      "created": "2024-01-10T10:30:00Z",
      "packet_count": 1250
    }
  ],
  "total_files": 1,
  "total_size": 1048576
}
```

### Capture Statistics
**GET** `/capture/stats`

Returns packet capture statistics.

**Response:**
```json
{
  "total_packets": 15432,
  "capture_duration": "01:23:45",
  "protocols": {
    "TCP": 8456,
    "UDP": 3210,
    "ICMP": 456,
    "ARP": 234,
    "Other": 76
  },
  "top_sources": [
    {"ip": "192.168.1.100", "packets": 2345},
    {"ip": "192.168.1.101", "packets": 1876}
  ]
}
```

### Start Capture
**POST** `/capture/start`

Starts a new packet capture session.

**Request Body:**
```json
{
  "interface": "eth0",
  "filter": "tcp port 80",
  "duration": 300
}
```

**Response:**
```json
{
  "status": "started",
  "capture_id": "cap_20240110_103000",
  "filename": "capture_20240110_103000.pcap",
  "estimated_end": "2024-01-10T10:35:00Z"
}
```

### Stop Capture
**POST** `/capture/stop`

Stops the current packet capture session.

**Request Body:**
```json
{
  "capture_id": "cap_20240110_103000"
}
```

**Response:**
```json
{
  "status": "stopped",
  "capture_id": "cap_20240110_103000",
  "final_packet_count": 1250,
  "file_size": 1048576
}
```

### Download Capture
**GET** `/capture/download/{filename}`

Downloads a specific capture file.

**Parameters:**
- `filename`: Name of the capture file

**Response:**
- Content-Type: `application/octet-stream`
- Content-Disposition: `attachment; filename="{filename}"`

## Error Responses

### 400 Bad Request
```json
{
  "error": "Invalid request",
  "message": "Missing required parameter: interface",
  "timestamp": "2024-01-10T10:30:00Z"
}
```

### 404 Not Found
```json
{
  "error": "Resource not found",
  "message": "Capture file not found: invalid_file.pcap",
  "timestamp": "2024-01-10T10:30:00Z"
}
```

### 500 Internal Server Error
```json
{
  "error": "Internal server error",
  "message": "Failed to start packet capture",
  "timestamp": "2024-01-10T10:30:00Z"
}
```

## Rate Limiting
- Default: 100 requests per minute per IP
- Burst: 20 requests per second

## WebSocket Events
**WS** `/ws/capture`

Real-time packet capture events.

**Message Types:**
```json
{
  "type": "packet_captured",
  "data": {
    "packet_id": 12345,
    "timestamp": "2024-01-10T10:30:00.123Z",
    "protocol": "TCP",
    "source": "192.168.1.100",
    "destination": "192.168.1.200"
  }
}
```

## Example Usage

### Python Client
```python
import requests

# Health check
response = requests.get('http://localhost:5000/health')
print(response.json())

# Start capture
capture_data = {
    "interface": "eth0",
    "filter": "tcp",
    "duration": 60
}
response = requests.post('http://localhost:5000/capture/start', 
                        json=capture_data)
print(response.json())
```

### curl Examples
```bash
# Health check
curl http://localhost:5000/health

# Get network info
curl http://localhost:5000/network/info

# List capture files
curl http://localhost:5000/capture/files

# Start capture
curl -X POST http://localhost:5000/capture/start \
     -H "Content-Type: application/json" \
     -d '{"interface":"eth0","duration":60}'

# Download capture
curl -O http://localhost:5000/capture/download/capture_latest.pcap
```

## HAProxy Statistics
**GET** `http://localhost:8080/stats`

Access HAProxy load balancer statistics dashboard.

Features:
- Real-time server status
- Request counters
- Response time metrics
- Health check status