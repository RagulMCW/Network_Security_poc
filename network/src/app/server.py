from flask import Flask, jsonify, request, send_file
import os
import datetime
import socket
import subprocess
import glob
from collections import defaultdict

app = Flask(__name__)

# In-memory storage for registered devices
registered_devices = {}
device_data_log = defaultdict(list)

# Enable CORS for simple HTML UI
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST')
    return response

@app.route('/')
def index():
    """Serve the dashboard HTML"""
    dashboard_path = '/app/network-monitor.html'
    if os.path.exists(dashboard_path):
        return send_file(dashboard_path)
    else:
        # Fallback to API info
        hostname = socket.gethostname()
        return jsonify({
            "message": "Network Security Monitor",
            "status": "running",
            "hostname": hostname,
            "timestamp": datetime.datetime.now().isoformat(),
            "server_id": os.getenv('SERVER_ID', 'flask-1'),
            "note": "Dashboard HTML not found. Access API endpoints directly."
        })

@app.route('/dashboard')
def dashboard():
    """Serve the dashboard HTML"""
    dashboard_path = '/app/network-monitor.html'
    if os.path.exists(dashboard_path):
        return send_file(dashboard_path)
    else:
        return "Dashboard not found", 404

@app.route('/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "services": ["tcpdump", "haproxy", "flask"],
        "timestamp": datetime.datetime.now().isoformat()
    }), 200

@app.route('/api/network/info')
def network_info():
    """Return basic network information"""
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except:
        local_ip = "unknown"
    
    return jsonify({
        "hostname": hostname,
        "local_ip": local_ip,
        "capture_status": "active",
        "timestamp": datetime.datetime.now().isoformat()
    })

@app.route('/api/captures')
def list_captures():
    """List available capture files"""
    captures_dir = '/captures'
    try:
        files = []
        if os.path.exists(captures_dir):
            for f in os.listdir(captures_dir):
                if f.endswith('.pcap') or 'capture_' in f:
                    file_path = os.path.join(captures_dir, f)
                    size = os.path.getsize(file_path)
                    files.append({
                        "filename": f,
                        "size_bytes": size,
                        "size_mb": round(size / 1024 / 1024, 2)
                    })
        
        return jsonify({
            "captures": files,
            "total_files": len(files)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/data', methods=['GET'])
def get_data():
    return jsonify({
        "data": ["network_packet_1", "network_packet_2", "network_packet_3"],
        "count": 3,
        "type": "network_monitoring_data"
    })

@app.route('/api/data', methods=['POST'])
def post_data():
    data = request.get_json()
    return jsonify({
        "message": "Network data received",
        "received_data": data,
        "timestamp": datetime.datetime.now().isoformat()
    }), 201

@app.route('/network/info')
def get_network_info():
    """Get connected devices and network information"""
    try:
        # Get latest capture file
        capture_dir = '/captures'
        devices = []
        total_packets = 0
        
        if os.path.exists(capture_dir):
            # Find latest capture file
            capture_files = sorted(glob.glob(os.path.join(capture_dir, 'capture_*.pcap*')))
            
            if capture_files:
                latest_file = capture_files[-1]
                
                # Use tcpdump to quickly extract IPs
                try:
                    result = subprocess.run(
                        ['tcpdump', '-n', '-r', latest_file, '-q'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    # Parse output to find unique IPs
                    unique_ips = set()
                    lines = result.stdout.split('\n')
                    total_packets = len([l for l in lines if l.strip()])
                    
                    for line in lines:
                        # Extract IPs from tcpdump output
                        parts = line.split()
                        for part in parts:
                            if '192.168.6.' in part:
                                # Clean up IP (remove port numbers)
                                ip = part.split(':')[0].split('.')[0:4]
                                if len(ip) == 4:
                                    clean_ip = '.'.join(ip)
                                    unique_ips.add(clean_ip)
                    
                    # Build device list
                    for ip in sorted(unique_ips):
                        devices.append(ip)
                
                except Exception as e:
                    print(f"Error parsing capture: {e}")
        
        return jsonify({
            "status": "success",
            "total_packets": total_packets,
            "devices": devices,
            "device_count": len(devices),
            "top_ips": devices[:10],
            "conversations": [f"{devices[i]} → {devices[i+1]}" for i in range(0, min(len(devices)-1, 4), 2)],
            "network": "192.168.6.0/24",
            "timestamp": datetime.datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e),
            "timestamp": datetime.datetime.now().isoformat()
        }), 500

@app.route('/capture/files')
def get_capture_files():
    """List all capture files"""
    try:
        capture_dir = '/captures'
        files = []
        
        if os.path.exists(capture_dir):
            for f in sorted(os.listdir(capture_dir)):
                if 'capture_' in f:
                    files.append(f)
        
        return jsonify(files)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/capture/analyze/<filename>')
def analyze_capture(filename):
    """Analyze a specific capture file"""
    try:
        capture_dir = '/captures'
        file_path = os.path.join(capture_dir, filename)
        
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404
        
        # Quick analysis with tcpdump
        result = subprocess.run(
            ['tcpdump', '-n', '-r', file_path, '-q'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Extract unique IPs
        unique_ips = set()
        lines = result.stdout.split('\n')
        
        for line in lines:
            parts = line.split()
            for part in parts:
                if '192.168.6.' in part:
                    ip = part.split(':')[0].split('.')[0:4]
                    if len(ip) == 4:
                        clean_ip = '.'.join(ip)
                        unique_ips.add(clean_ip)
        
        return jsonify({
            "filename": filename,
            "total_packets": len([l for l in lines if l.strip()]),
            "top_ips": sorted(list(unique_ips)),
            "timestamp": datetime.datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ============================================
# Virtual Device API Endpoints
# ============================================

@app.route('/api/device/register', methods=['POST'])
def register_device():
    """Register a new virtual device"""
    try:
        data = request.get_json()
        
        device_id = data.get('device_id')
        device_type = data.get('device_type', 'generic')
        ip_address = data.get('ip_address', request.remote_addr)
        mac_address = data.get('mac_address', 'unknown')
        
        if not device_id:
            return jsonify({"error": "device_id is required"}), 400
        
        # Store device info
        registered_devices[device_id] = {
            "device_id": device_id,
            "device_type": device_type,
            "ip_address": ip_address,
            "mac_address": mac_address,
            "registered_at": datetime.datetime.now().isoformat(),
            "last_seen": datetime.datetime.now().isoformat(),
            "status": "online"
        }
        
        print(f"[DEVICE REGISTERED] {device_id} ({device_type}) at {ip_address}")
        
        return jsonify({
            "status": "success",
            "message": f"Device {device_id} registered successfully",
            "device_info": registered_devices[device_id]
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Malware simulation endpoints (disguised as normal API endpoints)
@app.route('/api/analytics/track', methods=['POST'])
def analytics_track():
    """C2 Command & Control beacon endpoint (disguised as analytics)"""
    source_ip = request.remote_addr
    data = request.get_json(force=True, silent=True) or {}
    user_agent = request.headers.get('User-Agent', '')
    print(f"[SUSPICIOUS] Analytics tracking from {source_ip} | UA: {user_agent}")
    return jsonify({"status": "ok", "tracking_id": "12345"}), 200

@app.route('/api/backup/sync', methods=['POST'])
def backup_sync():
    """Data exfiltration endpoint (disguised as backup sync)"""
    source_ip = request.remote_addr
    data = request.get_json(force=True, silent=True) or {}
    user_agent = request.headers.get('User-Agent', '')
    data_size = data.get('size', 0)
    print(f"[SUSPICIOUS] Backup sync from {source_ip} | Size: {data_size} bytes | UA: {user_agent}")
    return jsonify({"status": "synced", "backup_id": "abc123"}), 200

@app.route('/api/files/upload', methods=['POST'])
def files_upload():
    """Malware file upload endpoint (disguised as file upload)"""
    source_ip = request.remote_addr
    data = request.get_json(force=True, silent=True) or {}
    user_agent = request.headers.get('User-Agent', '')
    filename = data.get('filename', 'unknown')
    print(f"[SUSPICIOUS] File upload from {source_ip} | File: {filename} | UA: {user_agent}")
    return jsonify({"status": "uploaded", "file_id": "xyz789"}), 200

# Legacy malware endpoints (keep for backward compatibility)
@app.route('/api/c2/beacon', methods=['POST'])
def c2_beacon():
    """C2 Command & Control beacon endpoint"""
    source_ip = request.remote_addr
    data = request.get_json(force=True, silent=True) or {}
    print(f"[MALWARE C2] Beacon from {source_ip}")
    return jsonify({"status": "received", "next_command": "none"}), 200

@app.route('/api/exfil/data', methods=['POST'])
def exfil_data():
    """Data exfiltration endpoint"""
    source_ip = request.remote_addr
    data = request.get_json(force=True, silent=True) or {}
    print(f"[MALWARE EXFIL] {data.get('size', 0)} bytes from {source_ip}")
    return jsonify({"status": "received"}), 200

@app.route('/api/upload/malware', methods=['POST'])
def upload_malware():
    """Malware file upload endpoint (EICAR test)"""
    source_ip = request.remote_addr
    data = request.get_json(force=True, silent=True) or {}
    print(f"[MALWARE UPLOAD] File '{data.get('filename')}' from {source_ip}")
    return jsonify({"status": "received"}), 200

@app.route('/api/device/data', methods=['POST'])
def receive_device_data():
    """Receive data from virtual devices"""
    try:
        data = request.get_json()
        
        device_id = data.get('device_id')
        if not device_id:
            return jsonify({"error": "device_id is required"}), 400
        
        # Update last seen time
        if device_id in registered_devices:
            registered_devices[device_id]['last_seen'] = datetime.datetime.now().isoformat()
            registered_devices[device_id]['status'] = 'online'
        
        # Store data in log (keep last 10 entries per device)
        device_data_log[device_id].append({
            "timestamp": data.get('timestamp'),
            "sensor_data": data.get('sensor_data'),
            "request_number": data.get('request_number')
        })
        
        # Keep only last 10 entries
        if len(device_data_log[device_id]) > 10:
            device_data_log[device_id] = device_data_log[device_id][-10:]
        
        print(f"[DATA RECEIVED] {device_id} - Request #{data.get('request_number')}")
        
        # Respond with optional commands (can be used for device control)
        response = {
            "status": "success",
            "message": "Data received successfully",
            "server_time": datetime.datetime.now().isoformat(),
            "device_id": device_id
        }
        
        # Example: Send commands to specific devices (optional)
        # if device_id == "device_001":
        #     response["command"] = "ping"
        
        return jsonify(response), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/device/status', methods=['GET'])
def device_status():
    """Get device status"""
    try:
        device_id = request.args.get('device_id')
        
        if device_id:
            # Return specific device status
            if device_id in registered_devices:
                return jsonify({
                    "status": "online",
                    "device": registered_devices[device_id],
                    "recent_data": device_data_log.get(device_id, [])[-5:]
                }), 200
            else:
                return jsonify({"error": "Device not found"}), 404
        else:
            # Return all devices status
            return jsonify({
                "total_devices": len(registered_devices),
                "devices": list(registered_devices.values()),
                "timestamp": datetime.datetime.now().isoformat()
            }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/devices/list', methods=['GET'])
def list_devices():
    """List all registered devices"""
    try:
        # Mark devices as offline if not seen in last 60 seconds
        current_time = datetime.datetime.now()
        
        for device_id, device_info in registered_devices.items():
            last_seen = datetime.datetime.fromisoformat(device_info['last_seen'])
            if (current_time - last_seen).seconds > 60:
                device_info['status'] = 'offline'
        
        return jsonify({
            "total_devices": len(registered_devices),
            "online_devices": len([d for d in registered_devices.values() if d['status'] == 'online']),
            "offline_devices": len([d for d in registered_devices.values() if d['status'] == 'offline']),
            "devices": list(registered_devices.values()),
            "timestamp": datetime.datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/devices/summary', methods=['GET'])
def devices_summary():
    """Get summary of all devices and their activity"""
    try:
        # Device type count
        device_types = defaultdict(int)
        for device in registered_devices.values():
            device_types[device['device_type']] += 1
        
        # IP range analysis
        ip_addresses = [d['ip_address'] for d in registered_devices.values()]
        
        return jsonify({
            "total_devices": len(registered_devices),
            "device_types": dict(device_types),
            "ip_addresses": ip_addresses,
            "online_count": len([d for d in registered_devices.values() if d['status'] == 'online']),
            "offline_count": len([d for d in registered_devices.values() if d['status'] == 'offline']),
            "network_range": "192.168.6.10-254",
            "timestamp": datetime.datetime.now().isoformat()
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    print(f"Starting Flask server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)