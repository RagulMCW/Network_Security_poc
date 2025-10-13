from flask import Flask, jsonify, request
import os
import datetime
import socket

app = Flask(__name__)

@app.route('/')
def hello():
    hostname = socket.gethostname()
    return jsonify({
        "message": "Network Security Monitor",
        "status": "running",
        "hostname": hostname,
        "timestamp": datetime.datetime.now().isoformat(),
        "server_id": os.getenv('SERVER_ID', 'flask-1')
    })

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

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    print(f"Starting Flask server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)