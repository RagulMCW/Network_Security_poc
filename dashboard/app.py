"""
Network Security Dashboard - Control Panel
Manage Docker network, devices, honeypot, and attackers from a web UI
"""

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import subprocess
import json
import os
from datetime import datetime
import re
import threading

# Load environment variables from MCP agent config
try:
    from dotenv import load_dotenv
    from pathlib import Path
    
    # Load MCP agent .env file
    mcp_env_path = Path(__file__).parent.parent / 'mcp_agent' / 'config' / '.env'
    if mcp_env_path.exists():
        load_dotenv(mcp_env_path)
        print(f"✅ Loaded MCP agent environment from: {mcp_env_path}")
    else:
        print(f"⚠️ MCP agent .env not found at: {mcp_env_path}")
except ImportError:
    print("⚠️ python-dotenv not installed, environment variables must be set manually")

app = Flask(__name__)
CORS(app)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NETWORK_DIR = os.path.join(BASE_DIR, 'network')
DEVICES_DIR = os.path.join(BASE_DIR, 'devices')
HONEYPOT_DIR = os.path.join(BASE_DIR, 'honey_pot')
ATTACKERS_DIR = os.path.join(BASE_DIR, 'attackers', 'dos_attacker')
BLOCKED_DEVICES_FILE = os.path.join(BASE_DIR, 'dashboard', 'blocked_devices.json')

# WSL paths (converted)
WSL_NETWORK_DIR = '/mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/network'
WSL_DEVICES_DIR = '/mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/devices'
WSL_HONEYPOT_DIR = '/mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/honey_pot'
WSL_ATTACKERS_DIR = '/mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/attackers/dos_attacker'

def load_blocked_devices():
    """Load blocked devices from JSON file"""
    try:
        if os.path.exists(BLOCKED_DEVICES_FILE):
            with open(BLOCKED_DEVICES_FILE, 'r') as f:
                return json.load(f)
        return []
    except Exception as e:
        print(f"Error loading blocked devices: {e}")
        return []

def save_blocked_devices(blocked_devices):
    """Save blocked devices to JSON file"""
    try:
        with open(BLOCKED_DEVICES_FILE, 'w') as f:
            json.dump(blocked_devices, f, indent=2)
        return True
    except Exception as e:
        print(f"Error saving blocked devices: {e}")
        return False

def add_blocked_device(ip, reason="Malware detected", container_id=None):
    """Add a device to blocked list"""
    blocked = load_blocked_devices()
    # Check if already blocked
    if not any(d['ip'] == ip for d in blocked):
        blocked.append({
            'ip': ip,
            'blocked_at': datetime.now().isoformat(),
            'reason': reason,
            'container_id': container_id,
            'status': 'blocked'
        })
        save_blocked_devices(blocked)
    return True

def remove_blocked_device(ip):
    """Remove a device from blocked list"""
    blocked = load_blocked_devices()
    blocked = [d for d in blocked if d['ip'] != ip]
    save_blocked_devices(blocked)
    return True

def run_wsl_command(command, timeout=30):
    """Execute WSL command and return output"""
    try:
        result = subprocess.run(
            ['wsl', 'bash', '-c', command],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',  # Replace problematic characters instead of crashing
            timeout=timeout
        )
        return {
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr
        }
    except Exception as e:
        return {
            'success': False,
            'output': '',
            'error': str(e)
        }

def run_cmd_command(command, cwd=None):
    """Execute Windows command"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',  # Replace problematic characters instead of crashing
            cwd=cwd,
            timeout=30
        )
        return {
            'success': result.returncode == 0,
            'output': result.stdout,
            'error': result.stderr
        }
    except Exception as e:
        return {
            'success': False,
            'output': '',
            'error': str(e)
        }


def local_summarize_analysis(analysis_text: str) -> str:
    """Create a compact, human-friendly summary from the raw analysis text.

    Best-effort fallback when the AI summarization API is unavailable. It
    extracts key sections from a typical analysis report.
    """
    try:
        lines = [l.strip() for l in analysis_text.splitlines() if l.strip()]
        total_packets = None
        for l in lines:
            m = re.search(r'Total Packets[:\s]+(\d+)', l, re.IGNORECASE)
            if m:
                total_packets = m.group(1)
                break

        def extract_block(header_keywords, max_lines=6):
            for i, ln in enumerate(lines):
                if any(k in ln.upper() for k in header_keywords):
                    return lines[i+1:i+1+max_lines]
            return []

        proto_block = extract_block(['PROTOCOL DISTRIBUTION'])
        top_sources = extract_block(['TOP SOURCE', 'TOP SOURCE IPS'])
        top_dests = extract_block(['TOP DEST', 'TOP DESTINATION'])
        anomalies = extract_block(['ANOMALIES', 'SECURITY ANOMALIES'])

        parts = []
        if total_packets:
            parts.append(f"Total packets: {total_packets}")
        if proto_block:
            parts.append("Protocol distribution: " + ", ".join(proto_block[:3]))
        if top_sources:
            parts.append("Top source IPs: " + ", ".join(top_sources[:3]))
        if top_dests:
            parts.append("Top destination IPs: " + ", ".join(top_dests[:3]))
        if anomalies:
            parts.append("Anomalies detected: " + "; ".join(anomalies[:5]))

        if not parts:
            return "No structured summary could be extracted from the analysis output. See raw data."

        return "\n".join(parts)
    except Exception:
        return "Failed to generate local summary"

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/status')
def get_status():
    """Get status of all components - OPTIMIZED for fast loading"""
    
    # Check Docker network (fast)
    network_result = run_wsl_command('docker network ls | grep custom_net', timeout=5)
    network_exists = network_result['success'] and 'custom_net' in network_result['output']
    
    # Get running containers (fast - single command)
    containers_result = run_wsl_command('docker ps --format "{{.Names}}|{{.Status}}|{{.Image}}"', timeout=5)
    containers = []
    
    if containers_result['success']:
        for line in containers_result['output'].strip().split('\n'):
            if line:
                parts = line.split('|')
                if len(parts) >= 3:
                    containers.append({
                        'name': parts[0],
                        'status': parts[1],
                        'image': parts[2]
                    })
    
    # Count devices (fast - name matching)
    device_containers = [c for c in containers if c['name'].startswith('device_') or c['name'].startswith('vdevice_')]
    
    # Quick categorization by name patterns (no container inspection needed)
    production_devices = []
    honeypot_devices = []
    
    for c in device_containers:
        # Simple heuristic: if name contains 'honeypot' or known honeypot pattern
        if 'honeypot' in c['name'].lower() or c['name'].startswith('hp_'):
            honeypot_devices.append({
                'name': c['name'],
                'status': c['status'],
                'image': c['image']
            })
        else:
            production_devices.append({
                'name': c['name'],
                'status': c['status'],
                'image': c['image']
            })
    
    # Check Beelzebub (fast - name matching)
    beelzebub_running = any('beelzebub' in c['name'].lower() for c in containers)
    
    # Check attackers (fast - name matching)
    dos_attacker_running = any(c['name'] == 'hping3-attacker' for c in containers)
    ssh_attacker_running = any(c['name'] == 'ssh-attacker' for c in containers)
    malware_attacker_running = any(c['name'] == 'malware_attacker' for c in containers)
    endpoint_behavior_attacker_running = any(c['name'] == 'endpoint_behavior_attacker' for c in containers)
    attacker_running = dos_attacker_running or ssh_attacker_running or malware_attacker_running or endpoint_behavior_attacker_running
    
    # Check network monitor (fast - name matching)
    monitor_running = any(c['name'] in ['monitor', 'net-monitor-wan', 'network-monitor'] for c in containers)
    
    # Load blocked devices
    blocked_devices = load_blocked_devices()
    
    return jsonify({
        'network': {
            'exists': network_exists,
            'name': 'custom_net' if network_exists else None
        },
        'devices': {
            'count': len(device_containers),
            'containers': device_containers
        },
        'production_devices': production_devices,
        'blocked_devices': blocked_devices,
        'beelzebub': {
            'running': beelzebub_running,
            'containers': [c for c in containers if 'beelzebub' in c['name'].lower()],
            'devices': honeypot_devices
        },
        'attackers': {
            'running': attacker_running,
            'dos_running': dos_attacker_running,
            'ssh_running': ssh_attacker_running,
            'malware_running': malware_attacker_running,
            'endpoint_behavior_running': endpoint_behavior_attacker_running,
            'containers': [c for c in containers if 'attacker' in c['name']]
        },
        'monitor': {
            'running': monitor_running,
            'container': next((c for c in containers if c['name'] in ['monitor', 'net-monitor-wan', 'network-monitor']), None)
        },
        'all_containers': containers
    })

@app.route('/api/network/create', methods=['POST'])
def create_network():
    """Create Docker custom_net network"""
    
    # Check if network exists
    check = run_wsl_command('docker network ls | grep custom_net')
    if check['success'] and 'custom_net' in check['output']:
        return jsonify({
            'success': True,
            'message': 'Network already exists',
            'existing': True
        })
    
    # Create network
    result = run_wsl_command('docker network create --subnet=192.168.6.0/24 custom_net')
    
    return jsonify({
        'success': result['success'],
        'message': 'Network created successfully' if result['success'] else result['error'],
        'output': result['output']
    })

@app.route('/api/network/delete', methods=['POST'])
def delete_network():
    """Delete Docker custom_net network"""
    
    # Stop all containers on network first
    stop_result = run_wsl_command('docker ps -q --filter network=custom_net | xargs -r docker stop')
    
    # Remove network
    result = run_wsl_command('docker network rm custom_net')
    
    return jsonify({
        'success': result['success'],
        'message': 'Network deleted successfully' if result['success'] else result['error'],
        'output': result['output']
    })

@app.route('/api/devices/list')
def list_devices():
    """List all device containers"""
    
    # Check both vdevice_ and device_ naming patterns
    result = run_wsl_command('docker ps -a --filter name=device --format "{{.Names}}|{{.Status}}|{{.ID}}"')
    
    devices = []
    if result['success']:
        for line in result['output'].strip().split('\n'):
            if line and ('vdevice_' in line or 'device_' in line):
                parts = line.split('|')
                if len(parts) >= 3:
                    # Extract device number from name like device_1, device_2, vdevice_001, etc.
                    match = re.search(r'(?:v)?device_(\d+)', parts[0])
                    device_id = match.group(1) if match else 'unknown'
                    
                    devices.append({
                        'id': device_id,
                        'name': parts[0],
                        'status': parts[1],
                        'container_id': parts[2],
                        'running': 'Up' in parts[1]
                    })
    
    return jsonify({
        'success': True,
        'devices': devices,
        'count': len(devices)
    })

@app.route('/api/devices/create', methods=['POST'])
def create_device():
    """Create a new device container"""
    
    data = request.json
    device_type = data.get('type', 'generic')  # iot_sensor, smartphone, laptop, camera, generic
    
    # Ensure custom_net network exists
    check_network = run_wsl_command('docker network inspect custom_net >/dev/null 2>&1')
    if not check_network['success']:
        print("Creating custom_net network...")
        create_network = run_wsl_command('docker network create --driver bridge --subnet=192.168.6.0/24 --gateway=192.168.6.1 custom_net')
        if not create_network['success']:
            return jsonify({
                'success': False,
                'message': 'Failed to create network',
                'error': create_network['error']
            })
    
    # Get next device number (use vdevice_ naming convention)
    result = run_wsl_command('docker ps -a --filter name=vdevice_ --format "{{.Names}}"')
    existing_ids = []
    
    if result['success']:
        for line in result['output'].strip().split('\n'):
            if line and 'vdevice_' in line:
                match = re.search(r'vdevice_(\d+)', line)
                if match:
                    existing_ids.append(int(match.group(1)))
    
    next_id = max(existing_ids) + 1 if existing_ids else 1
    device_name = f"vdevice_{next_id:03d}"
    device_id = f"device_{next_id:03d}"
    
    # Build device image if not exists
    print(f"Building device image...")
    build_cmd = f'cd /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/devices && docker build -t device-simulator .'
    build_result = run_wsl_command(build_cmd, timeout=180)
    
    if not build_result['success']:
        return jsonify({
            'success': False,
            'message': 'Failed to build device image',
            'error': build_result['error']
        })
    
    # Run device container
    run_cmd = f'docker run -d --name {device_name} --network custom_net -e DEVICE_ID={device_id} -e DEVICE_TYPE={device_type} -e SERVER_URL=http://192.168.6.131:5000 -e REQUEST_INTERVAL=10 device-simulator'
    
    print(f"Running device container: {run_cmd}")
    run_result = run_wsl_command(run_cmd)
    
    if not run_result['success']:
        return jsonify({
            'success': False,
            'message': f'Failed to create device: {run_result["error"]}',
            'error': run_result['error']
        })
    
    return jsonify({
        'success': True,
        'message': f'Device {device_name} created successfully',
        'device': {
            'id': next_id,
            'name': device_name,
            'type': device_type,
            'device_id': device_id
        }
    })

@app.route('/api/devices/delete/<device_id>', methods=['DELETE'])
def delete_device(device_id):
    """Delete a device container and clean up"""
    
    # device_id is the full container name (e.g., "vdevice_001" or "malware_attacker")
    # Use it directly without adding prefixes
    device_name = device_id
    
    # Stop container
    stop_result = run_wsl_command(f'docker stop {device_name}')
    
    # Remove container
    rm_result = run_wsl_command(f'docker rm {device_name}')
    
    success = stop_result['success'] or rm_result['success']
    
    return jsonify({
        'success': success,
        'message': f'Device {device_name} deleted successfully' if success else 'Failed to delete device',
        'output': rm_result['output']
    })

@app.route('/api/devices/cleanup', methods=['POST'])
def cleanup_devices():
    """Remove all stopped device containers and unused images"""
    
    # Remove stopped containers
    rm_containers = run_wsl_command('docker ps -a --filter name=device_ --filter status=exited -q | xargs -r docker rm')
    
    # Optionally remove unused images (commented out for safety)
    # rm_images = run_wsl_command('docker images -f dangling=true -q | xargs -r docker rmi')
    
    return jsonify({
        'success': True,
        'message': 'Cleanup completed',
        'removed_containers': rm_containers['output']
    })

@app.route('/api/devices/block', methods=['POST'])
def block_device():
    """Block a device by IP address - stops and removes the container"""
    data = request.get_json()
    ip = data.get('ip')
    reason = data.get('reason', 'Malware detected by AI agent')
    
    if not ip:
        return jsonify({'success': False, 'message': 'IP address required'}), 400
    
    try:
        # Get all containers with their networks
        ps_result = run_wsl_command('docker ps --format "{{.ID}}:{{.Names}}"', timeout=10)
        
        container_found = False
        container_id = None
        container_name = None
        
        if ps_result['success'] and ps_result['output'].strip():
            # Check each container for the IP
            for line in ps_result['output'].strip().split('\n'):
                if ':' in line:
                    cid, cname = line.split(':', 1)
                    # Check if this container has the target IP on any network
                    # Try custom_net first (most common)
                    ip_check_cmd = f'docker inspect {cid} --format "{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}" 2>/dev/null'
                    ip_check = run_wsl_command(ip_check_cmd, timeout=5)
                    
                    if ip_check['success'] and ip_check['output'].strip() == ip:
                        container_id = cid
                        container_name = cname
                        container_found = True
                        break
                    
                    # If not on custom_net, check all networks
                    inspect_result = run_wsl_command(f'docker inspect {cid} --format "{{{{.NetworkSettings.Networks}}}}"', timeout=5)
                    if inspect_result['success'] and (ip in inspect_result['output'] or f"{ip}/" in inspect_result['output']):
                        container_id = cid
                        container_name = cname
                        container_found = True
                        break
        
        if container_found and container_id:
            # Stop and remove the container
            print(f"🛑 Blocking container: {container_name} ({container_id}) with IP {ip}")
            stop_result = run_wsl_command(f'docker stop {container_id}', timeout=15)
            rm_result = run_wsl_command(f'docker rm -f {container_id}', timeout=10)
            
            # Add to blocked devices list
            add_blocked_device(ip, reason, container_id)
            
            return jsonify({
                'success': True,
                'message': f'Device {ip} blocked - container {container_name} stopped and removed',
                'ip': ip,
                'container_id': container_id,
                'container_name': container_name,
                'stopped': stop_result['success'],
                'removed': rm_result['success']
            })
        else:
            # No container found, but still add to blocked list
            print(f"⚠️ No container found with IP {ip}, adding to blocked list only")
            add_blocked_device(ip, reason)
            return jsonify({
                'success': True,
                'message': f'Device {ip} added to blocked list (no active container found with this IP)',
                'ip': ip,
                'warning': 'Container not found - may need manual cleanup'
            })
            
    except Exception as e:
        print(f"❌ Error blocking device {ip}: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/devices/unblock', methods=['POST'])
def unblock_device():
    """Unblock a device by IP or container name - removes from blocked list and restores network"""
    data = request.get_json()
    ip = data.get('ip')
    container_name = data.get('container_name')
    
    if not ip and not container_name:
        return jsonify({'success': False, 'message': 'IP address or container name required'}), 400
    
    try:
        # Find device in blocked_devices.json
        blocked_devices = load_blocked_devices()
        device_to_remove = None
        
        for device in blocked_devices:
            if device.get('original_ip') == ip or device.get('container_name') == container_name:
                device_to_remove = device
                break
        
        if not device_to_remove:
            return jsonify({'success': False, 'message': f'Device not found in blocked list'}), 404
        
        container = device_to_remove.get('container_name')
        original_ip = device_to_remove.get('original_ip', ip)
        method = device_to_remove.get('method', 'dnat_reroute')
        
        # Restore based on method
        if method == 'network_switch':
            # Disconnect from honeypot and reconnect to production
            honeypot_network = 'honey_pot_honeypot_net'
            disconnect_cmd = f'docker network disconnect {honeypot_network} {container} 2>/dev/null || true'
            run_wsl_command(disconnect_cmd)
            
            reconnect_cmd = f'docker network connect custom_net {container}'
            reconnect_result = run_wsl_command(reconnect_cmd)
            
            if not reconnect_result['success']:
                return jsonify({'success': False, 'message': f'Failed to restore network: {reconnect_result["output"]}'}), 500
        else:
            # Clear DNAT iptables rules
            iptables_clear = run_wsl_command(f'sudo iptables -t nat -D PREROUTING -s {original_ip} -j DNAT --to-destination 192.168.7.3 2>/dev/null || true')
            iptables_drop_clear = run_wsl_command(f'sudo iptables -D FORWARD -s {original_ip} -j DROP 2>/dev/null || true')
        
        # Remove from blocked devices list
        updated_devices = [d for d in blocked_devices if d != device_to_remove]
        save_blocked_devices(updated_devices)
        
        return jsonify({
            'success': True,
            'message': f'Device {container or ip} restored to production network',
            'ip': original_ip,
            'container': container
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/cleanup/all', methods=['POST'])
def cleanup_all():
    """NUCLEAR OPTION: Stop and remove ALL containers, images, and networks from this project"""
    
    results = []
    
    # 1. Stop ALL running containers (including dashboard will stop itself)
    print("🛑 Stopping all containers...")
    stop_result = run_wsl_command('docker stop $(docker ps -aq) 2>/dev/null || true')
    results.append(f"Stopped containers: {stop_result['output']}")
    
    # 2. Remove ALL containers (force remove)
    print("🗑️ Removing all containers...")
    rm_containers = run_wsl_command('docker rm -f $(docker ps -aq) 2>/dev/null || true')
    results.append(f"Removed containers: {rm_containers['output']}")
    
    # 3. Remove ALL project-related images (comprehensive list)
    print("🖼️ Removing ALL project images...")
    images_to_remove = [
        # Device images
        'device-simulator',
        'vdevice',
        # Attacker images
        'dos-attacker',
        'ssh-attacker',
        'malware-attacker',
        'malware_attacker',
        # Honeypot images
        'honeypot-server',
        'beelzebub',
        'cowrie',
        # Monitor images
        'monitor-image',
        'net-monitor-wan',
        'network-monitor',
        'network-security-monitor',
        'honeypot-monitor',
        # Dashboard
        'dashboard-app'
    ]
    
    for image in images_to_remove:
        rm_image = run_wsl_command(f'docker rmi -f {image} 2>/dev/null || true')
        if rm_image['output'].strip():
            results.append(f"Removed image: {image}")
    
    # 4. Remove ALL images containing project keywords
    print("🧨 Removing all network_security_poc images...")
    rm_all_project = run_wsl_command('docker images | grep -E "network_security_poc|device|attacker|honeypot|monitor" | awk \'{print $3}\' | xargs -r docker rmi -f 2>/dev/null || true')
    if rm_all_project['output'].strip():
        results.append(f"Bulk removed project images")
    
    # 5. Remove ALL unused/dangling images
    print("🧹 Removing ALL dangling and unused images...")
    prune_images = run_wsl_command('docker image prune -af')
    results.append(f"Pruned images: {prune_images['output']}")
    
    # 6. Remove ALL custom networks
    print("🌐 Removing ALL custom networks...")
    networks = ['custom_net', 'honey_pot_honeypot_net', 'attacker_net', 'monitor_net']
    for net in networks:
        rm_network = run_wsl_command(f'docker network rm {net} 2>/dev/null || true')
        if rm_network['output'].strip():
            results.append(f"Removed network: {net}")
    
    # 7. Remove ALL unused networks
    print("🔌 Pruning unused networks...")
    prune_networks = run_wsl_command('docker network prune -f')
    results.append(f"Pruned networks: {prune_networks['output']}")
    
    # 8. Clean up ALL volumes
    print("💾 Removing ALL unused volumes...")
    prune_volumes = run_wsl_command('docker volume prune -af')
    results.append(f"Pruned volumes: {prune_volumes['output']}")
    
    # 9. Final aggressive system prune (remove everything unused)
    print("🧼 Final COMPLETE system cleanup...")
    system_prune = run_wsl_command('docker system prune -af --volumes')
    results.append(f"System prune: {system_prune['output']}")
    
    return jsonify({
        'success': True,
        'message': '🧨 COMPLETE CLEANUP FINISHED - All containers, images, and networks removed!',
        'details': results
    })

@app.route('/api/beelzebub/start', methods=['POST'])
def start_beelzebub():
    """Start Beelzebub honeypot"""
    
    # Ensure honeypot_net exists
    honeypot_check = run_wsl_command('docker network ls | grep honeypot_net')
    if not (honeypot_check['success'] and 'honeypot_net' in honeypot_check['output']):
        create_result = run_wsl_command('docker network create --subnet=192.168.7.0/24 honeypot_net')
        if not create_result['success']:
            return jsonify({
                'success': False,
                'message': 'Failed to create honeypot_net'
            })
    
    # Start Beelzebub honeypot using docker-compose-simple.yml
    result = run_wsl_command(f'cd {WSL_HONEYPOT_DIR} && docker compose -f docker-compose-simple.yml up -d')
    
    return jsonify({
        'success': result['success'],
        'message': 'Beelzebub started successfully' if result['success'] else result['error'],
        'output': result['output']
    })

@app.route('/api/beelzebub/stop', methods=['POST'])
def stop_beelzebub():
    """Stop Beelzebub honeypot"""
    
    result = run_wsl_command(f'cd {WSL_HONEYPOT_DIR} && docker compose -f docker-compose-simple.yml down')
    
    return jsonify({
        'success': result['success'],
        'message': 'Beelzebub stopped successfully' if result['success'] else result['error']
    })

@app.route('/api/beelzebub/logs')
def get_beelzebub_logs():
    """Get ALL Beelzebub logs - unified view of all honeypot activity"""
    
    # Main log file
    log_file = os.path.join(HONEYPOT_DIR, 'logs', 'beelzebub.log')
    
    if not os.path.exists(log_file):
        return jsonify({
            'success': True,
            'logs': [],
            'count': 0,
            'message': 'No logs available yet. Start honeypot with START.bat'
        })
    
    logs = []
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            
            # Get last 30 lines - Real-time view of recent interactions
            for line in lines[-30:]:
                line = line.strip()
                if not line:
                    continue
                    
                try:
                    log_entry = json.loads(line)
                    
                    # Extract key info for dashboard - ALL events
                    event = log_entry.get('event', {})
                    formatted_log = {
                        'time': event.get('DateTime', log_entry.get('time')),
                        'protocol': event.get('Protocol', 'Unknown'),
                        'source_ip': event.get('SourceIp', 'Unknown'),
                        'user': event.get('User', ''),
                        'command': event.get('Command', ''),
                        'output': event.get('CommandOutput', ''),
                        'msg': event.get('Msg', log_entry.get('msg')),
                        'level': log_entry.get('level', 'info'),
                        'raw': log_entry
                    }
                    logs.append(formatted_log)
                    
                except json.JSONDecodeError:
                    continue
        
        logs.reverse()  # Most recent first
        
        return jsonify({
            'success': True,
            'logs': logs,
            'count': len(logs),
            'log_file': 'beelzebub.log'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'logs': [],
            'count': 0,
            'message': f'Error reading logs: {str(e)}'
        })

@app.route('/api/beelzebub/stats')
def get_beelzebub_stats():
    """Get Beelzebub statistics"""
    
    # Check if Beelzebub containers are running
    check_result = run_wsl_command('docker ps --filter "name=beelzebub" --format "{{.Names}},{{.Status}}"')
    
    running = False
    services_active = []
    
    if check_result['success'] and check_result['output'].strip():
        running = True
        for line in check_result['output'].strip().split('\n'):
            if line:
                container_name = line.split(',')[0]
                services_active.append(container_name)
    
    # Count log entries if Beelzebub is/was running
    logs_dir = os.path.join(HONEYPOT_DIR, 'logs')
    total_interactions = 0
    
    if os.path.exists(logs_dir):
        for log_file in os.listdir(logs_dir):
            if log_file.endswith('.log'):
                file_path = os.path.join(logs_dir, log_file)
                try:
                    with open(file_path, 'r') as f:
                        total_interactions += len(f.readlines())
                except:
                    pass
    
    return jsonify({
        'success': True,
        'running': running,
        'services': services_active,
        'total_interactions': total_interactions,
        'ports': {
            'ssh': 2222,
            'http_admin': 8080,
            'http_alt': 8081,
            'mysql': 3306,
            'postgresql': 5432,
            'log_viewer': 8888
        }
    })

@app.route('/api/beelzebub/llm_logs')
def get_llm_logs():
    """Get LLM AI response logs from Beelzebub honeypot"""
    
    beelzebub_log = os.path.join(HONEYPOT_DIR, 'logs', 'beelzebub.log')
    llm_jsonl_file = os.path.join(HONEYPOT_DIR, 'logs', 'llm_responses.jsonl')
    
    llm_responses = []
    
    # Primary source: Parse from main beelzebub.log
    if os.path.exists(beelzebub_log) and os.path.getsize(beelzebub_log) > 0:
        try:
            with open(beelzebub_log, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        
                        # Look for SSH Raw Command events with CommandOutput
                        if log_entry.get('msg') == 'New Event' and 'event' in log_entry:
                            event = log_entry['event']
                            command = event.get('Command', '').strip()
                            output = event.get('CommandOutput', '').strip()
                            
                            # Only include if command has AI-generated output (not empty, not "command not found")
                            if command and output and output != 'command not found' and len(output) > 0:
                                llm_responses.append({
                                    'time': event.get('DateTime', log_entry.get('time', 'N/A')),
                                    'source_ip': event.get('SourceIp', 'unknown'),
                                    'user': event.get('User', 'unknown'),
                                    'protocol': event.get('Protocol', 'SSH'),
                                    'command': command,
                                    'ai_response': output,
                                    'msg': event.get('Msg', 'SSH Raw Command')
                                })
                    except (json.JSONDecodeError, KeyError):
                        continue
        except Exception as e:
            print(f"Error reading beelzebub.log: {e}")
    
    # Fallback: Try reading from llm_responses.jsonl if it exists
    if not llm_responses and os.path.exists(llm_jsonl_file) and os.path.getsize(llm_jsonl_file) > 0:
        try:
            with open(llm_jsonl_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line.strip())
                        llm_responses.append({
                            'time': log_entry.get('time', 'N/A'),
                            'source_ip': log_entry.get('source_ip', 'unknown'),
                            'user': log_entry.get('user', 'unknown'),
                            'protocol': log_entry.get('protocol', 'SSH'),
                            'command': log_entry.get('command', ''),
                            'ai_response': log_entry.get('ai_response', ''),
                            'msg': log_entry.get('msg', 'SSH Command')
                        })
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            print(f"Error reading LLM JSONL: {e}")
    
    # Sort by time (newest first) and limit to last 100
    llm_responses.reverse()
    
    return jsonify({
        'success': True,
        'llm_responses': llm_responses[:100],  # Return last 100 responses
        'total_count': len(llm_responses)
    })

@app.route('/api/beelzebub/attackers')
def get_honeypot_attackers():
    """Get detailed attacker information from honeypot logs"""
    
    from collections import defaultdict
    from datetime import datetime
    
    # Beelzebub creates attacks.jsonl with structured attack data
    # Also check network_attacks.jsonl for DoS/flood attacks (hping3, etc.)
    attacks_file = os.path.join(HONEYPOT_DIR, 'logs', 'attacks.jsonl')
    network_attacks_file = os.path.join(HONEYPOT_DIR, 'logs', 'network_attacks.jsonl')
    ssh_log = os.path.join(HONEYPOT_DIR, 'logs', 'ssh-22.log')
    http_log = os.path.join(HONEYPOT_DIR, 'logs', 'http-8080.log')
    
    if not os.path.exists(attacks_file) and not os.path.exists(ssh_log) and not os.path.exists(http_log) and not os.path.exists(network_attacks_file):
        return jsonify({
            'success': True,
            'attackers': [],
            'total_attacks': 0,
            'unique_ips': 0,
            'credentials_tried': [],
            'commands_executed': [],
            'http_requests': [],
            'rerouted_devices': [],
            'message': 'No attack logs found. Start honeypot and wait for connections.'
        })
    
    # Parse logs and extract attacker data
    attackers_data = defaultdict(lambda: {
        'ip': '',
        'first_seen': None,
        'last_seen': None,
        'total_interactions': 0,
        'protocols': set(),
        'ports': set(),
        'credentials': [],
        'commands': [],
        'http_requests': [],
        'success_auth': False
    })
    
    all_credentials = []
    all_commands = []
    all_http_requests = []
    total_attacks = 0
    
    try:
        # Read attacks.jsonl if it exists
        if os.path.exists(attacks_file) and os.path.getsize(attacks_file) > 0:
            with open(attacks_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        attack = json.loads(line)
                        total_attacks += 1
                        
                        # Extract attacker IP
                        ip = attack.get('source_ip', attack.get('ip', 'unknown'))
                        if ip and ip != 'unknown':
                            attackers_data[ip]['ip'] = ip
                            attackers_data[ip]['total_interactions'] += 1
                            
                            # Track timestamps
                            timestamp = attack.get('timestamp', attack.get('time', ''))
                            if timestamp:
                                if not attackers_data[ip]['first_seen']:
                                    attackers_data[ip]['first_seen'] = timestamp
                                attackers_data[ip]['last_seen'] = timestamp
                            
                            # Track protocol/service
                            protocol = attack.get('protocol', attack.get('service', ''))
                            if protocol:
                                attackers_data[ip]['protocols'].add(protocol)
                            
                            # Track port
                            port = attack.get('port', '')
                            if port:
                                attackers_data[ip]['ports'].add(str(port))
                            
                            # Track credentials if present
                            username = attack.get('username', attack.get('user', ''))
                            password = attack.get('password', attack.get('pass', ''))
                            if username or password:
                                cred = {'username': username, 'password': password, 'ip': ip}
                                attackers_data[ip]['credentials'].append(cred)
                                all_credentials.append(cred)
                            
                            # Track commands if present
                            command = attack.get('command', attack.get('cmd', ''))
                            if command:
                                cmd_entry = {'command': command, 'ip': ip, 'time': timestamp}
                                attackers_data[ip]['commands'].append(cmd_entry)
                                all_commands.append(cmd_entry)
                            
                            # Track HTTP requests
                            http_path = attack.get('path', attack.get('url', ''))
                            http_method = attack.get('method', 'GET')
                            if http_path:
                                http_req = {'method': http_method, 'path': http_path, 'ip': ip, 'time': timestamp}
                                attackers_data[ip]['http_requests'].append(http_req)
                                all_http_requests.append(http_req)
                        
                    except json.JSONDecodeError:
                        continue
        
        # Read network_attacks.jsonl for DoS/flood attacks (hping3, etc.)
        if os.path.exists(network_attacks_file) and os.path.getsize(network_attacks_file) > 0:
            with open(network_attacks_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        attack = json.loads(line)
                        total_attacks += 1
                        
                        # Extract attacker IP and container name
                        ip = attack.get('source_ip', 'unknown')
                        container = attack.get('source_container', '')
                        attack_type = attack.get('attack_type', 'Network Flood')
                        packet_count = attack.get('packet_count', 0)
                        
                        if ip and ip != 'unknown':
                            attackers_data[ip]['ip'] = ip
                            attackers_data[ip]['total_interactions'] += 1
                            
                            # Track timestamps
                            timestamp = attack.get('timestamp', '')
                            if timestamp:
                                if not attackers_data[ip]['first_seen']:
                                    attackers_data[ip]['first_seen'] = timestamp
                                attackers_data[ip]['last_seen'] = timestamp
                            
                            # Track protocol
                            protocol = attack.get('protocol', 'network_flood')
                            attackers_data[ip]['protocols'].add(f"{attack_type} ({protocol})")
                            
                            # Add packet count info to commands section
                            if packet_count > 0:
                                cmd_entry = {
                                    'command': f"DoS Flood: {packet_count} packets/5s",
                                    'ip': ip,
                                    'time': timestamp
                                }
                                attackers_data[ip]['commands'].append(cmd_entry)
                                all_commands.append(cmd_entry)
                    
                    except json.JSONDecodeError:
                        continue
        
        # Also read SSH logs for additional data
        if os.path.exists(ssh_log) and os.path.getsize(ssh_log) > 0:
            with open(ssh_log, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    total_attacks += 1
                    # Parse SSH log entries (format may vary)
                    # This is a placeholder - actual parsing depends on Beelzebub log format
        
        # Also read HTTP logs
        if os.path.exists(http_log) and os.path.getsize(http_log) > 0:
            with open(http_log, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    total_attacks += 1
        
        # Get rerouted devices
        rerouted_devices = []
        try:
            # Check containers on honeypot network
            honeypot_inspect = run_wsl_command('docker network inspect honeypot_net --format "{{json .Containers}}"')
            
            if honeypot_inspect['success'] and honeypot_inspect['output'].strip() != '{}':
                honeypot_containers = json.loads(honeypot_inspect['output'].strip())
                
                for container_id, info in honeypot_containers.items():
                    container_name = info.get('Name', '')
                    container_ip = info.get('IPv4Address', '').split('/')[0]
                    
                    # Check if this is a device container (not honeypot itself)
                    if container_name.startswith('device_') or 'attacker' in container_name:
                        rerouted_devices.append({
                            'name': container_name,
                            'ip': container_ip,
                            'status': 'active',
                            'rerouted_at': 'N/A'  # Would need to track this separately
                        })
        except Exception as e:
            print(f"Error getting rerouted devices: {e}")
        
        # Convert to list format
        attackers_list = []
        for ip, data in attackers_data.items():
            if data['ip']:
                attackers_list.append({
                    'ip': data['ip'],
                    'first_seen': data['first_seen'],
                    'last_seen': data['last_seen'],
                    'total_interactions': data['total_interactions'],
                    'protocols': list(data['protocols']),
                    'ports': list(data['ports']),
                    'credentials': data['credentials'][:10],  # Top 10
                    'commands': data['commands'][:20],  # Top 20
                    'http_requests': data['http_requests'][:10]  # Top 10
                })
        
        # Sort by total interactions
        attackers_list.sort(key=lambda x: x['total_interactions'], reverse=True)
        
        return jsonify({
            'success': True,
            'attackers': attackers_list[:50],  # Top 50 attackers
            'total_attacks': total_attacks,
            'unique_ips': len(attackers_list),
            'credentials_tried': all_credentials[:100],  # Top 100 credentials
            'commands_executed': all_commands[:100],  # Top 100 commands
            'http_requests': all_http_requests[:100],  # Top 100 HTTP requests
            'rerouted_devices': rerouted_devices
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'attackers': [],
            'total_attacks': 0,
            'unique_ips': 0,
            'credentials_tried': [],
            'commands_executed': [],
            'http_requests': [],
            'rerouted_devices': []
        })

@app.route('/api/beelzebub/reroute', methods=['POST'])
def reroute_to_beelzebub():
    """Reroute device/attacker traffic to Beelzebub honeypot using DNAT iptables rules"""
    
    data = request.json
    ip_address = data.get('ip_address', '').strip()
    
    if not ip_address:
        return jsonify({
            'success': False,
            'message': 'IP address is required'
        })
    
    # Validate IP address format
    import re
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(ip_pattern, ip_address):
        return jsonify({
            'success': False,
            'message': 'Invalid IP address format'
        })
    
    honeypot_network = 'honey_pot_honeypot_net'
    
    # Get Beelzebub honeypot IP dynamically
    get_beelzebub_cmd = f'docker inspect beelzebub-honeypot --format "{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}" 2>/dev/null'
    beelzebub_result = run_wsl_command(get_beelzebub_cmd)
    honeypot_ip = beelzebub_result['output'].strip() if (beelzebub_result['success'] and beelzebub_result['output'].strip()) else '172.18.0.2'
    
    print(f"Rerouting {ip_address} to Beelzebub honeypot ({honeypot_ip})")
    
    # Find container with this IP address - first try custom_net
    find_simple_cmd = f'docker ps --format "{{{{.Names}}}}" --filter "network=custom_net"'
    
    simple_result = run_wsl_command(find_simple_cmd)
    container_candidates = simple_result['output'].strip().split('\n') if simple_result['success'] else []
    
    print(f"Found {len(container_candidates)} containers on custom_net: {container_candidates}")
    
    # For each candidate, check if it has the target IP
    container_name = ''
    for candidate in container_candidates:
        candidate = candidate.strip()
        if not candidate:
            continue
        
        check_ip_cmd = f'docker inspect {candidate} --format "{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}"'
        ip_result = run_wsl_command(check_ip_cmd)
        
        container_ip = ip_result['output'].strip() if ip_result['success'] else ''
        print(f"  Checking {candidate}: IP = {container_ip} (looking for {ip_address})")
        
        if ip_result['success'] and container_ip == ip_address:
            container_name = candidate
            print(f"  ✅ MATCH FOUND: {candidate}")
            break
    
    # If not found on custom_net, search all running containers
    if not container_name:
        print(f"⚠️ Not found on custom_net, searching all containers...")
        all_containers_cmd = 'docker ps --format "{{{{.Names}}}}"'
        all_result = run_wsl_command(all_containers_cmd)
        all_candidates = all_result['output'].strip().split('\n') if all_result['success'] else []
        
        for candidate in all_candidates:
            candidate = candidate.strip()
            if not candidate:
                continue
            
            # Check all networks this container is on
            networks_cmd = f'docker inspect {candidate} --format "{{{{json .NetworkSettings.Networks}}}}"'
            networks_result = run_wsl_command(networks_cmd)
            
            if networks_result['success']:
                # Parse networks and check IPs
                import json as json_lib
                try:
                    networks = json_lib.loads(networks_result['output'].strip())
                    for network_name, network_info in networks.items():
                        network_ip = network_info.get('IPAddress', '')
                        print(f"  Checking {candidate} on {network_name}: IP = {network_ip}")
                        if network_ip == ip_address:
                            container_name = candidate
                            print(f"  ✅ MATCH FOUND: {candidate} on {network_name}")
                            
                            # If found on a different network, reconnect to custom_net first
                            if network_name != 'custom_net':
                                print(f"  Reconnecting {candidate} to custom_net...")
                                reconnect_cmd = f'docker network connect custom_net {candidate}'
                                run_wsl_command(reconnect_cmd)
                            break
                except:
                    pass
            
            if container_name:
                break
    
    if not container_name:
        error_msg = f'No container found with IP {ip_address}. Container may be stopped or IP changed.'
        print(f"❌ {error_msg}")
        print(f"   Checked containers: {container_candidates}")
        return jsonify({
            'success': False,
            'message': error_msg
        })
    
    print(f"📦 Found container: {container_name} with IP {ip_address}")
    
    # Get Beelzebub honeypot IP and network
    get_beelzebub_network_cmd = 'docker inspect beelzebub-honeypot --format "{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{end}}" 2>/dev/null | grep -o "[^ ]*honeypot[^ ]*" | head -1'
    beelzebub_network_result = run_wsl_command(get_beelzebub_network_cmd)
    honeypot_network = beelzebub_network_result['output'].strip() if (beelzebub_network_result['success'] and beelzebub_network_result['output'].strip()) else 'honey_pot_honeypot_net'
    
    get_beelzebub_ip_cmd = f'docker inspect beelzebub-honeypot --format "{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}" 2>/dev/null'
    beelzebub_ip_result = run_wsl_command(get_beelzebub_ip_cmd)
    honeypot_target_ip = beelzebub_ip_result['output'].strip() if (beelzebub_ip_result['success'] and beelzebub_ip_result['output'].strip()) else '172.18.0.2'
    
    network_monitor_ip = "192.168.6.131"
    
    print(f"🍯 Honeypot network: {honeypot_network}")
    print(f"🍯 Honeypot IP: {honeypot_target_ip}")
    print(f"🎯 Network monitor: {network_monitor_ip}")
    
    # STEP 1: Add iptables DNAT rules to reroute traffic
    print(f"🔀 Setting up DNAT rerouting for {ip_address} → {honeypot_target_ip}")
    
    # DNAT rules for common ports
    dnat_rules = [
        f'iptables -t nat -A PREROUTING -s {ip_address} -d {network_monitor_ip} -p tcp --dport 5000 -j DNAT --to-destination {honeypot_target_ip}:8080',
        f'iptables -t nat -A PREROUTING -s {ip_address} -d {network_monitor_ip} -p tcp --dport 3306 -j DNAT --to-destination {honeypot_target_ip}:3306',
        f'iptables -t nat -A PREROUTING -s {ip_address} -d {network_monitor_ip} -p tcp --dport 5432 -j DNAT --to-destination {honeypot_target_ip}:5432',
        f'iptables -t nat -A PREROUTING -s {ip_address} -d {network_monitor_ip} -p tcp --dport 22 -j DNAT --to-destination {honeypot_target_ip}:22'
    ]
    
    # FORWARD rules to allow traffic
    forward_rules = [
        f'iptables -A FORWARD -s {ip_address} -d {honeypot_target_ip} -p tcp --dport 8080 -j ACCEPT',
        f'iptables -A FORWARD -s {ip_address} -d {honeypot_target_ip} -p tcp --dport 3306 -j ACCEPT',
        f'iptables -A FORWARD -s {ip_address} -d {honeypot_target_ip} -p tcp --dport 5432 -j ACCEPT',
        f'iptables -A FORWARD -s {ip_address} -d {honeypot_target_ip} -p tcp --dport 22 -j ACCEPT',
        f'iptables -A FORWARD -s {honeypot_target_ip} -d {ip_address} -j ACCEPT'
    ]
    
    # MASQUERADE for return traffic
    masquerade_rule = f'iptables -t nat -A POSTROUTING -d {honeypot_target_ip} -j MASQUERADE'
    
    # Apply all iptables rules
    all_rules = dnat_rules + forward_rules + [masquerade_rule]
    failed_rules = []
    applied_rules = 0
    
    for rule in all_rules:
        iptables_cmd = f'sudo {rule}'
        iptables_result = run_wsl_command(iptables_cmd)
        if iptables_result['success']:
            applied_rules += 1
            print(f"  ✅ Applied: {rule}")
        else:
            failed_rules.append(f"{rule}: {iptables_result.get('output', 'Unknown error')}")
            print(f"  ❌ Failed: {rule}")
    
    if failed_rules:
        return jsonify({
            'success': False,
            'message': f'Failed to apply {len(failed_rules)} iptables rules',
            'errors': failed_rules
        })
    
    print(f"✅ Applied {applied_rules} iptables DNAT rules")
    
    # STEP 2: Connect device to honeypot network (for bidirectional communication)
    connect_cmd = f'docker network connect {honeypot_network} {container_name} 2>&1'
    connect_result = run_wsl_command(connect_cmd)
    
    if not connect_result['success'] and 'already exists' not in connect_result['output']:
        print(f"⚠️ Note: Could not connect to {honeypot_network}: {connect_result['output']}")
    
    # Get device's new IP on honeypot network
    honeypot_ip_cmd = f'docker inspect {container_name} --format "{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}" 2>/dev/null'
    honeypot_ip_result = run_wsl_command(honeypot_ip_cmd)
    device_honeypot_ip = honeypot_ip_result['output'].strip() if (honeypot_ip_result['success'] and honeypot_ip_result['output'].strip()) else 'DNAT only'
    
    print(f"🔗 Device connected to honeypot network: {device_honeypot_ip}")
    
    # STEP 3: Log the reroute
    log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] DNAT REROUTE: {container_name} ({ip_address}) → Honeypot ({honeypot_target_ip}) via DNAT | Rules: {applied_rules}"
    
    try:
        os.makedirs(os.path.join(HONEYPOT_DIR, 'logs'), exist_ok=True)
        log_file = os.path.join(HONEYPOT_DIR, 'logs', 'reroutes.log')
        
        existing_logs = []
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                existing_logs = [line.strip() for line in f if line.strip()]
        
        existing_logs.append(log_entry)
        
        if len(existing_logs) > 100:
            existing_logs = existing_logs[-100:]
        
        with open(log_file, 'w') as f:
            for log in existing_logs:
                f.write(log + '\n')
    except Exception as e:
        print(f"Warning: Could not write to reroutes log: {e}")
    
    print(f"✅ Successfully deployed DNAT rerouting - traffic from {ip_address} is now being rerouted to honeypot")
    
    return jsonify({
        'success': True,
        'message': f'✅ Traffic rerouted via DNAT iptables rules! Device {container_name} stays on network at {ip_address}. Traffic to network-monitor ({network_monitor_ip}) is redirected to Beelzebub honeypot ({honeypot_target_ip}). {applied_rules} iptables rules applied.',
        'container_name': container_name,
        'original_ip': ip_address,
        'device_honeypot_ip': device_honeypot_ip,
        'honeypot_target': honeypot_target_ip,
        'method': 'DNAT_iptables',
        'rules_applied': applied_rules,
        'ports_rerouted': ['HTTP:5000→8080', 'MySQL:3306', 'PostgreSQL:5432', 'SSH:22'],
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/beelzebub/reroutes')
def get_reroutes():
    """Get list of rerouted IPs to Beelzebub - check blocked_devices.json and verify containers exist"""
    
    honeypot_network = 'honey_pot_honeypot_net'
    
    # Read reroutes log
    reroutes_log = os.path.join(HONEYPOT_DIR, 'logs', 'reroutes.log')
    reroutes = []
    
    if os.path.exists(reroutes_log):
        try:
            with open(reroutes_log, 'r') as f:
                for line in f:
                    if line.strip():
                        reroutes.append(line.strip())
        except Exception as e:
            print(f"Error reading reroutes log: {e}")
    
    active_reroutes = []
    
    # Get Beelzebub honeypot network and IP
    get_beelzebub_network_cmd = 'docker inspect beelzebub-honeypot --format "{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{end}}" 2>/dev/null | grep -o "[^ ]*honeypot[^ ]*" | head -1'
    beelzebub_network_result = run_wsl_command(get_beelzebub_network_cmd)
    beelzebub_network = beelzebub_network_result['output'].strip() if (beelzebub_network_result['success'] and beelzebub_network_result['output'].strip()) else 'honey_pot_honeypot_net'
    
    get_beelzebub_ip_cmd = f'docker inspect beelzebub-honeypot --format "{{{{.NetworkSettings.Networks.{beelzebub_network}.IPAddress}}}}" 2>/dev/null'
    beelzebub_ip_result = run_wsl_command(get_beelzebub_ip_cmd)
    honeypot_target_ip = beelzebub_ip_result['output'].strip() if (beelzebub_ip_result['success'] and beelzebub_ip_result['output'].strip()) else '172.18.0.2'
    
    # PRIMARY SOURCE: Read blocked_devices.json (MCP agent tracking file)
    blocked_devices = load_blocked_devices()
    containers_to_remove = []  # Track deleted containers
    
    for device in blocked_devices:
        container_name = device.get('container_name')
        if not container_name:
            continue
        
        # CRITICAL: Verify container still exists
        check_container_cmd = f'docker inspect {container_name} --format "{{{{.State.Running}}}}" 2>/dev/null'
        container_check = run_wsl_command(check_container_cmd)
        
        if not container_check['success'] or not container_check['output'].strip():
            print(f"⚠️ Container {container_name} no longer exists, will be removed from tracking")
            containers_to_remove.append(device)
            continue
        
        method = device.get('method', 'dnat_reroute')
        original_ip = device.get('original_ip', 'N/A')
        honeypot_ip = device.get('honeypot_ip', honeypot_target_ip)
        
        # Get current network status
        if method == 'network_switch':
            # Complete network switch - check if on honeypot network
            get_honeypot_ip_cmd = f'docker inspect {container_name} --format "{{{{.NetworkSettings.Networks.{beelzebub_network}.IPAddress}}}}" 2>/dev/null'
            honeypot_ip_check = run_wsl_command(get_honeypot_ip_cmd)
            current_honeypot_ip = honeypot_ip_check['output'].strip() if honeypot_ip_check['success'] and honeypot_ip_check['output'].strip() else None
            
            # Check if still on custom_net (shouldn't be)
            get_custom_ip_cmd = f'docker inspect {container_name} --format "{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}" 2>/dev/null'
            custom_ip_check = run_wsl_command(get_custom_ip_cmd)
            still_on_custom = custom_ip_check['success'] and custom_ip_check['output'].strip()
            
            if current_honeypot_ip:
                active_reroutes.append({
                    'container': container_name,
                    'ip': original_ip,
                    'honeypot_ip': current_honeypot_ip,
                    'network': f'Isolated (was {original_ip} → now {current_honeypot_ip})',
                    'method': 'network_switch',
                    'status': 'isolated',
                    'rules_count': 0,
                    'description': f'Complete network isolation - disconnected from production, connected to honeypot only'
                })
            elif still_on_custom:
                # Inconsistent state - marked as isolated but still on custom_net
                print(f"⚠️ {container_name} marked as isolated but still on custom_net")
        
        else:  # DNAT method
            # DNAT traffic rerouting - check iptables rules
            count_rules_cmd = f'sudo iptables -t nat -L PREROUTING -n 2>/dev/null | grep "{original_ip}" | grep "DNAT" | wc -l'
            count_result = run_wsl_command(count_rules_cmd)
            rules_count = int(count_result['output'].strip()) if (count_result['success'] and count_result['output'].strip().isdigit()) else 0
            
            if rules_count > 0:
                active_reroutes.append({
                    'container': container_name,
                    'ip': original_ip,
                    'honeypot_ip': honeypot_ip,
                    'network': f'custom_net (DNAT → {honeypot_ip})',
                    'method': 'DNAT_iptables',
                    'status': 'active',
                    'rules_count': rules_count,
                    'description': f'Traffic rerouted via {rules_count} iptables DNAT rules to Beelzebub honeypot'
                })
    
    # Clean up deleted containers from blocked_devices.json
    if containers_to_remove:
        print(f"🧹 Removing {len(containers_to_remove)} deleted containers from tracking")
        updated_devices = [d for d in blocked_devices if d not in containers_to_remove]
        save_blocked_devices(updated_devices)
    
    # FALLBACK: Check iptables DNAT rules to find any untracked rerouted devices
    iptables_check_cmd = f'sudo iptables -t nat -L PREROUTING -n -v 2>/dev/null | grep "DNAT" | grep "{honeypot_target_ip}"'
    iptables_result = run_wsl_command(iptables_check_cmd)
    
    tracked_ips = set(r['ip'] for r in active_reroutes)  # Track IPs already found
    
    if iptables_result['success'] and iptables_result['output'].strip():
        for line in iptables_result['output'].strip().split('\n'):
            # Parse iptables DNAT rule to extract source IP
            # Format: pkts bytes target prot opt in out source destination
            parts = line.split()
            
            # Look for source IP in 192.168.6.x range
            source_ip = None
            for part in parts:
                if part.startswith('192.168.6.') and '/' not in part and part != '192.168.6.0':
                    source_ip = part
                    break
            
            if source_ip and source_ip not in tracked_ips:
                tracked_ips.add(source_ip)
                
                # Find container with this IP on custom_net
                get_containers_cmd = 'docker ps --format "{{.Names}}" --filter "network=custom_net"'
                containers_result = run_wsl_command(get_containers_cmd)
                
                if containers_result['success'] and containers_result['output'].strip():
                    for container in containers_result['output'].strip().split('\n'):
                        container = container.strip()
                        if not container or 'network-monitor' in container:
                            continue
                        
                        # Get container IP on custom_net
                        ip_check_cmd = f'docker inspect {container} --format "{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}" 2>/dev/null'
                        ip_check = run_wsl_command(ip_check_cmd)
                        
                        if ip_check['success'] and ip_check['output'].strip() == source_ip:
                            # Count DNAT rules for this IP
                            count_rules_cmd = f'sudo iptables -t nat -L PREROUTING -n 2>/dev/null | grep "{source_ip}" | grep "DNAT" | wc -l'
                            count_result = run_wsl_command(count_rules_cmd)
                            rules_count = int(count_result['output'].strip()) if (count_result['success'] and count_result['output'].strip().isdigit()) else 0
                            
                            active_reroutes.append({
                                'container': container,
                                'ip': source_ip,
                                'network': f'custom_net (DNAT → {honeypot_target_ip})',
                                'method': 'DNAT_iptables',
                                'status': 'active',
                                'rules_count': rules_count,
                                'description': f'Traffic rerouted via {rules_count} iptables DNAT rules to Beelzebub honeypot'
                            })
                            break
    
    return jsonify({
        'success': True,
        'reroutes_log': reroutes[-50:],  # Last 50 entries
        'active_reroutes': active_reroutes,
        'count': len(reroutes)
    })

@app.route('/api/beelzebub/remove_reroute', methods=['POST'])
def remove_reroute():
    """Remove reroute rule for specific IP - restore container to production network"""
    
    honeypot_network = 'honeypot_net'
    
    data = request.json
    container_name = data.get('container_name', '').strip()
    
    if not container_name:
        return jsonify({
            'success': False,
            'message': 'Container name is required'
        })
    
    print(f"🔄 Restoring {container_name} back to production network")
    
    # Step 1: Get container's IP on custom_net (before removal)
    get_ip_cmd = f'docker inspect {container_name} --format "{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}"'
    ip_result = run_wsl_command(get_ip_cmd)
    container_ip = ip_result['output'].strip() if ip_result['success'] else None
    
    # Get Beelzebub IP for rule removal
    honeypot_network = 'honeypot_net'
    get_beelzebub_cmd = f'docker inspect beelzebub-honeypot --format "{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}" 2>/dev/null'
    beelzebub_result = run_wsl_command(get_beelzebub_cmd)
    beelzebub_ip = beelzebub_result['output'].strip() if (beelzebub_result['success'] and beelzebub_result['output'].strip()) else '192.168.7.3'
    
    # Step 2: Remove iptables rules that were redirecting traffic
    if container_ip:
        print(f"Removing iptables rules for {container_ip}")
        
        # Check all possible honeypot destinations (192.168.7.2, 192.168.7.3, 192.168.7.100)
        honeypot_destinations = ['192.168.7.2', '192.168.7.3', '192.168.7.100', beelzebub_ip]
        
        # Remove the DNAT and mangle rules for all possible destinations
        for dest_ip in set(honeypot_destinations):  # Use set to avoid duplicates
            iptables_remove_rules = [
                f'iptables -t nat -D PREROUTING -s {container_ip} -p tcp -j DNAT --to-destination {dest_ip}',
                f'iptables -t nat -D PREROUTING -s {container_ip} -p udp -j DNAT --to-destination {dest_ip}',
            ]
            
            for rule in iptables_remove_rules:
                rule_result = run_wsl_command(f'sudo {rule} 2>&1')
                # Ignore errors (rule might not exist)
        
        # Remove mangle rule
        mangle_rule = f'sudo iptables -t mangle -D PREROUTING -s {container_ip} -j MARK --set-mark 100 2>&1'
        run_wsl_command(mangle_rule)
        
        print(f"Removed all traffic redirection rules for {container_ip}")
    
    # Step 3: Disconnect from honeypot_net (but keep custom_net connection)
    disconnect_cmd = f'docker network disconnect {honeypot_network} {container_name}'
    disconnect_result = run_wsl_command(disconnect_cmd)
    
    if not disconnect_result['success']:
        print(f"Warning: Could not disconnect from honeypot network: {disconnect_result['output']}")
    
    # Step 4: Get current IP on custom_net (should be same as before)
    get_final_ip_cmd = f'docker inspect {container_name} --format "{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}"'
    final_ip_result = run_wsl_command(get_final_ip_cmd)
    final_ip = final_ip_result['output'].strip() if final_ip_result['success'] else 'unknown'
    
    # Step 5: Log the restore (with rotation - keep last 100 entries)
    log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Restored {container_name} ({final_ip}) to production network - removed traffic redirection"
    try:
        log_file = os.path.join(HONEYPOT_DIR, 'logs', 'reroutes.log')
        
        # Read existing logs
        existing_logs = []
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                existing_logs = [line.strip() for line in f if line.strip()]
        
        # Add new entry
        existing_logs.append(log_entry)
        
        # Keep only last 100 entries (log rotation)
        if len(existing_logs) > 100:
            existing_logs = existing_logs[-100:]
        
        # Write back
        with open(log_file, 'w') as f:
            for log in existing_logs:
                f.write(log + '\n')
    except:
        pass
    
    print(f"✅ Container {container_name} restored to production network (IP: {final_ip})")
    
    return jsonify({
        'success': True,
        'message': f'{container_name} restored to production network. Traffic redirection removed.',
        'ip': final_ip,
        'method': 'iptables_removed'
    })

@app.route('/api/beelzebub/clear_all_dnat', methods=['POST'])
def clear_all_dnat_rules():
    """Clear ALL DNAT iptables rules for all devices - nuclear option"""
    
    print("🧹 CLEARING ALL DNAT RULES FOR ALL DEVICES")
    
    try:
        # Step 1: Get all containers on custom_net with their IPs
        list_containers_cmd = 'docker network inspect custom_net --format "{{json .Containers}}"'
        containers_result = run_wsl_command(list_containers_cmd)
        
        cleared_rules = []
        errors = []
        
        if containers_result['success'] and containers_result['output'].strip():
            import json
            try:
                containers_data = json.loads(containers_result['output'])
                
                # Get all container IPs
                container_ips = []
                for container_id, container_info in containers_data.items():
                    ip = container_info.get('IPv4Address', '').split('/')[0]
                    name = container_info.get('Name', 'unknown')
                    if ip:
                        container_ips.append((ip, name))
                        print(f"Found container: {name} at {ip}")
                
                # Step 2: Get Beelzebub honeypot IPs (all possible destinations)
                beelzebub_ips = []
                
                # Check honey_pot_honeypot_net
                get_beelzebub1_cmd = 'docker inspect beelzebub-honeypot --format "{{.NetworkSettings.Networks.honey_pot_honeypot_net.IPAddress}}" 2>/dev/null'
                beelzebub1_result = run_wsl_command(get_beelzebub1_cmd)
                if beelzebub1_result['success'] and beelzebub1_result['output'].strip():
                    beelzebub_ips.append(beelzebub1_result['output'].strip())
                
                # Check honeypot_net
                get_beelzebub2_cmd = 'docker inspect beelzebub-honeypot --format "{{.NetworkSettings.Networks.honeypot_net.IPAddress}}" 2>/dev/null'
                beelzebub2_result = run_wsl_command(get_beelzebub2_cmd)
                if beelzebub2_result['success'] and beelzebub2_result['output'].strip():
                    beelzebub_ips.append(beelzebub2_result['output'].strip())
                
                # Add common honeypot IPs
                beelzebub_ips.extend(['192.168.7.2', '192.168.7.3', '172.18.0.2'])
                beelzebub_ips = list(set(beelzebub_ips))  # Remove duplicates
                
                print(f"Honeypot IPs to clear: {beelzebub_ips}")
                
                # Step 3: Remove DNAT rules for each container IP + honeypot IP combination
                network_monitor_ip = "192.168.6.131"
                
                for container_ip, container_name in container_ips:
                    for honeypot_ip in beelzebub_ips:
                        # DNAT rules for common ports
                        dnat_rules = [
                            f'iptables -t nat -D PREROUTING -s {container_ip} -d {network_monitor_ip} -p tcp --dport 5000 -j DNAT --to-destination {honeypot_ip}:8080',
                            f'iptables -t nat -D PREROUTING -s {container_ip} -d {network_monitor_ip} -p tcp --dport 3306 -j DNAT --to-destination {honeypot_ip}:3306',
                            f'iptables -t nat -D PREROUTING -s {container_ip} -d {network_monitor_ip} -p tcp --dport 5432 -j DNAT --to-destination {honeypot_ip}:5432',
                            f'iptables -t nat -D PREROUTING -s {container_ip} -d {network_monitor_ip} -p tcp --dport 22 -j DNAT --to-destination {honeypot_ip}:22',
                            # Generic DNAT rules
                            f'iptables -t nat -D PREROUTING -s {container_ip} -p tcp -j DNAT --to-destination {honeypot_ip}',
                            f'iptables -t nat -D PREROUTING -s {container_ip} -p udp -j DNAT --to-destination {honeypot_ip}'
                        ]
                        
                        # FORWARD rules
                        forward_rules = [
                            f'iptables -D FORWARD -s {container_ip} -d {honeypot_ip} -p tcp --dport 8080 -j ACCEPT',
                            f'iptables -D FORWARD -s {container_ip} -d {honeypot_ip} -p tcp --dport 3306 -j ACCEPT',
                            f'iptables -D FORWARD -s {container_ip} -d {honeypot_ip} -p tcp --dport 5432 -j ACCEPT',
                            f'iptables -D FORWARD -s {container_ip} -d {honeypot_ip} -p tcp --dport 22 -j ACCEPT',
                            f'iptables -D FORWARD -s {honeypot_ip} -d {container_ip} -j ACCEPT'
                        ]
                        
                        # MASQUERADE rule
                        masquerade_rule = f'iptables -t nat -D POSTROUTING -d {honeypot_ip} -j MASQUERADE'
                        
                        all_rules = dnat_rules + forward_rules + [masquerade_rule]
                        
                        # Execute all rules (ignore errors for non-existent rules)
                        for rule in all_rules:
                            rule_cmd = f'sudo {rule} 2>&1 || true'
                            rule_result = run_wsl_command(rule_cmd)
                            if rule_result['success'] and 'Bad rule' not in rule_result['output']:
                                cleared_rules.append(f"{container_name} ({container_ip}): Removed rule")
                    
                    # Remove mangle rules
                    mangle_rule = f'sudo iptables -t mangle -D PREROUTING -s {container_ip} -j MARK --set-mark 100 2>&1 || true'
                    run_wsl_command(mangle_rule)
                
                # Step 4: Flush DNAT-related chains (preserve Docker inter-container communication rules)
                # Get custom_net bridge name to preserve its ICC rule
                get_bridge_cmd = "docker network inspect custom_net --format '{{.Id}}' | cut -c1-12"
                bridge_result = run_wsl_command(get_bridge_cmd)
                bridge_id = bridge_result['output'].strip() if bridge_result['success'] else ''
                bridge_name = f"br-{bridge_id}" if bridge_id else "br-b1ac5d1cbe59"
                
                # Flush NAT tables (safe - doesn't affect FORWARD rules)
                flush_commands = [
                    'sudo iptables -t nat -F PREROUTING 2>&1 || true',
                    'sudo iptables -t nat -F POSTROUTING 2>&1 || true',
                    'sudo iptables -t mangle -F PREROUTING 2>&1 || true'
                ]
                
                for flush_cmd in flush_commands:
                    flush_result = run_wsl_command(flush_cmd)
                    if flush_result['success']:
                        cleared_rules.append(f"Flushed: {flush_cmd.split()[3]}")
                
                # For FORWARD chain: Remove only DNAT-related rules, keep Docker ICC rules
                # Find and remove DNAT ACCEPT rules (but not the bridge ICC rule)
                remove_dnat_forward_cmd = f"sudo iptables -S FORWARD | grep -E 'ACCEPT.*dpt:(5000|3306|5432|22|80|443|8080|21|23)' | sed 's/-A/-D/' | while read rule; do sudo iptables $rule 2>/dev/null || true; done"
                run_wsl_command(remove_dnat_forward_cmd)
                
                # Ensure Docker inter-container communication rule exists (critical for network functionality)
                ensure_icc_cmd = f"sudo iptables -C FORWARD -i {bridge_name} -o {bridge_name} -j ACCEPT 2>/dev/null || sudo iptables -I FORWARD 1 -i {bridge_name} -o {bridge_name} -j ACCEPT"
                icc_result = run_wsl_command(ensure_icc_cmd)
                if icc_result['success']:
                    cleared_rules.append(f"✅ Preserved Docker ICC rule for {bridge_name}")
                
                # Step 5: Log the mass clear
                log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] MASS CLEAR: Removed ALL DNAT rules for {len(container_ips)} devices"
                try:
                    log_file = os.path.join(HONEYPOT_DIR, 'logs', 'reroutes.log')
                    with open(log_file, 'a') as f:
                        f.write(log_entry + '\n')
                except:
                    pass
                
                print(f"✅ Cleared {len(cleared_rules)} DNAT rules for {len(container_ips)} devices")
                
                return jsonify({
                    'success': True,
                    'message': f'ALL DNAT rules cleared for {len(container_ips)} devices',
                    'devices_cleared': len(container_ips),
                    'rules_removed': len(cleared_rules),
                    'details': cleared_rules[:20]  # First 20 for display
                })
                
            except json.JSONDecodeError as e:
                return jsonify({
                    'success': False,
                    'message': f'Error parsing container data: {str(e)}'
                }), 500
        else:
            # No containers found, flush NAT rules only (preserve FORWARD ICC rules)
            # Get custom_net bridge name
            get_bridge_cmd = "docker network inspect custom_net --format '{{.Id}}' | cut -c1-12"
            bridge_result = run_wsl_command(get_bridge_cmd)
            bridge_id = bridge_result['output'].strip() if bridge_result['success'] else ''
            bridge_name = f"br-{bridge_id}" if bridge_id else "br-b1ac5d1cbe59"
            
            flush_commands = [
                'sudo iptables -t nat -F PREROUTING',
                'sudo iptables -t nat -F POSTROUTING',
                'sudo iptables -t mangle -F PREROUTING'
            ]
            
            for flush_cmd in flush_commands:
                run_wsl_command(flush_cmd)
            
            # Ensure Docker inter-container communication rule exists (critical)
            ensure_icc_cmd = f"sudo iptables -C FORWARD -i {bridge_name} -o {bridge_name} -j ACCEPT 2>/dev/null || sudo iptables -I FORWARD 1 -i {bridge_name} -o {bridge_name} -j ACCEPT"
            run_wsl_command(ensure_icc_cmd)
            
            return jsonify({
                'success': True,
                'message': 'All iptables DNAT chains flushed (Docker ICC rules preserved)',
                'devices_cleared': 0,
                'rules_removed': 4
            })
            
    except Exception as e:
        print(f"❌ Error clearing DNAT rules: {e}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500

@app.route('/api/analytics/attacks')
def get_attack_analytics():
    """Analyze attack patterns from honeypot logs"""
    
    from collections import Counter
    from datetime import datetime
    import json
    
    # Read attacks.jsonl
    attacks_file = os.path.join(HONEYPOT_DIR, 'logs', 'attacks.jsonl')
    attacks = []
    
    if os.path.exists(attacks_file):
        try:
            with open(attacks_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        try:
                            attacks.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            print(f"Error reading attacks log: {e}")
    
    if not attacks:
        return jsonify({
            'success': True,
            'total_attacks': 0,
            'unique_attackers': 0,
            'attack_rate': 0,
            'protocols': {},
            'top_attackers': [],
            'ports': {},
            'timeline': [],
            'urls': [],
            'user_agents': [],
            'attacker_profiles': [],
            'raw_logs': []
        })
    
    # Basic statistics
    total_attacks = len(attacks)
    
    # Analyze protocols
    protocols = Counter(attack.get('protocol', 'Unknown') for attack in attacks)
    
    # Analyze attackers
    attackers = Counter(attack.get('attacker_ip', 'Unknown') for attack in attacks)
    unique_attackers = len(attackers)
    
    # Top attackers (top 10)
    top_attackers = [
        {'ip': ip, 'count': count, 'percentage': round(count/total_attacks*100, 1)}
        for ip, count in attackers.most_common(10)
    ]
    
    # Analyze ports
    ports = Counter(attack.get('port', 0) for attack in attacks)
    most_attacked_port = ports.most_common(1)[0][0] if ports else '-'
    
    # Timeline analysis
    timestamps = []
    for attack in attacks:
        if 'timestamp' in attack:
            try:
                timestamps.append(datetime.fromisoformat(attack['timestamp']))
            except:
                pass
    
    attack_rate = 0
    timeline_data = {
        'first_attack': None,
        'last_attack': None,
        'duration': None
    }
    
    if timestamps:
        first_attack = min(timestamps)
        last_attack = max(timestamps)
        duration = last_attack - first_attack
        
        timeline_data = {
            'first_attack': first_attack.strftime('%Y-%m-%d %H:%M:%S'),
            'last_attack': last_attack.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': str(duration)
        }
        
        if duration.total_seconds() > 0:
            attack_rate = round(total_attacks / duration.total_seconds() * 60, 2)
    
    # Analyze HTTP requests
    http_attacks = [a for a in attacks if a.get('protocol') == 'HTTP']
    urls = []
    user_agents = []
    
    for attack in http_attacks:
        request = attack.get('request', '')
        lines = request.split('\\r\\n')
        
        # Extract URL
        if lines:
            parts = lines[0].split()
            if len(parts) >= 2:
                urls.append(parts[1])
        
        # Extract User-Agent
        for line in lines:
            if line.startswith('User-Agent:'):
                user_agents.append(line.split(':', 1)[1].strip())
    
    url_counter = Counter(urls)
    top_urls = [
        {'url': url, 'count': count}
        for url, count in url_counter.most_common(15)
    ]
    
    ua_counter = Counter(user_agents)
    top_user_agents = [
        {'agent': ua, 'count': count}
        for ua, count in ua_counter.most_common(10)
    ]
    
    # Attacker profiles
    attacker_profiles = []
    for ip, count in attackers.most_common(10):
        attacker_attacks = [a for a in attacks if a.get('attacker_ip') == ip]
        
        # Get protocols used
        attacker_protocols = Counter(a.get('protocol', 'Unknown') for a in attacker_attacks)
        
        # Get ports targeted
        attacker_ports = Counter(a.get('port', 0) for a in attacker_attacks)
        
        # Get URLs for HTTP attacks
        attacker_urls = []
        for attack in attacker_attacks:
            if attack.get('protocol') == 'HTTP':
                request = attack.get('request', '')
                lines = request.split('\\r\\n')
                if lines:
                    parts = lines[0].split()
                    if len(parts) >= 2:
                        attacker_urls.append(parts[1])
        
        url_counter_attacker = Counter(attacker_urls)
        
        attacker_profiles.append({
            'ip': ip,
            'total_attacks': count,
            'protocols': dict(attacker_protocols),
            'ports': list(attacker_ports.keys()),
            'top_urls': [
                {'url': url, 'count': url_count}
                for url, url_count in url_counter_attacker.most_common(5)
            ]
        })
    
    # Get last 50 raw attack logs
    raw_logs = attacks[-50:][::-1]  # Last 50, reversed (newest first)
    
    return jsonify({
        'success': True,
        'total_attacks': total_attacks,
        'unique_attackers': unique_attackers,
        'attack_rate': attack_rate,
        'most_attacked_port': most_attacked_port,
        'protocols': dict(protocols),
        'top_attackers': top_attackers,
        'ports': dict(ports),
        'timeline': timeline_data,
        'urls': top_urls,
        'user_agents': top_user_agents,
        'attacker_profiles': attacker_profiles,
        'raw_logs': raw_logs
    })

@app.route('/api/attackers/start', methods=['POST'])
def start_attackers():
    """Start DOS attacker containers"""
    
    # Ensure network exists
    network_check = run_wsl_command('docker network ls | grep custom_net')
    if not (network_check['success'] and 'custom_net' in network_check['output']):
        return jsonify({
            'success': False,
            'message': 'Network does not exist. Create network first.'
        })
    
    # Start attackers using docker-compose
    result = run_wsl_command(f'cd {WSL_ATTACKERS_DIR} && docker compose up -d --build', timeout=180)
    
    return jsonify({
        'success': result['success'],
        'message': 'Attackers started successfully' if result['success'] else result['error'],
        'output': result['output']
    })

@app.route('/api/attackers/stop', methods=['POST'])
def stop_attackers():
    """Stop DOS attacker containers"""
    
    # First, clean up iptables rules for the attacker
    cleanup_result = run_wsl_command('bash /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/attackers/dos_attacker/cleanup_iptables.sh 192.168.6.132')
    
    # Then stop the containers
    result = run_wsl_command(f'cd {WSL_ATTACKERS_DIR} && docker compose down')
    
    return jsonify({
        'success': result['success'],
        'message': 'Attackers stopped and iptables cleaned up' if result['success'] else result['error']
    })

@app.route('/api/ssh_attacker/start', methods=['POST'])
def start_ssh_attacker():
    """Start SSH brute force attacker"""
    
    # Ensure network exists
    network_check = run_wsl_command('docker network ls | grep custom_net')
    if not (network_check['success'] and 'custom_net' in network_check['output']):
        return jsonify({
            'success': False,
            'message': 'Network does not exist. Create network first.'
        })
    
    # Start SSH attacker using docker compose
    result = run_wsl_command('cd /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/attackers/ssh_attacker && docker compose up -d --build', timeout=180)
    
    return jsonify({
        'success': result['success'],
        'message': 'SSH Attacker started successfully' if result['success'] else result['error'],
        'output': result['output']
    })

@app.route('/api/ssh_attacker/stop', methods=['POST'])
def stop_ssh_attacker():
    """Stop SSH brute force attacker"""
    
    # First, clean up iptables rules for the SSH attacker (192.168.6.133)
    cleanup_result = run_wsl_command('bash /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/attackers/dos_attacker/cleanup_iptables.sh 192.168.6.133')
    
    # Then stop the container
    result = run_wsl_command('cd /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/attackers/ssh_attacker && docker compose down')
    
    return jsonify({
        'success': result['success'],
        'message': 'SSH Attacker stopped and iptables cleaned up' if result['success'] else result['error']
    })

@app.route('/api/ssh_attacker/logs', methods=['GET'])
def get_ssh_attacker_logs():
    """Get SSH attacker logs"""
    
    # Get container logs
    container_logs = run_wsl_command('docker logs --tail 100 ssh-attacker 2>&1')
    
    # Get summary log if exists
    summary_logs = run_wsl_command('cat /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/attackers/ssh_attacker/logs/ssh_summary.log 2>/dev/null || echo "No summary log yet"')
    
    return jsonify({
        'success': True,
        'container_logs': container_logs['output'] if container_logs['success'] else 'Container not running',
        'summary_logs': summary_logs['output'] if summary_logs['success'] else 'No summary log'
    })

# ===== Malware Attacker Control =====

@app.route('/api/malware_attacker/start', methods=['POST'])
def start_malware_attacker():
    """Start malware behavior simulation attacker"""
    
    # Ensure network exists
    network_check = run_wsl_command('docker network ls | grep custom_net')
    if not (network_check['success'] and 'custom_net' in network_check['output']):
        return jsonify({
            'success': False,
            'message': 'Network does not exist. Create network first.'
        })
    
    # Start malware attacker using docker compose
    result = run_wsl_command('cd /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/attackers/malware_attacker && docker compose up -d --build', timeout=180)
    
    return jsonify({
        'success': result['success'],
        'message': 'Malware Attacker started successfully' if result['success'] else result['error'],
        'output': result['output']
    })

@app.route('/api/malware_attacker/stop', methods=['POST'])
def stop_malware_attacker():
    """Stop malware behavior simulation attacker"""
    
    # Stop the container
    result = run_wsl_command('cd /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/attackers/malware_attacker && docker compose down')
    
    return jsonify({
        'success': result['success'],
        'message': 'Malware Attacker stopped successfully' if result['success'] else result['error']
    })

@app.route('/api/malware_attacker/logs', methods=['GET'])
def get_malware_attacker_logs():
    """Get malware attacker logs"""
    
    # Get container logs (using correct container name)
    container_logs = run_wsl_command('docker logs --tail 100 malware_attacker 2>&1')
    
    # Get consolidated malware log (all behaviors in one file)
    malware_log = run_wsl_command('cat /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/attackers/malware_attacker/logs/malware.log 2>/dev/null | tail -50 || echo "No logs yet"')
    
    return jsonify({
        'success': True,
        'container_logs': container_logs['output'] if container_logs['success'] else 'Container not running',
        'malware_logs': malware_log['output'],
        'beacon_logs': malware_log['output'],
        'exfil_logs': malware_log['output'],
        'eicar_logs': malware_log['output'],
        'dns_logs': malware_log['output'],
        'orchestrator_logs': malware_log['output']
    })

@app.route('/api/malware_attacker/status', methods=['GET'])
def get_malware_attacker_status():
    """Get malware attacker container status"""
    
    # Check if container is running (correct container name)
    status = run_wsl_command('docker ps -f name=malware_attacker --format "{{.Status}}"')
    is_running = status['success'] and status['output'].strip() != ''
    
    # Get container IP if running (correct IP: 192.168.6.200)
    ip_address = '192.168.6.200'
    if is_running:
        ip_result = run_wsl_command('docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" malware_attacker')
        if ip_result['success']:
            ip_address = ip_result['output'].strip()
    
    return jsonify({
        'success': True,
        'running': is_running,
        'status': status['output'].strip() if is_running else 'Not running',
        'ip_address': ip_address,
        'detection_type': 'Case 1: Signature-Based',
        'behaviors': {
            'malware_upload': 'Active' if is_running else 'Stopped'
        }
    })

# ===== Endpoint Behavior Attacker Control (Case 2) =====

@app.route('/api/endpoint_behavior_attacker/start', methods=['POST'])
def start_endpoint_behavior_attacker():
    """Start endpoint behavior attacker (Case 2 - Anomaly Detection)"""
    
    # Ensure network exists
    network_check = run_wsl_command('docker network ls | grep custom_net')
    if not (network_check['success'] and 'custom_net' in network_check['output']):
        return jsonify({
            'success': False,
            'message': 'Network does not exist. Create network first.'
        })
    
    # Start endpoint behavior attacker using docker compose
    result = run_wsl_command('cd /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/attackers/endpoint_behavior_attacker && docker compose up -d --build', timeout=180)
    
    return jsonify({
        'success': result['success'],
        'message': 'Endpoint Behavior Attacker started successfully' if result['success'] else result['error'],
        'output': result['output']
    })

@app.route('/api/endpoint_behavior_attacker/stop', methods=['POST'])
def stop_endpoint_behavior_attacker():
    """Stop endpoint behavior attacker"""
    
    # Stop the container
    result = run_wsl_command('cd /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/attackers/endpoint_behavior_attacker && docker compose down')
    
    return jsonify({
        'success': result['success'],
        'message': 'Endpoint Behavior Attacker stopped successfully' if result['success'] else result['error']
    })

@app.route('/api/endpoint_behavior_attacker/logs', methods=['GET'])
def get_endpoint_behavior_attacker_logs():
    """Get endpoint behavior attacker logs"""
    
    # Get container logs
    container_logs = run_wsl_command('docker logs --tail 100 endpoint_behavior_attacker 2>&1')
    
    # Get file logs
    file_logs = run_wsl_command('cat /mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/attackers/endpoint_behavior_attacker/logs/behavior_simulator.log 2>/dev/null | tail -100 || echo "No logs yet"')
    
    return jsonify({
        'success': True,
        'container_logs': container_logs['output'] if container_logs['success'] else 'Container not running',
        'file_logs': file_logs['output']
    })

@app.route('/api/endpoint_behavior_attacker/status', methods=['GET'])
def get_endpoint_behavior_attacker_status():
    """Get endpoint behavior attacker container status"""
    
    # Check if container is running
    status = run_wsl_command('docker ps -f name=endpoint_behavior_attacker --format "{{.Status}}"')
    is_running = status['success'] and status['output'].strip() != ''
    
    # Get container IP if running (configured IP: 192.168.6.201)
    ip_address = '192.168.6.201'
    if is_running:
        ip_result = run_wsl_command('docker inspect -f "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}" endpoint_behavior_attacker')
        if ip_result['success']:
            ip_address = ip_result['output'].strip()
    
    return jsonify({
        'success': True,
        'running': is_running,
        'status': status['output'].strip() if is_running else 'Not running',
        'ip_address': ip_address,
        'detection_type': 'Case 2: Behavior/Anomaly-Based',
        'behaviors': {
            'c2_beacon': 'Active' if is_running else 'Stopped',
            'data_exfiltration': 'Active' if is_running else 'Stopped',
            'dns_dga': 'Active' if is_running else 'Stopped',
            'port_scanning': 'Active' if is_running else 'Stopped',
            'api_abuse': 'Active' if is_running else 'Stopped',
            'credential_harvesting': 'Active' if is_running else 'Stopped',
            'privilege_escalation': 'Active' if is_running else 'Stopped',
            'lateral_movement': 'Active' if is_running else 'Stopped',
            'data_staging': 'Active' if is_running else 'Stopped'
        }
    })

# ===== Network Monitor Server Control =====

@app.route('/api/monitor/start', methods=['POST'])
def start_monitor():
    """Start network monitor server"""
    
    # Ensure custom_net exists first
    network_check = run_wsl_command('docker network ls | grep custom_net')
    if not (network_check['success'] and 'custom_net' in network_check['output']):
        print("Creating custom_net network...")
        create_net = run_wsl_command('docker network create --subnet=192.168.6.0/24 custom_net')
        if not create_net['success']:
            return jsonify({
                'success': False,
                'message': 'Failed to create network. Please create network first.',
                'error': create_net['error']
            })
    
    def run_monitor_startup():
        print("Starting monitor in background...")
        # Use docker-compose to start (build can take 2-3 minutes)
        # Increased timeout to 10 minutes for initial build
        result = run_wsl_command(f'cd {WSL_NETWORK_DIR} && docker compose up -d --build', timeout=600)
        print(f"Monitor startup result: {result['success']}")
        if not result['success']:
            print(f"Monitor startup error: {result['error']}")

    # Start in background thread
    thread = threading.Thread(target=run_monitor_startup)
    thread.start()
    
    return jsonify({
        'success': True,
        'message': 'Network monitor starting in background... This may take 2-3 minutes. Check status periodically.',
        'output': 'Startup process initiated in background'
    })

@app.route('/api/monitor/stop', methods=['POST'])
def stop_monitor():
    """Stop network monitor server"""
    
    result = run_wsl_command(f'cd {WSL_NETWORK_DIR} && docker compose down')
    
    return jsonify({
        'success': result['success'],
        'message': 'Network monitor stopped successfully' if result['success'] else result['error'],
        'output': result['output']
    })

@app.route('/api/monitor/status')
def get_monitor_status():
    """Get network monitor status"""
    
    result = run_wsl_command('docker ps --filter name=net-monitor-wan --format "{{.Status}}"')
    
    # Check if monitor container is running
    is_running = result['success'] and 'running' in result['output'].lower()
    
    return jsonify({
        'success': True,
        'running': is_running,
        'status': result['output'],
        'output': result['output']
    })

@app.route('/api/monitor/logs')
def get_monitor_logs():
    """Get network monitor container logs"""
    # Try all possible container names in order of likelihood
    container_names = ['network-monitor', 'net-monitor-wan', 'monitor']
    result = None
    for cname in container_names:
        result = run_wsl_command(f'docker logs --tail 200 {cname} 2>&1')
        if result['success'] and result['output']:
            container_used = cname
            break
    else:
        # If none succeeded, use the last result for error
        container_used = container_names[0]
    return jsonify({
        'success': result['success'],
        'logs': result['output'] if result['success'] else result['error'],
        'container': container_used
    })

@app.route('/api/logs/network')
def get_network_logs():
    """Get network analysis logs"""
    
    log_file = os.path.join(NETWORK_DIR, 'analyze_output.txt')
    
    if not os.path.exists(log_file):
        return jsonify({
            'success': True,
            'logs': 'No logs available yet',
            'timestamp': None
        })
    
    try:
        with open(log_file, 'r') as f:
            content = f.read()
        
        return jsonify({
            'success': True,
            'logs': content,
            'timestamp': datetime.fromtimestamp(os.path.getmtime(log_file)).isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/containers/logs/<container_name>')
def get_container_logs(container_name):
    """Get logs from specific container"""
    
    result = run_wsl_command(f'docker logs --tail 100 {container_name}')
    
    return jsonify({
        'success': result['success'],
        'logs': result['output'] if result['success'] else result['error'],
        'container': container_name
    })

# ===== Device Data Receiver Endpoints =====
# These endpoints receive data from device containers

device_registry = {}
device_data_log = []

def clear_old_data():
    """Clear old device registry and logs on dashboard restart"""
    global device_registry, device_data_log
    device_registry.clear()
    device_data_log.clear()
    print("🧹 Cleared old device data and logs")

@app.route('/api/device/register', methods=['POST'])
def register_device():
    """Register a device"""
    data = request.json
    device_id = data.get('device_id')
    
    device_registry[device_id] = {
        'device_id': device_id,
        'device_type': data.get('device_type'),
        'ip_address': data.get('ip_address'),
        'mac_address': data.get('mac_address'),
        'registered_at': datetime.now().isoformat(),
        'last_seen': datetime.now().isoformat(),
        'request_count': 0
    }
    
    print(f"✅ Device registered: {device_id} ({data.get('device_type')}) - IP: {data.get('ip_address')}")
    
    return jsonify({
        'success': True,
        'message': f'Device {device_id} registered successfully'
    })

@app.route('/api/device/data', methods=['POST'])
def receive_device_data():
    """Receive data from devices"""
    data = request.json
    device_id = data.get('device_id')
    
    # Update device registry
    if device_id in device_registry:
        device_registry[device_id]['last_seen'] = datetime.now().isoformat()
        device_registry[device_id]['request_count'] += 1
    
    # Log data
    device_data_log.append({
        'timestamp': datetime.now().isoformat(),
        'device_id': device_id,
        'device_type': data.get('device_type'),
        'sensor_data': data.get('sensor_data'),
        'ip_address': data.get('ip_address')
    })
    
    # Keep only last 500 entries
    if len(device_data_log) > 500:
        device_data_log.pop(0)
    
    print(f"📊 Data received from {device_id}: {data.get('sensor_data')}")
    
    return jsonify({
        'success': True,
        'message': 'Data received',
        'command': None  # Can send commands back to device
    })

@app.route('/api/device/status', methods=['GET'])
def device_status():
    """Get device status"""
    device_id = request.args.get('device_id')
    
    if device_id in device_registry:
        return jsonify({
            'success': True,
            'status': 'online',
            'device': device_registry[device_id]
        })
    
    return jsonify({
        'success': False,
        'status': 'unknown'
    })

@app.route('/api/devices/registry')
def get_device_registry():
    """Get all registered devices"""
    return jsonify({
        'success': True,
        'devices': list(device_registry.values()),
        'count': len(device_registry)
    })

@app.route('/api/devices/data/latest')
def get_latest_device_data():
    """Get latest device data"""
    count = int(request.args.get('count', 50))
    return jsonify({
        'success': True,
        'data': device_data_log[-count:],
        'total': len(device_data_log)
    })

@app.route('/api/network/map')
def get_network_map():
    """Get network topology map with all containers and devices"""
    
    # Get all containers on custom_net
    inspect_result = run_wsl_command('docker network inspect custom_net --format "{{json .Containers}}"')
    
    # Get all containers on honeypot_net (check both standalone and docker-compose network names)
    honeypot_inspect = run_wsl_command('docker network inspect honey_pot_honeypot_net --format "{{json .Containers}}" 2>/dev/null || docker network inspect honeypot_net --format "{{json .Containers}}" 2>/dev/null || echo "{}"')
    
    nodes = []
    connections = []
    
    if inspect_result['success'] and inspect_result['output'].strip():
        try:
            containers_data = json.loads(inspect_result['output'].strip())
            
            # Add gateway node (dashboard server)
            nodes.append({
                'id': 'gateway',
                'name': 'Dashboard Server',
                'type': 'gateway',
                'ip': '192.168.6.1',
                'status': 'running'
            })
            
            # Add all containers from Docker network
            for container_id, info in containers_data.items():
                container_name = info.get('Name', 'unknown')
                container_ip = info.get('IPv4Address', '').split('/')[0]
                
                # Determine container type
                if container_name.startswith('device_'):
                    node_type = 'device'
                    # Get device details from registry if available
                    device_id = container_name.replace('device_', 'device_')
                    # Look for matching device in registry
                    device_info = None
                    for dev_id, dev_data in device_registry.items():
                        if dev_id in container_name or container_name in dev_id:
                            device_info = dev_data
                            break
                    
                    display_name = f"{container_name}"
                    if device_info:
                        display_name += f" ({device_info.get('device_type', 'unknown')})"
                    
                elif 'honeypot' in container_name or 'beelzebub' in container_name:
                    node_type = 'honeypot'
                    if 'log-viewer' in container_name:
                        display_name = 'Honeypot Log Viewer'
                    else:
                        display_name = 'Honeypot Server'
                    node_data = {
                        'id': container_name,
                        'name': display_name,
                        'type': node_type,
                        'ip': container_ip,
                        'status': 'running',
                        'container_id': container_id[:12]
                    }
                elif 'monitor' in container_name or container_name == 'net-monitor-wan':
                    node_type = 'monitor'
                    display_name = 'Network Monitor Server'
                    node_data = {
                        'id': container_name,
                        'name': display_name,
                        'type': node_type,
                        'ip': container_ip,
                        'status': 'running',
                        'container_id': container_id[:12]
                    }
                elif 'attacker' in container_name:
                    node_type = 'attacker'
                    # For attacker nodes, use only the IP as the display name (if available)
                    display_name = container_ip if container_ip else container_name
                    node_data = {
                        'id': container_name,
                        'name': display_name,
                        'type': node_type,
                        'ip': container_ip,
                        'status': 'running',
                        'container_id': container_id[:12]
                    }
                else:
                    node_type = 'other'
                    display_name = container_name
                    node_data = {
                        'id': container_name,
                        'name': display_name,
                        'type': node_type,
                        'ip': container_ip,
                        'status': 'running',
                        'container_id': container_id[:12]
                    }
                nodes.append(node_data)
                
                # Create connection to gateway
                connections.append({
                    'from': 'gateway',
                    'to': container_name,
                    'type': 'network'
                })
        
        except json.JSONDecodeError:
            pass
    
    # Add honeypot network containers (separate network)
    if honeypot_inspect['success'] and honeypot_inspect['output'].strip() and honeypot_inspect['output'] != '{}':
        try:
            honeypot_containers = json.loads(honeypot_inspect['output'].strip())
            
            # Add containers on honeypot network (no separate gateway node)
            for container_id, info in honeypot_containers.items():
                container_name = info.get('Name', 'unknown')
                container_ip = info.get('IPv4Address', '').split('/')[0]
                
                # Check if already added (containers can be on multiple networks)
                already_exists = False
                for node in nodes:
                    if node['id'] == container_name:
                        already_exists = True
                        # Update node to show it's on honeypot network
                        node['honeypot_ip'] = container_ip
                        node['on_honeypot_network'] = True
                        break
                
                if not already_exists:
                    # Determine type
                    if 'beelzebub' in container_name:
                        if 'log-viewer' in container_name:
                            node_type = 'honeypot'
                            display_name = 'Honeypot Log Viewer'
                        else:
                            node_type = 'honeypot'
                            display_name = 'Beelzebub Honeypot'
                    elif container_name.startswith('device_'):
                        node_type = 'device'
                        display_name = container_name + ' (Rerouted)'
                    else:
                        node_type = 'other'
                        display_name = container_name
                    
                    nodes.append({
                        'id': container_name,
                        'name': display_name,
                        'type': node_type,
                        'ip': container_ip,
                        'status': 'running',
                        'container_id': container_id[:12],
                        'on_honeypot_network': True
                    })
                
                # Connection added directly to main gateway
                connections.append({
                    'from': 'gateway',
                    'to': container_name,
                    'type': 'honeypot_network'
                })
        
        except json.JSONDecodeError as e:
            print(f"Error parsing honeypot network: {e}")
            
            for container_id, info in honeypot_containers.items():
                container_name = info.get('Name', 'unknown')
                container_ip = info.get('IPv4Address', '').split('/')[0]
                
                # Check if this container is already in nodes (might be on both networks)
                existing_node = next((node for node in nodes if node['id'] == container_name), None)
                
                if existing_node:
                    # Update to show dual-network status
                    existing_node['honeypot_ip'] = container_ip
                    existing_node['dual_network'] = True
                    # Add connection directly to main gateway
                    connections.append({
                        'from': 'gateway',
                        'to': container_name,
                        'type': 'honeypot_network'
                    })
                else:
                    # Container only on honeypot network
                    if 'honeypot' in container_name:
                        display_name = 'Honeypot Server (Isolated)'
                        node_type = 'honeypot'
                    else:
                        display_name = container_name
                        node_type = 'honeypot_device'
                    
                    nodes.append({
                        'id': container_name,
                        'name': display_name,
                        'type': node_type,
                        'ip': container_ip,
                        'status': 'running',
                        'container_id': container_id[:12],
                        'network': 'honeypot_net'
                    })
                    
                    # Connect directly to main gateway
                    connections.append({
                        'from': 'gateway',
                        'to': container_name,
                        'type': 'honeypot_network'
                    })
        
        except json.JSONDecodeError:
            pass
    
    # Add devices from registry that might not be in Docker inspect
    for device_id, device_info in device_registry.items():
        # Check if device already in nodes
        device_exists = any(node['id'].startswith('device_') and device_id in node['id'] for node in nodes)
        
        if not device_exists:
            nodes.append({
                'id': device_id,
                'name': f"{device_id} ({device_info.get('device_type', 'unknown')})",
                'type': 'device',
                'ip': device_info.get('ip_address', 'N/A'),
                'status': 'registered',
                'last_seen': device_info.get('last_seen')
            })
            
            connections.append({
                'from': 'gateway',
                'to': device_id,
                'type': 'data'
            })
    
    return jsonify({
        'success': True,
        'nodes': nodes,
        'connections': connections,
        'network': {
            'name': 'custom_net',
            'subnet': '192.168.6.0/24',
            'gateway': '192.168.6.1'
        }
    })

# ==================== MCP AGENT ROUTES ====================

@app.route('/api/agent/status')
def get_agent_status():
    """Get MCP agent status"""
    try:
        # Get API key info (masked for security)
        api_key = os.getenv('ANTHROPIC_API_KEY')
        key_info = {
            'configured': bool(api_key),
            'key_preview': f"{api_key[:20]}...{api_key[-10:]}" if api_key and len(api_key) > 30 else 'Not set',
            'length': len(api_key) if api_key else 0
        }
        
        # Check if agent script exists
        agent_script = os.path.join(BASE_DIR, 'mcp_agent', 'client', 'agent.py')
        agent_available = os.path.exists(agent_script)
        
        # Check if MCP server exists
        server_script = os.path.join(BASE_DIR, 'mcp_agent', 'server', 'server.py')
        server_available = os.path.exists(server_script)
        
        return jsonify({
            'success': True,
            'active': agent_available and server_available and bool(api_key),
            'agent_available': agent_available,
            'server_available': server_available,
            'api_key_info': key_info,
            'model': 'glm-4.5',
            'execution_mode': 'subprocess',  # Each query runs in fresh process
            'features': {
                'multi_turn': True,
                'tool_calling': True,
                'planning': True,
                'todo_tracking': True,
                'max_iterations': 100
            },
            'available_tools': [
                'read_file', 'write_file', 'append_file', 'create_directory', 
                'list_directory', 'delete_file', 'file_exists',
                'run_command', 'run_batch_file', 'run_powershell',
                'wsl_command', 'wsl_bash_script', 'wsl_read_file', 'wsl_write_file',
                'docker_command', 'get_env_variable', 'set_env_variable',
                'analyze_traffic', 'move_device_to_honeypot'
            ]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'active': False
        })

@app.route('/api/agent/query', methods=['POST'])
def agent_query():
    """Process query through MCP Agent with multi-turn conversation support"""
    data = request.get_json()
    query = data.get('query', '').strip()
    
    if not query:
        return jsonify({
            'success': False,
            'error': 'Query is required'
        })
    
    try:
        # Run agent query in a completely separate process to avoid event loop conflicts
        import sys
        agent_script = os.path.join(BASE_DIR, 'mcp_agent', 'client', 'agent.py')
        venv_python = r'E:\nos\.venv\Scripts\python.exe'
        python_executable = venv_python if os.path.exists(venv_python) else 'python'
        
        # Set UTF-8 environment
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        
        # Run agent as subprocess (each query gets fresh event loop)
        print(f"🤖 Running agent query: {query[:100]}...")
        print(f"📂 Working directory: {os.path.join(BASE_DIR, 'mcp_agent', 'client')}")
        print(f"🐍 Python executable: {python_executable}")
        
        result = subprocess.run(
            [python_executable, agent_script, query],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=300,  # Increased to 5 minutes for complex queries
            cwd=os.path.join(BASE_DIR, 'mcp_agent', 'client'),
            env=env
        )
        
        print(f"✅ Agent completed with return code: {result.returncode}")
        
        if result.returncode == 0:
            response_text = result.stdout.strip()
            
            # Try to extract just the agent response (skip debug output)
            lines = response_text.split('\n')
            # Look for "Agent:" prefix or clean response
            agent_lines = []
            capture = False
            for line in lines:
                if line.startswith('Agent:'):
                    capture = True
                    agent_lines.append(line[6:].strip())  # Remove "Agent:" prefix
                elif capture and not line.startswith('🔧') and not line.startswith('✓'):
                    agent_lines.append(line)
            
            final_response = '\n'.join(agent_lines) if agent_lines else response_text
            
            return jsonify({
                'success': True,
                'response': final_response,
                'source': 'MCP Agent',
                'full_output': response_text  # Include full output for debugging
            })
        else:
            error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
            return jsonify({
                'success': False,
                'error': f'Agent error: {error_msg}',
                'returncode': result.returncode
            })
        
    except subprocess.TimeoutExpired:
        print("⏰ Agent query timed out after 300 seconds")
        return jsonify({
            'success': False,
            'error': 'Query timeout (300s). The agent took too long to process. Try a simpler query or check if MCP server is responding.'
        })
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': f'Dashboard error: {str(e)}',
            'error_type': type(e).__name__,
            'traceback': traceback.format_exc()
        })

@app.route('/api/agent/clear', methods=['POST'])
def agent_clear_history():
    """Clear agent conversation history - Not applicable in subprocess mode"""
    return jsonify({
        'success': True,
        'message': 'Each query runs in a fresh subprocess, so conversation history is already isolated per query'
    })

@app.route('/api/agent/stats')
def agent_stats():
    """Get detailed agent statistics - Not applicable in subprocess mode"""
    try:
        api_key = os.getenv('ANTHROPIC_API_KEY')
        
        return jsonify({
            'success': True,
            'execution_mode': 'subprocess',
            'note': 'Each query runs independently in a subprocess with fresh state',
            'api_configured': bool(api_key),
            'available_tools': 19,
            'features': {
                'multi_turn_per_query': True,
                'persistent_history': False,
                'max_iterations': 100
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/agent/test-key', methods=['POST'])
def test_anthropic_key():
    """Test if Anthropic API key is valid"""
    try:
        from anthropic import Anthropic
        
        api_key = os.getenv('ANTHROPIC_API_KEY')
        if not api_key:
            return jsonify({
                'success': False,
                'error': 'ANTHROPIC_API_KEY not configured'
            })
        
        # Try to create client and make a simple API call
        client = Anthropic(api_key=api_key)
        
        # Test with a minimal message
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=10,
            messages=[{"role": "user", "content": "Hi"}]
        )
        
        return jsonify({
            'success': True,
            'message': 'API key is valid',
            'model': 'claude-3-5-sonnet-20241022',
            'test_response': response.content[0].text if response.content else 'OK'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'API key test failed: {str(e)}',
            'error_type': type(e).__name__
        })

@app.route('/api/network/detection-info')
def get_network_detection_info():
    """Get comprehensive network detection info - malware, threats, anomalies"""
    try:
        detection_info = {
            'timestamp': datetime.now().isoformat(),
            'network_health': 'HEALTHY',
            'threats_detected': [],
            'malware_detected': [],
            'anomalies': [],
            'active_defenses': [],
            'statistics': {}
        }
        
        # Check for malware detections from zeek logs
        zeek_extracted_dir = os.path.join(NETWORK_DIR, 'zeek_logs', 'extracted_files')
        malware_count = 0
        if os.path.exists(zeek_extracted_dir):
            malware_count = len([f for f in os.listdir(zeek_extracted_dir) if os.path.isfile(os.path.join(zeek_extracted_dir, f))])
            if malware_count > 0:
                detection_info['malware_detected'].append({
                    'type': 'Extracted Files',
                    'count': malware_count,
                    'location': 'zeek_logs/extracted_files',
                    'severity': 'HIGH' if malware_count > 10 else 'MEDIUM',
                    'description': f'{malware_count} suspicious files extracted from network traffic'
                })
        
        # Check honeypot attack logs
        attacks_file = os.path.join(HONEYPOT_DIR, 'logs', 'attacks.jsonl')
        honeypot_attacks = 0
        if os.path.exists(attacks_file):
            try:
                with open(attacks_file, 'r', encoding='utf-8', errors='ignore') as f:
                    honeypot_attacks = sum(1 for line in f if line.strip())
                    if honeypot_attacks > 0:
                        detection_info['threats_detected'].append({
                            'type': 'Honeypot Attacks',
                            'count': honeypot_attacks,
                            'severity': 'HIGH',
                            'description': f'{honeypot_attacks} attack attempts captured by honeypot'
                        })
            except:
                pass
        
        # Check for network anomalies (DoS attacks)
        network_attacks_file = os.path.join(HONEYPOT_DIR, 'logs', 'network_attacks.jsonl')
        dos_attacks = 0
        if os.path.exists(network_attacks_file):
            try:
                with open(network_attacks_file, 'r', encoding='utf-8', errors='ignore') as f:
                    dos_attacks = sum(1 for line in f if line.strip())
                    if dos_attacks > 0:
                        detection_info['anomalies'].append({
                            'type': 'DoS/DDoS Attacks',
                            'count': dos_attacks,
                            'severity': 'CRITICAL',
                            'description': f'{dos_attacks} network flooding events detected'
                        })
            except:
                pass
        
        # Check active containers
        containers_result = run_wsl_command('docker ps --format "{{.Names}}"')
        active_containers = []
        if containers_result['success']:
            active_containers = [c.strip() for c in containers_result['output'].strip().split('\n') if c.strip()]
        
        # Check for active defense mechanisms
        if any('monitor' in c for c in active_containers):
            detection_info['active_defenses'].append({
                'name': 'Network Monitor',
                'status': 'ACTIVE',
                'description': 'Zeek-based traffic analysis and file extraction'
            })
        
        if any('beelzebub' in c for c in active_containers):
            detection_info['active_defenses'].append({
                'name': 'Honeypot (Beelzebub)',
                'status': 'ACTIVE',
                'description': 'Multi-protocol honeypot capturing attack attempts'
            })
        
        # Check for rerouted devices
        reroutes_log = os.path.join(HONEYPOT_DIR, 'logs', 'reroutes.log')
        rerouted_count = 0
        if os.path.exists(reroutes_log):
            try:
                with open(reroutes_log, 'r') as f:
                    rerouted_count = sum(1 for line in f if 'Rerouted' in line)
                    if rerouted_count > 0:
                        detection_info['active_defenses'].append({
                            'name': 'Quarantine',
                            'status': 'ACTIVE',
                            'description': f'{rerouted_count} devices isolated to honeypot network'
                        })
            except:
                pass
        
        # Calculate statistics
        detection_info['statistics'] = {
            'total_threats': len(detection_info['threats_detected']),
            'total_malware': len(detection_info['malware_detected']),
            'total_anomalies': len(detection_info['anomalies']),
            'malware_files_count': malware_count,
            'honeypot_attacks_count': honeypot_attacks,
            'dos_attacks_count': dos_attacks,
            'active_defenses_count': len(detection_info['active_defenses']),
            'rerouted_devices': rerouted_count
        }
        
        # Determine overall network health
        if detection_info['statistics']['total_threats'] > 10 or detection_info['statistics']['total_malware'] > 5:
            detection_info['network_health'] = 'CRITICAL'
        elif detection_info['statistics']['total_threats'] > 5 or detection_info['statistics']['total_malware'] > 0:
            detection_info['network_health'] = 'WARNING'
        else:
            detection_info['network_health'] = 'HEALTHY'
        
        return jsonify({
            'success': True,
            **detection_info
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'network_health': 'UNKNOWN',
            'threats_detected': [],
            'malware_detected': [],
            'anomalies': [],
            'active_defenses': [],
            'statistics': {}
        })

@app.route('/api/agent/reroute', methods=['POST'])
def agent_reroute_to_beelzebub():
    """Reroute device to Beelzebub honeypot via agent MCP tool"""
    data = request.get_json()
    device_ip = data.get('device_ip', '').strip()
    
    if not device_ip:
        return jsonify({
            'success': False,
            'error': 'Device IP is required'
        })
    
    try:
        print(f"🔄 [Quick Reroute] Attempting to reroute {device_ip}")
        
        # Find container with this IP - first try custom_net
        find_cmd = f'docker ps --format "{{{{.Names}}}}" --filter "network=custom_net"'
        result = run_wsl_command(find_cmd)
        container_candidates = result['output'].strip().split('\n') if result['success'] else []
        
        container_name = None
        found_on_network = 'custom_net'
        
        # Search containers on custom_net
        for candidate in container_candidates:
            candidate = candidate.strip()
            if not candidate:
                continue
            
            check_ip_cmd = f'docker inspect {candidate} --format "{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}"'
            ip_result = run_wsl_command(check_ip_cmd)
            
            container_ip = ip_result['output'].strip() if ip_result['success'] else ''
            if container_ip == device_ip:
                container_name = candidate
                break
        
        # If not found on custom_net, search all containers and all networks
        if not container_name:
            print(f"  ⚠️ Not found on custom_net, searching all containers...")
            all_containers_cmd = 'docker ps --format "{{{{.Names}}}}"'
            all_result = run_wsl_command(all_containers_cmd)
            all_candidates = all_result['output'].strip().split('\n') if all_result['success'] else []
            
            for candidate in all_candidates:
                candidate = candidate.strip()
                if not candidate:
                    continue
                
                # Check all networks this container is on
                networks_cmd = f'docker inspect {candidate} --format "{{{{json .NetworkSettings.Networks}}}}"'
                networks_result = run_wsl_command(networks_cmd)
                
                if networks_result['success']:
                    try:
                        import json as json_lib
                        networks = json_lib.loads(networks_result['output'].strip())
                        for network_name, network_info in networks.items():
                            network_ip = network_info.get('IPAddress', '')
                            if network_ip == device_ip:
                                container_name = candidate
                                found_on_network = network_name
                                print(f"  ✅ Found {candidate} with IP {device_ip} on {network_name}")
                                
                                # If found on a different network, reconnect to custom_net first
                                if network_name != 'custom_net':
                                    print(f"  Reconnecting {candidate} to custom_net...")
                                    reconnect_cmd = f'docker network connect custom_net {candidate}'
                                    run_wsl_command(reconnect_cmd)
                                break
                    except:
                        pass
                
                if container_name:
                    break
        
        if not container_name:
            return jsonify({
                'success': False,
                'error': f'No container found with IP {device_ip}. Container may be stopped or IP changed.'
            })
        
        print(f"  📦 Found container: {container_name}")
        
        # Get Beelzebub honeypot network and IP dynamically
        get_beelzebub_network_cmd = 'docker inspect beelzebub-honeypot --format "{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{end}}" 2>/dev/null | grep -o "[^ ]*honeypot[^ ]*" | head -1'
        beelzebub_network_result = run_wsl_command(get_beelzebub_network_cmd)
        honeypot_network = beelzebub_network_result['output'].strip() if (beelzebub_network_result['success'] and beelzebub_network_result['output'].strip()) else 'honey_pot_honeypot_net'
        
        get_beelzebub_ip_cmd = f'docker inspect beelzebub-honeypot --format "{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}" 2>/dev/null'
        beelzebub_ip_result = run_wsl_command(get_beelzebub_ip_cmd)
        honeypot_target_ip = beelzebub_ip_result['output'].strip() if (beelzebub_ip_result['success'] and beelzebub_ip_result['output'].strip()) else '172.18.0.2'
        
        print(f"🍯 Honeypot network: {honeypot_network}")
        print(f"🍯 Honeypot IP: {honeypot_target_ip}")
        
        # STEP 1: Add iptables DNAT rules to reroute ALL traffic to Beelzebub honeypot
        # Device STAYS on custom_net - only traffic is redirected
        print(f"🔀 Setting up DNAT rerouting for {device_ip} → {honeypot_target_ip}")
        
        # DNAT rules for ALL traffic from malicious device - reroute everything to honeypot
        dnat_rules = [
            # Reroute ALL HTTP/HTTPS traffic (any destination) to honeypot
            f'iptables -t nat -A PREROUTING -s {device_ip} -p tcp --dport 80 -j DNAT --to-destination {honeypot_target_ip}:8080',
            f'iptables -t nat -A PREROUTING -s {device_ip} -p tcp --dport 443 -j DNAT --to-destination {honeypot_target_ip}:8080',
            f'iptables -t nat -A PREROUTING -s {device_ip} -p tcp --dport 8080 -j DNAT --to-destination {honeypot_target_ip}:8080',
            f'iptables -t nat -A PREROUTING -s {device_ip} -p tcp --dport 5000 -j DNAT --to-destination {honeypot_target_ip}:8080',
            
            # Reroute ALL SSH traffic to honeypot SSH
            f'iptables -t nat -A PREROUTING -s {device_ip} -p tcp --dport 22 -j DNAT --to-destination {honeypot_target_ip}:22',
            
            # Reroute ALL MySQL traffic to honeypot
            f'iptables -t nat -A PREROUTING -s {device_ip} -p tcp --dport 3306 -j DNAT --to-destination {honeypot_target_ip}:3306',
            
            # Reroute ALL PostgreSQL traffic to honeypot
            f'iptables -t nat -A PREROUTING -s {device_ip} -p tcp --dport 5432 -j DNAT --to-destination {honeypot_target_ip}:5432',
            
            # Reroute FTP traffic
            f'iptables -t nat -A PREROUTING -s {device_ip} -p tcp --dport 21 -j DNAT --to-destination {honeypot_target_ip}:21',
            
            # Reroute Telnet traffic
            f'iptables -t nat -A PREROUTING -s {device_ip} -p tcp --dport 23 -j DNAT --to-destination {honeypot_target_ip}:23'
        ]
        
        # FORWARD rules to allow ALL traffic between malicious device and honeypot
        forward_rules = [
            # Allow all TCP traffic from malicious device to honeypot
            f'iptables -A FORWARD -s {device_ip} -d {honeypot_target_ip} -j ACCEPT',
            # Allow all return traffic from honeypot to malicious device
            f'iptables -A FORWARD -s {honeypot_target_ip} -d {device_ip} -j ACCEPT'
        ]
        
        # MASQUERADE for return traffic (source NAT)
        masquerade_rule = f'iptables -t nat -A POSTROUTING -s {device_ip} -d {honeypot_target_ip} -j MASQUERADE'
        
        # Apply all iptables rules
        all_rules = dnat_rules + forward_rules + [masquerade_rule]
        failed_rules = []
        applied_rules = 0
        
        for rule in all_rules:
            iptables_cmd = f'sudo {rule}'
            iptables_result = run_wsl_command(iptables_cmd)
            if iptables_result['success']:
                applied_rules += 1
                print(f"  ✅ Applied: {rule}")
            else:
                failed_rules.append(f"{rule}: {iptables_result.get('output', 'Unknown error')}")
                print(f"  ❌ Failed: {rule}")
        
        if failed_rules:
            return jsonify({
                'success': False,
                'error': f'Failed to apply {len(failed_rules)} iptables rules',
                'details': failed_rules
            })
        
        # STEP 2: Connect device to honeypot network (for direct bidirectional communication)
        connect_cmd = f'docker network connect {honeypot_network} {container_name} 2>&1'
        connect_result = run_wsl_command(connect_cmd)
        
        if not connect_result['success'] and 'already exists' not in connect_result.get('output', ''):
            # If connection fails, that's okay - DNAT rules are already in place
            print(f"⚠️ Note: Could not connect to {honeypot_network}, but DNAT rules applied")
        
        # STEP 3: Log the reroute
        log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] DNAT REROUTE (Agent): {container_name} ({device_ip}) → Honeypot ({honeypot_target_ip}) via DNAT | Rules: {applied_rules}\n"
        try:
            os.makedirs(os.path.join(HONEYPOT_DIR, 'logs'), exist_ok=True)
            with open(os.path.join(HONEYPOT_DIR, 'logs', 'reroutes.log'), 'a') as f:
                f.write(log_entry)
        except:
            pass
        
        print(f"  ✅ Successfully rerouted {container_name} traffic to honeypot via DNAT")
        
        return jsonify({
            'success': True,
            'message': f'✅ ALL traffic from {container_name} ({device_ip}) rerouted to Beelzebub honeypot ({honeypot_target_ip}) via DNAT iptables. Device stays on custom_net. {applied_rules} rules applied.',
            'device': container_name,
            'original_ip': device_ip,
            'honeypot_target': honeypot_target_ip,
            'method': 'DNAT_iptables',
            'rules_applied': applied_rules,
            'action': 'rerouted_to_honeypot'
        })
        
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

def start_mcp_server():
    """Start MCP server in background if not already running"""
    import psutil
    import sys
    
    # Check if MCP server is already running
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info.get('cmdline', [])
            if cmdline and 'server.py' in ' '.join(cmdline) and 'mcp_agent' in ' '.join(cmdline):
                print("✅ MCP server already running (PID: {})".format(proc.info['pid']))
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    # Start MCP server
    print("🚀 Starting MCP server...")
    mcp_server_path = os.path.join(BASE_DIR, 'mcp_agent', 'server', 'server.py')
    
    if not os.path.exists(mcp_server_path):
        print(f"⚠️  MCP server not found at {mcp_server_path}")
        return None
    
    try:
        # Start server as background process
        if sys.platform == 'win32':
            # Windows: Use CREATE_NEW_CONSOLE to run in background
            process = subprocess.Popen(
                [sys.executable, 'server.py'],
                cwd=os.path.join(BASE_DIR, 'mcp_agent', 'server'),
                creationflags=subprocess.CREATE_NEW_CONSOLE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        else:
            # Linux/Mac
            process = subprocess.Popen(
                [sys.executable, 'server.py'],
                cwd=os.path.join(BASE_DIR, 'mcp_agent', 'server'),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
        
        import time
        time.sleep(2)  # Give server time to start
        
        if process.poll() is None:
            print(f"✅ MCP server started (PID: {process.pid})")
            return process.pid
        else:
            print("⚠️  MCP server failed to start (check dependencies: pip install fastmcp)")
            return None
    except Exception as e:
        print(f"⚠️  Could not start MCP server: {e}")
        print("   Install dependencies: pip install fastmcp")
        return None

if __name__ == '__main__':
    clear_old_data()  # Clear old data on startup
    print("=" * 80)
    print("🚀 Network Security Dashboard Starting...")
    print("=" * 80)
    
    # Auto-start MCP server
    try:
        import psutil
        mcp_pid = start_mcp_server()
    except ImportError:
        print("⚠️  psutil not installed, cannot auto-start MCP server")
        print("   Install: pip install psutil")
        mcp_pid = None
    
    print("=" * 80)
    print("📊 Dashboard URL: http://localhost:5100")
    print("🔧 Control your entire network security setup from the web UI")
    print("📡 Device data receiver enabled on port 5100")
    print("=" * 80)
    print("🤖 MCP AI Agent Features:")
    print("   ✓ Multi-turn conversations with Claude 3.5 Sonnet")
    print("   ✓ 19 MCP tools for network security operations")
    print("   ✓ Automatic planning and TODO tracking")
    print("   ✓ Subprocess execution (fresh event loop per query)")
    print("   ✓ Up to 100 iterations per query")
    print("   ✓ Real-time token usage monitoring")
    print("   ✓ Integrated with FastMCP server")
    if mcp_pid:
        print(f"   ✓ MCP Server running (PID: {mcp_pid})")
    else:
        print("   ⚠️  MCP Server not started (install: pip install fastmcp)")
    print("=" * 80)
    print("⚠️  Note: Network monitor Flask API is on port 5000")
    print("=" * 80)
    # Use port 5100 to avoid conflict with network-monitor on port 5000
    app.run(host='0.0.0.0', port=5100, debug=True)
