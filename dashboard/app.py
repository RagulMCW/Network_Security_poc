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

# WSL paths (converted)
WSL_NETWORK_DIR = '/mnt/e/nos/Network_Security_poc/network'
WSL_DEVICES_DIR = '/mnt/e/nos/Network_Security_poc/devices'
WSL_HONEYPOT_DIR = '/mnt/e/nos/Network_Security_poc/honey_pot'
WSL_ATTACKERS_DIR = '/mnt/e/nos/Network_Security_poc/attackers/dos_attacker'

def run_wsl_command(command):
    """Execute WSL command and return output"""
    try:
        result = subprocess.run(
            ['wsl', 'bash', '-c', command],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',  # Replace problematic characters instead of crashing
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
    return render_template('control_panel.html')

@app.route('/api/status')
def get_status():
    """Get status of all components"""
    
    # Check Docker network
    network_result = run_wsl_command('docker network ls | grep custom_net')
    network_exists = network_result['success'] and 'custom_net' in network_result['output']
    
    # Check running containers
    containers_result = run_wsl_command('docker ps --format "{{.Names}}|{{.Status}}|{{.Image}}"')
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
    
    # Count devices
    device_containers = [c for c in containers if c['name'].startswith('device_')]
    
    # Check honeypot
    honeypot_running = any('honeypot' in c['name'] for c in containers)
    
    # Check attackers
    attacker_running = any('attacker' in c['name'] for c in containers)
    
    # Check network monitor (check both possible names)
    monitor_running = any(c['name'] in ['monitor', 'net-monitor-wan'] for c in containers)
    
    return jsonify({
        'network': {
            'exists': network_exists,
            'name': 'custom_net' if network_exists else None
        },
        'devices': {
            'count': len(device_containers),
            'containers': device_containers
        },
        'honeypot': {
            'running': honeypot_running,
            'containers': [c for c in containers if 'honeypot' in c['name']]
        },
        'attackers': {
            'running': attacker_running,
            'containers': [c for c in containers if 'attacker' in c['name']]
        },
        'monitor': {
            'running': monitor_running,
            'container': next((c for c in containers if c['name'] in ['monitor', 'net-monitor-wan']), None)
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
    
    result = run_wsl_command('docker ps -a --filter name=device_ --format "{{.Names}}|{{.Status}}|{{.ID}}"')
    
    devices = []
    if result['success']:
        for line in result['output'].strip().split('\n'):
            if line:
                parts = line.split('|')
                if len(parts) >= 3:
                    # Extract device number from name like device_1, device_2
                    match = re.search(r'device_(\d+)', parts[0])
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
    
    # Get next device number
    result = run_wsl_command('docker ps -a --filter name=device_ --format "{{.Names}}"')
    existing_ids = []
    
    if result['success']:
        for line in result['output'].strip().split('\n'):
            if line and 'device_' in line:
                match = re.search(r'device_(\d+)', line)
                if match:
                    existing_ids.append(int(match.group(1)))
    
    next_id = max(existing_ids) + 1 if existing_ids else 1
    device_name = f"device_{next_id}"
    device_id = f"device_{next_id:03d}"
    
    # Build device image if not exists
    print(f"Building device image...")
    build_cmd = f'cd /mnt/e/nos/Network_Security_poc/devices && docker build -t device-simulator .'
    build_result = run_wsl_command(build_cmd)
    
    if not build_result['success']:
        return jsonify({
            'success': False,
            'message': 'Failed to build device image',
            'error': build_result['error']
        })
    
    # Run device container
    run_cmd = f'docker run -d --name {device_name} --network custom_net -e DEVICE_ID={device_id} -e DEVICE_TYPE={device_type} -e SERVER_URL=http://192.168.6.1:5000 -e REQUEST_INTERVAL=10 device-simulator'
    
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
    
    device_name = f"device_{device_id}"
    
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

@app.route('/api/cleanup/all', methods=['POST'])
def cleanup_all():
    """NUCLEAR OPTION: Stop and remove ALL containers, images, and networks from this project"""
    
    results = []
    
    # 1. Stop ALL running containers
    print("🛑 Stopping all containers...")
    stop_result = run_wsl_command('docker stop $(docker ps -aq) 2>/dev/null || true')
    results.append(f"Stopped containers: {stop_result['output']}")
    
    # 2. Remove ALL containers
    print("🗑️ Removing all containers...")
    rm_containers = run_wsl_command('docker rm -f $(docker ps -aq) 2>/dev/null || true')
    results.append(f"Removed containers: {rm_containers['output']}")
    
    # 3. Remove specific project images
    print("🖼️ Removing project images...")
    images_to_remove = [
        'device-simulator',
        'dos-attacker',
        'honeypot-server',
        'monitor-image',
        'net-monitor-wan',
        'honeypot-monitor'
    ]
    
    for image in images_to_remove:
        rm_image = run_wsl_command(f'docker rmi -f {image} 2>/dev/null || true')
        if rm_image['output'].strip():
            results.append(f"Removed image {image}")
    
    # 4. Remove ALL unused images (dangling)
    print("🧹 Removing dangling images...")
    prune_images = run_wsl_command('docker image prune -f')
    results.append(f"Pruned images: {prune_images['output']}")
    
    # 5. Remove custom network
    print("🌐 Removing custom network...")
    rm_network = run_wsl_command('docker network rm custom_net 2>/dev/null || true')
    results.append(f"Removed network: {rm_network['output']}")
    
    # 6. Clean up volumes (optional, be careful!)
    print("💾 Removing unused volumes...")
    prune_volumes = run_wsl_command('docker volume prune -f')
    results.append(f"Pruned volumes: {prune_volumes['output']}")
    
    # 7. Final system prune
    print("🧼 Final system cleanup...")
    system_prune = run_wsl_command('docker system prune -f')
    results.append(f"System prune: {system_prune['output']}")
    
    return jsonify({
        'success': True,
        'message': '🧨 COMPLETE CLEANUP FINISHED - All containers, images, and networks removed!',
        'details': results
    })

@app.route('/api/honeypot/start', methods=['POST'])
def start_honeypot():
    """Start Beelzebub honeypot system"""
    
    # Ensure honeypot_net exists
    honeypot_check = run_wsl_command('docker network ls | grep honey_pot_honeypot_net')
    if not (honeypot_check['success'] and 'honey_pot_honeypot_net' in honeypot_check['output']):
        create_result = run_wsl_command('docker network create --subnet=192.168.7.0/24 honey_pot_honeypot_net')
        if not create_result['success']:
            return jsonify({
                'success': False,
                'message': 'Failed to create honeypot_net'
            })
    
    # Start Beelzebub honeypot using docker-compose-simple.yml
    result = run_wsl_command(f'cd {WSL_HONEYPOT_DIR} && docker compose -f docker-compose-simple.yml up -d')
    
    return jsonify({
        'success': result['success'],
        'message': 'Beelzebub honeypot started successfully (GLM-4.5 AI enabled)' if result['success'] else result['error'],
        'output': result['output']
    })

@app.route('/api/honeypot/stop', methods=['POST'])
def stop_honeypot():
    """Stop Beelzebub honeypot system"""
    
    result = run_wsl_command(f'cd {WSL_HONEYPOT_DIR} && docker compose -f docker-compose-simple.yml down')
    
    return jsonify({
        'success': result['success'],
        'message': 'Beelzebub honeypot stopped successfully' if result['success'] else result['error']
    })

@app.route('/api/honeypot/logs')
def get_honeypot_logs():
    """Get Beelzebub honeypot logs"""
    
    logs_file = os.path.join(HONEYPOT_DIR, 'logs', 'beelzebub.log')
    
    if not os.path.exists(logs_file):
        return jsonify({
            'success': True,
            'logs': [],
            'count': 0,
            'message': 'No logs available yet. Start the honeypot and wait for attacks.'
        })
    
    logs = []
    try:
        # Read JSONL log file
        with open(logs_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            # Get last 100 lines
            for line in lines[-100:]:
                line = line.strip()
                if line:
                    try:
                        # Try to parse as JSON
                        log_entry = json.loads(line)
                        logs.append(log_entry)
                    except json.JSONDecodeError:
                        # Not JSON, treat as plain text log
                        logs.append({
                            'level': 'info',
                            'msg': line,
                            'time': datetime.now().isoformat(),
                            'raw': True
                        })
        
        logs.reverse()  # Most recent first
        
        return jsonify({
            'success': True,
            'logs': logs,
            'count': len(logs)
        })
    except Exception as e:
        return jsonify({
            'success': True,  # Still return success to avoid error in UI
            'error': str(e),
            'logs': [],
            'count': 0,
            'message': f'Error reading logs: {str(e)}'
        })

@app.route('/api/honeypot/stats')
def get_honeypot_stats():
    """Get Beelzebub honeypot statistics"""
    
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
    
    # Count log entries if honeypot is/was running
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

@app.route('/api/honeypot/attackers')
def get_honeypot_attackers():
    """Get detailed attacker information from honeypot logs"""
    
    from collections import defaultdict
    from datetime import datetime
    
    logs_file = os.path.join(HONEYPOT_DIR, 'logs', 'beelzebub.log')
    
    if not os.path.exists(logs_file):
        return jsonify({
            'success': True,
            'attackers': [],
            'total_attacks': 0,
            'unique_ips': 0,
            'credentials_tried': [],
            'commands_executed': [],
            'http_requests': [],
            'rerouted_devices': []
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
        with open(logs_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    log_entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                # Extract attacker IP (if available in log)
                # Beelzebub logs might not have IP directly, we need to parse from connections
                # For now, we'll track service interactions and extract what we can
                
                msg = log_entry.get('msg', '')
                level = log_entry.get('level', '')
                timestamp = log_entry.get('time', '')
                port = log_entry.get('port', '')
                
                # Track SSH service interactions
                if 'ssh' in msg.lower() or port == ':22':
                    total_attacks += 1
                    # This is a simplified extraction - Beelzebub actual logs will have more detail
                    # You would need to enhance this based on actual log format
                
                # Track HTTP interactions
                if 'http' in msg.lower() or port == ':8080' or port == ':80':
                    total_attacks += 1
        
        # Get rerouted devices
        rerouted_devices = []
        try:
            # Check containers on honeypot network
            honeypot_inspect = run_wsl_command('docker network inspect honey_pot_honeypot_net --format "{{json .Containers}}"')
            
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

@app.route('/api/honeypot/reroute', methods=['POST'])
def reroute_to_honeypot():
    """Reroute device/attacker IP to honeypot network"""
    
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
    honeypot_ip = '192.168.7.100'  # Beelzebub honeypot IP
    
    print(f"🔄 Rerouting {ip_address} to honeypot network")
    
    # Find container with this IP address
    find_simple_cmd = f'docker ps --format "{{{{.Names}}}}" --filter "network=custom_net"'
    
    simple_result = run_wsl_command(find_simple_cmd)
    container_candidates = simple_result['output'].strip().split('\n') if simple_result['success'] else []
    
    # For each candidate, check if it has the target IP
    container_name = ''
    for candidate in container_candidates:
        candidate = candidate.strip()
        if not candidate:
            continue
        
        check_ip_cmd = f'docker inspect {candidate} --format "{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}"'
        ip_result = run_wsl_command(check_ip_cmd)
        
        if ip_result['success'] and ip_result['output'].strip() == ip_address:
            container_name = candidate
            break
    
    if not container_name:
        return jsonify({
            'success': False,
            'message': f'No container found with IP {ip_address}. Make sure the device is running on custom_net.'
        })
    
    print(f"📦 Found container: {container_name}")
    
    # Step 1: Ensure honeypot network exists
    check_honeypot_net = run_wsl_command(f'docker network ls | grep {honeypot_network}')
    if not (check_honeypot_net['success'] and honeypot_network in check_honeypot_net['output']):
        create_net = run_wsl_command(f'docker network create --subnet=192.168.7.0/24 {honeypot_network}')
        if not create_net['success']:
            return jsonify({
                'success': False,
                'message': f'Failed to create {honeypot_network}'
            })
    
    # Step 2: Disconnect from custom_net
    disconnect_cmd = f'docker network disconnect custom_net {container_name}'
    disconnect_result = run_wsl_command(disconnect_cmd)
    
    if not disconnect_result['success']:
        print(f"⚠️ Disconnect warning: {disconnect_result['output']}")
    
    # Step 3: Connect to honeypot_net
    connect_cmd = f'docker network connect {honeypot_network} {container_name}'
    connect_result = run_wsl_command(connect_cmd)
    
    if not connect_result['success']:
        # Rollback: reconnect to custom_net
        reconnect_cmd = f'docker network connect custom_net {container_name}'
        run_wsl_command(reconnect_cmd)
        
        return jsonify({
            'success': False,
            'message': f'Failed to connect {container_name} to honeypot network',
            'error': connect_result['output']
        })
    
    # Step 4: Get new IP on honeypot_net
    get_ip_cmd = f'docker inspect {container_name} --format "{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}"'
    ip_result = run_wsl_command(get_ip_cmd)
    new_ip = ip_result['output'].strip() if ip_result['success'] else 'unknown'
    
    # Step 5: Log the reroute
    log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Rerouted {container_name} ({ip_address}) to {honeypot_network} ({new_ip})"
    
    try:
        os.makedirs(os.path.join(HONEYPOT_DIR, 'logs'), exist_ok=True)
        with open(os.path.join(HONEYPOT_DIR, 'logs', 'reroutes.log'), 'a') as f:
            f.write(log_entry + '\n')
    except Exception as e:
        print(f"Warning: Could not write to reroutes log: {e}")
    
    print(f"✅ Successfully rerouted {container_name}: {ip_address} → {new_ip}")
    
    return jsonify({
        'success': True,
        'message': f'Successfully rerouted {container_name} to honeypot network. All traffic now goes to honeypot!',
        'container_name': container_name,
        'old_ip': ip_address,
        'new_ip': new_ip,
        'honeypot_network': honeypot_network,
        'honeypot_ip': honeypot_ip,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/honeypot/reroutes')
def get_reroutes():
    """Get list of rerouted IPs"""
    
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
    
    # Get containers on honeypot_net (these are rerouted)
    honeypot_containers_cmd = f'docker ps --filter "network={honeypot_network}" --format "{{{{.Names}}}}"'
    
    result = run_wsl_command(honeypot_containers_cmd)
    active_reroutes = []
    
    if result['success'] and result['output'].strip():
        container_names = result['output'].strip().split('\n')
        
        for container_name in container_names:
            container_name = container_name.strip()
            if not container_name or 'beelzebub' in container_name:
                continue
            
            # Filter for device/attacker containers only
            if container_name.startswith('device_') or container_name.startswith('hping') or container_name.startswith('curl'):
                # Get IP on honeypot_net
                ip_cmd = f'docker inspect {container_name} --format "{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}"'
                ip_result = run_wsl_command(ip_cmd)
                
                if ip_result['success'] and ip_result['output'].strip():
                    active_reroutes.append({
                        'container': container_name,
                        'ip': ip_result['output'].strip(),
                        'network': honeypot_network
                    })
    
    return jsonify({
        'success': True,
        'reroutes_log': reroutes[-50:],  # Last 50 entries
        'active_reroutes': active_reroutes,
        'count': len(reroutes)
    })

@app.route('/api/honeypot/remove_reroute', methods=['POST'])
def remove_reroute():
    """Remove reroute rule for specific IP - move container back to custom_net"""
    
    honeypot_network = 'honey_pot_honeypot_net'
    
    data = request.json
    container_name = data.get('container_name', '').strip()
    
    if not container_name:
        return jsonify({
            'success': False,
            'message': 'Container name is required'
        })
    
    print(f"🔄 Moving {container_name} back to custom_net")
    
    # Disconnect from honeypot_net
    disconnect_cmd = f'docker network disconnect {honeypot_network} {container_name}'
    disconnect_result = run_wsl_command(disconnect_cmd)
    
    # Reconnect to custom_net
    connect_cmd = f'docker network connect custom_net {container_name}'
    connect_result = run_wsl_command(connect_cmd)
    
    if not connect_result['success']:
        return jsonify({
            'success': False,
            'message': f'Failed to restore {container_name} to custom_net',
            'error': connect_result['error']
        })
    
    # Get new IP
    get_ip_cmd = f'docker inspect {container_name} --format "{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}"'
    ip_result = run_wsl_command(get_ip_cmd)
    new_ip = ip_result['output'].strip() if ip_result['success'] else 'unknown'
    
    # Log the restore
    log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Restored {container_name} to custom_net ({new_ip})"
    try:
        with open(os.path.join(HONEYPOT_DIR, 'logs', 'reroutes.log'), 'a') as f:
            f.write(log_entry + '\n')
    except:
        pass
    
    print(f"✅ Container {container_name} restored to custom_net (IP: {new_ip})")
    
    return jsonify({
        'success': True,
        'message': f'{container_name} restored to custom_net',
        'new_ip': new_ip
    })

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
    result = run_wsl_command(f'cd {WSL_ATTACKERS_DIR} && docker compose up -d --build')
    
    return jsonify({
        'success': result['success'],
        'message': 'Attackers started successfully' if result['success'] else result['error'],
        'output': result['output']
    })

@app.route('/api/attackers/stop', methods=['POST'])
def stop_attackers():
    """Stop DOS attacker containers"""
    
    result = run_wsl_command(f'cd {WSL_ATTACKERS_DIR} && docker compose down')
    
    return jsonify({
        'success': result['success'],
        'message': 'Attackers stopped successfully' if result['success'] else result['error']
    })

# ===== Network Monitor Server Control =====

@app.route('/api/monitor/start', methods=['POST'])
def start_monitor():
    """Start network monitor server"""
    
    # Use wsl-manager.sh to start
    result = run_wsl_command(f'cd {WSL_NETWORK_DIR} && bash wsl-manager.sh start')
    
    return jsonify({
        'success': result['success'],
        'message': 'Network monitor started successfully' if result['success'] else result['error'],
        'output': result['output']
    })

@app.route('/api/monitor/stop', methods=['POST'])
def stop_monitor():
    """Stop network monitor server"""
    
    result = run_wsl_command(f'cd {WSL_NETWORK_DIR} && bash wsl-manager.sh stop')
    
    return jsonify({
        'success': result['success'],
        'message': 'Network monitor stopped successfully' if result['success'] else result['error'],
        'output': result['output']
    })

@app.route('/api/monitor/status')
def get_monitor_status():
    """Get network monitor status"""
    
    result = run_wsl_command(f'cd {WSL_NETWORK_DIR} && bash wsl-manager.sh status')
    
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
    
    # Get logs from monitor container
    result = run_wsl_command('docker logs --tail 200 net-monitor-wan 2>&1')
    
    # If that fails, try 'monitor' name
    if not result['success'] or not result['output']:
        result = run_wsl_command('docker logs --tail 200 monitor 2>&1')
    
    return jsonify({
        'success': result['success'],
        'logs': result['output'] if result['success'] else result['error'],
        'container': 'monitor'
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
    
    # Get all containers on honey_pot_honeypot_net
    honeypot_inspect = run_wsl_command('docker network inspect honey_pot_honeypot_net --format "{{json .Containers}}" 2>/dev/null || echo "{}"')
    
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
                elif 'monitor' in container_name or container_name == 'net-monitor-wan':
                    node_type = 'monitor'
                    display_name = 'Network Monitor Server'
                elif 'attacker' in container_name:
                    node_type = 'attacker'
                    display_name = 'DOS Attacker'
                else:
                    node_type = 'other'
                    display_name = container_name
                
                nodes.append({
                    'id': container_name,
                    'name': display_name,
                    'type': node_type,
                    'ip': container_ip,
                    'status': 'running',
                    'container_id': container_id[:12]
                })
                
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
            
            # Add honeypot network gateway node
            honeypot_gateway_exists = False
            for node in nodes:
                if node['id'] == 'honeypot_gateway':
                    honeypot_gateway_exists = True
                    break
            
            if not honeypot_gateway_exists:
                nodes.append({
                    'id': 'honeypot_gateway',
                    'name': 'Honeypot Network',
                    'type': 'honeypot_network',
                    'ip': '192.168.7.1',
                    'status': 'running'
                })
                
                # Connect honeypot network to main gateway
                connections.append({
                    'from': 'gateway',
                    'to': 'honeypot_gateway',
                    'type': 'network_bridge'
                })
            
            # Add containers on honeypot network
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
                
                # Create connection to honeypot gateway
                connections.append({
                    'from': 'honeypot_gateway',
                    'to': container_name,
                    'type': 'honeypot_network'
                })
        
        except json.JSONDecodeError as e:
            print(f"Error parsing honeypot network: {e}")
            
            # Add honeypot network gateway node
            honeypot_gateway_exists = any(node['id'] == 'honeypot_gateway' for node in nodes)
            if not honeypot_gateway_exists and len(honeypot_containers) > 0:
                nodes.append({
                    'id': 'honeypot_gateway',
                    'name': 'Honeypot Network',
                    'type': 'honeypot_network',
                    'ip': '192.168.7.1',
                    'status': 'running'
                })
            
            for container_id, info in honeypot_containers.items():
                container_name = info.get('Name', 'unknown')
                container_ip = info.get('IPv4Address', '').split('/')[0]
                
                # Check if this container is already in nodes (might be on both networks)
                existing_node = next((node for node in nodes if node['id'] == container_name), None)
                
                if existing_node:
                    # Update to show dual-network status
                    existing_node['honeypot_ip'] = container_ip
                    existing_node['dual_network'] = True
                    # Add connection to honeypot gateway
                    connections.append({
                        'from': 'honeypot_gateway',
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
                    
                    # Connect to honeypot gateway
                    connections.append({
                        'from': 'honeypot_gateway',
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

# Global agent instance
mcp_agent_process = None
mcp_agent_active = False

@app.route('/api/agent/status')
def get_agent_status():
    """Get MCP agent status"""
    global mcp_agent_active
    
    # Get API key info (masked for security)
    api_key = os.getenv('ANTHROPIC_API_KEY')
    key_info = {
        'configured': bool(api_key),
        'key_preview': f"{api_key[:20]}...{api_key[-10:]}" if api_key and len(api_key) > 30 else 'Not set',
        'length': len(api_key) if api_key else 0
    }
    
    return jsonify({
        'success': True,
        'active': mcp_agent_active,
        'available_tools': [
            'analyze_traffic',
            'list_devices',
            'reroute_to_honeypot'
        ],
        'api_key_info': key_info,
        'base_url': os.getenv('ANTHROPIC_BASE_URL', 'Not set')
    })

@app.route('/api/agent/test-key', methods=['POST'])
def test_anthropic_key():
    """Test the Anthropic API key with a simple request"""
    api_key = os.getenv('ANTHROPIC_API_KEY')
    base_url = os.getenv('ANTHROPIC_BASE_URL')
    
    if not api_key:
        return jsonify({
            'success': False,
            'error': 'ANTHROPIC_API_KEY not set in environment'
        })
    
    try:
        from anthropic import Anthropic
        
        client = Anthropic(
            api_key=api_key,
            base_url=base_url if base_url else None
        )
        
        # Simple test request
        response = client.messages.create(
            model="glm-4.5",
            max_tokens=20,
            temperature=0.1,
            system="You are a test.",
            messages=[{"role": "user", "content": "Say 'test successful'"}]
        )
        
        return jsonify({
            'success': True,
            'message': 'API key is valid and working',
            'model': 'glm-4.5',
            'response': response.content[0].text if hasattr(response, 'content') else str(response),
            'key_preview': f"{api_key[:20]}...{api_key[-10:]}"
        })
        
    except Exception as e:
        error_str = str(e)
        return jsonify({
            'success': False,
            'error': error_str,
            'error_type': type(e).__name__,
            'key_preview': f"{api_key[:20]}...{api_key[-10:]}",
            'is_subscription_error': '1309' in error_str or '429' in error_str
        })

@app.route('/api/agent/query', methods=['POST'])
def agent_query():
    """Process user query through AI agent - simplified version without MCP"""
    data = request.get_json()
    query = data.get('query', '').strip().lower()
    
    if not query:
        return jsonify({
            'success': False,
            'error': 'Query is required'
        })
    
    try:
        # Direct tool execution based on query keywords
        response_text = ""
        
        # Analyze traffic
        if any(word in query for word in ['analyze', 'traffic', 'network', 'threat', 'attack']):
            output_path = os.path.join(NETWORK_DIR, 'analyze_output.txt')
            analysis_data = ""
            
            # Try to read analyze_output.txt first
            if os.path.exists(output_path):
                try:
                    with open(output_path, 'r', encoding='utf-8') as f:
                        analysis_data = f.read().strip()
                except Exception as e:
                    analysis_data = ""
            
            # If analyze_output.txt is empty or has errors, try reading PCAP files directly
            if not analysis_data or "Error analyzing capture" in analysis_data or "No data could be read" in analysis_data:
                captures_dir = os.path.join(NETWORK_DIR, 'captures')
                if os.path.exists(captures_dir):
                    files = [f for f in os.listdir(captures_dir) if f.endswith('.pcap')]
                    if files:
                        # Get last 3 PCAP files
                        sorted_files = sorted(files)
                        last_3_files = sorted_files[-3:] if len(sorted_files) >= 3 else sorted_files
                        
                        try:
                            from scapy.all import rdpcap, IP, TCP, UDP
                            
                            total_packets = 0
                            all_src_ips = {}
                            all_dst_ips = {}
                            protocols = {'TCP': 0, 'UDP': 0, 'Other': 0}
                            
                            for pcap_file in last_3_files:
                                file_path = os.path.join(captures_dir, pcap_file)
                                if os.path.getsize(file_path) > 0:
                                    try:
                                        packets = rdpcap(file_path)
                                        total_packets += len(packets)
                                        
                                        for pkt in packets:
                                            if IP in pkt:
                                                src = pkt[IP].src
                                                dst = pkt[IP].dst
                                                all_src_ips[src] = all_src_ips.get(src, 0) + 1
                                                all_dst_ips[dst] = all_dst_ips.get(dst, 0) + 1
                                                
                                                if TCP in pkt:
                                                    protocols['TCP'] += 1
                                                elif UDP in pkt:
                                                    protocols['UDP'] += 1
                                                else:
                                                    protocols['Other'] += 1
                                    except:
                                        pass
                            
                            # Build AGGRESSIVE analysis with threat detection
                            if total_packets > 0:
                                threats_detected = []
                                critical_threats = []
                                avg_packets = total_packets / len(all_src_ips) if all_src_ips else 0
                                
                                analysis_data = f"🚨 NETWORK SECURITY ANALYSIS\n"
                                analysis_data += "=" * 70 + "\n"
                                analysis_data += f"Analyzed Files: {', '.join(last_3_files)}\n"
                                analysis_data += f"Total Packets: {total_packets:,}\n"
                                analysis_data += f"Unique IPs: {len(all_src_ips)}\n"
                                analysis_data += "=" * 70 + "\n\n"
                                
                                analysis_data += "📡 PROTOCOL DISTRIBUTION:\n"
                                for proto, count in protocols.items():
                                    if count > 0:
                                        pct = (count / total_packets * 100)
                                        analysis_data += f"   {proto:8s}: {count:6d} packets ({pct:5.1f}%)\n"
                                analysis_data += "\n"
                                
                                analysis_data += "📤 TOP SOURCE IPs:\n"
                                sorted_srcs = sorted(all_src_ips.items(), key=lambda x: x[1], reverse=True)[:5]
                                for ip, count in sorted_srcs:
                                    pct = (count / total_packets * 100)
                                    analysis_data += f"   {ip:15s}: {count:6d} packets ({pct:5.1f}%)\n"
                                analysis_data += "\n"
                                
                                analysis_data += "📥 TOP DESTINATION IPs:\n"
                                sorted_dsts = sorted(all_dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]
                                for ip, count in sorted_dsts:
                                    pct = (count / total_packets * 100)
                                    analysis_data += f"   {ip:15s}: {count:6d} packets ({pct:5.1f}%)\n"
                                analysis_data += "\n"
                                
                                # AGGRESSIVE THREAT DETECTION
                                analysis_data += "🛡️  SECURITY THREAT ANALYSIS:\n"
                                
                                for src_ip, src_count in sorted_srcs[:10]:
                                    pct_of_traffic = (src_count / total_packets * 100)
                                    
                                    if src_count > 1000 or pct_of_traffic > 50:
                                        analysis_data += f"\n   🔴 CRITICAL THREAT: DoS/DDoS ATTACK from {src_ip}\n"
                                        analysis_data += f"      → Packet Volume: {src_count:,} packets ({pct_of_traffic:.1f}% of ALL traffic!)\n"
                                        analysis_data += f"      → Attack Type: Flooding/DoS attack overwhelming the network\n"
                                        analysis_data += f"      → ACTION REQUIRED: BLOCK THIS IP IMMEDIATELY!\n"
                                        threats_detected.append(f"CRITICAL DoS Attack from {src_ip} ({src_count:,} packets)")
                                        critical_threats.append(src_ip)
                                        
                                    elif src_count > 500 or src_count > (avg_packets * 4):
                                        analysis_data += f"\n   🟠 HIGH THREAT: Suspicious high traffic from {src_ip}\n"
                                        analysis_data += f"      → Packet Volume: {src_count:,} packets ({pct_of_traffic:.1f}% of traffic)\n"
                                        analysis_data += f"      → Likely Attack: DoS attempt or malicious bot activity\n"
                                        analysis_data += f"      → ACTION: Reroute to honeypot for analysis or block\n"
                                        threats_detected.append(f"HIGH: DoS attack from {src_ip} ({src_count:,} packets)")
                                        
                                    elif src_count > 200 or src_count > (avg_packets * 3):
                                        analysis_data += f"\n   🟡 WARNING: Elevated traffic from {src_ip}\n"
                                        analysis_data += f"      → Packet Volume: {src_count:,} packets ({pct_of_traffic:.1f}% of traffic)\n"
                                        analysis_data += f"      → Possible: Malware, compromised device, or early DoS\n"
                                        analysis_data += f"      → ACTION: Monitor closely, investigate device\n"
                                        threats_detected.append(f"WARNING: High traffic from {src_ip} ({src_count:,} packets)")
                                
                                if not threats_detected:
                                    analysis_data += "\n   ✅ No security threats detected\n"
                                else:
                                    analysis_data += f"\n{'='*70}\n"
                                    analysis_data += f"⚠️  TOTAL THREATS DETECTED: {len(threats_detected)}\n"
                                    if critical_threats:
                                        analysis_data += f"🔴 CRITICAL THREATS: {len(critical_threats)} (Immediate action required!)\n"
                                    analysis_data += f"{'='*70}\n"
                        
                        except ImportError:
                            analysis_data = "Scapy not installed. Cannot analyze PCAP files directly.\n"
                            analysis_data += "Install with: pip install scapy"
                        except Exception as e:
                            analysis_data = f"Error reading PCAP files: {str(e)}"
            
            # Now process the analysis data (whether from file or PCAP)
            if analysis_data:
                # Use AGGRESSIVE AI cybersecurity analyst
                if os.getenv('ANTHROPIC_API_KEY'):
                    try:
                        from anthropic import Anthropic
                        client = Anthropic(
                            api_key=os.getenv('ANTHROPIC_API_KEY'),
                            base_url=os.getenv('ANTHROPIC_BASE_URL', 'https://api.anthropic.com')
                        )
                        
                        # Check if threats were detected
                        threat_context = ""
                        if 'CRITICAL THREAT' in analysis_data or 'HIGH THREAT' in analysis_data:
                            threat_context = (
                                "⚠️⚠️⚠️ CRITICAL INSTRUCTION ⚠️⚠️⚠️\n"
                                "SECURITY THREATS DETECTED in the network data below.\n"
                                "You MUST classify these as ATTACKS, not 'normal communication'.\n"
                                "DO NOT dismiss or downplay these threats!\n\n"
                            )
                        
                        prompt = (
                            "🚨 YOU ARE A STRICT CYBERSECURITY ANALYST AT A SOC 🚨\n\n"
                            f"{threat_context}"
                            "CRITICAL RULES:\n"
                            "1. ANY IP sending >500 packets = DoS ATTACK (not 'normal')\n"
                            "2. ANY IP sending >1000 packets = CRITICAL THREAT\n"
                            "3. If threats are flagged in data, REPORT THEM AS ATTACKS\n"
                            "4. DO NOT say 'appears normal' when threats detected\n\n"
                            "YOUR REPORT MUST INCLUDE:\n"
                            "🚨 THREAT LEVEL: [CRITICAL/HIGH/MEDIUM/LOW]\n"
                            "🎯 ATTACK TYPE: DoS/Port Scan/Brute-force/None\n"
                            "💀 MALICIOUS IPs: List IPs with >500 packets as ATTACKERS\n"
                            "🛡️ ACTIONS: Specific steps to block/mitigate\n"
                            "⏱️ URGENCY: Critical/High/Medium/Low\n\n"
                            "Network data:\n" + analysis_data[:3000]
                        )
                        
                        ai_response = client.messages.create(
                            model="claude-3-5-sonnet-20241022",
                            max_tokens=2048,
                            temperature=0.1,
                            messages=[{"role": "user", "content": prompt}]
                        )
                        
                        response_text = ai_response.content[0].text
                        
                        # Add threat banner if critical threats
                        if 'CRITICAL THREAT' in analysis_data:
                            threat_banner = "🚨 ═══════════════════════════════════════\n"
                            threat_banner += "🚨  SECURITY ALERT: ATTACK IN PROGRESS!  🚨\n"
                            threat_banner += "🚨 ═══════════════════════════════════════\n\n"
                            response_text = threat_banner + response_text
                            
                    except Exception as e:
                        # Fallback to local summary
                        err_str = str(e)
                        fallback = local_summarize_analysis(analysis_data)
                        response_text = (
                            f"Network analysis available but AI summary failed: {err_str}\n\n"
                            f"Fallback summary:\n{fallback}\n\n"
                            f"Raw data (truncated):\n{analysis_data[:1000]}"
                        )
                else:
                    response_text = f"Network Analysis:\n{analysis_data[:1000]}\n\n(Install Anthropic API key for AI-powered summaries)"
            else:
                response_text = "No network analysis data available. Please:\n"
                response_text += "1. Start network monitoring\n"
                response_text += "2. Generate some network traffic\n"
                response_text += "3. Run the analysis tool or ask me to 'summarize pcap'"
        
        # Reroute device - redirect to Quick Reroute tool
        elif 'reroute' in query:
            import re
            ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', query)
            if ip_match:
                device_ip = ip_match.group(0)
                response_text = f"🔀 To reroute device {device_ip} to honeypot:\n\n"
                response_text += "Use the '🔀 Quick Reroute' button below this chat, or:\n"
                response_text += "1. Go to the Honeypot page\n"
                response_text += "2. Enter the device IP\n"
                response_text += "3. Click 'Reroute to Honeypot'\n\n"
                response_text += "This will isolate the suspicious device for analysis."
            else:
                response_text = "Please specify the device IP address.\nExample: 'reroute device 192.168.6.10'"
        
        # Help/default
        else:
            response_text = """🤖 Network Security AI Agent

Available Commands:

• **analyze** / **analyze traffic** - Full network security analysis
  - Detects DoS/DDoS attacks
  - Identifies suspicious IPs
  - Shows connected devices
  - Provides threat level and actions

• **status** - Quick network status check

• **security** - Security assessment

• **reroute device [IP]** - Instructions to isolate device

Just type naturally - I understand commands like:
  "analyze the network"
  "what threats do you see"
  "check security status"
  "analyze traffic patterns"

💡 Tip: Type "analyze" for a complete security report!"""
        
        return jsonify({
            'success': True,
            'query': query,
            'response': response_text
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route('/api/agent/reroute', methods=['POST'])
def agent_reroute_to_honeypot():
    """Reroute device to honeypot via agent tool"""
    data = request.get_json()
    device_ip = data.get('device_ip', '').strip()
    
    if not device_ip:
        return jsonify({
            'success': False,
            'error': 'Device IP is required'
        })
    
    try:
        # Find device container by IP
        inspect_result = run_wsl_command('docker network inspect custom_net --format "{{json .Containers}}"')
        
        if not inspect_result['success']:
            return jsonify({
                'success': False,
                'error': 'Failed to inspect network'
            })
        
        containers = json.loads(inspect_result['output'].strip())
        container_name = None
        
        for container_id, info in containers.items():
            container_ip = info.get('IPv4Address', '').split('/')[0]
            if container_ip == device_ip:
                container_name = info.get('Name', '')
                break
        
        if not container_name:
            return jsonify({
                'success': False,
                'error': f'No container found with IP {device_ip}'
            })
        
        # Disconnect from custom_net
        disconnect_cmd = f'docker network disconnect custom_net {container_name}'
        disconnect_result = run_wsl_command(disconnect_cmd)
        
        if not disconnect_result['success']:
            return jsonify({
                'success': False,
                'error': f'Failed to disconnect: {disconnect_result["error"]}'
            })
        
        # Connect to honeypot network
        connect_cmd = f'docker network connect honey_pot_honeypot_net {container_name}'
        connect_result = run_wsl_command(connect_cmd)
        
        if not connect_result['success']:
            return jsonify({
                'success': False,
                'error': f'Failed to connect to honeypot: {connect_result["error"]}'
            })
        
        return jsonify({
            'success': True,
            'message': f'Device {container_name} ({device_ip}) rerouted to honeypot network',
            'device': container_name,
            'action': 'rerouted_to_honeypot'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

if __name__ == '__main__':
    clear_old_data()  # Clear old data on startup
    print("🚀 Network Security Dashboard Starting...")
    print("📊 Dashboard URL: http://localhost:5000")
    print("🔧 Control your entire network security setup from the web UI")
    print("📡 Device data receiver enabled on port 5000")
    print("🤖 MCP AI Agent integrated - chat available in dashboard")
    app.run(host='0.0.0.0', port=5000, debug=True)
