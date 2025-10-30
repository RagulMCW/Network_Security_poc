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
    # Discover devices by network (custom_net vs honeypot_net)
    production_devices = []
    honeypot_devices = []
    try:
        for c in containers:
            # Inspect container network settings
            inspect_cmd = f"docker inspect --format '{{{{json .NetworkSettings.Networks}}}}' {c['name']}"
            net_info = run_wsl_command(inspect_cmd)
            networks = {}
            ip_address = None
            if net_info['success'] and net_info['output'].strip():
                try:
                    networks = json.loads(net_info['output'])
                    # Get first IP if available
                    for net_name, net_obj in networks.items():
                        ip = net_obj.get('IPAddress')
                        if ip:
                            ip_address = ip
                            break
                except Exception:
                    networks = {}

            entry = {
                'name': c['name'],
                'status': c['status'],
                'image': c['image'],
                'ip': ip_address,
                'networks': list(networks.keys())
            }

            if 'honeypot_net' in networks or any('honeypot' in net for net in networks.keys()):
                honeypot_devices.append(entry)
            elif 'custom_net' in networks or (ip_address and ip_address.startswith('192.168.6.')):
                production_devices.append(entry)
            else:
                # Unknown network - treat as production by default
                production_devices.append(entry)
    except Exception:
        # On error, leave lists empty - status will still include basic containers
        production_devices = []
        honeypot_devices = []
    
    # Check Beelzebub
    beelzebub_running = any('beelzebub' in c['name'].lower() for c in containers)
    
    # Check attackers (distinguish between DOS and SSH)
    dos_attacker_running = any(c['name'] == 'hping3-attacker' for c in containers)
    ssh_attacker_running = any(c['name'] == 'ssh-attacker' for c in containers)
    attacker_running = dos_attacker_running or ssh_attacker_running
    
    # Check network monitor (check both possible names)
    monitor_running = any(c['name'] in ['monitor', 'net-monitor-wan', 'network-monitor'] for c in containers)
    
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
        'beelzebub': {
            'running': beelzebub_running,
            'containers': [c for c in containers if 'beelzebub' in c['name'].lower()],
            'devices': honeypot_devices
        },
        'attackers': {
            'running': attacker_running,
            'dos_running': dos_attacker_running,
            'ssh_running': ssh_attacker_running,
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
    
    # Try both naming conventions: vdevice_XXX and device_XXX
    device_name = f"vdevice_{device_id}" if not device_id.startswith('device') else device_id
    
    # If device_id is just a number like "001", try vdevice_001
    if device_id.isdigit() or (len(device_id) == 3 and device_id.isdigit()):
        device_name = f"vdevice_{device_id}"
    
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
    """Get Beelzebub logs"""
    
    # Beelzebub creates multiple log files
    log_files = {
        'attacks': os.path.join(HONEYPOT_DIR, 'logs', 'attacks.jsonl'),
        'ssh': os.path.join(HONEYPOT_DIR, 'logs', 'ssh-22.log'),
        'http': os.path.join(HONEYPOT_DIR, 'logs', 'http-8080.log'),
        'mysql': os.path.join(HONEYPOT_DIR, 'logs', 'mysql-3306.log'),
        'postgres': os.path.join(HONEYPOT_DIR, 'logs', 'postgresql-5432.log')
    }
    
    # Try to find any existing log file
    existing_log = None
    for log_type, log_path in log_files.items():
        if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
            existing_log = log_path
            break
    
    if not existing_log:
        return jsonify({
            'success': True,
            'logs': [],
            'count': 0,
            'message': 'No logs available yet. Start Beelzebub and wait for attacks.'
        })
    
    logs = []
    try:
        # Read JSONL or text log file
        with open(existing_log, 'r', encoding='utf-8', errors='ignore') as f:
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
            'count': len(logs),
            'log_file': os.path.basename(existing_log)
        })
    except Exception as e:
        return jsonify({
            'success': True,  # Still return success to avoid error in UI
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
    """Reroute device/attacker IP to Beelzebub honeypot network"""
    
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
    
    honeypot_network = 'honeypot_net'
    
    # Get Beelzebub honeypot IP dynamically
    get_beelzebub_cmd = f'docker inspect beelzebub-honeypot --format "{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}" 2>/dev/null'
    beelzebub_result = run_wsl_command(get_beelzebub_cmd)
    honeypot_ip = beelzebub_result['output'].strip() if (beelzebub_result['success'] and beelzebub_result['output'].strip()) else '192.168.7.3'
    
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
    
    # Step 2: Check if already on honeypot_net
    check_on_honeypot = run_wsl_command(
        f'docker inspect {container_name} --format "{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}"'
    )
    already_on_honeypot = check_on_honeypot['success'] and check_on_honeypot['output'].strip()
    
    # Step 3: Connect to honeypot_net (DUAL-HOMED: keep custom_net connection)
    if not already_on_honeypot:
        print(f"Connecting {container_name} to {honeypot_network}...")
        connect_cmd = f'docker network connect {honeypot_network} {container_name}'
        connect_result = run_wsl_command(connect_cmd)
        
        print(f"Connect result: success={connect_result['success']}, output='{connect_result['output']}'")
        
        if not connect_result['success']:
            return jsonify({
                'success': False,
                'message': f'Failed to connect {container_name} to honeypot network',
                'error': connect_result['output']
            })
        
        print(f"✅ Successfully connected {container_name} to {honeypot_network}")
    else:
        print(f"Container {container_name} already on {honeypot_network}")
    
    # Verify connection was successful
    verify_cmd = f'docker inspect {container_name} --format "{{{{json .NetworkSettings.Networks}}}}"'
    verify_result = run_wsl_command(verify_cmd)
    
    if verify_result['success']:
        import json as json_lib
        try:
            networks = json_lib.loads(verify_result['output'].strip())
            connected_networks = list(networks.keys())
            print(f"Container networks after connection: {connected_networks}")
            
            if honeypot_network not in connected_networks:
                return jsonify({
                    'success': False,
                    'message': f'Failed to verify connection to {honeypot_network}. Current networks: {connected_networks}',
                    'error': 'Connection verification failed'
                })
        except Exception as e:
            print(f"Warning: Could not parse network verification: {e}")
    
    # Step 4: Get honeypot IP
    get_honeypot_ip_cmd = f'docker inspect {container_name} --format "{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}"'
    honeypot_ip_result = run_wsl_command(get_honeypot_ip_cmd)
    device_honeypot_ip = honeypot_ip_result['output'].strip() if honeypot_ip_result['success'] else 'unknown'
    
    # Step 5: Get Beelzebub honeypot IP (dynamically)
    get_beelzebub_ip_cmd = f'docker inspect beelzebub-honeypot --format "{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}" 2>/dev/null || echo "192.168.7.3"'
    beelzebub_ip_result = run_wsl_command(get_beelzebub_ip_cmd)
    honeypot_target_ip = beelzebub_ip_result['output'].strip() if beelzebub_ip_result['success'] and beelzebub_ip_result['output'].strip() else '192.168.7.3'
    
    print(f"Beelzebub honeypot IP: {honeypot_target_ip}")
    
    # Step 6: Setup iptables rules to redirect ALL traffic to honeypot
    # This ensures device traffic goes to honeypot while still being visible on custom_net
    
    # Redirect all outbound traffic from this device to honeypot
    iptables_rules = [
        # NAT all TCP traffic from device to honeypot
        f'iptables -t nat -A PREROUTING -s {ip_address} -p tcp -j DNAT --to-destination {honeypot_target_ip}',
        # NAT all UDP traffic from device to honeypot  
        f'iptables -t nat -A PREROUTING -s {ip_address} -p udp -j DNAT --to-destination {honeypot_target_ip}',
        # Mark packets from this device for special routing
        f'iptables -t mangle -A PREROUTING -s {ip_address} -j MARK --set-mark 100',
    ]
    
    # Apply iptables rules on host
    for rule in iptables_rules:
        rule_result = run_wsl_command(f'sudo {rule}')
        if not rule_result['success']:
            print(f"Warning: iptables rule failed: {rule}")
            print(f"  Error: {rule_result['output']}")
    
    print(f"✅ Applied traffic redirection rules for {ip_address} → {honeypot_target_ip}")
    
    print(f"✅ Applied traffic redirection rules for {ip_address} → {honeypot_target_ip}")
    
    # Step 6: Log the reroute (with rotation - keep last 100 entries)
    log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Rerouted {container_name} ({ip_address}) → Honeypot ({honeypot_target_ip}) | Device Honeypot IP: {device_honeypot_ip}"
    
    try:
        os.makedirs(os.path.join(HONEYPOT_DIR, 'logs'), exist_ok=True)
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
    except Exception as e:
        print(f"Warning: Could not write to reroutes log: {e}")
    
    print(f"✅ Successfully rerouted {container_name}: Traffic redirected to honeypot via iptables")
    
    return jsonify({
        'success': True,
        'message': f'Successfully rerouted {container_name} to honeypot! Traffic now redirected via iptables to {honeypot_target_ip}',
        'container_name': container_name,
        'original_ip': ip_address,
        'honeypot_ip': device_honeypot_ip,
        'honeypot_target': honeypot_target_ip,
        'honeypot_network': honeypot_network,
        'method': 'iptables_redirect',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/beelzebub/reroutes')
def get_reroutes():
    """Get list of rerouted IPs to Beelzebub"""
    
    honeypot_network = 'honeypot_net'
    
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
                        'network': honeypot_network,
                        'method': 'network_move'
                    })
    
    # Also check for iptables-redirected devices (still on custom_net but traffic redirected)
    iptables_check_cmd = 'sudo iptables -t nat -L PREROUTING -n -v 2>/dev/null | grep "DNAT" | grep "192.168.7"'
    iptables_result = run_wsl_command(iptables_check_cmd)
    
    if iptables_result['success'] and iptables_result['output'].strip():
        for line in iptables_result['output'].strip().split('\n'):
            # Parse iptables output line format:
            # pkts bytes target prot opt in out source destination to
            # Example: 3406 136K DNAT tcp -- * * 192.168.6.132 0.0.0.0/0 to:192.168.7.2
            parts = line.split()
            
            # Find source IP (position varies, look for 192.168.6.x)
            source_ip = None
            dest_ip = None
            
            for i, part in enumerate(parts):
                if part.startswith('192.168.6.'):
                    source_ip = part
                if part.startswith('to:192.168.7.'):
                    dest_ip = part.replace('to:', '')
            
            if source_ip:
                # Get all container IPs and names on custom_net
                get_containers_cmd = 'docker ps --format "{{.Names}}" --filter "network=custom_net"'
                containers_result = run_wsl_command(get_containers_cmd)
                
                if containers_result['success'] and containers_result['output'].strip():
                    for container in containers_result['output'].strip().split('\n'):
                        container = container.strip()
                        if not container:
                            continue
                        
                        # Get container IP on custom_net
                        ip_check_cmd = f'docker inspect {container} --format "{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}" 2>/dev/null'
                        ip_check = run_wsl_command(ip_check_cmd)
                        
                        if ip_check['success'] and ip_check['output'].strip() == source_ip:
                            # Check if not already in active_reroutes
                            if not any(r['container'] == container for r in active_reroutes):
                                active_reroutes.append({
                                    'container': container,
                                    'ip': source_ip,
                                    'network': f'custom_net → {dest_ip} (iptables)',
                                    'method': 'iptables_dnat',
                                    'redirect_to': dest_ip
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
    
    # First, clean up iptables rules for the attacker
    cleanup_result = run_wsl_command('bash /mnt/e/nos/Network_Security_poc/attackers/dos_attacker/cleanup_iptables.sh 192.168.6.132')
    
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
    result = run_wsl_command('cd /mnt/e/nos/Network_Security_poc/attackers/ssh_attacker && docker compose up -d --build')
    
    return jsonify({
        'success': result['success'],
        'message': 'SSH Attacker started successfully' if result['success'] else result['error'],
        'output': result['output']
    })

@app.route('/api/ssh_attacker/stop', methods=['POST'])
def stop_ssh_attacker():
    """Stop SSH brute force attacker"""
    
    # First, clean up iptables rules for the SSH attacker (192.168.6.133)
    cleanup_result = run_wsl_command('bash /mnt/e/nos/Network_Security_poc/attackers/dos_attacker/cleanup_iptables.sh 192.168.6.133')
    
    # Then stop the container
    result = run_wsl_command('cd /mnt/e/nos/Network_Security_poc/attackers/ssh_attacker && docker compose down')
    
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
    summary_logs = run_wsl_command('cat /mnt/e/nos/Network_Security_poc/attackers/ssh_attacker/logs/ssh_summary.log 2>/dev/null || echo "No summary log yet"')
    
    return jsonify({
        'success': True,
        'container_logs': container_logs['output'] if container_logs['success'] else 'Container not running',
        'summary_logs': summary_logs['output'] if summary_logs['success'] else 'No summary log'
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
                elif 'monitor' in container_name or container_name == 'net-monitor-wan':
                    node_type = 'monitor'
                    display_name = 'Network Monitor Server'
                elif 'attacker' in container_name:
                    node_type = 'attacker'
                    display_name = 'DOS Attacker'
                    
                    # Get attacker details
                    node_data = {
                        'id': container_name,
                        'name': display_name,
                        'type': node_type,
                        'ip': container_ip,
                        'status': 'running',
                        'container_id': container_id[:12],
                        'attacker_info': {
                            'attack_type': 'DoS/DDoS',
                            'target': 'Network flooding',
                            'threat_level': 'HIGH',
                            'description': 'Simulated DoS attacker sending high-volume traffic'
                        }
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
                
                nodes.append(node_data if 'attacker' in container_name else {
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

@app.route('/api/agent/query', methods=['POST'])
def agent_query():
    """Forward ALL user queries to MCP Agent - Dashboard is just a bridge"""
    data = request.get_json()
    query = data.get('query', '').strip()
    
    if not query:
        return jsonify({
            'success': False,
            'error': 'Query is required'
        })
    
    try:
        # Forward query to MCP agent via query_agent.py (CLI wrapper)
        mcp_client_path = os.path.join(BASE_DIR, 'mcp_agent', 'query_agent.py')
        
        if not os.path.exists(mcp_client_path):
            return jsonify({
                'success': False,
                'error': 'MCP Agent not found. Please ensure mcp_agent/query_agent.py exists.'
            })
        
        # Use virtual environment's Python (E:\nos\.venv\Scripts\python.exe)
        venv_python = r'E:\nos\.venv\Scripts\python.exe'
        
        # Fallback to system python if venv not found
        python_executable = venv_python if os.path.exists(venv_python) else 'python'
        
        # Set UTF-8 environment for subprocess to handle Unicode characters
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        
        # Run MCP agent with the user's query
        result = subprocess.run(
            [python_executable, mcp_client_path, query],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=60,
            cwd=os.path.join(BASE_DIR, 'mcp_agent'),
            env=env
        )
        
        if result.returncode == 0:
            response_text = result.stdout.strip()
            return jsonify({
                'success': True,
                'response': response_text,
                'source': 'MCP Agent'
            })
        else:
            error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
            return jsonify({
                'success': False,
                'error': f'MCP Agent error: {error_msg}',
                'returncode': result.returncode
            })
            
    except subprocess.TimeoutExpired:
        return jsonify({
            'success': False,
            'error': 'MCP Agent timeout (60s). Query took too long to process.'
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Dashboard error: {str(e)}',
            'error_type': type(e).__name__
        })

@app.route('/api/agent/test-key', methods=['POST'])
def test_anthropic_key():
    """DISABLED - API testing removed. Dashboard only forwards to MCP Agent."""
    return jsonify({
        'success': False,
        'error': 'API test endpoint disabled.',
        'message': 'Dashboard only forwards queries to MCP Agent. Use the chat interface instead.'
    })

@app.route('/api/agent/reroute', methods=['POST'])
def agent_reroute_to_beelzebub():
    """Reroute device to Beelzebub honeypot via agent tool"""
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
        
        # Ensure honeypot network exists
        create_net_cmd = 'docker network ls | grep honeypot_net || docker network create --subnet=192.168.7.0/24 honeypot_net'
        run_wsl_command(create_net_cmd)
        
        # Disconnect from custom_net
        disconnect_cmd = f'docker network disconnect custom_net {container_name}'
        disconnect_result = run_wsl_command(disconnect_cmd)
        
        if not disconnect_result['success'] and 'not connected' not in disconnect_result.get('error', '').lower():
            print(f"  ⚠️ Disconnect warning: {disconnect_result.get('error', '')}")
        
        # Connect to honeypot network
        connect_cmd = f'docker network connect honeypot_net {container_name}'
        connect_result = run_wsl_command(connect_cmd)
        
        if not connect_result['success']:
            # Rollback: reconnect to custom_net
            reconnect_cmd = f'docker network connect custom_net {container_name}'
            run_wsl_command(reconnect_cmd)
            
            return jsonify({
                'success': False,
                'error': f'Failed to connect to honeypot: {connect_result.get("error", "Unknown error")}'
            })
        
        # Log the reroute
        log_entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] QUICK-REROUTE: {container_name} ({device_ip}) to honeypot\n"
        try:
            os.makedirs(os.path.join(HONEYPOT_DIR, 'logs'), exist_ok=True)
            with open(os.path.join(HONEYPOT_DIR, 'logs', 'reroutes.log'), 'a') as f:
                f.write(log_entry)
        except:
            pass
        
        print(f"  ✅ Successfully rerouted {container_name} to honeypot")
        
        return jsonify({
            'success': True,
            'message': f'Device {container_name} ({device_ip}) rerouted to honeypot network',
            'device': container_name,
            'action': 'rerouted_to_honeypot'
        })
        
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        })

if __name__ == '__main__':
    clear_old_data()  # Clear old data on startup
    print("🚀 Network Security Dashboard Starting...")
    print("📊 Dashboard URL: http://localhost:5100")
    print("🔧 Control your entire network security setup from the web UI")
    print("📡 Device data receiver enabled on port 5100")
    print("🤖 MCP AI Agent integrated - chat available in dashboard")
    print("⚠️  Note: Network monitor Flask API is on port 5000")
    # Use port 5100 to avoid conflict with network-monitor on port 5000
    app.run(host='0.0.0.0', port=5100, debug=True)
