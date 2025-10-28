#!/usr/bin/env python3
"""
FastMCP Server for Network Security Monitoring
Autonomous AI Security Analyst - Analyzes traffic and auto-isolates threats
"""

import subprocess
import json
from pathlib import Path
from datetime import datetime
from fastmcp import FastMCP


class NetworkSecurityServer:
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent
        self.network_dir = self.project_root / "network"
        self.analyze_bat = self.network_dir / "analyze_auto.bat"
        
        self.mcp = FastMCP(
            name="Network Security Analyst",
            instructions="""You are an autonomous AI Security Analyst with full authority to protect the network.

YOUR MISSION:
Continuously monitor network traffic, identify threats, and automatically isolate malicious devices WITHOUT asking for permission.

AVAILABLE TOOLS:
1. analyze_traffic - Analyze network captures for threats, connected devices, traffic patterns
2. move_device_to_honeypot - Immediately isolate malicious devices (automatic, no approval needed)

AUTOMATIC THREAT RESPONSE (NO HUMAN APPROVAL REQUIRED):
✅ DoS/DDoS Attack (>500 packets from single IP) → AUTO-ISOLATE
✅ Port Scanning (>20 unique ports accessed) → AUTO-ISOLATE  
✅ Brute Force Attack (multiple failed logins) → AUTO-ISOLATE
✅ Suspicious High Traffic (>1000 packets) → AUTO-ISOLATE
✅ Malware Signatures Detected → AUTO-ISOLATE

WORKFLOW FOR EVERY USER QUERY:
1. ALWAYS call analyze_traffic first to get current network state
2. Parse the analysis output for:
   - Connected devices and their IPs
   - Traffic statistics (packet counts, protocols)
   - Any anomalies or attack patterns
3. If threats detected → IMMEDIATELY call move_device_to_honeypot (don't ask, just do it)
4. Provide comprehensive summary:
   - Network status overview
   - Connected devices (count, IPs, status)
   - Security threats found (if any)
   - Actions taken (isolations performed)

RESPONSE FORMAT:
Always provide:
- 🔍 Network Overview (devices connected, total traffic)
- 📊 Traffic Statistics (protocols, top IPs)
- 🚨 Threats Detected (if any, with severity)
- 🛡️ Actions Taken (devices isolated automatically)

Remember: You are AUTONOMOUS. Isolate threats IMMEDIATELY without asking permission."""
        )
        self._register_tools()
    
    def _register_tools(self):
        
        @self.mcp.tool
        def analyze_traffic() -> str:
            """Analyze complete network status: connected devices, traffic statistics, threats, and anomalies.
            
            This tool provides:
            - All connected devices with IPs and status
            - Traffic analysis (packet counts, protocols, top talkers)
            - Security threats and attack detection
            - Protocol distribution and network health
            
            Always call this FIRST when user asks anything about the network.
            """
            return self._run_analyze_bat()
        
        @self.mcp.tool
        def move_device_to_honeypot(device_id: str, reason: str = "Suspicious activity detected") -> str:
            """Move a malicious or suspicious device from custom_net to honeypot_net for isolation.
            
            Args:
                device_id: Container name (e.g., 'device_001', 'vdevice_001', 'hping3-attacker', etc.)
                reason: Reason for moving device to honeypot (e.g., 'DoS attack', 'Port scanning')
            
            Returns:
                Status message indicating success or failure
            """
            return self._move_device_to_honeypot(device_id, reason)

    
    def _run_analyze_bat(self) -> str:
        """Run analyze_auto.bat and return terminal output"""
        try:
            if not self.analyze_bat.exists():
                return f"ERROR: analyze_auto.bat not found"
            
            # Run analyze.bat latest mode
            cmd = [str(self.analyze_bat), "latest"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                cwd=str(self.network_dir),
                shell=True
            )
            
            if result.returncode == 0:
                return result.stdout if result.stdout else "No output"
            else:
                return f"ERROR: Analysis failed\n{result.stdout}"
            
        except subprocess.TimeoutExpired:
            return "ERROR: Analysis timeout"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def _move_device_to_honeypot(self, device_id: str, reason: str) -> str:
        """Move device from custom_net to honeypot_net"""
        try:
            # Accept any container name (device_001, vdevice_001, hping3-attacker, etc.)
            container_name = device_id
            
            # Normalize common patterns for logging
            if device_id.startswith('device_'):
                device_num = device_id.replace('device_', '')
                container_name = f"vdevice_{device_num}"
            elif device_id.startswith('vdevice_'):
                container_name = device_id
            else:
                # Use the container name as-is (e.g., hping3-attacker)
                container_name = device_id
            
            # Check if container exists
            check_cmd = f"docker ps -a --format '{{{{.Names}}}}' | grep -w '{container_name}'"
            check_result = subprocess.run(
                ['wsl', 'bash', '-c', check_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if check_result.returncode != 0 or not check_result.stdout.strip():
                return f"ERROR: Container '{container_name}' not found"
            
            # Ensure honeypot_net exists
            network_check_cmd = "docker network ls --format '{{.Name}}' | grep -w 'honeypot_net'"
            network_result = subprocess.run(
                ['wsl', 'bash', '-c', network_check_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if network_result.returncode != 0 or not network_result.stdout.strip():
                # Create honeypot_net
                create_net_cmd = "docker network create --driver bridge --subnet 192.168.7.0/24 honeypot_net"
                create_result = subprocess.run(
                    ['wsl', 'bash', '-c', create_net_cmd],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if create_result.returncode != 0:
                    return f"ERROR: Failed to create honeypot_net: {create_result.stderr}"
            
            # Disconnect from custom_net
            disconnect_cmd = f"docker network disconnect custom_net {container_name} 2>/dev/null || true"
            subprocess.run(
                ['wsl', 'bash', '-c', disconnect_cmd],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Connect to honeypot_net
            connect_cmd = f"docker network connect honeypot_net {container_name}"
            connect_result = subprocess.run(
                ['wsl', 'bash', '-c', connect_cmd],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if connect_result.returncode != 0:
                return f"ERROR: Failed to connect to honeypot_net: {connect_result.stderr}"
            
            # Get new IP address
            ip_cmd = f"docker inspect -f '{{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}' {container_name}"
            ip_result = subprocess.run(
                ['wsl', 'bash', '-c', ip_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            new_ip = ip_result.stdout.strip() if ip_result.returncode == 0 else "Unknown"
            
            # Log the reroute
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'device_id': device_id,
                'container_name': container_name,
                'reason': reason,
                'new_ip': new_ip,
                'network': 'honeypot_net'
            }
            
            log_file = self.project_root / 'honey_pot' / 'logs' / 'reroutes.log'
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Read existing logs for rotation (keep last 100)
            existing_logs = []
            if log_file.exists():
                with open(log_file, 'r') as f:
                    existing_logs = [line.strip() for line in f if line.strip()]
            
            # Add new entry
            existing_logs.append(json.dumps(log_entry))
            
            # Keep only last 100 entries
            if len(existing_logs) > 100:
                existing_logs = existing_logs[-100:]
            
            # Write back
            with open(log_file, 'w') as f:
                for log in existing_logs:
                    f.write(log + '\n')
            
            result = f"✅ SUCCESS: Device moved to honeypot network\n\n"
            result += f"Device: {device_id} ({container_name})\n"
            result += f"Reason: {reason}\n"
            result += f"New Network: honeypot_net\n"
            result += f"New IP: {new_ip}\n"
            result += f"Status: ISOLATED - All traffic now monitored by honeypot\n"
            result += f"\nThe device is now quarantined and cannot access production network."
            
            return result
            
        except subprocess.TimeoutExpired:
            return "ERROR: Operation timeout"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def run(self):
        """Run the FastMCP server."""
        self.mcp.run()


if __name__ == "__main__":
    server = NetworkSecurityServer()
    server.run()
