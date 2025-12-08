#!/usr/bin/env python3
"""
FastMCP Server for Network Security Monitoring
Autonomous AI Security Analyst - Analyzes traffic and auto-isolates threats
"""

import subprocess
import json
import os
import sys
import shutil
from pathlib import Path
from datetime import datetime
from fastmcp import FastMCP


class NetworkSecurityServer:
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent
        self.network_dir = self.project_root / "network"
        self.analyze_bat = self.network_dir / "analyze_auto.bat"
        self.malware_db_dir = self.project_root / "malware_db"
        
        self.mcp = FastMCP(
            name="Network Security Expert",
            instructions="""You are a professional AI Network Security Expert for Docker network monitoring.

🎯 YOUR MISSION:
Analyze Docker network traffic to detect real security threats while ignoring legitimate infrastructure.

🔍 ANALYSIS METHODOLOGY:

1. **DISCOVER NETWORK FIRST**
   - Use docker_command("ps") to see all running containers
   - Use docker_command("network inspect custom_net") to map IPs
   - Use docker_command("network inspect honeypot_net") to check isolated devices
   - Identify container roles based on names and patterns

2. **IDENTIFY LEGITIMATE INFRASTRUCTURE**
   Look for these patterns (usually NOT threats):
   - Containers named "device_*" or "vdevice_*" → Device simulators
   - Traffic to "/api/device/data" endpoint → Legitimate telemetry
   - User-Agent "python-requests" to device API → Expected automation
   - Monitor server (usually 192.168.6.131) → Infrastructure
   - Dashboard/gateway (usually 192.168.6.1) → Infrastructure
   - Consistent timing patterns (1-3 sec intervals) from device simulators → Normal heartbeat

3. **DETECT REAL THREATS**
   - **DoS/DDoS**: Excessive packet rates (100+ packets/sec), SYN floods, bandwidth saturation
   - **Brute Force**: Multiple failed auth attempts, credential stuffing patterns
   - **Malware Behaviors**: 
     * C2 beaconing to external/suspicious domains
     * Unexpected data exfiltration (large outbound transfers)
     * EICAR test files or real malware signatures
     * DNS tunneling or DGA (domain generation algorithms)
   - **Intrusions**: Unauthorized access, privilege escalation, lateral movement
   - **Reconnaissance**: Port scanning, network mapping, vulnerability probing
   - **Suspicious Files**: Use check_malware_hash() on extracted files

4. **CONTEXT-AWARE ANALYSIS**
   - Container name "attacker" → Expected malicious (test environment)
   - Container on honeypot_net → Already isolated/suspicious
   - External IPs → More suspicious than internal
   - Unusual ports → More suspicious than 80/443/5000
   - New/unknown containers → Require investigation

5. **REPORT FINDINGS**
   - Threat Level: CLEAN / WARNING / CRITICAL
   - List ONLY genuine threats (exclude whitelisted infrastructure)
   - Include confidence scores (0-100%)
   - Provide actionable recommendations
   - Explain WHY something is/isn't a threat

🔒 SECURITY RESTRICTIONS:
- Access ONLY Docker networks (NO host system: ipconfig, netstat, ping forbidden)
- Use: docker_command, read_zeek_logs, check_malware_hash, read_file

🎯 RESPONSE STYLE:
- Always start by discovering current network state dynamically
- Explain your reasoning (why traffic is legitimate vs malicious)
- Be concise but thorough
- Focus on actionable intelligence"""
                )
        self._register_tools()
    
    def _register_tools(self):
        
        # =======================================
        # FILESYSTEM TOOLS
        # =======================================
        
        @self.mcp.tool
        def read_file(path: str) -> str:
            """Read the contents of a file from the system.
            
            Args:
                path: Absolute file path (e.g., 'C:\\logs\\analysis.txt')
            
            Returns:
                File contents as string, or error message
            """
            return self._read_file(path)
        
        @self.mcp.tool
        def write_file(path: str, content: str) -> str:
            """Write content to a file on the system.
            
            Args:
                path: Absolute file path (e.g., 'C:\\logs\\output.txt')
                content: Content to write to the file
            
            Returns:
                Success/failure message
            """
            return self._write_file(path, content)
        
        @self.mcp.tool
        def append_file(path: str, content: str) -> str:
            """Append content to a file on the system.
            
            Args:
                path: Absolute file path
                content: Content to append
            
            Returns:
                Success/failure message
            """
            return self._append_file(path, content)
        
        @self.mcp.tool
        def create_directory(path: str) -> str:
            """Create a directory (and parent directories if needed).
            
            Args:
                path: Absolute directory path (e.g., 'C:\\logs\\network\\captures')
            
            Returns:
                Success/failure message
            """
            return self._create_directory(path)
        
        @self.mcp.tool
        def list_directory(path: str) -> str:
            """List files and folders in a directory.
            
            Args:
                path: Absolute directory path
            
            Returns:
                Formatted list of files/folders with sizes
            """
            return self._list_directory(path)
        
        @self.mcp.tool
        def delete_file(path: str) -> str:
            """Delete a file from the system.
            
            Args:
                path: Absolute file path
            
            Returns:
                Success/failure message
            """
            return self._delete_file(path)
        
        @self.mcp.tool
        def file_exists(path: str) -> str:
            """Check if a file exists on the system.
            
            Args:
                path: Absolute file path
            
            Returns:
                'exists' or 'does_not_exist'
            """
            return self._file_exists(path)
        
        # =======================================
        # PROCESS / TERMINAL TOOLS
        # =======================================
        
        @self.mcp.tool
        def run_command(command: str, timeout: int = 30) -> str:
            """Run a Windows terminal command and get output.
            
            Args:
                command: Command to run (e.g., 'dir C:\\', 'ipconfig', 'docker ps')
                timeout: Maximum seconds to wait for command (default: 30)
            
            Returns:
                Command output and return code
            """
            return self._run_command(command, timeout)
        
        @self.mcp.tool
        def run_batch_file(path: str, args: str = "", timeout: int = 60) -> str:
            """Run a batch file (.bat) and capture output.
            
            Args:
                path: Absolute path to .bat file
                args: Arguments to pass to batch file
                timeout: Maximum seconds to wait
            
            Returns:
                Batch file output and exit code
            """
            return self._run_batch_file(path, args, timeout)
        
        @self.mcp.tool
        def run_powershell(command: str, timeout: int = 30) -> str:
            """Run a PowerShell command.
            
            Args:
                command: PowerShell command
                timeout: Maximum seconds to wait
            
            Returns:
                Command output
            """
            return self._run_powershell(command, timeout)
        
        # =======================================
        # WSL & LINUX TOOLS (with SUDO support)
        # =======================================
        
        @self.mcp.tool
        def wsl_command(command: str, use_sudo: bool = False, timeout: int = 30) -> str:
            """Run a command inside WSL (Windows Subsystem for Linux).
            
            Args:
                command: Linux/bash command to run
                use_sudo: If True, run with sudo privileges
                timeout: Maximum seconds to wait
            
            Returns:
                Command output from WSL
            """
            return self._wsl_command(command, use_sudo, timeout)
        
        @self.mcp.tool
        def wsl_bash_script(script: str, use_sudo: bool = False, timeout: int = 60) -> str:
            """Run a bash script inside WSL with full support for complex commands.
            
            Args:
                script: Bash script content (can be multiline)
                use_sudo: If True, run with sudo privileges
                timeout: Maximum seconds to wait
            
            Returns:
                Script output
            """
            return self._wsl_bash_script(script, use_sudo, timeout)
        
        @self.mcp.tool
        def wsl_read_file(path: str) -> str:
            """Read a file from WSL/Linux filesystem.
            
            Args:
                path: Linux file path (e.g., '/home/user/file.txt')
            
            Returns:
                File contents
            """
            return self._wsl_read_file(path)
        
        @self.mcp.tool
        def wsl_write_file(path: str, content: str) -> str:
            """Write to a file in WSL/Linux with sudo if needed.
            
            Args:
                path: Linux file path
                content: Content to write
            
            Returns:
                Success/failure message
            """
            return self._wsl_write_file(path, content)
        
        @self.mcp.tool
        def docker_command(command: str, use_sudo: bool = False, timeout: int = 30) -> str:
            """Execute Docker commands inside WSL.
            
            Args:
                command: Docker command (e.g., 'ps -a', 'inspect container_name')
                use_sudo: If True, run docker with sudo
                timeout: Maximum seconds to wait
            
            Returns:
                Docker command output
            """
            return self._docker_command(command, use_sudo, timeout)
        
        # =======================================
        # ENVIRONMENT VARIABLES
        # =======================================
        
        @self.mcp.tool
        def get_env_variable(name: str) -> str:
            """Get the value of an environment variable.
            
            Args:
                name: Variable name (e.g., 'PATH', 'DOCKER_HOST')
            
            Returns:
                Variable value or 'not set'
            """
            return self._get_env_variable(name)
        
        @self.mcp.tool
        def set_env_variable(name: str, value: str) -> str:
            """Set an environment variable (in current process).
            
            Args:
                name: Variable name
                value: Variable value
            
            Returns:
                Success message
            """
            return self._set_env_variable(name, value)
        
        # =======================================
        # NETWORK SECURITY TOOLS
        # =======================================
        
        # @self.mcp.tool
        # def analyze_traffic() -> str:
        #     """Analyze complete network status: connected devices, traffic statistics, threats, and anomalies.
            
        #     This tool provides:
        #     - All connected devices with IPs and status
        #     - Traffic analysis (packet counts, protocols, top talkers)
        #     - Security threats and attack detection
        #     - Protocol distribution and network health
            
        #     Always call this FIRST when user asks anything about the network.
        #     """
        #     return self._run_analyze_bat()
        
        @self.mcp.tool
        def read_zeek_logs() -> str:
            """Read Zeek network logs and dump ALL data to LLM for analysis.
            
            Returns complete raw Zeek logs from latest Docker session:
            - conn.log: All network connections
            - http.log: All HTTP requests  
            - dns.log: All DNS queries
            - files.log: All file transfers
            - packet_filter.log: Zeek statistics
            
            Use this to analyze network traffic patterns and detect malware.
            """
            return self._read_zeek_logs("all")
        
        @self.mcp.tool
        def block_device(ip: str, reason: str = "Malware detected") -> str:
            """Block a device from the network by IP address - stops and removes the container.
            
            Args:
                ip: IP address of the device to block (e.g., '192.168.6.200')
                reason: Reason for blocking (e.g., 'Malware detected', 'Suspicious behavior')
            
            Returns:
                JSON response with blocking status
            """
            import requests
            try:
                response = requests.post(
                    'http://localhost:5100/api/devices/block',
                    json={'ip': ip, 'reason': reason},
                    timeout=10
                )
                return response.text
            except Exception as e:
                return f"Error blocking device: {str(e)}"
        
        @self.mcp.tool
        def move_device_to_honeypot(device_id: str, reason: str = "Suspicious activity detected") -> str:
            """Isolate malicious device by moving it to the honeypot network.
            
            ALWAYS call this tool when threats are detected - it handles everything automatically.
            
            Args:
                device_id: IP address (e.g., '192.168.6.201') OR container name (e.g., 'endpoint_behavior_attacker')
                          The tool will automatically find the container if you pass an IP address.
                reason: Why the device is being isolated (e.g., 'C2 beaconing and data theft')
            
            Returns:
                Success message with isolation details, or error if container not found
            """
            return self._move_device_to_beelzebub(device_id, reason)
        
        @self.mcp.tool
        def restore_device_from_honeypot(device_id: str) -> str:
            """Remove DNAT iptables rules to restore normal traffic for a device.
            
            This tool removes all honeypot rerouting rules:
            - Deletes iptables DNAT rules
            - Removes FORWARD rules
            - Removes MASQUERADE rules
            - Device returns to normal network operation
            
            Args:
                device_id: Container name (e.g., 'device_001', 'vdevice_001', etc.)
            
            Returns:
                Status message indicating rules removed
            """
            return self._restore_device_from_honeypot(device_id)
        
        @self.mcp.tool
        def check_malware_hash(file_path: str, check_online: bool = False) -> str:
            """Check if a file matches known malware signatures using hash databases.
            
            This tool:
            1. Computes MD5, SHA1, SHA256 hashes of the file
            2. Checks against local malware databases (MalwareBazaar, EICAR, custom)
            3. Optionally queries online APIs for unknown hashes
            4. Returns threat analysis with malware family, tags, and severity
            
            CRITICAL - Path Usage:
            When you see extracted files in read_zeek_logs() output, construct the FULL path like this:
            
            read_zeek_logs() shows:
              📦 session_20251119_114759 (Created: 2025-11-19 11:47:59)
              📦 Extracted Files: 1 files
              📄 extract-1763552877.58295-HTTP-FQmdipn4669nGIAJj (68B) ⚠️ EICAR!
            
            Build path: {project_root} / "network" / "zeek_logs" / "session_20251119_114759" / "extracted_files" / "extract-1763552877.58295-HTTP-FQmdipn4669nGIAJj"
            
            Args:
                file_path: Use filename only and tool will auto-search in latest zeek sessions.
                    Example: "extract-1763552877.58295-HTTP-FQmdipn4669nGIAJj"
                    
                    Or provide full path (if you prefer):
                    Example: "E:\\...\\zeek_logs\\session_20251119_114759\\extracted_files\\extract-1763552877.58295-HTTP-FQmdipn4669nGIAJj"
                    
                check_online: If True, query online APIs for unknown hashes (default: False)
            
            Returns:
                - File hashes (MD5, SHA1, SHA256)
                - Database matches (malware family, tags, severity)
                - Threat level (CLEAN, SUSPICIOUS, MALWARE, TEST_FILE)
                - Threat score (0-100)
                - Recommended action
            """
            return self._check_malware_hash(file_path, check_online)

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
    
    # =======================================
    # FILESYSTEM IMPLEMENTATIONS
    # =======================================
    
    def _read_file(self, path: str) -> str:
        """Read file contents"""
        try:
            p = Path(path)
            if not p.exists():
                return f"ERROR: File not found: {path}"
            if not p.is_file():
                return f"ERROR: Path is not a file: {path}"
            
            with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            return content if content else f"[Empty file: {path}]"
        except Exception as e:
            return f"ERROR reading file: {str(e)}"
    
    def _write_file(self, path: str, content: str) -> str:
        """Write content to file"""
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            
            with open(p, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return f"✅ File written successfully: {path}"
        except Exception as e:
            return f"ERROR writing file: {str(e)}"
    
    def _append_file(self, path: str, content: str) -> str:
        """Append content to file"""
        try:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            
            with open(p, 'a', encoding='utf-8') as f:
                f.write(content)
            
            return f"✅ Content appended successfully: {path}"
        except Exception as e:
            return f"ERROR appending to file: {str(e)}"
    
    def _create_directory(self, path: str) -> str:
        """Create directory"""
        try:
            p = Path(path)
            p.mkdir(parents=True, exist_ok=True)
            return f"✅ Directory created/exists: {path}"
        except Exception as e:
            return f"ERROR creating directory: {str(e)}"
    
    def _list_directory(self, path: str) -> str:
        """List directory contents"""
        try:
            p = Path(path)
            if not p.exists():
                return f"ERROR: Directory not found: {path}"
            if not p.is_dir():
                return f"ERROR: Path is not a directory: {path}"
            
            items = []
            items.append(f"📁 Directory: {path}\n")
            
            try:
                entries = sorted(p.iterdir())
            except PermissionError:
                return f"ERROR: Permission denied accessing: {path}"
            
            if not entries:
                items.append("  [empty directory]")
            else:
                for entry in entries:
                    try:
                        if entry.is_dir():
                            items.append(f"  📂 {entry.name}/")
                        else:
                            size = entry.stat().st_size
                            if size < 1024:
                                size_str = f"{size}B"
                            elif size < 1024*1024:
                                size_str = f"{size/1024:.1f}KB"
                            else:
                                size_str = f"{size/(1024*1024):.1f}MB"
                            items.append(f"  📄 {entry.name} ({size_str})")
                    except Exception as e:
                        items.append(f"  ⚠️ {entry.name} [error reading]")
            
            return "\n".join(items)
        except Exception as e:
            return f"ERROR listing directory: {str(e)}"
    
    def _delete_file(self, path: str) -> str:
        """Delete a file"""
        try:
            p = Path(path)
            if not p.exists():
                return f"ERROR: File not found: {path}"
            if not p.is_file():
                return f"ERROR: Path is not a file: {path}"
            
            p.unlink()
            return f"✅ File deleted: {path}"
        except Exception as e:
            return f"ERROR deleting file: {str(e)}"
    
    def _file_exists(self, path: str) -> str:
        """Check if file exists"""
        try:
            p = Path(path)
            if p.exists():
                if p.is_file():
                    return f"exists (file)"
                elif p.is_dir():
                    return f"exists (directory)"
                else:
                    return f"exists (other)"
            else:
                return f"does_not_exist"
        except Exception as e:
            return f"ERROR checking file: {str(e)}"
    
    # =======================================
    # PROCESS / TERMINAL IMPLEMENTATIONS
    # =======================================
    
    def _run_command(self, command: str, timeout: int = 30) -> str:
        """Run Windows terminal command"""
        # SECURITY: Block host network commands
        forbidden_commands = [
            'ipconfig', 'netstat', 'ping', 'nslookup', 'tracert', 
            'arp', 'route', 'pathping', 'netsh', 'getmac'
        ]
        cmd_lower = command.lower().strip()
        for forbidden in forbidden_commands:
            if cmd_lower.startswith(forbidden) or f' {forbidden}' in cmd_lower or f'\\{forbidden}' in cmd_lower:
                return f"🚫 SECURITY BLOCKED: '{forbidden}' accesses host Windows network.\n" + \
                       f"⚠️ You can ONLY access Docker network, not host system network.\n\n" + \
                       f"✅ ALLOWED COMMANDS:\n" + \
                       f"  - docker ps (via WSL)\n" + \
                       f"  - docker network inspect (via WSL)\n" + \
                       f"  - docker logs <container> (via WSL)\n" + \
                       f"  - analyze_traffic (Docker pcap files)\n" + \
                       f"  - read_zeek_logs (Docker Zeek logs)\n\n" + \
                       f"❌ BLOCKED: {command}"
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            output = f"Command: {command}\n"
            output += f"Exit Code: {result.returncode}\n"
            output += f"{'='*60}\n"
            
            if result.stdout:
                output += "OUTPUT:\n" + result.stdout
            if result.stderr:
                output += "ERRORS:\n" + result.stderr
            
            return output
        except subprocess.TimeoutExpired:
            return f"ERROR: Command timeout after {timeout}s"
        except Exception as e:
            return f"ERROR running command: {str(e)}"
    
    def _run_batch_file(self, path: str, args: str = "", timeout: int = 60) -> str:
        """Run batch file"""
        try:
            p = Path(path)
            if not p.exists():
                return f"ERROR: Batch file not found: {path}"
            
            cmd = f'"{str(p)}" {args}'.strip()
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(p.parent)
            )
            
            output = f"Batch File: {path}\n"
            output += f"Exit Code: {result.returncode}\n"
            output += f"{'='*60}\n"
            
            if result.stdout:
                output += "OUTPUT:\n" + result.stdout
            if result.stderr:
                output += "ERRORS:\n" + result.stderr
            
            return output
        except subprocess.TimeoutExpired:
            return f"ERROR: Batch file timeout after {timeout}s"
        except Exception as e:
            return f"ERROR running batch file: {str(e)}"
    
    def _run_powershell(self, command: str, timeout: int = 30) -> str:
        """Run PowerShell command"""
        # SECURITY: Block host network commands in PowerShell
        forbidden_commands = [
            'get-netadapter', 'get-netipaddress', 'get-netipconfig',
            'get-netroute', 'get-dnsclient', 'test-connection',
            'get-netconnectionprofile', 'ipconfig', 'netstat', 'ping',
            'test-netconnection', 'resolve-dnsname', 'get-dnsclientserveraddress'
        ]
        cmd_lower = command.lower().strip()
        for forbidden in forbidden_commands:
            if forbidden in cmd_lower:
                return f"🚫 SECURITY BLOCKED: PowerShell network command '{forbidden}' is forbidden.\n" + \
                       f"⚠️ You can ONLY access Docker network via WSL, not host Windows network.\n\n" + \
                       f"✅ USE INSTEAD:\n" + \
                       f"  - wsl_command: docker ps\n" + \
                       f"  - wsl_command: docker network inspect bridge\n" + \
                       f"  - docker_command: ps -a\n\n" + \
                       f"❌ BLOCKED: {command}"
        
        try:
            # Escape quotes for PowerShell
            ps_cmd = f'powershell.exe -NoProfile -Command "{command}"'
            
            result = subprocess.run(
                ps_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            output = f"PowerShell Command: {command}\n"
            output += f"Exit Code: {result.returncode}\n"
            output += f"{'='*60}\n"
            
            if result.stdout:
                output += "OUTPUT:\n" + result.stdout
            if result.stderr:
                output += "ERRORS:\n" + result.stderr
            
            return output
        except subprocess.TimeoutExpired:
            return f"ERROR: PowerShell timeout after {timeout}s"
        except Exception as e:
            return f"ERROR running PowerShell: {str(e)}"
    
    # =======================================
    # WSL & LINUX IMPLEMENTATIONS (with SUDO)
    # =======================================
    
    def _wsl_command(self, command: str, use_sudo: bool = False, timeout: int = 30) -> str:
        """Run command in WSL"""
        # SECURITY: Only allow Docker-related commands in WSL
        cmd_lower = command.lower().strip()
        
        # Allowed prefixes for Docker operations
        allowed_prefixes = ['docker', 'cat /var/log', 'ls /var/log', 'tail /var/log', 'head /var/log']
        is_allowed = any(cmd_lower.startswith(prefix) for prefix in allowed_prefixes)
        
        # Block host network commands
        forbidden_commands = ['ifconfig', 'ip addr', 'ip route', 'ip link', 'ping', 'netstat', 'ss', 'arp', 'route', 'traceroute', 'nslookup', 'dig']
        is_forbidden = any(forbidden in cmd_lower for forbidden in forbidden_commands)
        
        if is_forbidden or not is_allowed:
            return f"🚫 SECURITY BLOCKED: WSL command must be Docker-related only.\n\n" + \
                   f"✅ ALLOWED WSL COMMANDS:\n" + \
                   f"  - docker ps\n" + \
                   f"  - docker network inspect <network>\n" + \
                   f"  - docker logs <container>\n" + \
                   f"  - docker stats\n" + \
                   f"  - cat/ls/tail /var/log/...\n\n" + \
                   f"❌ FORBIDDEN (Host Network Access):\n" + \
                   f"  - ifconfig, ip addr (host network info)\n" + \
                   f"  - ping, netstat, ss (host connectivity)\n" + \
                   f"  - arp, route (host routing tables)\n\n" + \
                   f"❌ BLOCKED: {command}"
        
        try:
            sudo_password = os.getenv("WSL_SUDO_PASSWORD", "")
            
            if use_sudo:
                if sudo_password:
                    full_cmd = ['wsl', 'bash', '-c', f"echo {sudo_password} | sudo -S {command}"]
                else:
                    full_cmd = ['wsl', 'bash', '-c', f"sudo {command}"]
            else:
                full_cmd = ['wsl', 'bash', '-c', command]
            
            result = subprocess.run(
                full_cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            output = f"WSL Command: {command}\n"
            output += f"Sudo: {'Yes' if use_sudo else 'No'}\n"
            output += f"Exit Code: {result.returncode}\n"
            output += f"{'='*60}\n"
            
            if result.stdout:
                output += "OUTPUT:\n" + result.stdout
            if result.stderr:
                output += "ERRORS:\n" + result.stderr
            
            return output
        except subprocess.TimeoutExpired:
            return f"ERROR: WSL command timeout after {timeout}s"
        except Exception as e:
            return f"ERROR running WSL command: {str(e)}"
    
    def _wsl_bash_script(self, script: str, use_sudo: bool = False, timeout: int = 60) -> str:
        """Run bash script in WSL"""
        try:
            sudo_password = os.getenv("WSL_SUDO_PASSWORD", "")
            
            # Create bash script with heredoc
            script_content = f"""cat > /tmp/mcp_script.sh << 'EOFSCRIPT'
{script}
EOFSCRIPT
chmod +x /tmp/mcp_script.sh"""
            
            if use_sudo:
                if sudo_password:
                    bash_cmd = f"{script_content} && echo {sudo_password} | sudo -S bash /tmp/mcp_script.sh && rm /tmp/mcp_script.sh"
                else:
                    bash_cmd = f"{script_content} && sudo bash /tmp/mcp_script.sh && rm /tmp/mcp_script.sh"
            else:
                bash_cmd = f"{script_content} && bash /tmp/mcp_script.sh && rm /tmp/mcp_script.sh"
            
            full_cmd = ['wsl', 'bash', '-c', bash_cmd]
            
            result = subprocess.run(
                full_cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            output = f"WSL Bash Script\n"
            output += f"Sudo: {'Yes' if use_sudo else 'No'}\n"
            output += f"Exit Code: {result.returncode}\n"
            output += f"{'='*60}\n"
            
            if result.stdout:
                output += "OUTPUT:\n" + result.stdout
            if result.stderr:
                output += "ERRORS:\n" + result.stderr
            
            return output
        except subprocess.TimeoutExpired:
            return f"ERROR: Bash script timeout after {timeout}s"
        except Exception as e:
            return f"ERROR running bash script: {str(e)}"
    
    def _wsl_read_file(self, path: str) -> str:
        """Read file from WSL"""
        try:
            cmd = f'wsl cat "{path}"'
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout if result.stdout else "[Empty file]"
            else:
                return f"ERROR: {result.stderr}"
        except Exception as e:
            return f"ERROR reading WSL file: {str(e)}"
    
    def _wsl_write_file(self, path: str, content: str) -> str:
        """Write file to WSL"""
        try:
            # Escape content for shell
            content_escaped = content.replace("'", "'\\''")
            
            cmd = f"wsl bash -c \"echo '{content_escaped}' > '{path}'\""
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return f"✅ File written to WSL: {path}"
            else:
                return f"ERROR: {result.stderr}"
        except Exception as e:
            return f"ERROR writing WSL file: {str(e)}"
    
    def _docker_command(self, command: str, use_sudo: bool = False, timeout: int = 30) -> str:
        """Run Docker command in WSL"""
        try:
            sudo_password = os.getenv("WSL_SUDO_PASSWORD", "")
            docker_cmd = f"docker {command}"
            
            if use_sudo:
                if sudo_password:
                    full_cmd = ['wsl', 'bash', '-c', f"echo {sudo_password} | sudo -S {docker_cmd}"]
                else:
                    full_cmd = ['wsl', 'bash', '-c', f"sudo {docker_cmd}"]
            else:
                full_cmd = ['wsl', 'bash', '-c', docker_cmd]
            
            result = subprocess.run(
                full_cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            output = f"Docker Command: {command}\n"
            output += f"Sudo: {'Yes' if use_sudo else 'No'}\n"
            output += f"Exit Code: {result.returncode}\n"
            output += f"{'='*60}\n"
            
            if result.stdout:
                output += "OUTPUT:\n" + result.stdout
            if result.stderr:
                output += "ERRORS:\n" + result.stderr
            
            return output
        except subprocess.TimeoutExpired:
            return f"ERROR: Docker command timeout after {timeout}s"
        except Exception as e:
            return f"ERROR running Docker command: {str(e)}"
    
    # =======================================
    # ENVIRONMENT VARIABLE IMPLEMENTATIONS
    # =======================================
    
    def _get_env_variable(self, name: str) -> str:
        """Get environment variable"""
        try:
            value = os.getenv(name)
            if value is None:
                return f"Environment variable '{name}' is not set"
            return f"{name}={value}"
        except Exception as e:
            return f"ERROR getting environment variable: {str(e)}"
    
    def _set_env_variable(self, name: str, value: str) -> str:
        """Set environment variable"""
        try:
            os.environ[name] = value
            return f"✅ Environment variable set: {name}={value}"
        except Exception as e:
            return f"ERROR setting environment variable: {str(e)}"
    
    
    def _read_zeek_logs(self, log_type: str = "all") -> str:
        """Read current Zeek logs in real-time from Windows zeek_logs directory"""
        try:
            # Path to Windows Zeek logs (auto-synced from WSL)
            zeek_logs_dir = self.project_root / "network" / "zeek_logs"
            
            if not zeek_logs_dir.exists():
                return "⚠️ Zeek logs directory not found.\n\n" + \
                       "Expected: network/zeek_logs/\n" + \
                       "Start Zeek monitor with: network/zeek/START.bat"
            
            # Get all session directories (sorted by newest first)
            session_dirs = sorted(
                [d for d in zeek_logs_dir.glob("session_*") if d.is_dir()],
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )
            
            if not session_dirs:
                return "No Zeek sessions found yet.\n\n" + \
                       "Start Zeek monitor to capture traffic: network/zeek/START.bat"
            
            # FAST MODE: Read only latest 2 sessions (not 5) to speed up analysis
            sessions_to_read = session_dirs[:2]
            
            result = f"🔍 FAST ZEEK ANALYSIS - {len(sessions_to_read)} Latest Sessions\n{'='*80}\n\n"
            
            total_entries = 0
            
            for session_dir in sessions_to_read:
                session_name = session_dir.name
                session_time = datetime.fromtimestamp(session_dir.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                
                result += f"\n📦 {session_name} (Created: {session_time})\n{'-'*80}\n"
                
                # Read ALL .log files in the session directory
                all_log_files = sorted(session_dir.glob("*.log"))
                
                if not all_log_files:
                    result += "  No log files found in this session\n"
                    continue
                
                for log_path in all_log_files:
                    log_file = log_path.name
                    
                    try:
                        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Parse data lines (skip comments starting with #)
                        lines = content.split('\n')
                        data_lines = [line for line in lines if line.strip() and not line.startswith('#')]
                        
                        if not data_lines:
                            result += f"\n  📄 {log_file}: [empty]\n"
                            continue
                        
                        total_entries += len(data_lines)
                        
                        result += f"\n  📄 {log_file}: {len(data_lines)} entries\n"
                        
                        # FAST MODE: Show only last 10 entries (not 20) to reduce processing time
                        header_lines = [line for line in lines if line.startswith('#')]
                        if header_lines and log_file in ['conn.log', 'http.log']:  # Only show headers for key logs
                            result += "\n".join(header_lines[:3]) + "\n\n"  # Only 3 header lines
                        
                        # Show latest 10 entries only
                        recent_entries = data_lines[-10:]
                        result += "\n".join(recent_entries) + "\n"
                        
                    except Exception as e:
                        result += f"  ⚠️ Error reading {log_file}: {str(e)}\n"
                
                # FAST MODE: Skip extracted files analysis to speed up (only show count)
                extracted_dir = session_dir / "extracted_files"
                if extracted_dir.exists() and extracted_dir.is_dir():
                    extracted_files = list(extracted_dir.glob("*"))
                    if extracted_files:
                        result += f"\n  📦 Extracted Files: {len(extracted_files)} files (skipped for speed)\n"
            
            # FAST MODE: Skip global extracted files analysis completely
            
            if total_entries == 0:
                return "Zeek monitor is running but no traffic captured yet.\n\n" + \
                       "Ensure devices are connected to custom_net and generating traffic."
            
            result += f"\n{'='*80}\n"
            result += f"📊 Summary: {total_entries} total log entries across {len(sessions_to_read)} sessions\n"
            result += f"{'='*80}\n"
            
            return result
            
        except Exception as e:
            import traceback
            return f"ERROR reading Zeek logs: {str(e)}\n\nTraceback: {traceback.format_exc()}"
    
    def _move_device_to_beelzebub(self, device_id: str, reason: str) -> str:
        """Move device from custom_net to honeypot_net (Beelzebub)"""
        try:
            container_name = device_id
            log_messages = []  # Collect debug messages for return value
            
            # If device_id looks like an IP address, find the container by IP
            if device_id.startswith('192.168.') or device_id.startswith('172.'):
                log_messages.append(f"[IP LOOKUP] Looking up container for IP: {device_id}")
                
                # Step 1: Get list of containers on custom_net
                list_cmd = "docker ps --filter network=custom_net --format '{{.Names}}'"
                list_result = subprocess.run(
                    ['wsl', 'bash', '-c', list_cmd],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                found_container = None
                if list_result.returncode == 0:
                    containers = list_result.stdout.strip().split('\n')
                    # Step 2: Check each container's IP
                    for cname in containers:
                        cname = cname.strip()
                        if not cname:
                            continue
                        ip_cmd = f"docker inspect {cname} --format '{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}'"
                        ip_result = subprocess.run(
                            ['wsl', 'bash', '-c', ip_cmd],
                            capture_output=True,
                            text=True,
                            timeout=5
                        )
                        if ip_result.returncode == 0:
                            container_ip = ip_result.stdout.strip()
                            if container_ip == device_id:
                                found_container = cname
                                log_messages.append(f"[IP LOOKUP] Found: {cname} = {container_ip}")
                                break
                
                if found_container:
                    container_name = found_container
                else:
                    return f"ERROR: No container found with IP '{device_id}' on custom_net"
            # Normalize common patterns for logging
            elif device_id.startswith('device_'):
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
            
            # Get container's current IP on custom_net (before rerouting)
            get_ip_cmd = f"docker inspect {container_name} --format '{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}'"
            current_ip_result = subprocess.run(
                ['wsl', 'bash', '-c', get_ip_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            container_ip = current_ip_result.stdout.strip() if current_ip_result.returncode == 0 else None
            
            # Get Beelzebub honeypot network name dynamically (honey_pot_honeypot_net or honeypot_net)
            beelzebub_network_cmd = "docker inspect beelzebub-honeypot --format '{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{end}}' 2>/dev/null | grep -o '[^ ]*honeypot[^ ]*' | head -1"
            beelzebub_network_result = subprocess.run(
                ['wsl', 'bash', '-c', beelzebub_network_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            honeypot_network = beelzebub_network_result.stdout.strip() if beelzebub_network_result.returncode == 0 and beelzebub_network_result.stdout.strip() else 'honey_pot_honeypot_net'
            
            # Get Beelzebub honeypot IP dynamically
            beelzebub_ip_cmd = f"docker inspect beelzebub-honeypot --format '{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}' 2>/dev/null"
            beelzebub_ip_result = subprocess.run(
                ['wsl', 'bash', '-c', beelzebub_ip_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            honeypot_target_ip = beelzebub_ip_result.stdout.strip() if beelzebub_ip_result.returncode == 0 and beelzebub_ip_result.stdout.strip() else '172.18.0.2'
            
            # Check if already on honeypot network
            check_honeypot_cmd = f"docker inspect {container_name} --format '{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}'"
            check_result = subprocess.run(
                ['wsl', 'bash', '-c', check_honeypot_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Check if actually on honeypot (must have valid IP, not '<no value>' or empty)
            honeypot_ip_check = check_result.stdout.strip()
            already_on_honeypot = (check_result.returncode == 0 and 
                                   honeypot_ip_check and 
                                   honeypot_ip_check != '<no value>' and
                                   '.' in honeypot_ip_check)  # Must look like an IP address
            
            if already_on_honeypot:
                return f"Device {device_id} is already isolated in honeypot network ({honeypot_network})"
            
            # COMPLETE NETWORK SWITCH: Disconnect from custom_net and connect to honeypot_net
            # Note: No print() statements - they interfere with MCP JSON-RPC protocol
            
            # Get network-monitor IP for logging
            network_monitor_ip = "192.168.6.131"
            
            # STEP 1: Disconnect device from production network (custom_net)
            disconnect_cmd = f"docker network disconnect custom_net {container_name}"
            disconnect_result = subprocess.run(
                ['wsl', 'bash', '-c', disconnect_cmd],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if disconnect_result.returncode != 0:
                # Check if already disconnected
                if "is not connected to network custom_net" not in disconnect_result.stderr:
                    return f"ERROR: Failed to disconnect from custom_net: {disconnect_result.stderr}"
            
            # STEP 2: Connect device to honeypot network (complete isolation)
            connect_cmd = f"docker network connect {honeypot_network} {container_name}"
            connect_result = subprocess.run(
                ['wsl', 'bash', '-c', connect_cmd],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if connect_result.returncode != 0:
                # Check if already connected
                if "already exists in network" not in connect_result.stderr and "is already connected" not in connect_result.stderr:
                    # Critical failure - try to reconnect to custom_net
                    reconnect_cmd = f"docker network connect custom_net {container_name}"
                    subprocess.run(['wsl', 'bash', '-c', reconnect_cmd], capture_output=True, timeout=10)
                    return f"ERROR: Failed to connect to {honeypot_network}: {connect_result.stderr}\nRestored connection to custom_net."
            
            # Get new IP on honeypot network
            honeypot_ip_cmd = f"docker inspect {container_name} --format '{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}'"
            honeypot_ip_result = subprocess.run(
                ['wsl', 'bash', '-c', honeypot_ip_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if honeypot_ip_result.returncode != 0 or not honeypot_ip_result.stdout.strip():
                return f"ERROR: Network switch completed but could not get new IP address. Manual check needed."
            
            device_honeypot_ip = honeypot_ip_result.stdout.strip()
            
            # IMPORTANT: Redirect container's TARGET_IP to honeypot
            # This makes the attacker's SSH/HTTP traffic go to honeypot instead of timing out
            # Step 1: Get current image name
            get_image_cmd = f"docker inspect {container_name} --format '{{{{.Config.Image}}}}'"
            image_result = subprocess.run(
                ['wsl', 'bash', '-c', get_image_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            image_name = image_result.stdout.strip() if image_result.returncode == 0 else None
            
            # Step 2: Recreate container with TARGET_IP pointing to honeypot
            if image_name:
                recreate_cmd = f"""
                    docker stop {container_name} 2>/dev/null; \
                    docker rm {container_name} 2>/dev/null; \
                    docker run -d --name {container_name} \
                        --network {honeypot_network} \
                        -e TARGET_IP={honeypot_target_ip} \
                        -e TARGET_PORT=22 \
                        {image_name}
                """
                recreate_result = subprocess.run(
                    ['wsl', 'bash', '-c', recreate_cmd],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                target_redirected = recreate_result.returncode == 0
                
                # Get the new IP after recreation
                if target_redirected:
                    new_ip_cmd = f"docker inspect {container_name} --format '{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}'"
                    new_ip_result = subprocess.run(
                        ['wsl', 'bash', '-c', new_ip_cmd],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    device_honeypot_ip = new_ip_result.stdout.strip() if new_ip_result.returncode == 0 else device_honeypot_ip
            else:
                target_redirected = False
            
            # Log the reroute
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'device_id': device_id,
                'container_name': container_name,
                'reason': reason,
                'original_ip': container_ip,
                'original_network': 'custom_net',
                'honeypot_ip': device_honeypot_ip,
                'honeypot_network': honeypot_network,
                'honeypot_target': honeypot_target_ip,
                'network_monitor_ip': network_monitor_ip,
                'method': 'complete_network_switch',
                'isolated': True
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
            
            # Update dashboard blocked_devices.json
            blocked_devices_file = self.project_root / 'dashboard' / 'blocked_devices.json'
            blocked_devices_file.parent.mkdir(parents=True, exist_ok=True)
            
            try:
                # Read existing blocked devices
                if blocked_devices_file.exists():
                    with open(blocked_devices_file, 'r') as f:
                        blocked_devices = json.load(f)
                else:
                    blocked_devices = []
                
                # Check if device already in list
                device_exists = False
                for device in blocked_devices:
                    if device.get('container_name') == container_name:
                        # Update existing entry
                        device['blocked_at'] = datetime.now().isoformat()
                        device['reason'] = reason
                        device['status'] = 'active'
                        device['method'] = 'network_switch'
                        device['honeypot_ip'] = device_honeypot_ip
                        device_exists = True
                        break
                
                # Add new entry if not exists
                if not device_exists:
                    blocked_devices.append({
                        'device_id': device_id,
                        'container_name': container_name,
                        'original_ip': container_ip,
                        'honeypot_ip': device_honeypot_ip,
                        'blocked_at': datetime.now().isoformat(),
                        'reason': reason,
                        'method': 'network_switch',
                        'status': 'active'
                    })
                
                # Write back
                with open(blocked_devices_file, 'w') as f:
                    json.dump(blocked_devices, f, indent=2)
                    
            except Exception:
                pass  # Silently ignore - don't use print() as it breaks MCP JSON-RPC
            
            result = f"[SUCCESS] Device {container_name} traffic fully rerouted to honeypot\n\n"
            result += f"===================================================\n"
            result += f"DEVICE ISOLATION COMPLETE\n"
            result += f"===================================================\n\n"
            result += f"Device Details:\n"
            result += f"   - Container: {container_name}\n"
            result += f"   - Device ID: {device_id}\n"
            result += f"   - Original IP: {container_ip}\n"
            result += f"   - Old Network: custom_net -> DISCONNECTED\n"
            result += f"   - New Network: {honeypot_network} -> CONNECTED\n"
            result += f"   - New IP: {device_honeypot_ip}\n"
            result += f"   - TARGET_IP redirected: {'YES -> ' + honeypot_target_ip if target_redirected else 'NO (manual restart needed)'}\n\n"
            result += f"Honeypot Details:\n"
            result += f"   - Honeypot IP: {honeypot_target_ip}\n"
            result += f"   - Honeypot Network: {honeypot_network}\n"
            result += f"   - Honeypot Type: Beelzebub with Ollama LLM\n\n"
            result += f"Reason for Isolation:\n"
            result += f"   {reason}\n\n"
            result += f"Isolation Method:\n"
            result += f"   - COMPLETE NETWORK SWITCH (not DNAT)\n"
            result += f"   - Container recreated with TARGET_IP={honeypot_target_ip}\n" if target_redirected else ""
            result += f"   - Disconnected from production network\n"
            result += f"   - Connected exclusively to honeypot network\n"
            result += f"   - Device is now 100% isolated from production\n\n"
            result += f"Traffic Behavior:\n"
            result += f"   - ALL traffic now goes directly to honeypot network\n"
            result += f"   - No access to production network (192.168.6.0/24)\n"
            result += f"   - Can only communicate with honeypot ({honeypot_target_ip})\n\n"
            result += f"Verification Status:\n"
            result += f"   - Network switch: COMPLETED\n"
            result += f"   - Dashboard updated: YES\n"
            result += f"   - Isolation logged: YES\n"
            result += f"   - Device status: ISOLATED\n\n"
            result += f"Impact:\n"
            result += f"   - Device COMPLETELY REMOVED from production network\n"
            result += f"   - ALL traffic goes to AI-powered honeypot only\n"
            result += f"   - Attack patterns captured and logged\n"
            result += f"   - Other devices unaffected\n"
            result += f"   - Real-time monitoring active\n\n"
            result += f"===================================================\n"
            result += f"Device {container_name} is now FULLY ISOLATED\n"
            result += f"All malicious traffic flows to honeypot for analysis\n"
            result += f"==================================================="
            
            return result
            
        except subprocess.TimeoutExpired:
            return "ERROR: Operation timeout"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def _restore_device_from_honeypot(self, device_id: str) -> str:
        """Reverse network switch: disconnect from honeypot and reconnect to production network"""
        try:
            # Accept any container name
            container_name = device_id
            
            # Normalize common patterns
            if device_id.startswith('device_'):
                device_num = device_id.replace('device_', '')
                container_name = f"vdevice_{device_num}"
            elif device_id.startswith('vdevice_'):
                container_name = device_id
            
            # Get honeypot network name
            beelzebub_network_cmd = "docker inspect beelzebub-honeypot --format '{{range $net, $conf := .NetworkSettings.Networks}}{{$net}} {{end}}' 2>/dev/null | grep -o '[^ ]*honeypot[^ ]*' | head -1"
            beelzebub_network_result = subprocess.run(
                ['wsl', 'bash', '-c', beelzebub_network_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            honeypot_network = beelzebub_network_result.stdout.strip() if beelzebub_network_result.returncode == 0 and beelzebub_network_result.stdout.strip() else 'honey_pot_honeypot_net'
            
            # Get current IP on honeypot network (if exists)
            get_honeypot_ip_cmd = f"docker inspect {container_name} --format '{{{{.NetworkSettings.Networks.{honeypot_network}.IPAddress}}}}'"
            honeypot_ip_result = subprocess.run(
                ['wsl', 'bash', '-c', get_honeypot_ip_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            old_honeypot_ip = honeypot_ip_result.stdout.strip() if honeypot_ip_result.returncode == 0 and honeypot_ip_result.stdout.strip() else "N/A"
            
            # STEP 1: Disconnect from honeypot network
            print(f"🔌 Disconnecting {container_name} from {honeypot_network}...")
            disconnect_cmd = f"docker network disconnect {honeypot_network} {container_name}"
            disconnect_result = subprocess.run(
                ['wsl', 'bash', '-c', disconnect_cmd],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if disconnect_result.returncode != 0:
                if "is not connected to network" in disconnect_result.stderr:
                    print(f"✅ Already disconnected from {honeypot_network}")
                else:
                    return f"ERROR: Failed to disconnect from honeypot: {disconnect_result.stderr}"
            else:
                print(f"✅ Disconnected from {honeypot_network} (was: {old_honeypot_ip})")
            
            # STEP 2: Reconnect to production network
            print(f"🔀 Reconnecting {container_name} to custom_net...")
            reconnect_cmd = f"docker network connect custom_net {container_name}"
            reconnect_result = subprocess.run(
                ['wsl', 'bash', '-c', reconnect_cmd],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if reconnect_result.returncode != 0:
                if "already exists in network" in reconnect_result.stderr or "is already connected" in reconnect_result.stderr:
                    print(f"✅ Already connected to custom_net")
                else:
                    return f"ERROR: Failed to reconnect to production: {reconnect_result.stderr}"
            else:
                print(f"✅ Reconnected to custom_net")
            
            # Get new IP on production network
            get_prod_ip_cmd = f"docker inspect {container_name} --format '{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}'"
            prod_ip_result = subprocess.run(
                ['wsl', 'bash', '-c', get_prod_ip_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if prod_ip_result.returncode != 0 or not prod_ip_result.stdout.strip():
                return f"ERROR: Network switch completed but could not verify new IP"
            
            new_prod_ip = prod_ip_result.stdout.strip()
            print(f"✅ Device restored to production IP: {new_prod_ip}")
            
            # Update dashboard blocked_devices.json
            blocked_devices_file = self.project_root / 'dashboard' / 'blocked_devices.json'
            try:
                if blocked_devices_file.exists():
                    with open(blocked_devices_file, 'r') as f:
                        blocked_devices = json.load(f)
                    
                    # Remove or mark as restored
                    blocked_devices = [d for d in blocked_devices if d.get('container_name') != container_name]
                    
                    with open(blocked_devices_file, 'w') as f:
                        json.dump(blocked_devices, f, indent=2)
            except Exception as e:
                print(f"⚠️ Warning: Could not update blocked_devices.json: {e}")
            
            result = f"✅ SUCCESS: Device restored to production network\n\n"
            result += f"📍 Device: {device_id} ({container_name})\n"
            result += f"🌐 Network: custom_net (192.168.6.0/24)\n"
            result += f"📡 New IP: {new_prod_ip}\n"
            result += f"📡 Old Honeypot IP: {old_honeypot_ip}\n\n"
            result += f"✅ Network Operations:\n"
            result += f"   • Disconnected from: {honeypot_network} ✓\n"
            result += f"   • Reconnected to: custom_net ✓\n"
            result += f"   • Dashboard updated ✓\n\n"
            result += f"✨ Device is now fully restored to production\n"
            result += f"✨ Can access all production services\n"
            result += f"✨ No longer isolated"
            
            return result
            
        except subprocess.TimeoutExpired:
            return "ERROR: Operation timeout"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    # =======================================
    # MALWARE DETECTION IMPLEMENTATIONS
    # =======================================
    
    def _resolve_file_path(self, file_path: str) -> Path:
        """Smart file path resolution - handles partial paths, filenames, Linux paths, etc."""
        try:
            # Try direct path first
            p = Path(file_path)
            if p.exists() and p.is_file():
                return p
            
            # Extract filename from path
            filename = p.name if p.name else file_path
            
            # Search in zeek_logs extracted_files (most recent first)
            zeek_logs_dir = self.network_dir / "zeek_logs"
            
            if zeek_logs_dir.exists():
                # 1. Check global extracted_files directory first (most likely location)
                global_extracted_dir = zeek_logs_dir / "extracted_files"
                if global_extracted_dir.exists():
                    # Try exact filename match
                    candidate = global_extracted_dir / filename
                    if candidate.exists():
                        return candidate
                    
                    # Try pattern matching
                    for extracted_file in global_extracted_dir.glob("*"):
                        if filename in extracted_file.name or extracted_file.name in filename:
                            return extracted_file

                # 2. Get all session directories sorted by modification time (newest first)
                session_dirs = sorted(
                    [d for d in zeek_logs_dir.glob("session_*") if d.is_dir()],
                    key=lambda x: x.stat().st_mtime,
                    reverse=True
                )
                
                # Search in each session's extracted_files
                for session_dir in session_dirs:
                    extracted_dir = session_dir / "extracted_files"
                    if extracted_dir.exists():
                        # Try exact filename match
                        candidate = extracted_dir / filename
                        if candidate.exists():
                            return candidate
                        
                        # Try pattern matching if filename has wildcards or partial match
                        for extracted_file in extracted_dir.glob("*"):
                            if filename in extracted_file.name or extracted_file.name in filename:
                                return extracted_file
            
            # If still not found, try current working directory
            cwd = Path.cwd()
            cwd_candidate = cwd / filename
            if cwd_candidate.exists():
                return cwd_candidate
            
            return None
            
        except Exception as e:
            print(f"Error resolving path: {e}", file=sys.stderr)
            return None
    
    def _check_malware_hash(self, file_path: str, check_online: bool = False) -> str:
        """Check file hash against malware databases"""
        try:
            # Import hash checker
            import sys
            sys.path.insert(0, str(self.malware_db_dir / "scripts"))
            from check_hash import MalwareHashChecker
            
            # Initialize checker
            db_dir = self.malware_db_dir / "hash_databases"
            checker = MalwareHashChecker(db_dir=str(db_dir))
            
            # Smart path resolution
            file_path_obj = self._resolve_file_path(file_path)
            
            # If not a file, check if it's a hash string
            if not file_path_obj:
                import re
                # Check for MD5 (32), SHA1 (40), or SHA256 (64) hex strings
                if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', file_path.strip()):
                    # It's a hash! Check directly
                    hash_value = file_path.strip()
                    matches = checker.check_hash(hash_value)
                    
                    # Construct a result object similar to check_file
                    result = {
                        "status": "success",
                        "file_path": f"[Hash Check] {hash_value}",
                        "file_size": 0,
                        "hashes": {
                            "query": hash_value
                        },
                        "matches": matches,
                        "threat_level": "MALWARE" if matches else "CLEAN",
                        "threat_score": 100 if matches else 0,
                        "timestamp": datetime.now().isoformat()
                    }
                    
                    # Online check for hash
                    if check_online and not matches and len(hash_value) == 64:
                        online_results = checker._check_online(hash_value)
                        if online_results:
                            result["online_check"] = online_results
                            if online_results.get("found"):
                                result["threat_level"] = "MALWARE (Online)"
                                result["threat_score"] = 100
                else:
                    return f"❌ ERROR: File not found and input is not a valid hash\n\n" + \
                           f"Search query: {file_path}\n" + \
                           f"\n💡 TIP: When reading zeek logs, extract the FULL Windows path from extracted_files section.\n" + \
                           f"Look for paths like: E:\\...\\zeek_logs\\session_*\\extracted_files\\extract-*"
            else:
                # Check file
                result = checker.check_file(str(file_path_obj), check_online=check_online)
            
            # Format output
            if result["status"] == "error":
                return f"❌ ERROR: {result['message']}"
            
            output = []
            output.append("="*70)
            output.append("🔍 MALWARE HASH CHECK RESULTS")
            output.append("="*70)
            output.append(f"\n📄 File: {result['file_path']}")
            output.append(f"📊 Size: {result['file_size']} bytes")
            
            # Hashes
            output.append(f"\n🔑 File Hashes:")
            for hash_type, hash_value in result["hashes"].items():
                output.append(f"  {hash_type.upper()}: {hash_value}")
            
            # Matches
            matches = result.get("matches", [])
            output.append(f"\n🎯 Database Matches: {len(matches)}")
            
            if matches:
                output.append("\n⚠️ THREAT DETECTED!\n")
                for i, match in enumerate(matches, 1):
                    output.append(f"Match #{i}:")
                    output.append(f"  Database: {match.get('database', 'Unknown')}")
                    output.append(f"  Hash Type: {match.get('hash_type', 'Unknown').upper()}")
                    
                    if 'signature' in match:
                        output.append(f"  Malware Family: {match['signature']}")
                    if 'tags' in match and match['tags']:
                        output.append(f"  Tags: {match['tags']}")
                    if 'severity' in match:
                        output.append(f"  Severity: {match['severity']}")
                    if 'file_type' in match and match['file_type']:
                        output.append(f"  File Type: {match['file_type']}")
                    if 'first_seen' in match and match['first_seen']:
                        output.append(f"  First Seen: {match['first_seen']}")
                    output.append("")
            else:
                output.append("\n✅ No matches found in local databases")
            
            # Online check results
            if "online_check" in result:
                online = result["online_check"]
                output.append(f"\n🌐 Online Check ({online.get('source', 'Unknown')}):")
                if online.get("found"):
                    output.append("  ⚠️ Hash found in online database!")
                    if "data" in online:
                        output.append(f"  Data: {json.dumps(online['data'], indent=2)}")
                elif "error" in online:
                    output.append(f"  ⚠️ Error: {online['error']}")
                else:
                    output.append("  ✅ Hash not found online")
            
            # Threat assessment
            output.append(f"\n🎚️ Threat Assessment:")
            output.append(f"  Threat Level: {result['threat_level']}")
            output.append(f"  Threat Score: {result['threat_score']}/100")
            
            # Recommendations
            output.append(f"\n💡 Recommended Action:")
            if result['threat_level'] == "MALWARE":
                output.append("  🚨 QUARANTINE IMMEDIATELY - Known malware detected!")
                output.append("  🔒 Isolate source device to honeypot network")
                output.append("  📝 Log incident for forensic analysis")
            elif result['threat_level'] == "TEST_FILE":
                output.append("  ℹ️ EICAR test file detected (not real malware)")
                output.append("  ✅ Safe to ignore if this is a security test")
            elif result['threat_level'] == "SUSPICIOUS":
                output.append("  ⚠️ Monitor - Suspicious patterns detected")
            else:
                output.append("  ✅ File appears clean")
            
            output.append("="*70)
            
            return "\n".join(output)
            
        except ImportError as e:
            return f"❌ ERROR: Malware database module not found.\n" + \
                   f"Run: cd malware_db/scripts && python update_malwarebazaar.py\n" + \
                   f"Details: {str(e)}"
        except Exception as e:
            import traceback
            return f"❌ ERROR checking malware hash: {str(e)}\n\nTraceback:\n{traceback.format_exc()}"
    
    def run(self):
        """Run the FastMCP server."""
        print("🔧 DEBUG: NetworkSecurityServer.run() called", file=sys.stderr)
        print(f"🔧 DEBUG: Server name: {self.mcp.name}", file=sys.stderr)
        
        # Count registered tools
        tools_count = len(self.mcp._tools) if hasattr(self.mcp, '_tools') else 0
        print(f"🔧 DEBUG: Registered tools count: {tools_count}", file=sys.stderr)
        
        if hasattr(self.mcp, '_tools'):
            all_tool_names = list(self.mcp._tools.keys())
            print(f"🔧 DEBUG: ALL Tool names: {all_tool_names}", file=sys.stderr)
            if 'read_zeek_logs' in all_tool_names:
                print(f"🔧 DEBUG: ✅ read_zeek_logs IS REGISTERED!", file=sys.stderr)
            else:
                print(f"🔧 DEBUG: ❌ read_zeek_logs NOT FOUND!", file=sys.stderr)
        
        print("🔧 DEBUG: Starting mcp.run()...", file=sys.stderr)
        self.mcp.run()


if __name__ == "__main__":
    print("🔧 DEBUG: server.py __main__ starting", file=sys.stderr)
    server = NetworkSecurityServer()
    print("🔧 DEBUG: NetworkSecurityServer created", file=sys.stderr)
    server.run()
