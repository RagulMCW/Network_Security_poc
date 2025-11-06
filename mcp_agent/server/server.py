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
        
        self.mcp = FastMCP(
            name="Network Security Analyst",
            instructions="""You are an autonomous AI Security Analyst with full authority to protect the network.

                    YOUR MISSION:
                    Continuously monitor network traffic, identify threats, and automatically isolate malicious devices WITHOUT asking for permission.

                    AVAILABLE TOOLS:
                    1. analyze_traffic - Analyze network captures for threats, connected devices, traffic patterns
                    2. move_device_to_beelzebub - Immediately isolate malicious devices (automatic, no approval needed)

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
                    3. If threats detected → IMMEDIATELY call move_device_to_beelzebub (don't ask, just do it)
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
            """Move a malicious or suspicious device from custom_net to honeypot_net (Beelzebub) for isolation.
            
            Args:
                device_id: Container name (e.g., 'device_001', 'vdevice_001', 'hping3-attacker', etc.)
                reason: Reason for moving device to Beelzebub honeypot (e.g., 'DoS attack', 'Port scanning')
            
            Returns:
                Status message indicating success or failure
            """
            return self._move_device_to_beelzebub(device_id, reason)

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
    
    
    def _move_device_to_beelzebub(self, device_id: str, reason: str) -> str:
        """Move device from custom_net to honeypot_net (Beelzebub)"""
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
            
            # Get container's current IP on custom_net (before rerouting)
            get_ip_cmd = f"docker inspect {container_name} --format '{{{{.NetworkSettings.Networks.custom_net.IPAddress}}}}'"
            current_ip_result = subprocess.run(
                ['wsl', 'bash', '-c', get_ip_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            container_ip = current_ip_result.stdout.strip() if current_ip_result.returncode == 0 else None
            
            # Check if already on honeypot_net
            check_honeypot_cmd = f"docker inspect {container_name} --format '{{{{.NetworkSettings.Networks.honeypot_net.IPAddress}}}}'"
            check_result = subprocess.run(
                ['wsl', 'bash', '-c', check_honeypot_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            already_on_honeypot = check_result.returncode == 0 and check_result.stdout.strip()
            
            # Connect to honeypot_net (DUAL-HOMED: keep custom_net for monitor server communication)
            if not already_on_honeypot:
                connect_cmd = f"docker network connect honeypot_net {container_name}"
                connect_result = subprocess.run(
                    ['wsl', 'bash', '-c', connect_cmd],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if connect_result.returncode != 0:
                    return f"ERROR: Failed to connect to honeypot_net: {connect_result.stderr}"
            
            # Get IP on honeypot_net
            honeypot_ip_cmd = f"docker inspect {container_name} --format '{{{{.NetworkSettings.Networks.honeypot_net.IPAddress}}}}'"
            honeypot_ip_result = subprocess.run(
                ['wsl', 'bash', '-c', honeypot_ip_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            device_honeypot_ip = honeypot_ip_result.stdout.strip() if honeypot_ip_result.returncode == 0 else "Unknown"
            
            # Get Beelzebub honeypot IP dynamically (check both standalone and docker-compose networks)
            beelzebub_ip_cmd = "docker inspect beelzebub-honeypot --format '{{range $net, $conf := .NetworkSettings.Networks}}{{if or (eq $net \"honeypot_net\") (contains $net \"honeypot\")}}{{$conf.IPAddress}}{{end}}{{end}}' 2>/dev/null || echo '172.18.0.2'"
            beelzebub_ip_result = subprocess.run(
                ['wsl', 'bash', '-c', beelzebub_ip_cmd],
                capture_output=True,
                text=True,
                timeout=5
            )
            honeypot_target_ip = beelzebub_ip_result.stdout.strip() if beelzebub_ip_result.returncode == 0 and beelzebub_ip_result.stdout.strip() else '172.18.0.2'
            
            if container_ip:
                # Apply iptables DNAT rules to redirect traffic
                iptables_rules = [
                    f'iptables -t nat -A PREROUTING -s {container_ip} -p tcp -j DNAT --to-destination {honeypot_target_ip}',
                    f'iptables -t nat -A PREROUTING -s {container_ip} -p udp -j DNAT --to-destination {honeypot_target_ip}',
                    f'iptables -t mangle -A PREROUTING -s {container_ip} -j MARK --set-mark 100',
                ]
                
                for rule in iptables_rules:
                    subprocess.run(
                        ['wsl', 'bash', '-c', f'sudo {rule}'],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
            
            # Log the reroute
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'device_id': device_id,
                'container_name': container_name,
                'reason': reason,
                'original_ip': container_ip,
                'honeypot_ip': device_honeypot_ip,
                'honeypot_target': honeypot_target_ip,
                'network': 'honeypot_net',
                'method': 'iptables_redirect'
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
            
            result = f"SUCCESS: Device moved to honeypot network\n\n"
            result += f"Device: {device_id} ({container_name})\n"
            result += f"Reason: {reason}\n"
            result += f"Original IP: {container_ip}\n"
            result += f"Honeypot IP: {device_honeypot_ip}\n"
            result += f"Traffic Target: {honeypot_target_ip}\n"
            result += f"Method: iptables DNAT redirect\n"
            result += f"Status: ISOLATED\n"
            result += f"\nDevice quarantined. All traffic redirected to honeypot via iptables."
            
            return result
            
        except subprocess.TimeoutExpired:
            return "ERROR: Operation timeout"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def run(self):
        """Run the FastMCP server."""
        print("🔧 DEBUG: NetworkSecurityServer.run() called", file=sys.stderr)
        print(f"🔧 DEBUG: Server name: {self.mcp.name}", file=sys.stderr)
        
        # Count registered tools
        tools_count = len(self.mcp._tools) if hasattr(self.mcp, '_tools') else 0
        print(f"🔧 DEBUG: Registered tools count: {tools_count}", file=sys.stderr)
        
        if hasattr(self.mcp, '_tools'):
            print(f"🔧 DEBUG: Tool names: {list(self.mcp._tools.keys())[:5]}", file=sys.stderr)
        
        print("🔧 DEBUG: Starting mcp.run()...", file=sys.stderr)
        self.mcp.run()


if __name__ == "__main__":
    print("🔧 DEBUG: server.py __main__ starting", file=sys.stderr)
    server = NetworkSecurityServer()
    print("🔧 DEBUG: NetworkSecurityServer created", file=sys.stderr)
    server.run()
