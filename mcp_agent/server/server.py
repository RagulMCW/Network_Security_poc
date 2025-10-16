#!/usr/bin/env python3
"""
FastMCP Server for Network Security Monitoring
Simple server with 2 tools: analyze traffic and list devices
"""

import subprocess
import requests
from pathlib import Path
from datetime import datetime
from fastmcp import FastMCP


class NetworkSecurityServer:
    
    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent
        self.network_dir = self.project_root / "network"
        self.analyze_bat = self.network_dir / "analyze_auto.bat"
        self.flask_api = "http://192.168.6.131:5000"
        
        self.mcp = FastMCP(
            name="Network Security Monitor",
            instructions="""You are a network security assistant. 

When user asks about anomalies, threats, or attacks -> Use analyze_traffic
When user asks about devices or connections -> Use list_devices

Explain findings clearly."""
        )
        self._register_tools()
    
    def _register_tools(self):
        
        @self.mcp.tool
        def analyze_traffic() -> str:
            """Analyze network traffic for threats and anomalies"""
            return self._run_analyze_bat()
        
        @self.mcp.tool
        def list_devices() -> str:
            """List connected devices and their details"""
            return self._get_devices()

    
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
    
    def _get_devices(self) -> str:
        """Get connected devices from Flask API"""
        try:
            # Try to get devices from Flask API
            response = requests.get(f"{self.flask_api}/api/devices/list", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                devices = data.get('devices', [])
                
                if not devices:
                    return "No devices connected"
                
                # Format output
                result = f"CONNECTED DEVICES\n"
                result += f"Total: {data.get('total_devices', 0)} devices\n"
                result += f"Online: {data.get('online_devices', 0)} | Offline: {data.get('offline_devices', 0)}\n\n"
                
                for device in devices:
                    result += f"Device: {device.get('device_id', 'Unknown')}\n"
                    result += f"  Type: {device.get('device_type', 'N/A')}\n"
                    result += f"  IP: {device.get('ip_address', 'N/A')}\n"
                    result += f"  MAC: {device.get('mac_address', 'N/A')}\n"
                    result += f"  Status: {device.get('status', 'N/A')}\n"
                    result += f"  Last Seen: {device.get('last_seen', 'N/A')}\n"
                    result += "\n"
                
                return result
            else:
                return f"ERROR: API returned status {response.status_code}"
                
        except requests.exceptions.ConnectionError:
            return "ERROR: Cannot connect to device API. Is Flask server running at http://192.168.6.131:5000?"
        except requests.exceptions.Timeout:
            return "ERROR: API request timeout"
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def run(self):
        """Run the FastMCP server."""
        self.mcp.run()


if __name__ == "__main__":
    server = NetworkSecurityServer()
    server.run()
