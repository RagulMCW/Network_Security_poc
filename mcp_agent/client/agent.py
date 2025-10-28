#!/usr/bin/env python3
"""
Intelligent MCP Agent Client

Network Security Monitor - Uses AI to analyze packet captures and provide security insights.
"""

import asyncio
import json
import os
import sys
import subprocess
from typing import Dict, Any, List, Optional
from pathlib import Path

from fastmcp import Client
from anthropic import Anthropic

# Try to import dotenv, but don't fail if not available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # Environment variables can be set manually


class MCPAgent:
    """Network Security Monitor MCP agent for analyzing packet captures."""

    def __init__(self, server_path: Optional[str] = None, quiet: bool = False):
        """
        Initialize the MCP agent.

        Args:
            server_path: Path to the MCP server script. If None, uses default.
            quiet: Suppress verbose output
        """
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not self.anthropic_api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY environment variable not set. "
                "Please set it or add it to your .env file."
            )

        # Initialize clients
        self.anthropic_client = Anthropic(api_key=self.anthropic_api_key)

        # Quiet mode
        self.quiet = quiet

        # Default server path - relative to the client file
        if server_path is None:
            server_path = str(Path(__file__).parent.parent / "server" / "server.py")

        self.mcp_client = Client(server_path)

        if not self.quiet:
            print("Ready")

    def _load_available_tools(self):
        """Tools are loaded from server at runtime."""
        pass

    async def call_mcp_tool(self, tool_name: str, parameters: Optional[Dict[str, Any]] = None) -> str:
        """
        Call an MCP tool with given parameters.

        Args:
            tool_name: Name of the tool to call
            parameters: Optional parameters for the tool

        Returns:
            Tool execution result as string
        """
        try:
            async with self.mcp_client:
                result = None
                if parameters:
                    # Try different parameter passing approaches for FastMCP
                    try:
                        # Try with arguments keyword
                        result = await self.mcp_client.call_tool(tool_name, arguments=parameters)
                    except TypeError:
                        try:
                            # Try with parameters as second argument
                            result = await self.mcp_client.call_tool(tool_name, parameters)
                        except TypeError:
                            try:
                                # Try unpacking parameters as keyword arguments
                                result = await self.mcp_client.call_tool(tool_name, **parameters)
                            except TypeError as e:
                                raise TypeError(f"call_tool parameter passing failed: {e}")
                else:
                    result = await self.mcp_client.call_tool(tool_name)

                # Access the result data properly
                if hasattr(result, 'data'):
                    return str(result.data) if result.data is not None else "Tool returned no data"
                elif hasattr(result, 'content'):
                    return str(result.content)
                else:
                    return str(result)

        except Exception as e:
            return f"Error calling tool {tool_name}: {e}"

    async def decide_tool_calls(self, user_query: str) -> Dict[str, Any]:
        """
        Use glm-4.5 to decide which tools to call based on user query.
        Uses iterative tool calling like the GLM-only reference.

        Args:
            user_query: User's natural language query

        Returns:
            Dictionary with tool calls decision
        """
        try:
            # Build the complete prompt
            system_prompt = self._build_decision_prompt(user_query)

            # Call GLM-4.5 for decision
            # Note: Anthropic SDK versions differ; this tries the 'messages.create' pattern.
            response = self.anthropic_client.messages.create(
                model="glm-4.5",
                max_tokens=1024,
                temperature=0.1,
                system=self._build_system_prompt(),
                messages=[{"role": "user", "content": system_prompt}]
            )

            # Parse GLM's response - support a couple different response shapes
            glm_response = ""
            if hasattr(response, "content"):
                # some SDK shapes use response.content as list
                try:
                    glm_response = response.content[0].text
                except Exception:
                    # final fallback to string conversion
                    glm_response = str(response.content)
            else:
                glm_response = str(response)

            # Debug: Show what GLM decided
            if not self.quiet:
                print(f"GLM's raw response: {glm_response}")

            decision = self._parse_decision_response(glm_response)

            # Debug: Show parsed decision
            if not self.quiet:
                print(f"Parsed decision: {decision}")

            return decision

        except Exception as e:
            print(f"Error in decision making: {e}")
            # Fallback decision
            return {
                "reasoning": "Error in decision making, defaulting to list captures",
                "tool_calls": [{"tool_name": "list_packet_captures", "parameters": {}}]
            }

    def _build_decision_prompt(self, user_query: str) -> str:
        """Build network security analysis decision prompt."""
        return f"""You are a Network Security Analyst. Analyze packet captures to detect threats.

        AVAILABLE TOOLS:
        - analyze_traffic() - Analyze network traffic for threats
        - list_devices() - List connected devices

        USER QUERY: {user_query}

        INSTRUCTIONS:
        - If user asks to analyze: call analyze_traffic
        - If user asks about devices: call list_devices
        - Always take action immediately

        OUTPUT STRICTLY AS A SINGLE JSON OBJECT ONLY. NO PROSE. NO MARKDOWN.

        Response as JSON:
        {{
            "reasoning": "Brief explanation",
            "tool_calls": [
                {{
                    "tool_name": "tool_name",
                    "parameters": {{}}
                }}
            ]
        }}"""

    def _build_system_prompt(self) -> str:
        """System prompt for network security analysis."""
        return (
            "You are a Network Security Analyst AI.\n"
            "\n"
            "TOOLS:\n"
            "- analyze_traffic(): Analyze network traffic for threats\n"
            "- list_devices(): List connected devices\n"
            "\n"
            "Be concise. Focus on security. Explain findings clearly.\n"
        )

    def _parse_decision_response(self, claude_response: str) -> Dict[str, Any]:
        """Parse Claude's decision response."""
        try:
            # Find JSON in the response
            start_idx = claude_response.find('{')
            end_idx = claude_response.rfind('}') + 1
            json_str = claude_response[start_idx:end_idx]
            return json.loads(json_str)
        except Exception:
            # Fallback decision
            return {
                "reasoning": "Fallback to analyze traffic",
                "tool_calls": [{"tool_name": "analyze_traffic", "parameters": {}}]
            }

    async def execute_tool_calls(self, tool_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Execute the decided tool calls.

        Args:
            tool_calls: List of tool calls to execute

        Returns:
            List of execution results
        """
        results = []

        if not tool_calls:
            return results

        for tool_call in tool_calls:
            tool_name = tool_call.get("tool_name") or tool_call.get("tool") or ""
            parameters = tool_call.get("parameters", {}) or {}

            if not self.quiet:
                print(f"Calling tool: {tool_name} with parameters: {parameters}")
            result = await self.call_mcp_tool(tool_name, parameters)

            results.append({
                "tool": tool_name,
                "parameters": parameters,
                "result": result
            })

        return results

    def _generate_response(self, user_query: str, tool_results: List[Dict]) -> str:
        """
        Generate formatted response based on tool results.

        Args:
            user_query: Original user query
            tool_results: Results from tool execution

        Returns:
            Generated response string
        """
        if not tool_results:
            if any(word in user_query.lower() for word in ['tools', 'available', 'what can', 'help', 'capabilities']):
                return self._generate_tools_list_response()
            return "I can help analyze network traffic from packet captures. Try asking me to 'analyze latest capture' or 'list captures'."

        # Simply return the tool results
        response_parts = []
        for result in tool_results:
            tool_name = result.get("tool", "unknown")
            tool_result = result.get("result", "No result")
            response_parts.append(f"**{tool_name}**:\n{tool_result}")
        
        return "\n\n".join(response_parts)

    def _generate_tools_list_response(self) -> str:
        """Generate simple tools list response."""
        return """Available tools:
- analyze_traffic: Analyze network traffic
- list_devices: List connected devices"""

    async def process_query(self, user_query: str) -> str:
        """
        Process a user query - direct tool execution, no AI overhead.

        Args:
            user_query: User's natural language query

        Returns:
            Final response string
        """
        try:
            query_lower = user_query.lower()
            
            # === ANALYZE TRAFFIC - Main network security analysis ===
            if any(word in query_lower for word in ['analyze', 'traffic', 'threat', 'attack', 'security', 'network', 'status', 'summary']):
                if not self.quiet:
                    print("🔍 Analyzing network traffic from PCAP files...")
                
                # Read PCAP files directly with scapy
                captures_dir = r"E:\nos\Network_Security_poc\network\captures"
                
                try:
                    import os
                    files = [f for f in os.listdir(captures_dir) if f.endswith('.pcap')]
                    
                    if not files:
                        return "❌ No PCAP files found. Start network monitoring first."
                    
                    # Get last 3 PCAP files
                    sorted_files = sorted(files)
                    last_3_files = sorted_files[-3:] if len(sorted_files) >= 3 else sorted_files
                    
                    try:
                        from scapy.all import rdpcap, IP, TCP, UDP, ARP, Ether
                        
                        total_packets = 0
                        all_src_ips = {}
                        all_dst_ips = {}
                        all_devices = {}  # Track MAC -> IP mappings
                        protocols = {'TCP': 0, 'UDP': 0, 'ARP': 0, 'Other': 0}
                        tcp_ports = {}
                        udp_ports = {}
                        ip_port_access = {}  # Track which IPs access which ports (for port scan detection)
                        
                        for pcap_file in last_3_files:
                            file_path = os.path.join(captures_dir, pcap_file)
                            file_size = os.path.getsize(file_path)
                            
                            if file_size > 0:
                                try:
                                    packets = rdpcap(file_path)
                                    total_packets += len(packets)
                                    
                                    for pkt in packets:
                                        # Extract device info from Ethernet layer
                                        if Ether in pkt:
                                            mac_src = pkt[Ether].src
                                            mac_dst = pkt[Ether].dst
                                            
                                            if IP in pkt:
                                                ip_src = pkt[IP].src
                                                ip_dst = pkt[IP].dst
                                                
                                                # Track devices (MAC -> IP mapping)
                                                if mac_src not in all_devices:
                                                    all_devices[mac_src] = {'ips': set(), 'packets_sent': 0, 'packets_received': 0}
                                                all_devices[mac_src]['ips'].add(ip_src)
                                                all_devices[mac_src]['packets_sent'] += 1
                                                
                                                if mac_dst not in all_devices:
                                                    all_devices[mac_dst] = {'ips': set(), 'packets_sent': 0, 'packets_received': 0}
                                                all_devices[mac_dst]['ips'].add(ip_dst)
                                                all_devices[mac_dst]['packets_received'] += 1
                                                
                                                # Track IP traffic
                                                all_src_ips[ip_src] = all_src_ips.get(ip_src, 0) + 1
                                                all_dst_ips[ip_dst] = all_dst_ips.get(ip_dst, 0) + 1
                                                
                                                # Track protocols and ports
                                                if TCP in pkt:
                                                    protocols['TCP'] += 1
                                                    dst_port = pkt[TCP].dport
                                                    tcp_ports[dst_port] = tcp_ports.get(dst_port, 0) + 1
                                                    
                                                    # Track ports accessed by each IP (for port scan detection)
                                                    if ip_src not in ip_port_access:
                                                        ip_port_access[ip_src] = set()
                                                    ip_port_access[ip_src].add(dst_port)
                                                    
                                                elif UDP in pkt:
                                                    protocols['UDP'] += 1
                                                    dst_port = pkt[UDP].dport
                                                    udp_ports[dst_port] = udp_ports.get(dst_port, 0) + 1
                                                    
                                                    # Track UDP ports per IP too
                                                    if ip_src not in ip_port_access:
                                                        ip_port_access[ip_src] = set()
                                                    ip_port_access[ip_src].add(f"UDP:{dst_port}")
                                                    
                                                else:
                                                    protocols['Other'] += 1
                                        
                                        # Count ARP packets
                                        if ARP in pkt:
                                            protocols['ARP'] += 1
                                            
                                except Exception as e:
                                    if not self.quiet:
                                        print(f"⚠️ Error reading {pcap_file}: {e}")
                        
                        if total_packets == 0:
                            return "⚠️ PCAP files found but contain no packets. Network monitoring may not be working."
                        
                        # Build comprehensive analysis report
                        analysis_data = f"📊 NETWORK TRAFFIC ANALYSIS\n"
                        analysis_data += "=" * 70 + "\n"
                        analysis_data += f"Analyzed Files: {', '.join(last_3_files)}\n"
                        analysis_data += f"Total Packets Captured: {total_packets}\n"
                        analysis_data += f"Unique Devices Detected: {len(all_devices)}\n"
                        analysis_data += f"Unique Source IPs: {len(all_src_ips)}\n"
                        analysis_data += f"Unique Destination IPs: {len(all_dst_ips)}\n"
                        analysis_data += "=" * 70 + "\n\n"
                        
                        # Get network information for each IP using Docker
                        def get_device_network(ip_addr):
                            """Determine which network an IP belongs to"""
                            try:
                                # Check if IP is in custom_net range (192.168.6.x)
                                if ip_addr.startswith('192.168.6.'):
                                    # Query Docker to see if container is actually in honeypot
                                    inspect_cmd = f'docker ps --format "{{{{.Names}}}}"'
                                    result = subprocess.run(['wsl', 'bash', '-c', inspect_cmd], 
                                                          capture_output=True, text=True, timeout=5)
                                    
                                    for container in result.stdout.strip().split('\n'):
                                        if not container:
                                            continue
                                        # Get container IP
                                        ip_cmd = f'docker inspect {container} --format "{{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}"'
                                        ip_result = subprocess.run(['wsl', 'bash', '-c', ip_cmd],
                                                                  capture_output=True, text=True, timeout=5)
                                        if ip_addr in ip_result.stdout:
                                            # Check which network
                                            net_cmd = f'docker inspect {container} --format "{{{{json .NetworkSettings.Networks}}}}"'
                                            net_result = subprocess.run(['wsl', 'bash', '-c', net_cmd],
                                                                       capture_output=True, text=True, timeout=5)
                                            if 'honeypot_net' in net_result.stdout:
                                                return 'honeypot_net', container
                                            elif 'custom_net' in net_result.stdout:
                                                return 'custom_net', container
                                    return 'custom_net', 'unknown'
                                elif ip_addr.startswith('192.168.7.'):
                                    return 'honeypot_net', 'unknown'
                                else:
                                    return 'unknown', 'unknown'
                            except:
                                return 'unknown', 'unknown'
                        
                        # Separate devices by network
                        production_devices = []
                        honeypot_devices = []
                        
                        if all_devices:
                            for mac, info in all_devices.items():
                                ips = list(info['ips'])
                                if ips:
                                    ip = ips[0]
                                    network, container = get_device_network(ip)
                                    device_data = {
                                        'mac': mac,
                                        'ip': ip,
                                        'container': container,
                                        'packets_sent': info['packets_sent'],
                                        'packets_received': info['packets_received']
                                    }
                                    
                                    if network == 'honeypot_net':
                                        honeypot_devices.append(device_data)
                                    else:
                                        production_devices.append(device_data)
                        
                        # Display Production Network Devices
                        analysis_data += "🌐 PRODUCTION NETWORK (custom_net - 192.168.6.0/24):\n"
                        if production_devices:
                            for idx, dev in enumerate(production_devices, 1):
                                analysis_data += f"   ├─ Node {idx}: {dev['container'] if dev['container'] != 'unknown' else 'Device'}\n"
                                analysis_data += f"   │  ├─ IP Address: {dev['ip']}\n"
                                analysis_data += f"   │  ├─ MAC Address: {dev['mac']}\n"
                                analysis_data += f"   │  ├─ Packets Sent: {dev['packets_sent']}\n"
                                analysis_data += f"   │  └─ Packets Received: {dev['packets_received']}\n"
                                if idx < len(production_devices):
                                    analysis_data += "   │\n"
                        else:
                            analysis_data += "   └─ No active devices\n"
                        analysis_data += "\n"
                        
                        # Display Honeypot Network Devices
                        analysis_data += "🍯 HONEYPOT NETWORK (honeypot_net - 192.168.7.0/24):\n"
                        if honeypot_devices:
                            for idx, dev in enumerate(honeypot_devices, 1):
                                analysis_data += f"   ├─ ⚠️  ISOLATED Node {idx}: {dev['container'] if dev['container'] != 'unknown' else 'Device'}\n"
                                analysis_data += f"   │  ├─ IP Address: {dev['ip']}\n"
                                analysis_data += f"   │  ├─ MAC Address: {dev['mac']}\n"
                                analysis_data += f"   │  ├─ Packets Sent: {dev['packets_sent']}\n"
                                analysis_data += f"   │  └─ Packets Received: {dev['packets_received']}\n"
                                if idx < len(honeypot_devices):
                                    analysis_data += "   │\n"
                        else:
                            analysis_data += "   └─ No isolated devices (network secure)\n"
                        analysis_data += "\n"
                        
                        # Protocol Distribution
                        analysis_data += "📡 PROTOCOL DISTRIBUTION:\n"
                        for proto, count in protocols.items():
                            if count > 0:
                                pct = (count / total_packets * 100)
                                analysis_data += f"   {proto:8s}: {count:6d} packets ({pct:5.1f}%)\n"
                        analysis_data += "\n"
                        
                        # Top Source IPs
                        analysis_data += "📤 TOP SOURCE IPs (Most Active):\n"
                        sorted_srcs = sorted(all_src_ips.items(), key=lambda x: x[1], reverse=True)[:10]
                        for ip, count in sorted_srcs:
                            pct = (count / total_packets * 100)
                            analysis_data += f"   {ip:15s}: {count:6d} packets ({pct:5.1f}%)\n"
                        analysis_data += "\n"
                        
                        # Top Destination IPs
                        analysis_data += "📥 TOP DESTINATION IPs:\n"
                        sorted_dsts = sorted(all_dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]
                        for ip, count in sorted_dsts:
                            pct = (count / total_packets * 100)
                            analysis_data += f"   {ip:15s}: {count:6d} packets ({pct:5.1f}%)\n"
                        analysis_data += "\n"
                        
                        # Top TCP Ports
                        if tcp_ports:
                            analysis_data += "🔌 TOP TCP PORTS:\n"
                            sorted_tcp = sorted(tcp_ports.items(), key=lambda x: x[1], reverse=True)[:5]
                            for port, count in sorted_tcp:
                                analysis_data += f"   Port {port:5d}: {count:6d} packets\n"
                            analysis_data += "\n"
                        
                        # Top UDP Ports
                        if udp_ports:
                            analysis_data += "🔌 TOP UDP PORTS:\n"
                            sorted_udp = sorted(udp_ports.items(), key=lambda x: x[1], reverse=True)[:5]
                            for port, count in sorted_udp:
                                analysis_data += f"   Port {port:5d}: {count:6d} packets\n"
                            analysis_data += "\n"
                        
                        # Security Analysis with REALISTIC Threat Detection
                        analysis_data += "🛡️  SECURITY THREAT ANALYSIS:\n"
                        threats_detected = []
                        critical_threats = []
                        devices_to_isolate = []  # Track devices for auto-isolation
                        
                        # Define known servers to EXCLUDE from attack detection
                        SERVER_IPS = ['192.168.6.131']  # net-monitor-wan server
                        
                        # Calculate average packets per device (excluding server)
                        device_ips = {ip: count for ip, count in all_src_ips.items() if ip not in SERVER_IPS}
                        avg_packets = sum(device_ips.values()) / len(device_ips) if device_ips else 0
                        
                        # REALISTIC DoS/DDoS Detection for 30 seconds of traffic (3 PCAP files @ 10s each)
                        # Normal device HTTP traffic: 20-150 packets per 30 seconds
                        # DoS Attack Volume: >1500 packets in 30s (50 packets/second) = FLOODING
                        # CRITICAL DoS: >3000 packets in 30s (100 packets/second) = MASSIVE FLOOD
                        for src_ip, src_count in sorted_srcs[:10]:
                            # Skip the server itself - it's supposed to handle lots of traffic
                            if src_ip in SERVER_IPS:
                                continue
                            
                            pct_of_traffic = (src_count / total_packets * 100)
                            
                            if src_count > 3000 or pct_of_traffic > 70:
                                threat_level = "🔴 CRITICAL THREAT"
                                analysis_data += f"\n   {threat_level}: DoS/DDoS ATTACK from {src_ip}\n"
                                analysis_data += f"      → Packet Volume: {src_count:,} packets in 30 seconds ({pct_of_traffic:.1f}% of traffic)\n"
                                analysis_data += f"      → Attack Rate: ~{src_count//30} packets/second (FLOODING!)\n"
                                analysis_data += f"      → Attack Type: Volume-based DoS overwhelming network bandwidth\n"
                                analysis_data += f"      → Impact: CRITICAL - Network severely degraded\n"
                                analysis_data += f"      → AUTO-ACTION: Isolating {src_ip} to honeypot NOW!\n"
                                threats_detected.append(f"CRITICAL DoS Attack from {src_ip} ({src_count:,} packets)")
                                critical_threats.append(src_ip)
                                devices_to_isolate.append(src_ip)
                                
                            elif src_count > 1500 or pct_of_traffic > 60:
                                threat_level = "🟠 HIGH THREAT"
                                analysis_data += f"\n   {threat_level}: Suspicious flooding from {src_ip}\n"
                                analysis_data += f"      → Packet Volume: {src_count:,} packets in 30 seconds ({pct_of_traffic:.1f}% of traffic)\n"
                                analysis_data += f"      → Attack Rate: ~{src_count//30} packets/second\n"
                                analysis_data += f"      → Likely: DoS attempt or compromised device\n"
                                analysis_data += f"      → AUTO-ACTION: Isolating {src_ip} to honeypot\n"
                                threats_detected.append(f"HIGH: Possible DoS from {src_ip} ({src_count:,} packets)")
                                devices_to_isolate.append(src_ip)
                        
                        # Check for port scanning (reconnaissance attack)
                        # Port scan = ONE IP accessing MANY different ports (>20)
                        port_scanners = []
                        for src_ip, ports_accessed in ip_port_access.items():
                            if src_ip not in SERVER_IPS and len(ports_accessed) > 20:
                                port_scanners.append((src_ip, len(ports_accessed)))
                        
                        if port_scanners:
                            for scanner_ip, port_count in port_scanners:
                                analysis_data += f"\n   🔴 CRITICAL: PORT SCANNING ATTACK from {scanner_ip}!\n"
                                analysis_data += f"      → Scanned Ports: {port_count} unique ports accessed\n"
                                analysis_data += f"      → Attack Phase: Reconnaissance (mapping vulnerabilities)\n"
                                analysis_data += f"      → Next Expected: Exploitation attempts on found services\n"
                                analysis_data += f"      → AUTO-ACTION: Isolating {scanner_ip} to honeypot\n"
                                threats_detected.append(f"Port Scanning Attack from {scanner_ip} ({port_count} ports)")
                                critical_threats.append(scanner_ip)
                                devices_to_isolate.append(scanner_ip)
                        
                        # Check for brute-force attacks
                        suspicious_ports = {
                            22: 'SSH', 23: 'Telnet', 3389: 'RDP', 
                            445: 'SMB', 3306: 'MySQL', 5432: 'PostgreSQL',
                            21: 'FTP', 25: 'SMTP'
                        }
                        for port, port_name in suspicious_ports.items():
                            if port in tcp_ports and tcp_ports[port] > 10:
                                analysis_data += f"\n   � HIGH THREAT: {port_name} BRUTE-FORCE ATTACK\n"
                                analysis_data += f"      → Connection Attempts: {tcp_ports[port]} on port {port}\n"
                                analysis_data += f"      → Attack Type: Password cracking / unauthorized access\n"
                                analysis_data += f"      → Risk: Credential compromise, system takeover\n"
                                analysis_data += f"      → ACTION: Enable fail2ban, enforce MFA, review logs\n"
                                threats_detected.append(f"{port_name} Brute-force Attack ({tcp_ports[port]} attempts)")
                        
                        # Check for unusual protocol distribution (malware C2)
                        if protocols.get('Other', 0) > (total_packets * 0.2):
                            analysis_data += f"\n   🟡 WARNING: Unusual protocol distribution\n"
                            analysis_data += f"      → Unknown Protocols: {protocols['Other']} packets ({protocols['Other']/total_packets*100:.1f}%)\n"
                            analysis_data += f"      → Possible: Malware C2 channels, covert tunnels\n"
                            analysis_data += f"      → ACTION: Deep packet inspection, endpoint scan\n"
                            threats_detected.append(f"Unusual Protocol Usage ({protocols['Other']} packets)")
                        
                        # Summary
                        if not threats_detected:
                            analysis_data += "\n   ✅ No security threats detected\n"
                            analysis_data += "   ✅ Network traffic appears normal\n"
                        else:
                            analysis_data += f"\n{'='*70}\n"
                            analysis_data += f"⚠️  TOTAL THREATS DETECTED: {len(threats_detected)}\n"
                            if critical_threats:
                                analysis_data += f"🔴 CRITICAL THREATS: {len(critical_threats)} (Immediate action required!)\n"
                            analysis_data += f"{'='*70}\n"
                        
                        analysis_data += "\n" + "=" * 70 + "\n"
                        
                        # Send to GLM for AI summary with STRICT cybersecurity expert prompt
                        try:
                            # Build threat context for AI
                            threat_context = ""
                            if threats_detected:
                                threat_context = (
                                    "⚠️⚠️⚠️ CRITICAL INSTRUCTION ⚠️⚠️⚠️\n"
                                    f"The automated analysis has detected {len(threats_detected)} SECURITY THREATS.\n"
                                    "You MUST classify these as ATTACKS, not 'normal communication'.\n"
                                    "DO NOT dismiss or downplay these threats.\n"
                                    "These are MALICIOUS activities that require immediate action.\n\n"
                                    "DETECTED THREATS:\n"
                                )
                                for threat in threats_detected:
                                    threat_context += f"  - {threat}\n"
                                threat_context += "\n"
                            
                            ai_prompt = (
                                "🔒 YOU ARE AN EXPERT NETWORK SECURITY ANALYST 🔒\n\n"
                                f"{threat_context}"
                                "ANALYSIS GUIDELINES:\n"
                                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                                "✅ Normal Traffic (30 seconds): 20-150 packets per device (HTTP/API)\n"
                                "🟠 Suspicious: >1500 packets in 30s = 50 packets/second (Flooding)\n"
                                "🔴 CRITICAL DoS: >3000 packets in 30s = 100 packets/second (Attack!)\n"
                                "🔴 Port Scan: ONE IP accessing >20 different ports\n"
                                "🔴 Brute-force: >10 failed authentication attempts\n"
                                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                                "📋 YOUR REPORT FORMAT:\n\n"
                                "**THREAT LEVEL:** [CRITICAL/HIGH/MEDIUM/LOW/NONE]\n\n"
                                "**🎯 NETWORK STATUS:**\n"
                                "- If NO threats detected: Describe normal network activity professionally\n"
                                "- If threats detected: Identify attack type and explain clearly\n\n"
                                "**🛡️ ANALYSIS:**\n"
                                "- Explain what you see in the traffic data\n"
                                "- If malicious IPs found: List them with packet counts and attack rate\n"
                                "- If normal: Explain why the traffic is legitimate\n\n"
                                "**⏱️ RECOMMENDED ACTIONS:**\n"
                                "- If CRITICAL: Immediate isolation to honeypot (auto-executed)\n"
                                "- If HIGH: Investigation and monitoring\n"
                                "- If NONE: Continue normal monitoring\n\n"
                                "Remember: 192.168.6.131 is the SERVER, not a device. Server traffic is expected.\n"
                                "Be professional and accurate. Only flag REAL attacks (>1500 packets/30s).\n\n"
                                f"{analysis_data}\n"
                                """"""
                            )
                            
                            response = self.anthropic_client.messages.create(
                                model="claude-3-5-sonnet-20241022",
                                max_tokens=2048,
                                temperature=0.1,  # Lower temperature for more consistent strict analysis
                                messages=[{"role": "user", "content": ai_prompt}]
                            )
                            
                            ai_summary = response.content[0].text
                            
                            # AUTO-ISOLATE malicious devices to honeypot using MCP tool
                            isolation_results = []
                            if devices_to_isolate:
                                if not self.quiet:
                                    print(f"\n🚨 AUTO-ISOLATING {len(devices_to_isolate)} malicious device(s) using MCP tool...")
                                
                                for malicious_ip in devices_to_isolate:
                                    try:
                                        # Find container name from IP
                                        inspect_cmd = f'docker ps --format "{{{{.Names}}}}"'
                                        containers = subprocess.run(['wsl', 'bash', '-c', inspect_cmd], 
                                                                  capture_output=True, text=True, timeout=10).stdout.strip().split('\n')
                                        
                                        container_found = None
                                        for container in containers:
                                            if not container or 'monitor' in container or 'beelzebub' in container:
                                                continue
                                            
                                            # Get container IP
                                            ip_cmd = f'docker inspect {container} --format "{{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}"'
                                            container_ip = subprocess.run(['wsl', 'bash', '-c', ip_cmd],
                                                                        capture_output=True, text=True, timeout=10).stdout.strip()
                                            
                                            if malicious_ip in container_ip:
                                                container_found = container
                                                break
                                        
                                        if container_found:
                                            # Use MCP tool to isolate device
                                            isolation_msg = f"🚨 Calling MCP tool: move_device_to_honeypot({container_found}, 'DoS Attack Detected')"
                                            if not self.quiet:
                                                print(isolation_msg)
                                            
                                            # Extract device_id (e.g., 'vdevice_001' -> 'device_001' or keep as is)
                                            device_id = container_found  # MCP tool handles both formats
                                            
                                            # Call MCP tool for isolation
                                            mcp_result = await self.call_mcp_tool(
                                                "move_device_to_honeypot",
                                                {"device_id": device_id, "reason": f"DoS Attack from {malicious_ip}"}
                                            )
                                            
                                            isolation_results.append(f"✅ MCP Tool Result: {mcp_result}")
                                        else:
                                            isolation_results.append(f"⚠️ Container not found for IP {malicious_ip}")
                                    
                                    except Exception as iso_error:
                                        isolation_results.append(f"❌ Failed to isolate {malicious_ip}: {str(iso_error)}")
                            
                            # Add threat summary at top
                            if threats_detected:
                                threat_summary = " " + "=" * 68 + "\n"
                                threat_summary += " ⚠️  SECURITY ALERT: ACTIVE ATTACK DETECTED! ⚠️  \n"
                                threat_summary += " " + "=" * 68 + "\n"
                                for threat in threats_detected:
                                    threat_summary += f"   💀 {threat}\n"
                                threat_summary += " " + "=" * 68 + "\n\n"
                                
                                # Add isolation results if any
                                if isolation_results:
                                    threat_summary += "🛡️ AUTO-ISOLATION ACTIONS TAKEN:\n"
                                    for result in isolation_results:
                                        threat_summary += f"   {result}\n"
                                    threat_summary += "\n"
                                
                                return f"{threat_summary}🤖 CYBERSECURITY ANALYST REPORT:\n\n{ai_summary}\n\n📊 RAW TRAFFIC DATA:\n{analysis_data}"
                            else:
                                return f"🤖 CYBERSECURITY ANALYST REPORT:\n\n{ai_summary}\n\n📊 RAW TRAFFIC DATA:\n{analysis_data}"
                            
                        except Exception as e:
                            # If AI fails, just return the detailed analysis
                            return f"⚠️ AI analysis unavailable: {str(e)}\n\n{analysis_data}"
                        
                    except ImportError:
                        return "❌ Scapy library not installed.\n\nInstall with: pip install scapy"
                    
                except Exception as e:
                    return f"❌ Error analyzing traffic: {str(e)}"
            
            # === HELP / UNKNOWN COMMANDS ===
            else:
                return (
                    "🤖 Network Security AI Agent\n\n"
                    "Available commands:\n"
                    "  • analyze / analyze traffic - Full network analysis with device info\n"
                    "  • status - Current network status\n"
                    "  • security - Security assessment\n\n"
                    "Just type naturally and I'll analyze your network!"
                )
                
        except Exception as e:
            error_msg = f"Error: {e}"
            if not self.quiet:
                print(error_msg)
            return error_msg

    def _format_conversation_for_glm(self, conversation_history: List[Dict]) -> List[Dict[str, Any]]:
        """Format conversation history for GLM API."""
        messages = []
        
        for entry in conversation_history:
            if entry["role"] in ["user", "assistant"]:
                message = {
                    "role": entry["role"],
                    "content": entry["content"]
                }
                messages.append(message)
        
        return messages
    
    def _get_anthropic_tools(self) -> list:
        """Convert MCP tools to Anthropic tools format."""
        return [
                {
                    "name": "analyze_traffic",
                    "description": "Summarize the latest network analysis output. Report how many devices are connected, highlight any problems or intrusions detected, identify which IPs carry the most packets, and provide a clear, concise answer as a network security and observability agent. Respond in plain language for non-technical users.",
                    "input_schema": {
                        "type": "object",
                        "properties": {}
                    }
                },
                {
                    "name": "list_devices",
                    "description": "List all devices currently connected to the network. Include device names, types, and any relevant details in a way that's easy to understand.",
                    "input_schema": {
                        "type": "object",
                        "properties": {}
                    }
                },
                # ...existing code...
            ]
        
        return anthropic_tools

    async def chat_loop(self):
        """Main interactive chat loop."""
        if not self.quiet:
            print("Network Security Agent")
            print("=" * 40)
            print("Commands: analyze | status | security | quit")
            print("=" * 40)

        while True:
            try:
                user_query = input("\nYou: ").strip()

                if user_query.lower() in ['quit', 'exit', 'bye']:
                    print("Goodbye!")
                    break

                if not user_query:
                    continue

                # Process the query
                response = await self.process_query(user_query)
                print(f"\n{response}")

            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except Exception as e:
                print(f"\nError: {e}")


async def main():
    """Main function."""
    if len(sys.argv) > 1 and sys.argv[1] in ["--help", "-h"]:
        print("Usage: python agent.py")
        print("Environment: Set ANTHROPIC_API_KEY for Claude model access")
        print("\nThis creates an intelligent MCP agent that uses Claude to:")
        print("  • Understand your natural language queries")
        print("  • Decide which MCP tools to call")
        print("  • Execute the tools automatically")
        print("  • Provide intelligent responses based on the results")
        return

    try:
        # QUIET mode from environment toggles tool-only concise output
        quiet = os.getenv("MCP_AGENT_QUIET", "0") == "1"
        agent = MCPAgent(quiet=quiet)
        await agent.chat_loop()
    except ValueError as e:
        print(f"Configuration Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
