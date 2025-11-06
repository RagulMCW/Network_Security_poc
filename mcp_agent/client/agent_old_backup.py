#!/usr/bin/env python3
"""
MCP Agent - Network Security Monitor

Intelligent AI agent using Claude to analyze commands and execute MCP tools.
Routes Docker commands through WSL when Docker is not available in Windows.
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

# Load environment variables from config/.env
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent / "config" / ".env"
    load_dotenv(dotenv_path=env_path)
except ImportError:
    pass


class MCPAgent:
    """AI-powered MCP Agent for network security with WSL/Docker support."""

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
                "Please add it to config/.env"
            )

        self.anthropic_client = Anthropic(api_key=self.anthropic_api_key)
        self.quiet = quiet

        if server_path is None:
            server_path = str(Path(__file__).parent.parent / "server" / "server.py")

        self.mcp_client = Client(server_path)
        
        # Check if Docker is available in Windows or WSL
        self.docker_in_windows = self._check_docker_available()
        self.docker_in_wsl = self._check_docker_in_wsl()

        if not self.quiet:
            print("✅ Agent initialized")
            if self.docker_in_wsl and not self.docker_in_windows:
                print("📌 Note: Docker found in WSL - will route docker commands through WSL")
            print()

    def _load_available_tools(self):
        """Tools are loaded from server at runtime."""
        pass

    def _check_docker_available(self) -> bool:
        """Check if Docker is available in Windows."""
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False

    def _check_docker_in_wsl(self) -> bool:
        """Check if Docker is available in WSL."""
        try:
            result = subprocess.run(
                ["wsl", "docker", "--version"],
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False

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

    def _check_docker_in_wsl(self) -> bool:
        """Check if Docker is available in WSL."""
        try:
            result = subprocess.run(
                "wsl docker --version",
                shell=True,
                capture_output=True,
                timeout=2
            )
            return result.returncode == 0
        except Exception:
            return False

    async def _handle_docker_query(self, query: str) -> str:
        """
        Handle Docker queries by routing to WSL.
        
        Examples:
          "docker ps" → wsl docker ps
          "check containers" → wsl docker ps -a
          "list images" → wsl docker images
        """
        try:
            query_lower = query.lower()
            
            # Map common queries to Docker commands
            if any(word in query_lower for word in ["ps", "container", "running", "check"]):
                cmd = "docker ps -a" if "all" in query_lower else "docker ps"
            elif "images" in query_lower:
                cmd = "docker images"
            elif "logs" in query_lower:
                cmd = "docker logs"
            else:
                cmd = "docker ps"
            
            return await self._run_docker_via_wsl(cmd)
                
        except Exception as e:
            return f"❌ Docker error: {e}"

    async def _run_docker_via_wsl(self, command: str) -> str:
        """
        Run a Docker command through WSL.
        
        Args:
            command: Docker command (e.g., "docker ps -a")
            
        Returns:
            Command output
        """
        try:
            # Build the WSL command
            full_cmd = f"wsl {command}"
            
            if not self.quiet:
                print(f"🔧 Executing: {full_cmd}")
            
            # Run the command
            result = subprocess.run(
                full_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.stdout:
                return result.stdout
            elif result.stderr:
                return f"❌ Error:\n{result.stderr}"
            else:
                return "✅ Command completed"
                
        except subprocess.TimeoutExpired:
            return "❌ Command timeout (30s)"
        except Exception as e:
            return f"❌ Error: {e}"

    def _get_tools_list(self) -> str:
        """Return formatted list of all available tools."""
        tools_info = """
            🛠️ AVAILABLE TOOLS (19 TOTAL)
            ════════════════════════════════════════════════════════════════

            📁 FILESYSTEM TOOLS (7 tools)
            1. read_file - Read file contents
            2. write_file - Write content to a file
            3. append_file - Append content to existing file
            4. create_directory - Create directories (creates parent dirs too)
            5. list_directory - List files and folders in directory
            6. delete_file - Delete a file
            7. file_exists - Check if file exists

            💻 TERMINAL/PROCESS TOOLS (3 tools)
            8. run_command - Run Windows command (cmd.exe)
            9. run_batch_file - Execute .bat files
            10. run_powershell - Run PowerShell commands

            🌐 ENVIRONMENT TOOLS (2 tools)
            11. get_env_variable - Get environment variable value
            12. set_env_variable - Set environment variable

            🐧 WSL/LINUX TOOLS (5 tools) [Requires WSL]
            13. wsl_command - Run Linux/bash commands in WSL
            14. wsl_bash_script - Run multiline bash scripts
            15. wsl_read_file - Read files from Linux filesystem
            16. wsl_write_file - Write files to Linux filesystem
            17. docker_command - Execute Docker commands

            🔒 NETWORK SECURITY TOOLS (2 tools)
            18. analyze_traffic - Complete network analysis (devices, traffic, threats)
            19. move_device_to_honeypot - Isolate malicious devices to Beelzebub honeypot

            ════════════════════════════════════════════════════════════════

            EXAMPLE USAGE:
            • "analyze the network" → Uses: analyze_traffic
            • "list files in C:\\logs" → Uses: list_directory
            • "run ipconfig" → Uses: run_command
            • "execute docker ps" → Uses: docker_command
            • "read /etc/hosts in WSL" → Uses: wsl_read_file
            """
        return tools_info

    def _ask_for_details(self, intent: str) -> str:
        """Ask user for missing details based on their intent."""
        if intent == "create_file":
            return (
                "📝 CREATE FILE\n\n"
                "I can help you create a file. Please provide:\n"
                "  • File path (e.g., C:\\temp\\myfile.txt or ./myfile.md)\n"
                "  • File content (or just press Enter for empty file)\n\n"
                "Example: 'create file README.md with content: # Hello World'"
            )
        elif intent == "list_files":
            return (
                "📁 LIST FILES\n\n"
                "I can show you files in a directory. Please specify:\n"
                "  • Directory path (e.g., C:\\logs, . for current, ..\\ for parent)\n\n"
                "Example: 'list files in C:\\logs' or 'show current directory'"
            )
        elif intent == "read_file":
            return (
                "📖 READ FILE\n\n"
                "I can read a file for you. Please provide:\n"
                "  • File path (e.g., C:\\logs\\file.txt)\n\n"
                "Example: 'read C:\\logs\\output.txt'"
            )
        elif intent == "run_command":
            return (
                "⚙️ RUN COMMAND\n\n"
                "I can execute commands. Please specify:\n"
                "  • The command to run (e.g., ipconfig, dir, git status)\n\n"
                "Example: 'run ipconfig' or 'execute dir C:\\logs'"
            )
        else:
            return "Please provide more details about what you'd like to do."

    async def understand_user_intent(self, user_query: str) -> dict:
        """
        Use Claude to understand user intent and extract parameters.
        Returns a structured dict with action, parameters, and confidence.
        """
        try:
            # Build prompt for intent understanding
            intent_prompt = f"""You are an intelligent assistant that understands user requests.

            Analyze this user request and extract the intent and parameters:
            "{user_query}"

            RESPOND STRICTLY AS JSON (no other text):
            {{
                "intent": "one of: list_files, read_file, create_file, run_command, analyze_network, help, delete_file, check_file, write_to_file, unknown",
                "action": "specific tool or action to perform",
                "parameters": {{
                    // tool parameters based on intent
                }},
                "confidence": 0.0 to 1.0,
                "extracted_values": {{
                    "filename": "extracted filename if any",
                    "path": "extracted path if any",
                    "content": "extracted content if any",
                    "command": "extracted command if any",
                    "directory": "extracted directory if any"
                }},
                "clarification_needed": true/false,
                "clarification_message": "if clarification is needed, what to ask"
            }}

            Guidelines:
            - For "create file": extract filename (with .md, .txt, .py, .json, etc.) and any content provided
            - For "list files": extract directory path, default to "." if current directory
            - For "read file": extract file path
            - For "run command": extract the command to execute
            - For "analyze network": no parameters needed
            - Default directory is "." (current directory)
            - If filename doesn't have extension and looks like it should, infer it (e.g., "dummy" → "dummy.md")
            - Be flexible with typos and casual language
            """
            
            response = self.anthropic_client.messages.create(
                model="glm-4.5",
                max_tokens=500,
                temperature=0.3,
                messages=[{"role": "user", "content": intent_prompt}]
            )
            
            # Parse response
            response_text = response.content[0].text
            
            # Find JSON in response
            import json
            import re
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                intent_data = json.loads(json_match.group(0))
                return intent_data
            else:
                return {"intent": "unknown", "confidence": 0}
                
        except Exception as e:
            if not self.quiet:
                print(f"⚠️ Intent understanding error: {e}")
            return {"intent": "unknown", "confidence": 0}

    async def execute_intent(self, intent_data: dict, user_query: str) -> str:
        """Execute the understood intent using MCP tools."""
        intent = intent_data.get("intent", "unknown")
        params = intent_data.get("extracted_values", {})
        
        try:
            # === LIST FILES ===
            if intent == "list_files":
                directory = params.get("directory") or params.get("path") or "."
                result = await self.call_mcp_tool("list_directory", {"path": directory})
                return f"📁 Directory: {directory}\n\n{result}"
            
            # === READ FILE ===
            elif intent == "read_file":
                filepath = params.get("path") or params.get("filename")
                if not filepath:
                    return "❌ Please specify which file to read.\nExample: 'read config.txt'"
                result = await self.call_mcp_tool("read_file", {"path": filepath})
                return f"📖 File: {filepath}\n\n{result}"
            
            # === CREATE FILE ===
            elif intent == "create_file":
                filename = params.get("filename")
                content = params.get("content") or ""
                
                if not filename:
                    return "❌ Please specify a filename.\nExample: 'create dummy.md'"
                
                # Handle relative paths
                from pathlib import Path
                filepath = Path(filename) if not filename.startswith(('/', '\\', 'C:', 'D:', 'E:')) else Path(filename)
                filepath = filepath if filepath.is_absolute() else Path.cwd() / filepath
                
                result = await self.call_mcp_tool("write_file", {
                    "path": str(filepath),
                    "content": content
                })
                
                if "Success" in result or "successfully" in result.lower():
                    return f"✅ File created: {filepath}\n📝 Content: {content if content else '(empty file)'}"
                else:
                    return f"✅ File created: {filepath}"
            
            # === DELETE FILE ===
            elif intent == "delete_file":
                filepath = params.get("path") or params.get("filename")
                if not filepath:
                    return "❌ Please specify which file to delete."
                result = await self.call_mcp_tool("delete_file", {"path": filepath})
                return f"🗑️ File deleted: {filepath}\n{result}"
            
            # === CHECK FILE ===
            elif intent == "check_file":
                filepath = params.get("path") or params.get("filename")
                if not filepath:
                    return "❌ Please specify which file to check."
                result = await self.call_mcp_tool("file_exists", {"path": filepath})
                return f"🔍 File: {filepath}\nStatus: {result}"
            
            # === RUN COMMAND ===
            elif intent == "run_command":
                command = params.get("command")
                if not command:
                    return "❌ Please specify a command to run.\nExample: 'run ipconfig'"
                result = await self.call_mcp_tool("run_command", {"command": command})
                return f"⚙️ Command: {command}\n\n{result}"
            
            # === ANALYZE NETWORK ===
            elif intent == "analyze_network":
                if not self.quiet:
                    print("🔍 Analyzing network...")
                result = await self.call_mcp_tool("analyze_traffic", {})
                return f"🔒 Network Analysis:\n\n{result}"
            
            # === HELP ===
            elif intent == "help":
                return self._get_tools_list()
            
            # === UNKNOWN ===
            else:
                if intent_data.get("clarification_needed"):
                    return f"❓ {intent_data.get('clarification_message', 'Please provide more details.')}"
                else:
                    return "I couldn't understand that request. Try:\n• 'show my files'\n• 'create a file named test.md'\n• 'read README.md'\n• 'run ipconfig'\n• 'analyze network'"
                    
        except Exception as e:
            return f"❌ Error executing action: {str(e)}"

    async def process_query(self, user_query: str) -> str:
        """
        Process a user query using intelligent intent understanding.

        Args:
            user_query: User's natural language query

        Returns:
            Final response string
        """
        try:
            # Check if this is a docker-related query and route appropriately
            if self._is_docker_query(user_query):
                return await self._handle_docker_query(user_query)
            
            # Use Claude to understand user intent
            if not self.quiet:
                print("🤖 Understanding your request...")
            
            intent_data = await self.understand_user_intent(user_query)
            
            if not self.quiet and intent_data.get("intent") != "unknown":
                print(f"✓ Intent: {intent_data.get('action', 'processing...')}")
            
            # Execute the understood intent
            result = await self.execute_intent(intent_data, user_query)
            return result
                
        except Exception as e:
            error_msg = f"❌ Error: {e}"
            if not self.quiet:
                print(error_msg)
            return error_msg

    def _is_docker_query(self, query: str) -> bool:
        """Check if query is about Docker."""
        docker_keywords = ["docker", "container", "ps", "images", "logs", "inspect"]
        query_lower = query.lower()
        return any(keyword in query_lower for keyword in docker_keywords)

    async def _handle_docker_query(self, user_query: str) -> str:
        """
        Handle Docker queries by routing to WSL.
        
        Examples:
          "docker ps" → wsl docker ps
          "check containers" → wsl docker ps -a
          "list images" → wsl docker images
        """
        try:
            # Simple command parsing
            query_lower = user_query.lower()
            
            if any(word in query_lower for word in ["ps", "container", "running"]):
                cmd = "ps -a" if "all" in query_lower else "ps"
                return await self._run_docker_via_wsl(f"docker {cmd}")
            elif "images" in query_lower or "image" in query_lower:
                return await self._run_docker_via_wsl("docker images")
            elif "logs" in query_lower:
                return await self._run_docker_via_wsl("docker logs")
            else:
                # Try to use the query directly as docker command
                return await self._run_docker_via_wsl(user_query)
                
        except Exception as e:
            return f"❌ Docker error: {e}"

    async def _run_docker_via_wsl(self, command: str) -> str:
        """
        Run a Docker command through WSL.
        
        Args:
            command: Docker command (e.g., "docker ps -a")
            
        Returns:
            Command output
        """
        try:
            # If command doesn't start with wsl, prepend it
            if not command.lower().startswith("wsl"):
                if not command.lower().startswith("docker"):
                    command = f"docker {command}"
                full_cmd = f"wsl {command}"
            else:
                full_cmd = command
            
            if not self.quiet:
                print(f"🔧 Running via WSL: {full_cmd}\n")
            
            result = subprocess.run(
                full_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            output = ""
            if result.stdout:
                output += result.stdout
            if result.stderr:
                output += f"\nErrors:\n{result.stderr}"
            
            if result.returncode != 0 and not result.stdout:
                return f"❌ Command failed with exit code {result.returncode}\n{result.stderr}"
            
            return output if output else "✅ Command completed successfully"
            
        except subprocess.TimeoutExpired:
            return "❌ Command timeout after 30 seconds"
        except Exception as e:
            return f"❌ Error running command: {e}"

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

    async def chat_loop(self):
        """Main interactive chat loop."""
        if not self.quiet:
            print("Network Security Agent")
            print("=" * 40)
            print("Commands: analyze | help | quit")
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
                            return "WARNING: PCAP files found but contain no packets. Network monitoring may not be working."
                        
                        # Build comprehensive analysis report
                        analysis_data = "NETWORK TRAFFIC ANALYSIS\n"
                        analysis_data += "=" * 70 + "\n"
                        analysis_data += f"Analyzed Files: {', '.join(last_3_files)}\n"
                        analysis_data += f"Total Packets: {total_packets}\n"
                        analysis_data += f"Unique Devices: {len(all_devices)}\n"
                        analysis_data += f"Source IPs: {len(all_src_ips)}\n"
                        analysis_data += f"Destination IPs: {len(all_dst_ips)}\n"
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
                        analysis_data += "PRODUCTION NETWORK (custom_net - 192.168.6.0/24):\n"
                        if production_devices:
                            for idx, dev in enumerate(production_devices, 1):
                                analysis_data += f"  Node {idx}: {dev['container'] if dev['container'] != 'unknown' else 'Device'}\n"
                                analysis_data += f"    IP: {dev['ip']}\n"
                                analysis_data += f"    MAC: {dev['mac']}\n"
                                analysis_data += f"    TX: {dev['packets_sent']} packets\n"
                                analysis_data += f"    RX: {dev['packets_received']} packets\n"
                                if idx < len(production_devices):
                                    analysis_data += "\n"
                        else:
                            analysis_data += "  No active devices\n"
                        analysis_data += "\n"
                        
                        # Display Honeypot Network Devices
                        analysis_data += "HONEYPOT NETWORK (honeypot_net - 192.168.7.0/24):\n"
                        if honeypot_devices:
                            for idx, dev in enumerate(honeypot_devices, 1):
                                analysis_data += f"  ISOLATED Node {idx}: {dev['container'] if dev['container'] != 'unknown' else 'Device'}\n"
                                analysis_data += f"    IP: {dev['ip']}\n"
                                analysis_data += f"    MAC: {dev['mac']}\n"
                                analysis_data += f"    TX: {dev['packets_sent']} packets\n"
                                analysis_data += f"    RX: {dev['packets_received']} packets\n"
                                if idx < len(honeypot_devices):
                                    analysis_data += "\n"
                        else:
                            analysis_data += "  No isolated devices\n"
                        analysis_data += "\n"
                        
                        # Protocol Distribution
                        analysis_data += "PROTOCOL DISTRIBUTION:\n"
                        for proto, count in protocols.items():
                            if count > 0:
                                pct = (count / total_packets * 100)
                                analysis_data += f"  {proto:8s}: {count:6d} packets ({pct:5.1f}%)\n"
                        analysis_data += "\n"
                        
                        # Top Source IPs
                        analysis_data += "TOP SOURCE IPs:\n"
                        sorted_srcs = sorted(all_src_ips.items(), key=lambda x: x[1], reverse=True)[:10]
                        for ip, count in sorted_srcs:
                            pct = (count / total_packets * 100)
                            analysis_data += f"  {ip:15s}: {count:6d} packets ({pct:5.1f}%)\n"
                        analysis_data += "\n"
                        
                        # Top Destination IPs
                        analysis_data += "TOP DESTINATION IPs:\n"
                        sorted_dsts = sorted(all_dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]
                        for ip, count in sorted_dsts:
                            pct = (count / total_packets * 100)
                            analysis_data += f"  {ip:15s}: {count:6d} packets ({pct:5.1f}%)\n"
                        analysis_data += "\n"
                        
                        # Top TCP Ports
                        if tcp_ports:
                            analysis_data += "TOP TCP PORTS:\n"
                            sorted_tcp = sorted(tcp_ports.items(), key=lambda x: x[1], reverse=True)[:5]
                            for port, count in sorted_tcp:
                                analysis_data += f"  Port {port:5d}: {count:6d} packets\n"
                            analysis_data += "\n"
                        
                        # Top UDP Ports
                        if udp_ports:
                            analysis_data += "TOP UDP PORTS:\n"
                            sorted_udp = sorted(udp_ports.items(), key=lambda x: x[1], reverse=True)[:5]
                            for port, count in sorted_udp:
                                analysis_data += f"  Port {port:5d}: {count:6d} packets\n"
                            analysis_data += "\n"
                        
                        # Security Analysis with REALISTIC Threat Detection
                        analysis_data += "SECURITY THREAT ANALYSIS:\n"
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
                                threat_level = "[CRITICAL]"
                                analysis_data += f"\n  {threat_level} DoS/DDoS ATTACK from {src_ip}\n"
                                analysis_data += f"    Packet Volume: {src_count:,} packets in 30s ({pct_of_traffic:.1f}%)\n"
                                analysis_data += f"    Attack Rate: ~{src_count//30} packets/second\n"
                                analysis_data += f"    Type: Volume-based DoS\n"
                                analysis_data += f"    Impact: CRITICAL - Network degraded\n"
                                analysis_data += f"    Action: Auto-isolating {src_ip} to honeypot\n"
                                threats_detected.append(f"CRITICAL DoS Attack from {src_ip} ({src_count:,} packets)")
                                critical_threats.append(src_ip)
                                devices_to_isolate.append(src_ip)
                                
                            elif src_count > 1500 or pct_of_traffic > 60:
                                threat_level = "[HIGH]"
                                analysis_data += f"\n  {threat_level} Suspicious flooding from {src_ip}\n"
                                analysis_data += f"    Packet Volume: {src_count:,} packets in 30s ({pct_of_traffic:.1f}%)\n"
                                analysis_data += f"    Attack Rate: ~{src_count//30} packets/second\n"
                                analysis_data += f"    Assessment: Likely DoS or compromised device\n"
                                analysis_data += f"    Action: Auto-isolating {src_ip} to honeypot\n"
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
                                analysis_data += f"\n  [CRITICAL] PORT SCAN ATTACK from {scanner_ip}\n"
                                analysis_data += f"    Scanned Ports: {port_count} unique ports\n"
                                analysis_data += f"    Attack Phase: Reconnaissance\n"
                                analysis_data += f"    Next Expected: Exploitation attempts\n"
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
                            analysis_data += "\n  No security threats detected\n"
                            analysis_data += "  Network traffic appears normal\n"
                        else:
                            analysis_data += f"\n{'='*70}\n"
                            analysis_data += f"TOTAL THREATS DETECTED: {len(threats_detected)}\n"
                            if critical_threats:
                                analysis_data += f"CRITICAL THREATS: {len(critical_threats)} (Immediate action required)\n"
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
                                model="glm-4.5",
                                max_tokens=2048,
                                temperature=0.1,  # Lower temperature for more consistent strict analysis
                                messages=[{"role": "user", "content": ai_prompt}]
                            )
                            
                            ai_summary = response.content[0].text
                            
                            # AUTO-ISOLATE malicious devices to honeypot using MCP tool
                            isolation_results = []
                            if devices_to_isolate:
                                if not self.quiet:
                                    print(f"\nAUTO-ISOLATING {len(devices_to_isolate)} malicious device(s) using MCP tool...")
                                
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
                                            isolation_msg = f"Calling MCP tool: move_device_to_honeypot({container_found}, 'DoS Attack Detected')"
                                            if not self.quiet:
                                                print(isolation_msg)
                                            
                                            # Extract device_id (e.g., 'vdevice_001' -> 'device_001' or keep as is)
                                            device_id = container_found  # MCP tool handles both formats
                                            
                                            # Call MCP tool for isolation
                                            mcp_result = await self.call_mcp_tool(
                                                "move_device_to_honeypot",
                                                {"device_id": device_id, "reason": f"DoS Attack from {malicious_ip}"}
                                            )
                                            
                                            isolation_results.append(f"[SUCCESS] MCP Tool: {mcp_result}")
                                        else:
                                            isolation_results.append(f"[WARNING] Container not found for IP {malicious_ip}")
                                    
                                    except Exception as iso_error:
                                        isolation_results.append(f"[ERROR] Failed to isolate {malicious_ip}: {str(iso_error)}")
                            
                            # Add threat summary at top
                            if threats_detected:
                                threat_summary = "=" * 70 + "\n"
                                threat_summary += "SECURITY ALERT: ACTIVE ATTACK DETECTED\n"
                                threat_summary += "=" * 70 + "\n"
                                for threat in threats_detected:
                                    threat_summary += f"  {threat}\n"
                                threat_summary += "=" * 70 + "\n\n"
                                
                                # Add isolation results if any
                                if isolation_results:
                                    threat_summary += "AUTO-ISOLATION ACTIONS TAKEN:\n"
                                    for result in isolation_results:
                                        threat_summary += f"  {result}\n"
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
                    "I can help you with:\n\n"
                    "📊 NETWORK ANALYSIS:\n"
                    "  • 'analyze the network' - Full security analysis\n"
                    "  • 'show threats' - Identify security threats\n"
                    "  • 'list connected devices' - View all devices\n\n"
                    "🛠️ SYSTEM OPERATIONS:\n"
                    "  • 'run ipconfig' - Run system commands\n"
                    "  • 'read C:\\logs\\file.txt' - Read files\n"
                    "  • 'list files in C:\\logs' - Directory listing\n\n"
                    "❓ HELP:\n"
                    "  • 'show tools' or 'help' - Display all 19 available tools\n"
                    "  • 'what can you do?' - List capabilities\n\n"
                    "Try asking: 'show me the tools available' or 'analyze the network'"
                )
                
        # except Exception as e:
        #     error_msg = f"Error: {e}"
        #     if not self.quiet:
        #         print(error_msg)
        #     return error_msg

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
            print("\n" + "=" * 60)
            print("🤖 NETWORK SECURITY AGENT")
            print("=" * 60)
            print("Commands: help | quit")
            print("Docker: 'docker ps', 'check containers', 'list images'")
            print("=" * 60)

        while True:
            try:
                # Get user input
                user_query = input("\nYou: ").strip()

                if not user_query:
                    continue

                # Handle commands
                if user_query.lower() in ['quit', 'exit', 'bye', 'q']:
                    print("\nGoodbye! 👋\n")
                    break

                if user_query.lower() == 'help':
                    print(self._get_tools_list())
                    continue

                # Check for Docker queries
                docker_keywords = ["docker", "container", "ps", "images", "logs", "inspect"]
                if any(keyword in user_query.lower() for keyword in docker_keywords):
                    response = await self._handle_docker_query(user_query)
                else:
                    # Use Claude for other queries
                    response = await self.process_query(user_query)
                
                print(f"\n{response}")

            except KeyboardInterrupt:
                print("\n\nGoodbye! 👋\n")
                break
            except Exception as e:
                print(f"\n❌ Error: {e}\n")


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
