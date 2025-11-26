#!/usr/bin/env python3
"""
MCP Agent - Network Security Monitor

Intelligent AI agent with context management, planning, and TODO tracking.
Routes Docker commands through WSL when needed.
"""

import asyncio
import subprocess
import sys
import os
import json
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime

from fastmcp import Client
from anthropic import Anthropic
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

# Load environment variables
try:
    from dotenv import load_dotenv
    env_path = Path(__file__).parent.parent / "config" / ".env"
    load_dotenv(dotenv_path=env_path)
except ImportError:
    pass


@dataclass
class ContextWindowManager:
    """Manages context window usage and token tracking."""
    total_tokens: int = 200000
    reserve_percent: int = 20
    current_tokens: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    
    def estimate_tokens(self, text: str) -> int:
        """Estimate token count (~4 chars per token)."""
        return len(text) // 4
    
    def update_usage(self, input_tokens: int, output_tokens: int):
        """Update token usage from API response."""
        self.current_tokens = input_tokens + output_tokens
        self.total_input_tokens += input_tokens
        self.total_output_tokens += output_tokens
    
    def get_usage_percent(self) -> float:
        """Get current usage as percentage."""
        usable = self.total_tokens - int(self.total_tokens * (self.reserve_percent / 100))
        return (self.current_tokens / usable) * 100 if usable > 0 else 0
    
    def should_summarize(self) -> bool:
        """Check if we should summarize context."""
        return self.get_usage_percent() > 80
    
    def get_status_display(self) -> str:
        """Get formatted status."""
        used_pct = self.get_usage_percent()
        if used_pct < 50:
            return f"✓ Context: {used_pct:.1f}% used"
        elif used_pct < 80:
            return f"⚠ Context: {used_pct:.1f}% used"
        else:
            return f"⚡ Context: {used_pct:.1f}% used (near limit)"


@dataclass
class TodoItem:
    """Represents a TODO item in the execution plan."""
    id: int
    title: str
    description: str
    status: str = "not-started"  # not-started, in-progress, completed
    
    def __str__(self):
        status_icon = {"not-started": "⏸", "in-progress": "▶", "completed": "✅"}
        return f"{status_icon.get(self.status, '•')} [{self.id}] {self.title}"


class NetworkSecurityAgent:
    """Simplified wrapper for dashboard integration."""
    
    def __init__(self):
        """Initialize with quiet mode for web UI."""
        self.agent = None
    
    async def query(self, query_text: str, tool_callback=None) -> str:
        """Process a query with optional tool progress callback."""
        # Create agent with callback
        self.agent = MCPAgent(quiet=True, tool_callback=tool_callback)
        
        try:
            # Initialize and run query
            await self.agent.initialize()
            response = await self.agent.process_query(query_text)
            return response
        finally:
            # Cleanup
            if self.agent:
                await self.agent.cleanup()


class MCPAgent:
    """AI-powered MCP Agent with intelligent planning and TODO tracking."""

    def __init__(self, server_path: Optional[str] = None, quiet: bool = False, tool_callback=None):
        """Initialize the agent with intelligent features."""
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not self.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY not set in config/.env")

        self.anthropic_client = Anthropic(api_key=self.anthropic_api_key)
        self.quiet = quiet
        self.tool_callback = tool_callback  # Callback for tool progress
        
        # Context management
        self.context_manager = ContextWindowManager()
        self.conversation_history = []
        self.execution_log = []
        
        # Planning and TODO tracking
        self.todos: List[TodoItem] = []
        self.current_plan: List[str] = []
        
        # MCP Server - Use correct absolute path
        if server_path is None:
            server_path = "E:\\Malware_detection_using_Aiagent\\Network_Security_poc\\mcp_agent\\server\\server.py"
        
        self.mcp_client = Client(server_path)
        self.tools = []
        
        # Docker availability
        self.docker_in_wsl = self._check_docker_in_wsl()

        # Only print minimal info
        if not self.quiet:
            print("✅ Agent Ready")
            print()

    def _check_docker_in_wsl(self) -> bool:
        """Check if Docker is available in WSL."""
        try:
            result = subprocess.run(
                ["wsl", "docker", "--version"],
                capture_output=True,
                timeout=2,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False

    async def initialize(self):
        """Initialize MCP client and load tools."""
        try:
            # Silent initialization - no debug output
            await self.mcp_client.__aenter__()
            
            # Load tools from the connected client
            tools_result = await self.mcp_client.list_tools()
            
            if hasattr(tools_result, 'tools'):
                self.tools = tools_result.tools
            elif isinstance(tools_result, list):
                self.tools = tools_result
            else:
                self.tools = []
            
            if not self.quiet and self.tools:
                print(f"✓ Loaded {len(self.tools)} tools\n")
                
        except Exception as e:
            print(f"❌ ERROR: Could not load tools - {e}")
            print(f"❌ ERROR type: {type(e)}")
            import traceback
            print(f"❌ Traceback:\n{traceback.format_exc()}")
            # Clean up if initialization failed
            try:
                await self.mcp_client.__aexit__(None, None, None)
            except:
                pass
    
    async def cleanup(self):
        """Cleanup MCP client connection."""
        try:
            await self.mcp_client.__aexit__(None, None, None)
        except Exception as e:
            if not self.quiet:
                print(f"⚠ Warning during cleanup: {e}")

    def _add_todo(self, title: str, description: str) -> TodoItem:
        """Add a new TODO item."""
        todo_id = len(self.todos) + 1
        todo = TodoItem(id=todo_id, title=title, description=description)
        self.todos.append(todo)
        return todo

    def _update_todo_status(self, todo_id: int, status: str):
        """Update TODO status."""
        for todo in self.todos:
            if todo.id == todo_id:
                todo.status = status
                if not self.quiet:
                    print(f"📋 {todo}")
                break

    def _display_todos(self):
        """Display all TODO items."""
        if not self.todos:
            return
        
        print("\n📋 TODO List:")
        print("=" * 60)
        for todo in self.todos:
            print(f"  {todo}")
            if todo.description and len(todo.description) < 100:
                print(f"     {todo.description}")
        print("=" * 60)

    def _parse_plan_from_response(self, response_text: str) -> Tuple[List[str], List[Tuple[str, str]]]:
        """Parse plan and TODOs from glm-4.5's response."""
        plan_steps = []
        todos = []
        
        # Look for JSON plan in response
        try:
            if "```json" in response_text:
                json_start = response_text.find("```json") + 7
                json_end = response_text.find("```", json_start)
                json_str = response_text[json_start:json_end].strip()
                plan_data = json.loads(json_str)
                
                if "steps" in plan_data:
                    plan_steps = plan_data["steps"]
                if "todos" in plan_data:
                    for todo_data in plan_data["todos"]:
                        if isinstance(todo_data, dict):
                            todos.append((todo_data.get("title", ""), todo_data.get("description", "")))
                        elif isinstance(todo_data, str):
                            todos.append((todo_data, ""))
        except json.JSONDecodeError:
            pass
        
        return plan_steps, todos

    async def call_mcp_tool(self, tool_name: str, parameters: Optional[Dict[str, Any]] = None) -> str:
        """Call an MCP tool with given parameters."""
        try:
            # Use the persistent connection (already connected from initialize)
            if parameters:
                result = await self.mcp_client.call_tool(tool_name, parameters)
            else:
                result = await self.mcp_client.call_tool(tool_name, {})
            
            if hasattr(result, 'content') and result.content:
                if isinstance(result.content, list):
                    return "\n".join(str(item.text) if hasattr(item, 'text') else str(item) 
                                   for item in result.content)
                return str(result.content)
            return "Tool executed successfully"
        except Exception as e:
            error_msg = f"Error calling tool: {str(e)}"
            if not self.quiet:
                print(f"❌ DEBUG: {error_msg}")
                import traceback
                print(f"❌ DEBUG: Traceback:\n{traceback.format_exc()}")
            return error_msg

    def _is_docker_query(self, user_input: str) -> bool:
        """Check if query is Docker-related."""
        docker_keywords = ["docker", "container", "image"]
        return any(keyword in user_input.lower() for keyword in docker_keywords)

    async def _handle_docker_via_wsl(self, docker_command: str) -> str:
        """Handle Docker command via WSL."""
        if not docker_command.strip().startswith("docker"):
            docker_command = f"docker {docker_command}"
        
        try:
            result = subprocess.run(
                ["wsl"] + docker_command.split(),
                capture_output=True,
                text=True,
                timeout=30
            )
            output = result.stdout if result.returncode == 0 else result.stderr
            return output or "Command executed"
        except subprocess.TimeoutExpired:
            return "Docker command timed out"
        except Exception as e:
            return f"Error: {str(e)}"

    def _build_system_prompt(self) -> str:
        """Build system prompt with context awareness."""
        tools_desc = "\n".join([f"- {tool.name}: {tool.description}" 
                               if hasattr(tool, 'description') else f"- {tool.name}" 
                               for tool in self.tools])
        
        prompt = f"""You are an Advanced Network Security Anomaly Detection & Malware Verification Expert AI Agent.

CRITICAL WORKFLOW: Detect anomalies FIRST, then verify malware signatures ONLY when suspicious files are found.

Your expertise:
- Behavioral anomaly detection in network traffic
- Statistical analysis of connection patterns
- Identifying deviations from normal baseline behavior
- Hash-based malware verification when suspicious files are detected
- Evidence-based threat assessment

Available tools:
{tools_desc}

INTELLIGENT ANALYSIS WORKFLOW (Follow this EXACT sequence):

NETWORK ENVIRONMENT CONTEXT:
You are monitoring a security testing environment. Extract all network details from Zeek logs dynamically.

🖥️ INFRASTRUCTURE (Extract from logs):
- Identify network range from conn.log IP addresses
- Locate network monitor IP (usually receives most traffic)
- Find dashboard/server ports from http.log

📦 ATTACKER IDENTIFICATION (Detect from behavior):
Analyze logs to identify attackers by their behavior patterns:

1. Malware/C2 Activity:
   - Look for: Automated beacons, file uploads, data exfiltration patterns
   - Endpoints may include: firmware updates, telemetry, storage sync, file uploads
   - Identify source IP from logs showing these patterns
   
2. Brute Force Activity:
   - Look for: Repeated authentication attempts, SSH connections
   - Identify source IP from conn.log with high connection counts
   
3. DoS/Flooding:
   - Look for: High-volume connection floods
   - Identify source IP with abnormal connection rates

🌐 LEGITIMATE DEVICES (Detect from behavior):
- Normal IoT devices show: Variable timing, realistic sensor patterns
- Device registration and periodic data submissions
- Identify based on behavioral analysis, not static IPs

INTELLIGENT ANALYSIS WORKFLOW (Follow this EXACT sequence):

═══════════════════════════════════════════════════════════════════
PHASE 1: READ ZEEK LOGS & BEHAVIORAL ANALYSIS
═══════════════════════════════════════════════════════════════════

1. READ ZEEK LOGS (use read_zeek_logs tool)
   - Get latest conn.log, http.log, dns.log, files.log from the most recent session
   - Focus on the latest session folder (session_TIMESTAMP format)
   - Parse all log entries to understand current network state
   - Extract attacker IPs, destination IPs, timestamps, data volumes

2. BEHAVIORAL ANOMALY DETECTION
   Analyze for these patterns WITHOUT checking hashes yet:

   A. FREQUENCY ANOMALIES:
      - Connections at suspicious intervals (e.g., exactly every 1-2 seconds)
      - Unusually high connection rates from single IP
      - Repetitive requests to same endpoint
      → INDICATOR: Automated behavior, possible C2 beacon

   B. DATA SIZE ANOMALIES:
      - Large data transfers to unusual endpoints
      - Repeated transfers of similar sizes
      - Data uploads significantly larger than downloads
      → INDICATOR: Data exfiltration, backup abuse

   C. USER-AGENT ANOMALIES:
      - Non-standard user agents (e.g., python-requests, custom names)
      - Suspicious naming patterns
      - Automated tool signatures
      → INDICATOR: Automated tools, malware, scripts

   D. ENDPOINT ANOMALIES:
      - /api/v1/firmware/update receiving frequent requests
      - Normal-looking endpoints with abnormal traffic patterns
      - APIs called at machine-precise intervals
      → INDICATOR: API abuse, disguised malware communication

   E. DNS/PROTOCOL ANOMALIES:
      - DNS queries to random/generated domains
      - High NXDOMAIN rates
      - Unusual port usage
      → INDICATOR: DNS tunneling, DGA malware

   F. FILE TRANSFER DETECTION:
      - Check files.log for ANY file transfers
      - Look for mime_type = "application/octet-stream", "text/plain", or suspicious file extensions
      - Note source IP, destination, file size
      → INDICATOR: Potential malware file transfer

3. ASSIGN INITIAL SUSPICION SCORE (1-10):
   - Low (1-3): Single minor anomaly
   - Medium (4-6): Multiple anomalies or file transfer detected
   - High (7-8): Many anomalies + file transfer
   - Critical (9-10): Obvious malicious pattern

═══════════════════════════════════════════════════════════════════
PHASE 2: MALWARE HASH VERIFICATION (ONLY IF SUSPICIOUS FILES FOUND)
═══════════════════════════════════════════════════════════════════

4. CHECK FILES.LOG FOR HASHES
   IF and ONLY IF:
   - files.log shows file transfers (check mime_type, filename fields)
   - OR behavioral analysis score >= 6 (Medium/High/Critical)
   - OR suspicious endpoint activity (/firmware/update, /files/upload)

   Then:
   a) Read files.log from the latest session
   b) Extract SHA256 hash values from suspicious file entries
   c) Look for files from suspicious IPs identified in Phase 1
   d) Note: files.log format has hash fields (md5, sha1, sha256)

5. VERIFY HASHES AGAINST MALWARE DATABASE
   For each suspicious hash found:
   
   a) Use check_malware_hash tool with the SHA256 hash
   b) The tool will:
      - Check local databases first (fast)
      - Query MalwareBazaar API if needed (use --online flag for unknown hashes)
      - Return threat details if found
   
   c) Parse the result:
      - threat_level: CLEAN, TEST_FILE, MALWARE
      - threat_score: 0-100
      - signature: Malware family name
      - database: Where it was found
   
   d) If MALWARE detected:
      - Extract malware family/signature
      - Note file type, tags, first seen date
      - Correlate with behavioral analysis

6. CORRELATE HASH RESULTS WITH BEHAVIOR
   - If hash is malware AND behavior is suspicious: CONFIRMED THREAT
   - If hash is clean BUT behavior is highly suspicious: POTENTIAL ZERO-DAY
   - If hash is malware BUT behavior is normal: FALSE POSITIVE (test file?)

═══════════════════════════════════════════════════════════════════
PHASE 3: EVIDENCE-BASED REPORTING
═══════════════════════════════════════════════════════════════════

7. COMPILE EVIDENCE
   For each suspicious IP/device, provide:
   
   BEHAVIORAL EVIDENCE:
   - Specific log entries showing anomalies
   - Frequency calculations (e.g., "requests every 1.0s ±0.1s")
   - Data size patterns (e.g., "consistent 56-byte payloads")
   - Timeline of suspicious activity
   
   MALWARE EVIDENCE (if hash verified):
   - SHA256 hash of malicious file
   - Malware family/signature name
   - MalwareBazaar details (first seen, tags, file type)
   - Match confidence (local DB vs online verification)
   - Related hashes (MD5, SHA1)
   
   CORRELATION:
   - How behavior matches known malware patterns
   - Timeline correlation (file transfer → C2 beacons)
   - IP address connections

8. FINAL THREAT ASSESSMENT
   Format your response EXACTLY like this:

   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   🚨 THREAT DETECTED: [IP Address]
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   
   📊 THREAT LEVEL: [CRITICAL/HIGH/MEDIUM/LOW]
   🎯 THREAT SCORE: [X/10]
   
   📋 BEHAVIORAL ANOMALIES:
   1. [Anomaly Type]: [Specific evidence from logs]
      Evidence: [Quote from log or specific metric]
   2. [Anomaly Type]: [Specific evidence]
   ...
   
   🔍 MALWARE VERIFICATION:
   [ONLY IF HASH WAS CHECKED AND FOUND]
   ✓ Malicious File Detected
   
   File Details:
   - SHA256: [hash]
   - Malware Family: [signature name from MalwareBazaar]
   - File Type: [type]
   - Source: [database name]
   - First Seen: [date]
   - Tags: [tags]
   
   Hash Verification:
   - Database: [MalwareBazaar/custom/eicar]
   - Threat Level: [MALWARE/TEST_FILE]
   - Confidence: [X%]
   
   Additional Hashes:
   - MD5: [hash]
   - SHA1: [hash]
   
   [IF NO MALWARE HASH FOUND]
   ℹ️ No malicious files detected in files.log
   Note: Threat assessment based on behavioral analysis only
   
   ⏱️ TIMELINE:
   - [Timestamp]: [Activity description with log reference]
   - [Timestamp]: [Activity description]
   
   💡 CONFIDENCE: [X%] - [Reasoning]
   
   🎯 RECOMMENDED ACTIONS:
   1. [Immediate action based on threat level]
   2. [Investigation steps]
   3. [Mitigation strategy]
   
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   
   📝 EXECUTIVE SUMMARY
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   
   🔴 WHAT HAPPENED:
   [Clear 2-3 sentence explanation of the attack/suspicious activity]
   
   ⚠️ THREAT TYPE:
   - Attack Classification: [C2 Communication / Data Exfiltration / Malware Transfer / etc.]
   - Severity: [CRITICAL/HIGH/MEDIUM/LOW]
   - Status: [Active / Completed / Ongoing]
   
   🎭 ATTACKER INFORMATION:
   - Source IP: [IP address]
   - Hostname: [if available from logs]
   - MAC Address: [if available]
   - Device Type: [Container/Physical/Unknown]
   - First Seen: [timestamp from logs]
   - Last Activity: [timestamp from logs]
   - Total Connections: [count from conn.log]
   - Data Transferred: [total bytes from logs]
   
   🎯 TARGETED RESOURCES:
   - Destination IP: [target IP]
   - Targeted Endpoints: [list of URIs/services]
   - Compromised Services: [which services were attacked]
   
   🔍 ROOT CAUSE:
   [What allowed this to happen - vulnerability, misconfiguration, etc.]
   
   💥 IMPACT ASSESSMENT:
   - Data Loss: [Yes/No/Unknown - amount if known]
   - System Compromise: [Yes/No/Potential]
   - Lateral Movement: [Yes/No/Potential]
   - Duration: [How long attack lasted]
   - Affected Assets: [List of IPs/services impacted]
   
   🛡️ MITIGATION STATUS:
   - Current State: [Contained/Ongoing/Unmitigated]
   - Isolation Needed: [Yes/No]
   - Priority: [P0-Critical / P1-High / P2-Medium / P3-Low]
   
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

═══════════════════════════════════════════════════════════════════
IMPORTANT RULES
═══════════════════════════════════════════════════════════════════

✓ DO:
- Always read logs FIRST before checking hashes
- Only check hashes if files.log shows file transfers OR suspicion score >= 6
- Provide specific evidence with log timestamps
- Correlate behavioral and hash-based evidence
- Explain confidence level and reasoning
- Quote actual log entries as evidence

✗ DON'T:
- Check hashes without reading logs first
- Check hashes for every session automatically
- Declare malware without evidence
- Rely only on hash checking
- Make assumptions without log data
- Skip behavioral analysis

TOOL USAGE SEQUENCE:
1. read_zeek_logs (ALWAYS FIRST)
2. Analyze behavior internally
3. check_malware_hash (ONLY IF suspicious files found in files.log)
4. Generate report with evidence

Context: {self.context_manager.get_status_display()}"""
        
        return prompt

    async def process_query(self, user_input: str) -> str:
        """Process user query with intelligent planning and multi-turn tool execution."""
        # Add to conversation history
        self.conversation_history.append({
            "role": "user",
            "content": user_input
        })
        
        # Handle slash commands
        if user_input.startswith("/"):
            return await self._handle_slash_command(user_input)
        
        # Build messages for glm-4.5
        messages = []
        
        # Add conversation history (keep last 10 exchanges)
        for msg in self.conversation_history[-20:]:
            messages.append(msg)
        
        # Build tool definitions once
        tool_definitions = []
        for tool in self.tools:
            tool_def = {
                "name": tool.name,
                "description": getattr(tool, 'description', ''),
            }
            if hasattr(tool, 'inputSchema'):
                tool_def["input_schema"] = tool.inputSchema
            tool_definitions.append(tool_def)
        
        try:
            # Multi-turn conversation loop
            iteration = 0
            max_iterations = 100
            final_response_text = ""
            
            while iteration < max_iterations:
                iteration += 1
                
                # Call glm-4.5
                response = self.anthropic_client.messages.create(
                    model="glm-4.5",  # Fixed: using correct glm-4.5 model
                    max_tokens=4096,
                    system=self._build_system_prompt(),
                    messages=messages,
                    tools=tool_definitions if tool_definitions else None
                )
                
                # Update token usage silently
                if hasattr(response, 'usage'):
                    self.context_manager.update_usage(
                        response.usage.input_tokens,
                        response.usage.output_tokens
                    )
                
                # Check stop reason
                stop_reason = response.stop_reason
                
                # Process response content
                response_text = ""
                tool_calls = []
                
                for block in response.content:
                    if hasattr(block, 'text'):
                        response_text += block.text
                    elif hasattr(block, 'type') and block.type == 'tool_use':
                        tool_calls.append(block)
                
                # Parse plan on first iteration
                if iteration == 1:
                    plan_steps, todos = self._parse_plan_from_response(response_text)
                    if plan_steps:
                        self.current_plan = plan_steps
                        if not self.quiet:
                            print("\n📝 Plan:")
                            for i, step in enumerate(plan_steps, 1):
                                print(f"   {i}. {step}")
                    
                    if todos:
                        for title, desc in todos:
                            self._add_todo(title, desc)
                        self._display_todos()
                
                # Save text for final response
                final_response_text = response_text
                
                # If no tool calls, we're done
                if stop_reason == "end_turn" or not tool_calls:
                    break
                
                # Execute tool calls
                if tool_calls:
                    
                    # Add assistant message with tool calls
                    assistant_message = {
                        "role": "assistant",
                        "content": response.content
                    }
                    messages.append(assistant_message)
                    
                    # Execute each tool and collect results
                    tool_results = []
                    
                    for i, tool_call in enumerate(tool_calls):
                        todo_id = i + 1
                        if todo_id <= len(self.todos):
                            self._update_todo_status(todo_id, "in-progress")
                        
                        # Simple tool progress output (just the name)
                        if not self.quiet:
                            print(f"🔧 {tool_call.name}")
                        
                        # Call tool callback if provided (for web UI)
                        if self.tool_callback:
                            self.tool_callback(tool_call.name, 'running')
                        
                        # Call the tool
                        tool_result_text = await self.call_mcp_tool(
                            tool_call.name,
                            tool_call.input if hasattr(tool_call, 'input') else {}
                        )
                        
                        # Build tool result for Anthropic API
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_call.id,
                            "content": tool_result_text
                        })
                        
                        # Mark as completed
                        if self.tool_callback:
                            self.tool_callback(tool_call.name, 'completed')
                        
                        if todo_id <= len(self.todos):
                            self._update_todo_status(todo_id, "completed")
                    
                    # Add tool results as user message
                    user_message = {
                        "role": "user",
                        "content": tool_results
                    }
                    messages.append(user_message)
                    
                    # Continue loop to get glm-4.5's response to tool results
                    continue
                
                # If we get here without tool calls, break
                break
            
            if iteration >= max_iterations:
                final_response_text += f"\n\n⚠️ Reached maximum iterations ({max_iterations})"
            
            # Add final assistant response to conversation history
            self.conversation_history.append({
                "role": "assistant",
                "content": final_response_text
            })
            
            return final_response_text
            
        except Exception as e:
            error_msg = f"Error processing query: {str(e)}"
            print(f"❌ {error_msg}")
            import traceback
            print(f"❌ Traceback:\n{traceback.format_exc()}")
            return error_msg

    async def _handle_slash_command(self, command: str) -> str:
        """Handle slash commands."""
        cmd = command.lower().strip()
        
        if cmd == "/context":
            return f"""
Context Status:
- Usage: {self.context_manager.get_usage_percent():.1f}%
- Input tokens: {self.context_manager.total_input_tokens:,}
- Output tokens: {self.context_manager.total_output_tokens:,}
- Conversation length: {len(self.conversation_history)} messages
"""
        
        elif cmd == "/stats":
            return f"""
Session Statistics:
- Total queries: {len([m for m in self.conversation_history if m['role'] == 'user'])}
- TODOs created: {len(self.todos)}
- TODOs completed: {len([t for t in self.todos if t.status == 'completed'])}
- Execution log entries: {len(self.execution_log)}
"""
        
        elif cmd == "/todos":
            if not self.todos:
                return "No TODOs yet."
            result = "\n📋 Current TODOs:\n"
            for todo in self.todos:
                result += f"  {todo}\n"
            return result
        
        elif cmd == "/help":
            return """
Available Commands:
- /context   - Show context window usage
- /stats     - Show session statistics
- /todos     - Show current TODO list
- /help      - Show this help message
- /clear     - Clear conversation history
- /quit      - Exit the agent

Regular queries are processed by glm-4.5 with tool access.
"""
        
        elif cmd == "/clear":
            self.conversation_history = []
            self.todos = []
            self.current_plan = []
            self.execution_log = []
            return "✓ Cleared conversation history and TODOs"
        
        elif cmd == "/quit":
            sys.exit(0)
        
        else:
            return f"Unknown command: {command}. Type /help for available commands."

    def chat_loop_sync(self):
        """Synchronous interactive chat loop using prompt_toolkit."""
        print("\n" + "=" * 60)
        print("Network Security Agent - Interactive Mode")
        print("=" * 60)
        print("Commands: /help, /context, /stats, /todos, /quit")
        print("=" * 60 + "\n")
        
        # Create prompt session
        session = PromptSession()
        
        # Initialize tools in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.initialize())
        
        try:
            while True:
                try:
                    # Get user input with proper terminal handling
                    with patch_stdout():
                        user_input = session.prompt("\nYou: ").strip()
                    
                    if not user_input:
                        continue
                    
                    if user_input.lower() in ["quit", "exit", "/quit"]:
                        print("\n👋 Goodbye!")
                        break
                    
                    # Process query in the event loop
                    response = loop.run_until_complete(self.process_query(user_input))
                    
                    # Display response
                    print(f"\nAgent: {response}")
                    
                except KeyboardInterrupt:
                    print("\n\n👋 Goodbye!")
                    break
                except EOFError:
                    print("\n\n👋 Goodbye!")
                    break
                except Exception as e:
                    print(f"\n❌ Error: {e}")
        finally:
            # Cleanup MCP client connection
            loop.run_until_complete(self.cleanup())
            loop.close()

    async def run_query(self, query: str) -> str:
        """Run a single query (non-interactive mode)."""
        try:
            await self.initialize()
            return await self.process_query(query)
        finally:
            await self.cleanup()


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="MCP Agent - Network Security Monitor")
    parser.add_argument("query", nargs="*", help="Query to process (if not provided, enters chat mode)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Suppress verbose output")
    
    args = parser.parse_args()
    
    # Create agent
    agent = MCPAgent(quiet=args.quiet)
    
    if args.query:
        # Single query mode
        query = " ".join(args.query)
        
        async def run_single_query():
            result = await agent.run_query(query)
            print(result)
        
        asyncio.run(run_single_query())
    else:
        # Interactive chat mode - use synchronous version
        agent.chat_loop_sync()


if __name__ == "__main__":
    main()
