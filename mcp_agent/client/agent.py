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


class MCPAgent:
    """AI-powered MCP Agent with intelligent planning and TODO tracking."""

    def __init__(self, server_path: Optional[str] = None, quiet: bool = False):
        """Initialize the agent with intelligent features."""
        self.anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not self.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY not set in config/.env")

        self.anthropic_client = Anthropic(api_key=self.anthropic_api_key)
        self.quiet = quiet
        
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
        
        if not self.quiet:
            print(f"🔧 DEBUG: Server path: {server_path}")
            print(f"🔧 DEBUG: Server exists: {Path(server_path).exists()}")
        
        self.mcp_client = Client(server_path)
        self.tools = []
        
        # Docker availability
        self.docker_in_wsl = self._check_docker_in_wsl()

        if not self.quiet:
            print("✅ Agent initialized")
            if self.docker_in_wsl:
                print("📌 Docker found in WSL")
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
            print("🔧 DEBUG: Starting MCP client initialization...")
            print(f"🔧 DEBUG: MCP client type: {type(self.mcp_client)}")
            print(f"🔧 DEBUG: MCP client transport: {type(self.mcp_client.transport)}")
            
            # Enter the client context (keeps connection alive)
            print("🔧 DEBUG: Entering client context...")
            await self.mcp_client.__aenter__()
            print("🔧 DEBUG: Client context entered successfully")
            
            # Check if client is initialized
            print(f"🔧 DEBUG: Client initialized: {self.mcp_client.initialize_result is not None}")
            if self.mcp_client.initialize_result:
                print(f"🔧 DEBUG: Server name: {self.mcp_client.initialize_result.serverInfo.name}")
                print(f"🔧 DEBUG: Server capabilities: {self.mcp_client.initialize_result.capabilities}")
            
            # Load tools from the connected client
            print("🔧 DEBUG: Calling list_tools()...")
            tools_result = await self.mcp_client.list_tools()
            print(f"🔧 DEBUG: tools_result type: {type(tools_result)}")
            # print(f"🔧 DEBUG: tools_result: {tools_result}")
            
            if hasattr(tools_result, 'tools'):
                self.tools = tools_result.tools
                print(f"🔧 DEBUG: Found {len(self.tools)} tools via .tools attribute")
            else:
                print(f"🔧 DEBUG: No .tools attribute, checking if result is list...")
                if isinstance(tools_result, list):
                    self.tools = tools_result
                    print(f"🔧 DEBUG: Result is list with {len(self.tools)} tools")
                else:
                    self.tools = []
                    print(f"🔧 DEBUG: Could not extract tools from result")
            
            if self.tools:
                print(f"\n✓ Loaded {len(self.tools)} MCP tools:")
                for i, tool in enumerate(self.tools[:5], 1):  # Show first 5
                    tool_name = tool.name if hasattr(tool, 'name') else str(tool)
                    print(f"  {i}. {tool_name}")
                if len(self.tools) > 5:
                    print(f"  ... and {len(self.tools) - 5} more")
            else:
                print(f"\n⚠ WARNING: No tools loaded from server")
                
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
        
        prompt = f"""You are an intelligent network security AI agent. You have access to these MCP tools:

{tools_desc}

IMPORTANT CAPABILITIES:
1. PLANNING: Before complex tasks, create a JSON plan:
   {{"steps": ["step1", "step2"], "todos": [{{"title": "...", "description": "..."}}]}}

2. DOCKER: If Docker command needed and WSL is available, use docker_command tool or suggest WSL route.

3. CONTEXT: Current token usage: {self.context_manager.get_status_display()}

4. TODO TRACKING: Track progress through multiple steps.

When the user asks a question:
1. If complex, create a plan first (JSON format)
2. Execute tools as needed
3. Provide clear, concise responses
4. Suggest next steps if appropriate"""
        
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
        
        if not self.quiet and tool_definitions:
            print(f"\n🔧 DEBUG: Sending {len(tool_definitions)} tool definitions to glm-4.5")
            print(f"🔧 DEBUG: Tool names: {[t['name'] for t in tool_definitions[:5]]}")
        
        try:
            # Multi-turn conversation loop
            iteration = 0
            max_iterations = 100
            final_response_text = ""
            
            while iteration < max_iterations:
                iteration += 1
                
                if not self.quiet:
                    print(f"\n🔄 Iteration {iteration}/{max_iterations}")
                
                # Call glm-4.5
                response = self.anthropic_client.messages.create(
                    model="glm-4.5",  # Fixed: using correct glm-4.5 model
                    max_tokens=4096,
                    system=self._build_system_prompt(),
                    messages=messages,
                    tools=tool_definitions if tool_definitions else None
                )
                
                # Update token usage
                if hasattr(response, 'usage'):
                    self.context_manager.update_usage(
                        response.usage.input_tokens,
                        response.usage.output_tokens
                    )
                    if not self.quiet:
                        print(f"{self.context_manager.get_status_display()}")
                
                # Check stop reason
                stop_reason = response.stop_reason
                if not self.quiet:
                    print(f"🔧 DEBUG: Stop reason: {stop_reason}")
                
                # Process response content
                response_text = ""
                tool_calls = []
                
                for block in response.content:
                    if hasattr(block, 'text'):
                        response_text += block.text
                    elif hasattr(block, 'type') and block.type == 'tool_use':
                        tool_calls.append(block)
                
                # Display text response if any
                if response_text and not self.quiet:
                    print(f"\n💬 glm-4.5 says: {response_text[:200]}{'...' if len(response_text) > 200 else ''}")
                
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
                    if not self.quiet:
                        print(f"\n✅ Conversation complete (no more tool calls)")
                    break
                
                # Execute tool calls
                if tool_calls:
                    if not self.quiet:
                        print(f"\n🔧 DEBUG: glm-4.5 requested {len(tool_calls)} tool call(s)")
                    
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
                        
                        if not self.quiet:
                            print(f"\n🔧 Tool Call #{i+1}:")
                            print(f"   Name: {tool_call.name}")
                            print(f"   ID: {tool_call.id if hasattr(tool_call, 'id') else 'N/A'}")
                            if hasattr(tool_call, 'input'):
                                print(f"   Input: {json.dumps(tool_call.input, indent=6)}")
                        
                        # Call the tool
                        tool_result_text = await self.call_mcp_tool(
                            tool_call.name,
                            tool_call.input if hasattr(tool_call, 'input') else {}
                        )
                        
                        if not self.quiet:
                            print(f"✓ Result preview: {tool_result_text[:200]}...")
                        
                        # Build tool result for Anthropic API
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_call.id,
                            "content": tool_result_text
                        })
                        
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
