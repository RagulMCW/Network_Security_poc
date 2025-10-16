#!/usr/bin/env python3
"""
Intelligent MCP Agent Client

Network Security Monitor - Uses AI to analyze packet captures and provide security insights.
"""

import asyncio
import json
import os
import sys
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
            
            # Direct tool mapping - no AI decision needed
            if any(word in query_lower for word in ['summarize', 'summary', 'latest pcap']):
                if not self.quiet:
                    print("Summarizing latest pcap...")
                result = await self.call_mcp_tool("summarize_latest_pcap")
                return result

            elif any(word in query_lower for word in ['analyze', 'threat', 'attack', 'anomal', 'security']):
                if not self.quiet:
                    print("Retrieving analysis output...")
                output_path = r"E:\nos\Network_Security_poc\network\analyze_output.txt"
                try:
                    with open(output_path, "r", encoding="utf-8") as f:
                        data = f.read()
                    if not data.strip():
                        return "No analysis output found. Please run the analysis manually."
                    # Summarize using LLM
                    prompt = (
                        "You are a network security and observability agent. "
                        "Summarize the following network analysis report for a non-technical user. "
                        "Clearly state how many devices are connected, any problems or intrusions detected, which IPs carry the most packets, and any other important findings.\n\n" + data
                    )
                    response = self.anthropic_client.messages.create(
                        model="glm-4.5",
                        max_tokens=512,
                        temperature=0.1,
                        system="You are a helpful network security assistant.",
                        messages=[{"role": "user", "content": prompt}]
                    )
                    # Extract summary from response
                    if hasattr(response, "content"):
                        try:
                            summary = response.content[0].text
                        except Exception:
                            summary = str(response.content)
                    else:
                        summary = str(response)
                    return summary
                except Exception as e:
                    return f"Error reading or summarizing analysis output: {e}"

            elif any(word in query_lower for word in ['device', 'connect', 'list']):
                if not self.quiet:
                    print("Getting devices...")
                result = await self.call_mcp_tool("list_devices")
                return result

            else:
                return "Available commands:\n- analyze (analyze network traffic)\n- list devices (show connected devices)\n- summarize latest pcap (send pcap to LLM)"
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
            print("Commands: analyze | list devices | summarize latest pcap | quit")
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
