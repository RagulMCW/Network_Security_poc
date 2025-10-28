#!/usr/bin/env python3
"""
MCP Agent Query Tool

Simple CLI tool to query the MCP agent with a single question and get a response.
Used by the dashboard to forward user queries to the autonomous agent.
"""

import asyncio
import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).parent / "config" / ".env")
    load_dotenv()
except ImportError:
    pass

from client.agent import MCPAgent


async def query_agent(user_query: str) -> str:
    """
    Query the agent with a single question and return the response.
    
    Args:
        user_query: The user's question
        
    Returns:
        The agent's response as a string
    """
    try:
        agent = MCPAgent(quiet=True)  # Quiet mode - just return the response
        response = await agent.process_query(user_query)
        return response
    except Exception as e:
        return f"❌ Agent Error: {str(e)}"


def main():
    """Main CLI entry point."""
    # Set UTF-8 encoding for stdout to handle Unicode characters (emojis, etc.)
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    
    if len(sys.argv) < 2:
        print("Usage: python query_agent.py <your question>")
        print("\nExample:")
        print("  python query_agent.py \"analyze network traffic\"")
        print("  python query_agent.py \"what devices are connected?\"")
        sys.exit(1)
    
    # Join all arguments as the query (allows spaces without quotes)
    query = " ".join(sys.argv[1:])
    
    # Run the async query
    response = asyncio.run(query_agent(query))
    
    # Print response (dashboard will capture this)
    print(response)


if __name__ == "__main__":
    main()
