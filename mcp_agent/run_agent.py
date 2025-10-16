#!/usr/bin/env python3
"""
MCP Agent Launcher

Simple launcher for the network security monitoring MCP agent.
"""

import os
import sys
import subprocess
from pathlib import Path

# Try to import dotenv, but don't fail if not available
try:
    from dotenv import load_dotenv
    dotenv_available = True
except ImportError:
    dotenv_available = False
    print("Warning: python-dotenv not installed. Install with: pip install python-dotenv")

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Load environment variables if dotenv is available
if dotenv_available:
    load_dotenv(project_root / "config" / ".env")
    load_dotenv()  # Also load from current directory


def check_configuration():
    """Check if the agent is properly configured."""
    issues = []
    
    # Check API key
    if not os.getenv("ANTHROPIC_API_KEY"):
        issues.append("ANTHROPIC_API_KEY environment variable not set")
        issues.append("  -> Set it in your .env file or environment")
    
    # Check if network captures directory exists
    captures_path = project_root.parent / "network" / "captures"
    if not captures_path.exists():
        issues.append(f"Network captures directory not found: {captures_path}")
        issues.append("  -> This is okay if you haven't started network monitoring yet")
    
    return issues


def main():
    """Main launcher function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Network Security Monitor MCP Agent")
    parser.add_argument("--quiet", action="store_true", 
                       help="Run in quiet mode with concise summaries")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Network Security Monitor - MCP Agent")
    print("=" * 60)
    
    # Check configuration
    issues = check_configuration()
    if issues:
        print("\nConfiguration Status:")
        for issue in issues:
            print(f"   {issue}")
        
        # Check if there are critical issues
        critical = any("ANTHROPIC_API_KEY" in issue for issue in issues)
        if critical:
            print("\nERROR: Critical configuration issues found. Please fix and try again.")
            return 1
        else:
            print("\nNon-critical warnings only. Continuing...")
    else:
        print("\nConfiguration looks good!")
    
    print("\nStarting Agent...")
    print("=" * 60)
    print("Commands: analyze | list devices | summarize latest pcap | quit")
    print("=" * 60)
    
    # Start the agent
    try:
        agent_path = project_root / "client" / "agent.py"
        env = os.environ.copy()
        env["MCP_AGENT_QUIET"] = "1" if args.quiet else "0"
        subprocess.run([sys.executable, str(agent_path)], env=env)
        return 0
    except KeyboardInterrupt:
        print("\n\nAgent stopped by user. Goodbye!")
        return 0
    except Exception as e:
        print(f"\nERROR running agent: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
