
# Network Security Monitor - MCP Agent

## Overview
A professional AI-powered agent for network security analysis. It analyzes network packet captures, detects threats, and provides actionable insights in plain language. Designed for simplicity, speed, and clarity.

## Features
- **Packet Capture Analysis**: Detects threats and anomalies in .pcap files
- **Device Listing**: Shows all connected devices
- **AI Summarization**: Converts technical analysis into simple, actionable reports
- **Fast, Clean Interface**: No unnecessary tools or overhead

## Quick Start
1. **Clone the repository**
2. **Configure your environment**
   - Copy `config/env.example` to `config/.env`
   - Add your Anthropic API key to `.env` as `ANTHROPIC_API_KEY=your_api_key_here`
3. **Install dependencies**
   - `pip install -r config/requirements.txt`
4. **Run the agent**
   - `python mcp_agent/run_agent.py`

## Usage
- **analyze**: Summarize the latest network analysis output (from `network/analyze_output.txt`)
- **list devices**: Show all connected devices
- **quit**: Exit the agent

## Example Workflow
1. Run your packet capture and analysis scripts (see `network/README.md`)
2. Use the agent to get a summarized security report:
   - `You: analyze`
   - Agent responds with a clear summary of threats, device count, and top IPs

## Project Structure
```
Network_Security_poc/
├── mcp_agent/
│   ├── client/agent.py        # MCP agent client
│   ├── server/server.py       # MCP server (optional)
│   ├── config/.env            # API key configuration
│   ├── run_agent.py           # Main launcher
├── network/
│   ├── analyze_auto.bat       # Analysis batch script
│   ├── analyze_output.txt     # Latest analysis output
│   ├── captures/              # Packet capture files (.pcap)
```

## Requirements
- Python 3.8+
- Anthropic API key
- Scapy
- FastMCP
- Network packet captures (.pcap)

## Professional Notes
- All unnecessary markdown files and documentation have been removed for clarity.
- This README is the single source of truth for setup and usage.
- For advanced network setup, see `network/README.md`.

## Support
For issues or questions, contact the project maintainer.
