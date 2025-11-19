# Zeek Network Monitor

Real-time network traffic analysis for Docker networks using Zeek IDS.

## Overview

This monitoring system captures and analyzes network traffic from Docker bridge interfaces, generating detailed logs every 2-3 seconds. It runs on WSL (Windows Subsystem for Linux) and automatically saves analysis results to Windows.

## Features

- Continuous real-time packet capture
- Automated Zeek log generation every 2-3 seconds
- Automatic Windows folder synchronization
- Session-based log organization
- Automatic cleanup (keeps last 5 sessions)
- Passwordless operation after initial setup

## Requirements

- Windows 10/11 with WSL2
- Docker Desktop running
- Zeek 8.0+ installed in WSL
- Passwordless sudo configured
- Network named "custom_net" in Docker

## Quick Start

### Start Monitoring

Double-click START.bat or run from command line

A new window will open showing the monitor running. Keep this window open.

### Stop Monitoring

Double-click STOP.bat or run from command line

Alternatively, close the monitor window or press Ctrl+C.

## Output

### Log Location

Logs are automatically saved to zeek_logs folder with the following structure:

- session_YYYYMMDD_HHMMSS/
  - conn.log (Connection records)
  - http.log (HTTP transactions)
  - files.log (File transfers)
  - packet_filter.log (Filter statistics)
  - weird.log (Unusual activity if detected)

### Session Management

- New session created every 2-3 seconds
- Only last 5 sessions are kept
- Older sessions automatically deleted
- Sessions stored in both WSL and Windows

## Architecture

### Components

1. zeek_monitor.sh
   - Main monitoring script
   - Runs on WSL host
   - Captures traffic via tcpdump
   - Processes with Zeek analyzer

2. START.bat
   - Windows launcher
   - Opens persistent monitor window
   - No password required

3. STOP.bat
   - Graceful shutdown
   - Kills all monitor processes
   - Preserves existing logs

### Workflow

Docker Bridge (custom_net) -> tcpdump (2-second rotation) -> PCAP files -> Zeek Analyzer -> Log Files -> Auto-copy to Windows

## Configuration

### Network Settings

Edit zeek_monitor.sh to change the monitored network

Default: NETWORK_NAME="custom_net"

### Session Retention

Modify the number of sessions to keep

Default: MAX_SESSIONS=5

### Capture Interval

Change tcpdump rotation interval in seconds

Default: -G 2 (2 seconds)

## Troubleshooting

### Monitor won't start

Check if Zeek is installed:
wsl zeek --version

Check if custom_net exists:
wsl docker network ls | grep custom_net

### No logs generated

Verify devices are sending traffic:
wsl docker ps

Check tcpdump is running:
wsl ps aux | grep tcpdump

### Permission errors

Configure passwordless sudo in WSL

## Technical Details

### Zeek Analysis

- Runs in offline mode
- Processes PCAP files from tcpdump
- Generates standard Zeek logs
- No network connection required

### Performance

- Minimal CPU usage (2-5%)
- Low memory footprint (approximately 100MB)
- Handles high-frequency traffic
- Automatic resource cleanup

### Security

- Only captures Docker bridge traffic
- SSH traffic excluded (port 22)
- Local processing only
- No external connections

## Integration

### MCP Agent

The monitoring system integrates with the MCP (Model Context Protocol) agent for reading and analyzing logs.

### Custom Scripts

Access logs programmatically by reading from the zeek_logs folder.

## Maintenance

### Clean All Logs

Delete all session folders from zeek_logs directory

### View Monitor Status

wsl ps aux | grep zeek_monitor

### Manual Start (for debugging)

wsl sudo bash zeek_monitor.sh

## Version

1.0 - Initial release with continuous monitoring, auto Windows sync, session management, and professional cleanup

## License

Part of Network Security POC project
