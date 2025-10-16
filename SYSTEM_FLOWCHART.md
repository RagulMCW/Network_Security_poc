# Network Security POC - System Flowchart

## Complete System Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NETWORK SECURITY POC                             │
│                     Complete System Architecture                         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 1: NETWORK TRAFFIC CAPTURE                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  Network Interface        │
                    │  (Monitoring Network)     │
                    │                           │
                    │  • Captures all packets   │
                    │  • Saves to .pcap files   │
                    └───────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  Packet Capture Storage   │
                    │                           │
                    │  📁 network/captures/     │
                    │  • capture_*.pcap files   │
                    │  • Timestamped files      │
                    └───────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 2: USER INTERACTION (MCP AGENT)                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  User Types Command       │
                    │                           │
                    │  Examples:                │
                    │  • "analyze latest"       │
                    │  • "list captures"        │
                    │  • "analyze all"          │
                    └───────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  MCP Agent Client         │
                    │  (client/agent.py)        │
                    │                           │
                    │  🤖 AI-Powered:           │
                    │  • Understands query      │
                    │  • Decides which tools    │
                    │  • Calls MCP server       │
                    └───────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  MCP Server               │
                    │  (server/server.py)       │
                    │                           │
                    │  Available Tools:         │
                    │  1. analyze_network       │
                    │  2. list_captures         │
                    └───────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 3: PACKET ANALYSIS                                                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  Tool Selection           │
                    │                           │
                    │  IF "analyze":            │
                    │    → analyze.bat          │
                    │                           │
                    │  IF "list":               │
                    │    → list files           │
                    └───────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  analyze.bat              │
                    │  (network/analyze.bat)    │
                    │                           │
                    │  Executes Python script:  │
                    └───────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  analyze_capture.py       │
                    │  (network/scripts/)       │
                    │                           │
                    │  Uses Scapy library to:   │
                    │  • Parse .pcap files      │
                    │  • Extract protocols      │
                    │  • Identify conversations │
                    │  • Detect anomalies       │
                    │  • Calculate statistics   │
                    └───────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 4: ANALYSIS RESULTS                                                │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  Analysis Output          │
                    │                           │
                    │  📊 Generated Data:       │
                    │  • Protocol breakdown     │
                    │  • Top talkers            │
                    │  • Packet counts          │
                    │  • Bandwidth usage        │
                    │  • Security threats       │
                    └───────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  Return to MCP Server     │
                    │                           │
                    │  Raw analysis data        │
                    │  (text format)            │
                    └───────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 5: AI INTERPRETATION                                               │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  MCP Agent Receives Data  │
                    │                           │
                    │  AI interprets results    │
                    └───────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  AI Processing            │
                    │  (Anthropic Claude)       │
                    │                           │
                    │  🧠 AI Analyzes:          │
                    │  • Security threats       │
                    │  • Anomalies detected     │
                    │  • Traffic patterns       │
                    │  • Risk assessment        │
                    └───────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│ STEP 6: USER RESPONSE                                                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  Formatted Response       │
                    │                           │
                    │  📝 User-Friendly Output: │
                    │  • Clear summary          │
                    │  • Security findings      │
                    │  • Recommendations        │
                    │  • Simple language        │
                    └───────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────┐
                    │  Display to User          │
                    │                           │
                    │  Terminal output shown    │
                    └───────────────────────────┘


═══════════════════════════════════════════════════════════════════════════
                          DETAILED COMPONENT BREAKDOWN
═══════════════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────────────┐
│ COMPONENT 1: PACKET CAPTURE SYSTEM                                      │
└─────────────────────────────────────────────────────────────────────────┘

    Purpose: Capture live network traffic
    Location: network/captures/
    Output: .pcap files (packet capture format)
    
    Flow:
    Network Traffic → Capture Tool → .pcap files → Storage


┌─────────────────────────────────────────────────────────────────────────┐
│ COMPONENT 2: MCP AGENT (AI-Powered Interface)                           │
└─────────────────────────────────────────────────────────────────────────┘

    Purpose: Intelligent user interface for security analysis
    Location: mcp_agent/
    
    Components:
    
    ┌────────────────────┐         ┌────────────────────┐
    │  Client            │         │  Server            │
    │  (agent.py)        │ ◄────► │  (server.py)       │
    │                    │         │                    │
    │  • User input      │         │  • Tool execution  │
    │  • AI decisions    │         │  • Script runner   │
    │  • Response format │         │  • Result return   │
    └────────────────────┘         └────────────────────┘
            │                              │
            │                              │
            ▼                              ▼
    ┌────────────────────┐         ┌────────────────────┐
    │  Anthropic Claude  │         │  analyze.bat       │
    │  API (AI Brain)    │         │  (Windows script)  │
    └────────────────────┘         └────────────────────┘


┌─────────────────────────────────────────────────────────────────────────┐
│ COMPONENT 3: ANALYSIS ENGINE                                            │
└─────────────────────────────────────────────────────────────────────────┘

    Purpose: Deep packet inspection and analysis
    Location: network/scripts/analyze_capture.py
    
    Technology: Python + Scapy library
    
    Analysis Performed:
    
    ┌─────────────────────────────────────────────────┐
    │  1. Protocol Analysis                           │
    │     • TCP, UDP, ICMP, HTTP, HTTPS, DNS, etc.   │
    └─────────────────────────────────────────────────┘
                        │
                        ▼
    ┌─────────────────────────────────────────────────┐
    │  2. Conversation Tracking                       │
    │     • Source ↔ Destination pairs               │
    │     • Packet counts per conversation            │
    └─────────────────────────────────────────────────┘
                        │
                        ▼
    ┌─────────────────────────────────────────────────┐
    │  3. Top Talkers Identification                  │
    │     • Most active IP addresses                  │
    │     • Bandwidth consumption                     │
    └─────────────────────────────────────────────────┘
                        │
                        ▼
    ┌─────────────────────────────────────────────────┐
    │  4. Security Analysis                           │
    │     • Port scanning detection                   │
    │     • Unusual patterns                          │
    │     • Potential threats                         │
    └─────────────────────────────────────────────────┘


═══════════════════════════════════════════════════════════════════════════
                            EXAMPLE USER FLOW
═══════════════════════════════════════════════════════════════════════════

1️⃣  User starts agent:
    > start_agent.bat
    
2️⃣  Agent initializes:
    ✓ Loads configuration
    ✓ Connects to AI (Anthropic Claude)
    ✓ Starts MCP server
    ✓ Ready for commands

3️⃣  User types command:
    You: analyze latest capture
    
4️⃣  AI understands and decides:
    🤖 "User wants to analyze the most recent packet capture"
    🤖 "I need to call: analyze_network_traffic(mode='latest')"
    
5️⃣  MCP Server executes:
    • Finds latest .pcap file
    • Runs analyze.bat
    • Executes analyze_capture.py
    • Parses packets with Scapy
    
6️⃣  Analysis completes:
    📊 Results generated:
       - 1250 packets analyzed
       - Protocols: HTTP (45%), HTTPS (30%), DNS (15%), Other (10%)
       - Top talker: 192.168.1.100 (450 packets)
       - No threats detected
       
7️⃣  AI interprets and formats:
    🧠 "This is normal web browsing traffic"
    🧠 "No security concerns detected"
    🧠 "Provide user-friendly summary"
    
8️⃣  User sees response:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Analysis: Latest Capture
    
    📁 File: capture_20251014_091140.pcap
    📊 Packets: 1,250
    
    Protocols Detected:
    • HTTP: 45% (web traffic)
    • HTTPS: 30% (secure web)
    • DNS: 15% (domain lookups)
    • Other: 10%
    
    Top Active Devices:
    • 192.168.1.100: 450 packets
    • 192.168.1.105: 320 packets
    
    🛡️ Security Status: ✓ NO THREATS
    
    This appears to be normal web browsing
    activity with no suspicious patterns.
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


═══════════════════════════════════════════════════════════════════════════
                              DATA FLOW DIAGRAM
═══════════════════════════════════════════════════════════════════════════

Network     Capture      MCP          Analysis      AI           User
Traffic  →  Storage   →  Agent    →   Engine    →  Brain   →   Display

  🌐    →    💾      →    🤖      →     🔬      →    🧠    →     💬
Packets   .pcap files   Commands   Scapy tool   Claude AI   Terminal


═══════════════════════════════════════════════════════════════════════════
                           KEY TECHNOLOGIES USED
═══════════════════════════════════════════════════════════════════════════

┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
│  Python 3.13.6      │  │  FastMCP 2.12.4     │  │  Anthropic Claude   │
│  Programming        │  │  MCP Framework      │  │  AI Model           │
└─────────────────────┘  └─────────────────────┘  └─────────────────────┘

┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
│  Scapy 2.6.1        │  │  .pcap Format       │  │  Batch Scripts      │
│  Packet Analysis    │  │  Packet Storage     │  │  Windows Automation │
└─────────────────────┘  └─────────────────────┘  └─────────────────────┘


═══════════════════════════════════════════════════════════════════════════
                            SYSTEM ADVANTAGES
═══════════════════════════════════════════════════════════════════════════

✅ AI-Powered Analysis
   • Natural language interface
   • Intelligent interpretation
   • User-friendly summaries

✅ Automated Security Monitoring
   • Real-time packet analysis
   • Threat detection
   • Anomaly identification

✅ Flexible Architecture
   • Easy to extend
   • Modular components
   • Scalable design

✅ Simple User Experience
   • Type commands in plain English
   • No technical knowledge required
   • Clear, actionable results


═══════════════════════════════════════════════════════════════════════════
                          FILE STRUCTURE REFERENCE
═══════════════════════════════════════════════════════════════════════════

Network_Security_poc/
│
├── mcp_agent/                    ← AI Agent (Main Interface)
│   ├── client/agent.py          ← User interaction & AI logic
│   ├── server/server.py         ← Tool execution & script runner
│   ├── run_agent.py             ← Agent launcher
│   └── start_agent.bat          ← Quick start script
│
├── network/                      ← Analysis System
│   ├── captures/*.pcap          ← Captured packet files
│   ├── scripts/analyze_capture.py ← Packet analysis engine
│   └── analyze.bat              ← Analysis executor
│
└── config/.env                   ← API keys & configuration


═══════════════════════════════════════════════════════════════════════════
                              QUICK START
═══════════════════════════════════════════════════════════════════════════

To use the system:

1. Start the agent:
   > cd E:\nos\Network_Security_poc\mcp_agent
   > start_agent.bat

2. Type commands:
   You: analyze latest capture
   You: list captures
   You: analyze all

3. Get AI-powered security insights instantly!

═══════════════════════════════════════════════════════════════════════════
