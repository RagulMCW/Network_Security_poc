# Status

✅ Clean folder (6 items only)
✅ 3 tools: analyze_traffic, list_devices, summarize_latest_pcap
✅ **Uses MCP Protocol** (FastMCP client/server)
✅ Fast mode: ~1 second (no AI decision overhead)
✅ Ready to use

## MCP Architecture

```
User → Keyword Match → MCP Client → MCP Server → Tool
                       (line 93)     (line 35)
```

## Usage

```bash
python run_agent.py
```

Commands: `analyze` | `list devices` | `summarize latest pcap` | `quit`
