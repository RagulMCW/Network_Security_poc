#!/usr/bin/env python3
"""Show recent SSH commands and LLM responses"""

import json

log_file = r'e:\Malware_detection_using_Aiagent\Network_Security_poc\honey_pot\logs\beelzebub.log'

print("=" * 80)
print("Last 5 SSH Commands with LLM Responses from endpoint_behavior_attacker")
print("=" * 80)
print()

count = 0
with open(log_file, 'r') as f:
    lines = f.readlines()
    
    # Get last 200 lines and filter
    for line in lines[-200:]:
        if '172.18.0.3' in line and 'SSH Raw Command' in line:
            try:
                event = json.loads(line)
                cmd = event['event'].get('Command', '').strip()
                output = event['event'].get('CommandOutput', '').strip()
                
                if cmd and output:  # Only show if both exist
                    count += 1
                    print(f"[{count}] Command: {cmd}")
                    print(f"    LLM Response:")
                    # Show first 200 chars of response
                    if len(output) > 200:
                        print(f"    {output[:200]}...")
                    else:
                        print(f"    {output}")
                    print("-" * 80)
                    print()
                    
                    if count >= 5:
                        break
            except:
                continue

if count == 0:
    print("No SSH commands with responses found in recent logs")
else:
    print(f"✅ Found {count} recent SSH commands with LLM responses")
    print()
    print("Traffic is flowing successfully:")
    print("  • Attacker executes SSH commands")
    print("  • Beelzebub honeypot captures them")
    print("  • Ollama LLM generates realistic responses")
    print("  • All logged for analysis")
