#!/usr/bin/env python3
"""
Extract LLM Responses from Beelzebub Logs
Creates a clean log of all AI-generated responses
"""

import json
import os
from pathlib import Path
from datetime import datetime

LOGS_DIR = Path(__file__).parent / "logs"
BEELZEBUB_LOG = LOGS_DIR / "beelzebub.log"
LLM_LOG = LOGS_DIR / "llm_responses.jsonl"

def extract_llm_logs():
    """Extract all LLM responses from beelzebub.log"""
    
    if not BEELZEBUB_LOG.exists():
        print(f"❌ Log file not found: {BEELZEBUB_LOG}")
        return
    
    llm_count = 0
    
    with open(BEELZEBUB_LOG, 'r', encoding='utf-8', errors='ignore') as f_in:
        with open(LLM_LOG, 'w', encoding='utf-8') as f_out:
            for line in f_in:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    log_entry = json.loads(line)
                    event = log_entry.get('event', {})
                    
                    # Only entries with CommandOutput (AI responses)
                    if event.get('CommandOutput') and event.get('Command'):
                        llm_entry = {
                            'time': event.get('DateTime'),
                            'source_ip': event.get('SourceIp'),
                            'user': event.get('User'),
                            'protocol': event.get('Protocol'),
                            'command': event.get('Command'),
                            'ai_response': event.get('CommandOutput'),
                            'msg': event.get('Msg')
                        }
                        
                        f_out.write(json.dumps(llm_entry) + '\n')
                        llm_count += 1
                        
                except json.JSONDecodeError:
                    continue
    
    print(f"✅ Extracted {llm_count} LLM responses → {LLM_LOG.name}")
    
    # Show last 5 responses
    if llm_count > 0:
        print(f"\n📋 Last 5 AI Responses:")
        with open(LLM_LOG, 'r') as f:
            lines = f.readlines()
            for line in lines[-5:]:
                try:
                    entry = json.loads(line)
                    print(f"\n🕐 {entry['time']}")
                    print(f"   Command: {entry['command'][:60]}...")
                    print(f"   Response: {entry['ai_response'][:80]}...")
                except:
                    pass

if __name__ == '__main__':
    print("🔍 Extracting LLM responses from honeypot logs...\n")
    extract_llm_logs()
