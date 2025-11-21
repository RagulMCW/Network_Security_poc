import os
from pathlib import Path
from datetime import datetime
import time

class MockServer:
    def __init__(self):
        self.project_root = Path(r"e:\Malware_detection_using_Aiagent\Network_Security_poc")
        self.network_dir = self.project_root / "network"

    def _read_zeek_logs(self, log_type: str = "all") -> str:
        """Read current Zeek logs in real-time from Windows zeek_logs directory"""
        try:
            # Path to Windows Zeek logs (auto-synced from WSL)
            zeek_logs_dir = self.project_root / "network" / "zeek_logs"
            
            if not zeek_logs_dir.exists():
                return "⚠️ Zeek logs directory not found."
            
            # Get all session directories (sorted by newest first)
            session_dirs = sorted(
                [d for d in zeek_logs_dir.glob("session_*") if d.is_dir()],
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )
            
            if not session_dirs:
                return "No Zeek sessions found yet."
            
            # Read latest 5 sessions for real-time analysis
            sessions_to_read = session_dirs[:5]
            
            result = f"🔍 REAL-TIME ZEEK ANALYSIS - {len(sessions_to_read)} Latest Sessions\n{'='*80}\n\n"
            
            total_entries = 0
            
            for session_dir in sessions_to_read:
                session_name = session_dir.name
                session_time = datetime.fromtimestamp(session_dir.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                
                result += f"\n📦 {session_name} (Created: {session_time})\n{'-'*80}\n"
                
                # Read ALL .log files in the session directory
                all_log_files = sorted(session_dir.glob("*.log"))
                
                if not all_log_files:
                    result += "  No log files found in this session\n"
                    continue
                
                for log_path in all_log_files:
                    log_file = log_path.name
                    
                    try:
                        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        # Parse data lines (skip comments starting with #)
                        lines = content.split('\n')
                        data_lines = [line for line in lines if line.strip() and not line.startswith('#')]
                        
                        if not data_lines:
                            result += f"\n  📄 {log_file}: [empty]\n"
                            continue
                        
                        total_entries += len(data_lines)
                        
                        result += f"\n  📄 {log_file}: {len(data_lines)} entries\n"
                        
                        # Show header and recent entries (last 20)
                        header_lines = [line for line in lines if line.startswith('#')]
                        if header_lines:
                            result += "\n".join(header_lines[:10]) + "\n\n"
                        
                        # Show latest entries
                        recent_entries = data_lines[-20:]
                        result += "\n".join(recent_entries) + "\n"
                        
                    except Exception as e:
                        result += f"  ⚠️ Error reading {log_file}: {str(e)}\n"
                
                # Check for extracted_files directory
                extracted_dir = session_dir / "extracted_files"
                if extracted_dir.exists() and extracted_dir.is_dir():
                    extracted_files = list(extracted_dir.glob("*"))
                    if extracted_files:
                        result += f"\n  📦 Extracted Files: {len(extracted_files)} files\n"
                        result += f"  {'─'*60}\n"
                        
                        for extracted_file in extracted_files[:10]:  # Show first 10
                            try:
                                file_size = extracted_file.stat().st_size
                                with open(extracted_file, 'r', encoding='utf-8', errors='ignore') as f:
                                    file_content = f.read()
                                
                                # Check for EICAR in extracted files
                                has_eicar = "EICAR" in file_content
                                eicar_marker = " ⚠️ EICAR!" if has_eicar else ""
                                
                                result += f"\n  📄 {extracted_file.name} ({file_size}B){eicar_marker}\n"
                                
                                # Show content preview (first 300 chars)
                                preview = file_content[:300]
                                if len(file_content) > 300:
                                    preview += "..."
                                result += f"     {preview}\n"
                                
                            except Exception as e:
                                result += f"  ⚠️ {extracted_file.name}: {str(e)}\n"
                        
                        if len(extracted_files) > 10:
                            result += f"\n  ... and {len(extracted_files) - 10} more files\n"
            
            result += f"\n{'='*80}\n"
            result += f"📊 Summary: {total_entries} total log entries across {len(sessions_to_read)} sessions\n"
            result += f"{'='*80}\n"
            
            return result
        except Exception as e:
            return f"Error: {e}"

if __name__ == "__main__":
    start_time = time.time()
    server = MockServer()
    print("Starting read_zeek_logs...")
    output = server._read_zeek_logs()
    end_time = time.time()
    print(f"Finished in {end_time - start_time:.4f} seconds")
    print(f"Output length: {len(output)} chars")
    # print(output[:2000]) # Print first 2000 chars
