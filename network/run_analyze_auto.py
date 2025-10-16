import os
import time
import subprocess
from pathlib import Path

NETWORK_DIR = Path(__file__).parent
CAPTURES_DIR = NETWORK_DIR / "captures"
ANALYZE_BAT = NETWORK_DIR / "analyze_auto.bat"
OUTPUT_FILE = NETWORK_DIR / "analyze_output.txt"

# Track last processed pcap
last_processed = None

def get_latest_pcap():
    files = sorted(CAPTURES_DIR.glob("*.pcap*"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None

def run_analysis():
    result = subprocess.run([str(ANALYZE_BAT)], capture_output=True, text=True, shell=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(result.stdout)
        f.write("\n---\n")
        f.write(result.stderr)

if __name__ == "__main__":
    while True:
        latest_pcap = get_latest_pcap()
        if latest_pcap and (last_processed is None or latest_pcap != last_processed):
            run_analysis()
            last_processed = latest_pcap
        time.sleep(5)  # Check every 5 seconds
