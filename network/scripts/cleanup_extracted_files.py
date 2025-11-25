import os
import time
import sys
from pathlib import Path

# Configuration
# Adjust path relative to this script: ../zeek_logs/extracted_files
BASE_DIR = Path(__file__).parent.parent
EXTRACTED_DIR = BASE_DIR / "zeek_logs" / "extracted_files"
MAX_FILES = 5
CHECK_INTERVAL = 2  # Seconds

def cleanup_files():
    """Keep only the 5 most recent files in the directory."""
    if not EXTRACTED_DIR.exists():
        print(f"Waiting for directory: {EXTRACTED_DIR}")
        return

    try:
        # Get list of files with full paths
        files = [f for f in EXTRACTED_DIR.iterdir() if f.is_file() and f.name.startswith("extract-")]
        
        # Sort by modification time (newest first)
        files.sort(key=lambda f: f.stat().st_mtime, reverse=True)
        
        # Check if we have more than MAX_FILES
        if len(files) > MAX_FILES:
            files_to_delete = files[MAX_FILES:]
            
            print(f"Found {len(files)} files. Cleaning up {len(files_to_delete)} old files...")
            
            for file_path in files_to_delete:
                try:
                    file_path.unlink()
                    print(f"🗑️ Deleted: {file_path.name}")
                except Exception as e:
                    print(f"❌ Error deleting {file_path.name}: {e}")
                    
    except Exception as e:
        print(f"Error during cleanup: {e}")

def main():
    print(f"🧹 Starting Auto-Cleanup Service")
    print(f"📂 Monitoring: {EXTRACTED_DIR}")
    print(f"🔢 Max Files: {MAX_FILES}")
    print("Press Ctrl+C to stop")
    print("-" * 50)
    
    while True:
        cleanup_files()
        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Cleanup service stopped.")
