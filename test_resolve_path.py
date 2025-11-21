
import sys
from pathlib import Path

def resolve_file_path(file_path: str, network_dir: Path) -> Path:
    """Smart file path resolution - handles partial paths, filenames, Linux paths, etc."""
    try:
        # Try direct path first
        p = Path(file_path)
        if p.exists() and p.is_file():
            return p
        
        # Extract filename from path
        filename = p.name if p.name else file_path
        
        # Search in zeek_logs extracted_files (most recent first)
        zeek_logs_dir = network_dir / "zeek_logs"
        
        if zeek_logs_dir.exists():
            # 1. Check global extracted_files directory first (most likely location)
            global_extracted_dir = zeek_logs_dir / "extracted_files"
            if global_extracted_dir.exists():
                # Try exact filename match
                candidate = global_extracted_dir / filename
                if candidate.exists():
                    return candidate
                
                # Try pattern matching
                for extracted_file in global_extracted_dir.glob("*"):
                    if filename in extracted_file.name or extracted_file.name in filename:
                        return extracted_file

            # 2. Get all session directories sorted by modification time (newest first)
            session_dirs = sorted(
                [d for d in zeek_logs_dir.glob("session_*") if d.is_dir()],
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )
            
            # Search in each session's extracted_files
            for session_dir in session_dirs:
                extracted_dir = session_dir / "extracted_files"
                if extracted_dir.exists():
                    # Try exact filename match
                    candidate = extracted_dir / filename
                    if candidate.exists():
                        return candidate
                    
                    # Try pattern matching if filename has wildcards or partial match
                    for extracted_file in extracted_dir.glob("*"):
                        if filename in extracted_file.name or extracted_file.name in filename:
                            return extracted_file
        
        # If still not found, try current working directory
        cwd = Path.cwd()
        cwd_candidate = cwd / filename
        if cwd_candidate.exists():
            return cwd_candidate
        
        return None
        
    except Exception as e:
        print(f"Error resolving path: {e}", file=sys.stderr)
        return None

if __name__ == "__main__":
    project_root = Path("e:/Malware_detection_using_Aiagent/Network_Security_poc")
    network_dir = project_root / "network"
    
    # Test with a file we know exists from the previous list_dir output
    # extract-1763703604.736937-HTTP-FcyXIt35juHxD21e1
    test_filename = "extract-1763703604.736937-HTTP-FcyXIt35juHxD21e1"
    
    print(f"Testing resolution for: {test_filename}")
    resolved = resolve_file_path(test_filename, network_dir)
    
    if resolved:
        print(f"✅ SUCCESS: Resolved to {resolved}")
    else:
        print(f"❌ FAILED: Could not resolve {test_filename}")
        
    # Test with a partial name
    partial_name = "FcyXIt35juHxD21e1"
    print(f"\nTesting resolution for partial: {partial_name}")
    resolved_partial = resolve_file_path(partial_name, network_dir)
    
    if resolved_partial:
        print(f"✅ SUCCESS: Resolved to {resolved_partial}")
    else:
        print(f"❌ FAILED: Could not resolve {partial_name}")
