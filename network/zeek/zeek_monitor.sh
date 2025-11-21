#!/bin/bash

# Zeek Network Monitor (Auto-Rotation Mode)
# Rotates sessions every 2 seconds, keeps last 5 sessions.

INTERFACE="eth0"
ZEEK_LOGS_DIR="/app/zeek_logs"
DURATION=2 # Seconds per session
MAX_SESSIONS=5

echo "Starting Zeek Monitor in Auto-Rotation Mode..."
echo "Interface: $INTERFACE"
echo "Session Duration: $DURATION seconds"
echo "Max Sessions: $MAX_SESSIONS"

# Ensure base directory exists
mkdir -p "$ZEEK_LOGS_DIR"

cleanup_old_sessions() {
    echo "Cleaning up old sessions (keeping last $MAX_SESSIONS)..."
    # List sessions, sort by time (oldest first), head to get the ones to delete
    # We use ls -1dt to sort by time (newest first), then tail to get the oldest
    
    # Count current sessions
    COUNT=$(ls -1d "$ZEEK_LOGS_DIR"/session_* 2>/dev/null | wc -l)
    
    if [ "$COUNT" -gt "$MAX_SESSIONS" ]; then
        REMOVE_COUNT=$((COUNT - MAX_SESSIONS))
        echo "Found $COUNT sessions. Removing oldest $REMOVE_COUNT..."
        
        # Get oldest sessions to remove
        ls -1dt "$ZEEK_LOGS_DIR"/session_* | tail -n "$REMOVE_COUNT" | while read -r DIR; do
            echo "Removing old session: $DIR"
            rm -rf "$DIR"
        done
    fi
}

while true; do
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    SESSION_DIR="$ZEEK_LOGS_DIR/session_$TIMESTAMP"
    
    echo "----------------------------------------"
    echo "Starting new session: $SESSION_DIR"
    mkdir -p "$SESSION_DIR"
    
    # Start Zeek in the background
    # We use -i for interface and write logs to the session directory
    cd "$SESSION_DIR"
    
    echo "Capturing for $DURATION seconds..."
    # Start Zeek as a background process
    /opt/zeek/bin/zeek -i "$INTERFACE" local "Site::local_nets={192.168.0.0/16}" &
    ZEEK_PID=$!
    
    # Wait for the specified duration
    sleep "$DURATION"
    
    # Stop Zeek
    echo "Stopping Zeek (PID: $ZEEK_PID)..."
    kill "$ZEEK_PID" 2>/dev/null
    wait "$ZEEK_PID" 2>/dev/null
    
    # Ensure all logs are flushed/moved if Zeek didn't write them directly (Zeek writes to CWD)
    # Since we cd'd into SESSION_DIR, logs should be there.
    
    # Cleanup old sessions
    cleanup_old_sessions
    
    echo "Session $TIMESTAMP completed."
done
