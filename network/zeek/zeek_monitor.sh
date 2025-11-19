#!/bin/bash
# Zeek Network Monitor for Docker Networks
# Captures and analyzes network traffic from Docker bridge interface
# Version: 1.0

set +e
export PATH=/opt/zeek/bin:$PATH

# Configuration
NETWORK_NAME="custom_net"
OUTPUT_DIR="/tmp/zeek_output"
WINDOWS_DIR="/mnt/e/Malware_detection_using_Aiagent/Network_Security_poc/network/zeek_logs"
PCAP_DIR="/tmp/zeek_pcaps"
PROCESSED_FILE="/tmp/zeek_processed.txt"
MAX_SESSIONS=5

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

validate_network() {
    if ! docker network inspect "$NETWORK_NAME" &>/dev/null; then
        log_message "ERROR: Network '$NETWORK_NAME' not found"
        exit 1
    fi
    
    BRIDGE_IFACE=$(docker network inspect "$NETWORK_NAME" -f '{{.Id}}' | cut -c1-12)
    BRIDGE_NAME="br-${BRIDGE_IFACE}"
    
    if ! ip link show "$BRIDGE_NAME" &>/dev/null; then
        log_message "ERROR: Bridge interface '$BRIDGE_NAME' not found"
        exit 1
    fi
    
    log_message "Monitoring: $NETWORK_NAME ($BRIDGE_NAME)"
}

setup_directories() {
    mkdir -p "$OUTPUT_DIR" "$PCAP_DIR" "$WINDOWS_DIR"
    touch "$PROCESSED_FILE"
}

cleanup_old_sessions() {
    local wsl_count=$(ls -1d "$OUTPUT_DIR"/session_* 2>/dev/null | wc -l)
    local win_count=$(ls -1d "$WINDOWS_DIR"/session_* 2>/dev/null | wc -l)
    
    [ "$wsl_count" -gt "$MAX_SESSIONS" ] && ls -1td "$OUTPUT_DIR"/session_* | tail -n +$((MAX_SESSIONS + 1)) | xargs rm -rf 2>/dev/null
    [ "$win_count" -gt "$MAX_SESSIONS" ] && ls -1td "$WINDOWS_DIR"/session_* | tail -n +$((MAX_SESSIONS + 1)) | xargs rm -rf 2>/dev/null
}

start_tcpdump() {
    if ! pgrep -f "tcpdump.*$BRIDGE_NAME" >/dev/null; then
        tcpdump -i "$BRIDGE_NAME" -s 0 -G 2 -w "$PCAP_DIR/capture_%Y%m%d_%H%M%S.pcap" not port 22 >/dev/null 2>&1 &
        log_message "tcpdump started (PID: $!)"
    fi
}

process_pcap() {
    local pcap="$1"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local session_dir="$OUTPUT_DIR/session_$timestamp"
    
    mkdir -p "$session_dir"
    log_message "Analyzing: $(basename $pcap)"
    
    cd "$session_dir" && zeek -C -r "$pcap" 2>/dev/null || true
    
    if [ $(ls -1 "$session_dir"/*.log 2>/dev/null | wc -l) -gt 0 ]; then
        cp -r "$session_dir" "$WINDOWS_DIR/session_$timestamp" 2>/dev/null || true
        log_message "Session created: session_$timestamp"
    fi
    
    echo "$pcap" >> "$PROCESSED_FILE"
}

monitor_loop() {
    log_message "Starting continuous monitoring"
    
    while true; do
        start_tcpdump
        
        mapfile -t pcap_files < <(find "$PCAP_DIR" -name "*.pcap" -type f 2>/dev/null || true)
        
        for pcap in "${pcap_files[@]}"; do
            [ -f "$pcap" ] || continue
            grep -Fxq "$pcap" "$PROCESSED_FILE" 2>/dev/null && continue
            
            sleep 1
            process_pcap "$pcap"
        done
        
        cleanup_old_sessions
        sleep 2
    done
}

# Main execution
validate_network
setup_directories
monitor_loop
