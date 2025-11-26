#!/usr/bin/env python3
"""
Endpoint Behavior-Based Malware Simulator (Case 2 - Anomaly Detection)

This simulator demonstrates malicious endpoint behaviors WITHOUT using real malware files.
Instead, it uses DUMMY files and focuses on behavioral anomalies that should trigger
anomaly-based detection systems.

Malicious Behaviors Simulated:
1. C2 Beacon - Command & Control communication
2. Data Exfiltration - Stealing data disguised as backup
3. DNS DGA Attacks - Domain Generation Algorithm queries
4. Port Scanning - Rapid scanning of multiple ports
5. Credential Harvesting - Suspicious file access patterns
6. Privilege Escalation Attempts - Repeated permission requests
7. Lateral Movement - Attempting to access other network devices
8. Data Staging - Collecting files in unusual locations
9. Abnormal API Usage - High-frequency suspicious API calls
"""

import requests
import socket
import time
import random
import hashlib
import json
import os
import subprocess
import uuid
from datetime import datetime
from threading import Thread

# Configuration
TARGET_IP = os.getenv('TARGET_IP', '192.168.6.131')
TARGET_PORT = os.getenv('TARGET_PORT', '5000')
C2_INTERVAL = int(os.getenv('C2_INTERVAL', '5'))
EXFIL_INTERVAL = int(os.getenv('EXFIL_INTERVAL', '15'))
DNS_INTERVAL = int(os.getenv('DNS_INTERVAL', '20'))
SCAN_INTERVAL = int(os.getenv('SCAN_INTERVAL', '10'))
API_ABUSE_INTERVAL = int(os.getenv('API_ABUSE_INTERVAL', '5'))
CREDENTIAL_ACCESS_INTERVAL = int(os.getenv('CREDENTIAL_ACCESS_INTERVAL', '8'))

LOG_FILE = "/app/logs/behavior_simulator.log"

def log_message(message):
    """Log message with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    print(log_entry)
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(log_entry + "\n")
    except:
        pass

def generate_dummy_file():
    """Generate a dummy file with benign content"""
    content = f"Dummy file generated at {datetime.now()}\n"
    content += f"Random data: {random.randint(1000000, 9999999)}\n"
    content += "This is NOT malware. Just a dummy file for testing.\n"
    return content.encode()

# ============================================================================
# BEHAVIOR 1: C2 Beacon (Command & Control)
# ============================================================================
def c2_beacon_behavior():
    """
    Simulate C2 beacon - Command & Control communication
    Disguised as analytics/telemetry but with suspicious patterns
    """
    log_message("[BEHAVIOR] Starting C2 Beacon Thread")
    
    counter = 0
    
    while True:
        try:
            counter += 1
            
            # Create beacon payload
            beacon_data = {
                "type": "heartbeat",
                "device_id": f"endpoint-{random.randint(1000, 9999)}",
                "timestamp": datetime.now().isoformat(),
                "sequence": counter,
                "status": "active"
            }
            
            url = f"http://{TARGET_IP}:{TARGET_PORT}/api/v1/telemetry/events"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'X-Session-ID': str(uuid.uuid4()),
                'Content-Type': 'application/json'
            }
            
            response = requests.post(url, json=beacon_data, headers=headers, timeout=5)
            
            log_message(f"[C2 BEACON] Heartbeat #{counter} sent - Status: {response.status_code}")
            
            time.sleep(C2_INTERVAL)
            
        except Exception as e:
            log_message(f"[C2 BEACON] Error: {e}")
            time.sleep(C2_INTERVAL)

# ============================================================================
# BEHAVIOR 2: Data Exfiltration
# ============================================================================
def data_exfiltration_behavior():
    """
    Simulate data exfiltration - Disguised as cloud backup/sync
    Sends chunks of dummy data to simulate data theft
    """
    log_message("[BEHAVIOR] Starting Data Exfiltration Thread")
    
    counter = 0
    file_types = ["credentials.txt", "documents.pdf", "database.sql", "config.json", "keys.pem"]
    
    while True:
        try:
            counter += 1
            
            # Generate dummy exfiltration data
            data_size = random.randint(1000, 5000)
            dummy_data = generate_dummy_file()
            
            exfil_payload = {
                "type": "sync",
                "filename": random.choice(file_types),
                "data": dummy_data.decode('utf-8', errors='ignore')[:1000],  # Truncate for transport
                "size": data_size,
                "batch": counter,
                "timestamp": datetime.now().isoformat()
            }
            
            url = f"http://{TARGET_IP}:{TARGET_PORT}/api/v2/storage/sync"
            headers = {
                'User-Agent': 'CloudBackup-Agent/4.7.2 (Windows NT 10.0; Win64; x64)',
                'X-Sync-Session': str(uuid.uuid4()),
                'Content-Type': 'application/json'
            }
            
            response = requests.post(url, json=exfil_payload, headers=headers, timeout=5)
            
            log_message(f"[DATA EXFIL] Batch #{counter} - {data_size} bytes - Status: {response.status_code}")
            
            time.sleep(EXFIL_INTERVAL)
            
        except Exception as e:
            log_message(f"[DATA EXFIL] Error: {e}")
            time.sleep(EXFIL_INTERVAL)

# ============================================================================
# BEHAVIOR 3: DNS DGA Attacks (Domain Generation Algorithm)
# ============================================================================
def dns_dga_behavior():
    """
    Simulate DNS NXDOMAIN attacks - Domain Generation Algorithm
    Creates suspicious DNS queries to non-existent domains
    """
    log_message("[BEHAVIOR] Starting DNS DGA Thread")
    
    counter = 0
    
    while True:
        try:
            counter += 1
            
            # Generate random domain names (DGA simulation)
            domains = [
                f"cdn-{uuid.uuid4().hex[:8]}.cloudfront.net",
                f"api-{uuid.uuid4().hex[:8]}.amazonaws.com",
                f"assets-{uuid.uuid4().hex[:8]}.azureedge.net",
                f"media-{uuid.uuid4().hex[:8]}.gcp.cloud",
                f"sync-{uuid.uuid4().hex[:8]}.dropbox.com"
            ]
            
            log_message(f"[DNS DGA] Attack round #{counter} - Querying {len(domains)} random domains")
            
            for domain in domains:
                try:
                    # Try DNS lookup (will fail - NXDOMAIN)
                    socket.gethostbyname(domain)
                except socket.gaierror:
                    # Expected - domain doesn't exist
                    log_message(f"[DNS DGA] NXDOMAIN query: {domain}")
                except Exception:
                    pass
            
            time.sleep(DNS_INTERVAL)
            
        except Exception as e:
            log_message(f"[DNS DGA] Error: {e}")
            time.sleep(DNS_INTERVAL)

# ============================================================================
# BEHAVIOR 4: Port Scanning (Reconnaissance)
# ============================================================================
def port_scanning_behavior():
    """
    Simulate port scanning behavior - a common reconnaissance technique
    Rapidly scans multiple ports to identify open services
    """
    log_message("[BEHAVIOR] Starting Port Scanning Thread")
    
    ports_to_scan = [21, 22, 23, 25, 80, 443, 445, 3389, 5000, 8080, 8443, 9000]
    
    while True:
        try:
            log_message(f"[PORT SCAN] Scanning {len(ports_to_scan)} ports on {TARGET_IP}")
            
            for port in ports_to_scan:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((TARGET_IP, port))
                
                if result == 0:
                    log_message(f"[PORT SCAN] Port {port} is OPEN")
                else:
                    log_message(f"[PORT SCAN] Port {port} is closed")
                
                sock.close()
                time.sleep(0.1)  # Small delay between scans
            
            log_message(f"[PORT SCAN] Completed scan of {len(ports_to_scan)} ports")
            time.sleep(SCAN_INTERVAL)
            
        except Exception as e:
            log_message(f"[PORT SCAN] Error: {e}")
            time.sleep(SCAN_INTERVAL)

# ============================================================================
# BEHAVIOR 2: Suspicious API Abuse
# ============================================================================
def suspicious_api_abuse():
    """
    Simulate high-frequency API calls with suspicious patterns
    Sends dummy files repeatedly to trigger rate-limiting alerts
    """
    log_message("[BEHAVIOR] Starting API Abuse Thread")
    
    api_endpoints = [
        "/api/v1/files/upload",
        "/api/v1/config/update",
        "/api/v1/users/list",
        "/api/v1/admin/settings",
        "/api/v2/storage/sync"
    ]
    
    counter = 0
    
    while True:
        try:
            counter += 1
            endpoint = random.choice(api_endpoints)
            url = f"http://{TARGET_IP}:{TARGET_PORT}{endpoint}"
            
            # Create dummy file content
            dummy_content = generate_dummy_file()
            
            # Prepare suspicious headers
            headers = {
                'User-Agent': f'SuspiciousBot/1.0.{counter}',
                'X-Automated-Request': 'true',
                'X-Request-ID': f'automated-{counter}',
                'Content-Type': 'application/octet-stream'
            }
            
            # Send dummy file
            response = requests.post(url, data=dummy_content, headers=headers, timeout=5)
            
            log_message(f"[API ABUSE] Request #{counter} to {endpoint} - Status: {response.status_code}")
            
            # Very short interval to create suspicious high-frequency pattern
            time.sleep(API_ABUSE_INTERVAL)
            
        except Exception as e:
            log_message(f"[API ABUSE] Error: {e}")
            time.sleep(API_ABUSE_INTERVAL)

# ============================================================================
# BEHAVIOR 3: Credential Harvesting Simulation
# ============================================================================
def credential_harvesting_behavior():
    """
    Simulate attempts to access credential files and sensitive data
    Sends requests mimicking credential theft patterns
    """
    log_message("[BEHAVIOR] Starting Credential Harvesting Thread")
    
    credential_paths = [
        "/etc/passwd",
        "/etc/shadow",
        "/root/.ssh/id_rsa",
        "/home/user/.aws/credentials",
        "/home/user/.docker/config.json",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Users\\Administrator\\AppData\\Local\\Microsoft\\Credentials"
    ]
    
    counter = 0
    
    while True:
        try:
            counter += 1
            target_path = random.choice(credential_paths)
            
            # Send request attempting to access credentials
            url = f"http://{TARGET_IP}:{TARGET_PORT}/api/v1/files/read"
            payload = {
                "type": "credential_access",
                "path": target_path,
                "requester": "system_backup",
                "timestamp": datetime.now().isoformat()
            }
            
            headers = {
                'User-Agent': 'SystemBackupService/2.1',
                'X-Access-Type': 'privileged',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=5)
            
            log_message(f"[CREDENTIAL HARVEST] Attempt #{counter} - Path: {target_path} - Status: {response.status_code}")
            
            time.sleep(CREDENTIAL_ACCESS_INTERVAL)
            
        except Exception as e:
            log_message(f"[CREDENTIAL HARVEST] Error: {e}")
            time.sleep(CREDENTIAL_ACCESS_INTERVAL)

# ============================================================================
# BEHAVIOR 4: Privilege Escalation Attempts
# ============================================================================
def privilege_escalation_behavior():
    """
    Simulate repeated privilege escalation attempts
    Multiple failed authentication or permission requests
    """
    log_message("[BEHAVIOR] Starting Privilege Escalation Thread")
    
    commands = [
        "sudo su -",
        "net user administrator",
        "runas /user:administrator",
        "chmod 777 /etc/passwd",
        "icacls C:\\Windows\\System32 /grant Everyone:F"
    ]
    
    counter = 0
    
    while True:
        try:
            counter += 1
            command = random.choice(commands)
            
            url = f"http://{TARGET_IP}:{TARGET_PORT}/api/v1/system/execute"
            payload = {
                "type": "privilege_escalation",
                "command": command,
                "user": "low_privilege_user",
                "attempt": counter,
                "timestamp": datetime.now().isoformat()
            }
            
            headers = {
                'User-Agent': 'SystemManager/1.0',
                'X-Privilege-Request': 'elevated',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=5)
            
            log_message(f"[PRIVILEGE ESCALATION] Attempt #{counter} - Command: {command} - Status: {response.status_code}")
            
            time.sleep(12)
            
        except Exception as e:
            log_message(f"[PRIVILEGE ESCALATION] Error: {e}")
            time.sleep(12)

# ============================================================================
# BEHAVIOR 5: Lateral Movement Simulation
# ============================================================================
def lateral_movement_behavior():
    """
    Simulate lateral movement attempts - trying to access other devices
    """
    log_message("[BEHAVIOR] Starting Lateral Movement Thread")
    
    # Simulate scanning network for other devices
    target_ips = [
        "192.168.6.100",
        "192.168.6.101",
        "192.168.6.102",
        "192.168.6.103",
        "192.168.6.131",
        "192.168.6.150"
    ]
    
    counter = 0
    
    while True:
        try:
            counter += 1
            target = random.choice(target_ips)
            
            url = f"http://{TARGET_IP}:{TARGET_PORT}/api/v1/network/connect"
            payload = {
                "type": "lateral_movement",
                "target_ip": target,
                "protocol": "smb",
                "credentials": "Administrator:Password123",
                "attempt": counter,
                "timestamp": datetime.now().isoformat()
            }
            
            headers = {
                'User-Agent': 'WindowsNetworkService/10.0',
                'X-Connection-Type': 'network_share',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=5)
            
            log_message(f"[LATERAL MOVEMENT] Attempt #{counter} to {target} - Status: {response.status_code}")
            
            time.sleep(15)
            
        except Exception as e:
            log_message(f"[LATERAL MOVEMENT] Error: {e}")
            time.sleep(15)

# ============================================================================
# BEHAVIOR 6: Data Staging with Dummy Files
# ============================================================================
def data_staging_behavior():
    """
    Simulate data staging - collecting files in unusual temporary locations
    Uses dummy files instead of real data
    """
    log_message("[BEHAVIOR] Starting Data Staging Thread")
    
    counter = 0
    
    while True:
        try:
            counter += 1
            
            # Create multiple dummy files simulating data collection
            dummy_files = []
            for i in range(5):
                filename = f"collected_data_{counter}_{i}.tmp"
                content = generate_dummy_file()
                dummy_files.append({
                    "filename": filename,
                    "size": len(content),
                    "hash": hashlib.md5(content).hexdigest()
                })
            
            url = f"http://{TARGET_IP}:{TARGET_PORT}/api/v1/staging/collect"
            payload = {
                "type": "data_staging",
                "staging_location": "/tmp/.hidden_staging",
                "files": dummy_files,
                "total_size": sum(f["size"] for f in dummy_files),
                "timestamp": datetime.now().isoformat()
            }
            
            headers = {
                'User-Agent': 'DataCollector/3.2',
                'X-Staging-Operation': 'true',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=5)
            
            log_message(f"[DATA STAGING] Batch #{counter} - {len(dummy_files)} dummy files - Status: {response.status_code}")
            
            time.sleep(18)
            
        except Exception as e:
            log_message(f"[DATA STAGING] Error: {e}")
            time.sleep(18)

# ============================================================================
# Main Execution
# ============================================================================
def main():
    """Start all behavioral attack threads"""
    
    log_message("=" * 70)
    log_message("ENDPOINT BEHAVIOR-BASED ATTACKER STARTED")
    log_message("Detection Method: ANOMALY/BEHAVIOR DETECTION (Case 2)")
    log_message("=" * 70)
    log_message(f"Target: {TARGET_IP}:{TARGET_PORT}")
    log_message(f"Behaviors: 9 malicious patterns")
    log_message(f"File Type: DUMMY files (NO real malware)")
    log_message("=" * 70)
    
    # Start all behavior threads
    threads = [
        Thread(target=c2_beacon_behavior, daemon=True, name="C2Beacon"),
        Thread(target=data_exfiltration_behavior, daemon=True, name="DataExfiltration"),
        Thread(target=dns_dga_behavior, daemon=True, name="DNS_DGA"),
        Thread(target=port_scanning_behavior, daemon=True, name="PortScanning"),
        Thread(target=suspicious_api_abuse, daemon=True, name="APIAbuse"),
        Thread(target=credential_harvesting_behavior, daemon=True, name="CredentialHarvest"),
        Thread(target=privilege_escalation_behavior, daemon=True, name="PrivilegeEscalation"),
        Thread(target=lateral_movement_behavior, daemon=True, name="LateralMovement"),
        Thread(target=data_staging_behavior, daemon=True, name="DataStaging")
    ]
    
    for thread in threads:
        thread.start()
        log_message(f"[MAIN] Started thread: {thread.name}")
        time.sleep(1)
    
    log_message("[MAIN] All behavior threads running")
    log_message("=" * 70)
    
    # Keep main thread alive
    try:
        while True:
            time.sleep(60)
            log_message("[MAIN] Status: All behavior threads active")
    except KeyboardInterrupt:
        log_message("[MAIN] Shutting down...")

if __name__ == '__main__':
    main()
