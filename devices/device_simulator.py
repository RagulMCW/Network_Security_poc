#!/usr/bin/env python3
"""
Virtual Device Simulator
Simulates real network devices that communicate with the monitoring server.
Generates realistic network traffic for packet capture and analysis.
"""

import os
import sys
import time
import json
import random
import socket
import requests
from datetime import datetime

# Configuration from environment variables
DEVICE_ID = os.getenv('DEVICE_ID', 'device_001')
DEVICE_TYPE = os.getenv('DEVICE_TYPE', 'generic')
SERVER_URL = os.getenv('SERVER_URL', 'http://192.168.6.131:5002')
REQUEST_INTERVAL = int(os.getenv('REQUEST_INTERVAL', '5'))

# Device types and their behaviors
DEVICE_TYPES = {
    'iot_sensor': {
        'data': ['temperature', 'humidity', 'pressure'],
        'interval_range': (3, 10),
        'payload_size': 'small'
    },
    'smartphone': {
        'data': ['location', 'battery', 'network_status'],
        'interval_range': (5, 15),
        'payload_size': 'medium'
    },
    'laptop': {
        'data': ['cpu_usage', 'memory_usage', 'disk_usage', 'network_traffic'],
        'interval_range': (10, 30),
        'payload_size': 'large'
    },
    'camera': {
        'data': ['motion_detected', 'recording_status', 'storage_used'],
        'interval_range': (2, 8),
        'payload_size': 'medium'
    },
    'generic': {
        'data': ['status', 'uptime', 'health'],
        'interval_range': (5, 15),
        'payload_size': 'small'
    }
}


class VirtualDevice:
    """Simulates a network device with realistic behavior"""
    
    def __init__(self, device_id, device_type):
        self.device_id = device_id
        self.device_type = device_type
        self.config = DEVICE_TYPES.get(device_type, DEVICE_TYPES['generic'])
        self.start_time = time.time()
        self.request_count = 0
        self.ip_address = self.get_ip_address()
        self.mac_address = self.get_mac_address()
        
        print(f"[{self.device_id}] Virtual device initialized")
        print(f"  Type: {self.device_type}")
        print(f"  IP: {self.ip_address}")
        print(f"  MAC: {self.mac_address}")
        print(f"  Server: {SERVER_URL}")
        print("-" * 50)
    
    def get_ip_address(self):
        """Get container's IP address"""
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            return ip
        except Exception as e:
            return "unknown"
    
    def get_mac_address(self):
        """Get container's MAC address (simulated)"""
        # In Docker, each container has a unique MAC
        # We'll read it from the network interface if possible
        try:
            import subprocess
            result = subprocess.check_output(['cat', '/sys/class/net/eth0/address'])
            return result.decode().strip()
        except:
            # Generate a fake MAC if we can't read the real one
            return ':'.join([f'{random.randint(0, 255):02x}' for _ in range(6)])
    
    def generate_sensor_data(self):
        """Generate realistic sensor data based on device type"""
        data = {}
        
        for sensor in self.config['data']:
            if sensor == 'temperature':
                data[sensor] = round(random.uniform(18.0, 28.0), 2)
            elif sensor == 'humidity':
                data[sensor] = round(random.uniform(30.0, 70.0), 2)
            elif sensor == 'pressure':
                data[sensor] = round(random.uniform(980.0, 1020.0), 2)
            elif sensor == 'battery':
                data[sensor] = random.randint(20, 100)
            elif sensor == 'cpu_usage':
                data[sensor] = random.randint(10, 80)
            elif sensor == 'memory_usage':
                data[sensor] = random.randint(30, 90)
            elif sensor == 'disk_usage':
                data[sensor] = random.randint(40, 85)
            elif sensor == 'location':
                data[sensor] = {
                    'lat': round(random.uniform(40.0, 41.0), 6),
                    'lon': round(random.uniform(-74.0, -73.0), 6)
                }
            elif sensor == 'motion_detected':
                data[sensor] = random.choice([True, False])
            elif sensor == 'recording_status':
                data[sensor] = random.choice(['active', 'idle', 'standby'])
            else:
                data[sensor] = random.choice(['ok', 'active', 'normal'])
        
        return data
    
    def create_payload(self):
        """Create a realistic device payload"""
        uptime = int(time.time() - self.start_time)
        
        payload = {
            'device_id': self.device_id,
            'device_type': self.device_type,
            'timestamp': datetime.now().isoformat(),
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'uptime_seconds': uptime,
            'request_number': self.request_count,
            'sensor_data': self.generate_sensor_data(),
            'metadata': {
                'firmware_version': '1.0.0',
                'protocol': 'HTTP/1.1',
                'status': 'online'
            }
        }
        
        return payload
    
    def register_device(self):
        """Register device with the server"""
        try:
            payload = {
                'device_id': self.device_id,
                'device_type': self.device_type,
                'ip_address': self.ip_address,
                'mac_address': self.mac_address,
                'action': 'register'
            }
            
            response = requests.post(
                f"{SERVER_URL}/api/device/register",
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                print(f"[{self.device_id}] Successfully registered with server")
                return True
            else:
                print(f"[{self.device_id}] Registration failed: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"[{self.device_id}] Registration error: {e}")
            return False
    
    def send_data(self):
        """Send data to the server"""
        try:
            payload = self.create_payload()
            
            response = requests.post(
                f"{SERVER_URL}/api/device/data",
                json=payload,
                timeout=5
            )
            
            self.request_count += 1
            
            if response.status_code == 200:
                result = response.json()
                print(f"[{self.device_id}] Data sent successfully (#{self.request_count})")
                print(f"  Server response: {result.get('message', 'OK')}")
                
                # Check if server sent any commands
                if 'command' in result:
                    self.handle_command(result['command'])
                
                return True
            else:
                print(f"[{self.device_id}] Send failed: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"[{self.device_id}] Send error: {e}")
            return False
    
    def fetch_status(self):
        """Fetch status from server (GET request)"""
        try:
            response = requests.get(
                f"{SERVER_URL}/api/device/status",
                params={'device_id': self.device_id},
                timeout=5
            )
            
            if response.status_code == 200:
                status = response.json()
                print(f"[{self.device_id}] Status check: {status.get('status', 'unknown')}")
                return status
                
        except requests.exceptions.RequestException as e:
            print(f"[{self.device_id}] Status check error: {e}")
            return None
    
    def handle_command(self, command):
        """Handle commands received from server"""
        print(f"[{self.device_id}] Received command: {command}")
        
        if command == 'ping':
            print(f"[{self.device_id}] Responding to ping")
        elif command == 'reboot':
            print(f"[{self.device_id}] Simulating reboot...")
            time.sleep(2)
        elif command == 'update':
            print(f"[{self.device_id}] Simulating firmware update...")
            time.sleep(3)
    
    def run(self):
        """Main device loop"""
        print(f"[{self.device_id}] Starting device simulation...")
        
        # Register with server
        self.register_device()
        time.sleep(2)
        
        # Main loop
        while True:
            try:
                # Send data to server
                self.send_data()
                
                # Occasionally fetch status (every 3rd request)
                if self.request_count % 3 == 0:
                    time.sleep(1)
                    self.fetch_status()
                
                # Wait with some randomness (realistic behavior)
                min_interval, max_interval = self.config['interval_range']
                wait_time = random.uniform(min_interval, max_interval)
                
                print(f"[{self.device_id}] Waiting {wait_time:.1f}s until next request...")
                print("-" * 50)
                time.sleep(wait_time)
                
            except KeyboardInterrupt:
                print(f"\n[{self.device_id}] Shutting down...")
                break
            except Exception as e:
                print(f"[{self.device_id}] Error in main loop: {e}")
                time.sleep(5)


def main():
    """Main entry point"""
    print("=" * 50)
    print("Virtual Device Simulator")
    print("=" * 50)
    
    # Create and run device
    device = VirtualDevice(DEVICE_ID, DEVICE_TYPE)
    device.run()


if __name__ == '__main__':
    main()
