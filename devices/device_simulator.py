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
REQUEST_INTERVAL = int(os.getenv('REQUEST_INTERVAL', '1'))

# Realistic user agents for IoT devices
USER_AGENTS = [
    'IoTDevice/2.1 (Linux; Android 9.0)',
    'Mozilla/5.0 (compatible; IoT-Gateway/1.0)',
    'DeviceClient/3.2.1 (ARM; Linux)',
    'SensorHub/1.5.0',
    'SmartHome/2.0 (ESP32)',
    'MQTTClient/1.0',
    'HTTPClient/2.3.1'
]

# Device types and their behaviors
DEVICE_TYPES = {
    'iot_sensor': {
        'data': ['temperature', 'humidity', 'pressure'],
        'interval_range': (5, 15),  # More realistic: 5-15 seconds
        'payload_size': 'small',
        'burst_chance': 0.1,  # 10% chance of burst mode
        'sleep_chance': 0.05  # 5% chance of going offline briefly
    },
    'smartphone': {
        'data': ['location', 'battery', 'network_status'],
        'interval_range': (8, 20),  # Smartphones report less frequently
        'payload_size': 'medium',
        'burst_chance': 0.05,
        'sleep_chance': 0.03
    },
    'laptop': {
        'data': ['cpu_usage', 'memory_usage', 'disk_usage', 'network_traffic'],
        'interval_range': (10, 30),  # Laptops report less frequently
        'payload_size': 'large',
        'burst_chance': 0.15,
        'sleep_chance': 0.02
    },
    'camera': {
        'data': ['motion_detected', 'recording_status', 'storage_used'],
        'interval_range': (3, 12),  # Cameras may report on motion
        'payload_size': 'medium',
        'burst_chance': 0.2,  # More bursts when motion detected
        'sleep_chance': 0.01
    },
    'generic': {
        'data': ['status', 'uptime', 'health'],
        'interval_range': (7, 18),  # Generic devices vary
        'payload_size': 'small',
        'burst_chance': 0.05,
        'sleep_chance': 0.05
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
        self.last_sensor_values = {}  # Track previous values for realistic drift
        self.in_burst_mode = False
        self.burst_counter = 0
        self.user_agent = random.choice(USER_AGENTS)  # Random but consistent user agent
        self.connection_failures = 0
        
        print(f"[{self.device_id}] Virtual device initialized")
        print(f"  Type: {self.device_type}")
        print(f"  IP: {self.ip_address}")
        print(f"  MAC: {self.mac_address}")
        print(f"  User-Agent: {self.user_agent}")
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
        """Generate realistic sensor data with drift (values change gradually, not randomly)"""
        data = {}
        
        for sensor in self.config['data']:
            # Get previous value or initialize
            prev_value = self.last_sensor_values.get(sensor)
            
            if sensor == 'temperature':
                if prev_value is None:
                    value = round(random.uniform(18.0, 28.0), 2)
                else:
                    # Drift by ±0.5 degrees
                    value = round(prev_value + random.uniform(-0.5, 0.5), 2)
                    value = max(15.0, min(32.0, value))  # Clamp to realistic range
                data[sensor] = value
                
            elif sensor == 'humidity':
                if prev_value is None:
                    value = round(random.uniform(30.0, 70.0), 2)
                else:
                    value = round(prev_value + random.uniform(-2.0, 2.0), 2)
                    value = max(20.0, min(90.0, value))
                data[sensor] = value
                
            elif sensor == 'pressure':
                if prev_value is None:
                    value = round(random.uniform(980.0, 1020.0), 2)
                else:
                    value = round(prev_value + random.uniform(-1.0, 1.0), 2)
                    value = max(970.0, min(1030.0, value))
                data[sensor] = value
                
            elif sensor == 'battery':
                if prev_value is None:
                    value = random.randint(60, 100)
                else:
                    # Battery drains slowly
                    value = max(20, prev_value - random.randint(0, 2))
                    # Occasionally charge
                    if random.random() < 0.1:
                        value = min(100, value + random.randint(5, 15))
                data[sensor] = value
                
            elif sensor == 'cpu_usage':
                if prev_value is None:
                    value = random.randint(10, 80)
                else:
                    # CPU usage fluctuates more
                    value = prev_value + random.randint(-15, 20)
                    value = max(5, min(95, value))
                data[sensor] = value
                
            elif sensor == 'memory_usage':
                if prev_value is None:
                    value = random.randint(30, 90)
                else:
                    # Memory usage is more stable
                    value = prev_value + random.randint(-5, 5)
                    value = max(20, min(95, value))
                data[sensor] = value
                
            elif sensor == 'disk_usage':
                if prev_value is None:
                    value = random.randint(40, 85)
                else:
                    # Disk usage only increases slowly
                    value = min(95, prev_value + random.randint(0, 1))
                data[sensor] = value
                
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
            
            # Save current value
            if sensor in data and not isinstance(data[sensor], dict):
                self.last_sensor_values[sensor] = data[sensor]
        
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
            
            headers = {
                'User-Agent': self.user_agent,
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{SERVER_URL}/api/device/register",
                json=payload,
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                print(f"[{self.device_id}] Successfully registered with server")
                self.connection_failures = 0
                return True
            else:
                print(f"[{self.device_id}] Registration failed: {response.status_code}")
                self.connection_failures += 1
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"[{self.device_id}] Registration error: {e}")
            self.connection_failures += 1
            return False
    
    def send_data(self):
        """Send data to the server"""
        try:
            # Simulate occasional network failures (1% chance)
            if random.random() < 0.01:
                print(f"[{self.device_id}] Simulated network timeout")
                self.connection_failures += 1
                return False
            
            payload = self.create_payload()
            
            headers = {
                'User-Agent': self.user_agent,
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                f"{SERVER_URL}/api/device/data",
                json=payload,
                headers=headers,
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
                
                # Determine wait time - with burst mode support
                min_interval, max_interval = self.config['interval_range']
                
                # Enter burst mode randomly
                if not self.in_burst_mode and random.random() < self.config.get('burst_chance', 0):
                    self.in_burst_mode = True
                    self.burst_counter = random.randint(3, 8)  # Send 3-8 rapid requests
                    print(f"[{self.device_id}] 🔥 BURST MODE ACTIVATED ({self.burst_counter} requests)")
                
                # In burst mode, send rapidly
                if self.in_burst_mode:
                    wait_time = random.uniform(0.5, 2.0)  # Quick bursts
                    self.burst_counter -= 1
                    if self.burst_counter <= 0:
                        self.in_burst_mode = False
                        print(f"[{self.device_id}] ✅ Burst mode complete, returning to normal")
                else:
                    # Normal mode - realistic intervals with jitter
                    base_interval = random.uniform(min_interval, max_interval)
                    jitter = random.uniform(-1.5, 2.0)  # Add random jitter
                    wait_time = max(3.0, base_interval + jitter)  # At least 3 seconds
                
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
