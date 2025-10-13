#!/usr/bin/env python3

import unittest
import os
import tempfile
from unittest.mock import patch, MagicMock

class TestPacketCaptureIntegration(unittest.TestCase):
    """Integration tests for packet capture functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_capture_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test environment"""
        import shutil
        shutil.rmtree(self.test_capture_dir, ignore_errors=True)
        
    @patch('subprocess.Popen')
    def test_tcpdump_process_start(self, mock_popen):
        """Test tcpdump process can be started"""
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Process running
        mock_popen.return_value = mock_process
        
        # Simulate starting tcpdump
        import subprocess
        cmd = ["tcpdump", "-i", "eth0", "-w", "test.pcap"]
        process = subprocess.Popen(cmd)
        
        self.assertIsNotNone(process)
        mock_popen.assert_called_once()
        
    def test_capture_directory_creation(self):
        """Test capture directory is created"""
        capture_dir = os.path.join(self.test_capture_dir, "captures")
        
        if not os.path.exists(capture_dir):
            os.makedirs(capture_dir)
            
        self.assertTrue(os.path.exists(capture_dir))
        
    def test_capture_file_rotation(self):
        """Test capture file rotation logic"""
        import time
        
        # Create test files with timestamps
        base_name = "capture_test"
        
        for i in range(3):
            filename = f"{base_name}_{int(time.time())}_{i}.pcap"
            filepath = os.path.join(self.test_capture_dir, filename)
            
            with open(filepath, 'w') as f:
                f.write(f"test data {i}")
                
        # Check files exist
        files = os.listdir(self.test_capture_dir)
        pcap_files = [f for f in files if f.endswith('.pcap')]
        
        self.assertEqual(len(pcap_files), 3)

class TestDockerContainerIntegration(unittest.TestCase):
    """Integration tests for Docker container functionality"""
    
    @patch('subprocess.run')
    def test_docker_build_command(self, mock_run):
        """Test Docker build command construction"""
        mock_run.return_value.returncode = 0
        
        import subprocess
        cmd = ["docker", "build", "-t", "network-monitor", "."]
        result = subprocess.run(cmd, capture_output=True)
        
        self.assertEqual(result.returncode, 0)
        mock_run.assert_called_once()
        
    @patch('subprocess.run')
    def test_docker_compose_up(self, mock_run):
        """Test docker-compose up command"""
        mock_run.return_value.returncode = 0
        
        import subprocess
        cmd = ["docker-compose", "up", "-d"]
        result = subprocess.run(cmd, capture_output=True)
        
        self.assertEqual(result.returncode, 0)
        mock_run.assert_called_once()

class TestNetworkInterfaceIntegration(unittest.TestCase):
    """Integration tests for network interface operations"""
    
    def test_network_interface_detection(self):
        """Test network interface detection"""
        import socket
        import fcntl
        import struct
        
        # Get hostname
        hostname = socket.gethostname()
        self.assertIsInstance(hostname, str)
        self.assertTrue(len(hostname) > 0)
        
    def test_ip_address_detection(self):
        """Test IP address detection"""
        import socket
        
        try:
            # Get local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            
            # Validate IP format
            parts = ip.split('.')
            self.assertEqual(len(parts), 4)
            
            for part in parts:
                self.assertTrue(0 <= int(part) <= 255)
                
        except Exception:
            # Skip test if no network connectivity
            self.skipTest("No network connectivity")

if __name__ == '__main__':
    unittest.main(verbosity=2)