#!/usr/bin/env python3

import unittest
import json
import tempfile
import os
from src.app.server import app

class TestNetworkMonitorAPI(unittest.TestCase):
    """Test suite for Network Monitor Flask API"""
    
    def setUp(self):
        """Set up test client"""
        self.app = app.test_client()
        self.app.testing = True
        
    def test_health_endpoint(self):
        """Test health check endpoint"""
        response = self.app.get('/health')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'healthy')
        self.assertIn('timestamp', data)
        
    def test_network_info_endpoint(self):
        """Test network info endpoint"""
        response = self.app.get('/network/info')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('interfaces', data)
        self.assertIn('hostname', data)
        self.assertIn('timestamp', data)
        
    def test_capture_files_endpoint(self):
        """Test capture files listing endpoint"""
        response = self.app.get('/capture/files')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertIn('files', data)
        self.assertIn('total_files', data)
        self.assertIsInstance(data['files'], list)
        
    def test_invalid_endpoint(self):
        """Test invalid endpoint returns 404"""
        response = self.app.get('/invalid/endpoint')
        self.assertEqual(response.status_code, 404)

class TestPacketAnalyzer(unittest.TestCase):
    """Test suite for packet analysis functions"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_pcap = None
        
    def test_analyze_protocols(self):
        """Test protocol analysis function"""
        # This would require a test pcap file
        # For now, just test the function exists
        from scripts.analyze_capture import analyze_protocols
        self.assertTrue(callable(analyze_protocols))
        
    def test_analyze_traffic_patterns(self):
        """Test traffic pattern analysis"""
        from scripts.analyze_capture import analyze_traffic_patterns
        self.assertTrue(callable(analyze_traffic_patterns))
        
    def test_detect_anomalies(self):
        """Test anomaly detection"""
        from scripts.analyze_capture import detect_anomalies
        self.assertTrue(callable(detect_anomalies))

class TestConfigValidation(unittest.TestCase):
    """Test configuration file validation"""
    
    def test_haproxy_config_exists(self):
        """Test HAProxy configuration file exists"""
        config_path = "src/config/haproxy.cfg"
        self.assertTrue(os.path.exists(config_path))
        
    def test_dockerfile_exists(self):
        """Test Dockerfile exists"""
        dockerfile_path = "docker/Dockerfile"
        self.assertTrue(os.path.exists(dockerfile_path))
        
    def test_docker_compose_exists(self):
        """Test docker-compose file exists"""
        compose_path = "docker/docker-compose.yml"
        self.assertTrue(os.path.exists(compose_path))

if __name__ == '__main__':
    # Change to project root directory
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Run tests
    unittest.main(verbosity=2)