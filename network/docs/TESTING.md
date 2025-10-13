# Network Security Monitor - Testing Guide

## Overview
This document provides comprehensive testing procedures for the Network Security Monitor project.

## Prerequisites
- Docker and Docker Compose installed
- WSL2 (for Windows users)
- Python 3.8+ with scapy library

## Quick Test
```bash
# Start services
./scripts/quickstart.sh

# For WSL users
./scripts/quickstart.sh --wsl
```

## Unit Testing

### Flask API Tests
```bash
# Test health endpoint
curl http://localhost:5000/health

# Test network info
curl http://localhost:5000/network/info

# Test capture files list
curl http://localhost:5000/capture/files
```

### Container Health Tests
```bash
# Check container status
docker-compose ps

# View service logs
docker-compose logs flask-app
docker-compose logs haproxy
```

### Network Capture Testing
```bash
# Generate test traffic
curl -X POST http://localhost:5000/network/info
wget http://localhost:5000/health

# Check capture files
ls -la captures/

# Analyze captured packets
python scripts/analyze_capture.py captures/capture_*.pcap
```

## Integration Testing

### End-to-End Workflow
1. Start all services
2. Generate network traffic
3. Verify packet capture
4. Analyze captured data
5. Check service health

### Performance Testing
```bash
# Load testing with curl
for i in {1..100}; do
    curl http://localhost:5000/health &
done
wait

# Check HAProxy statistics
curl http://localhost:8080/stats
```

## WSL-Specific Testing

### Port Forwarding Verification
```bash
# From Windows PowerShell
Test-NetConnection localhost -Port 5000
Test-NetConnection localhost -Port 8080

# Check port proxy
netsh interface portproxy show v4tov4
```

### Cross-Platform Access
```bash
# Test from Windows browser
# http://localhost:5000
# http://localhost:8080/stats

# Test from WSL terminal
curl http://localhost:5000/health
```

## Troubleshooting Tests

### Common Issues
1. **Port conflicts**
   ```bash
   netstat -tulpn | grep :5000
   netstat -tulpn | grep :8080
   ```

2. **Docker issues**
   ```bash
   docker-compose down
   docker system prune -f
   docker-compose up --build
   ```

3. **Permission issues**
   ```bash
   # Check container capabilities
   docker exec network-monitor capsh --print
   ```

## Automated Testing Script
```bash
#!/bin/bash
# test_suite.sh

echo "Running Network Security Monitor Test Suite"

# Start services
./scripts/quickstart.sh

# Wait for services to start
sleep 10

# Run tests
echo "Testing Flask API..."
curl -f http://localhost:5000/health || exit 1

echo "Testing HAProxy..."
curl -f http://localhost:8080/stats || exit 1

echo "Generating test traffic..."
for i in {1..50}; do
    curl http://localhost:5000/network/info >/dev/null 2>&1
done

# Wait for capture
sleep 5

# Check captures
if ls captures/*.pcap 1> /dev/null 2>&1; then
    echo "✓ Packet capture working"
    python scripts/analyze_capture.py captures/*.pcap
else
    echo "✗ No packet captures found"
    exit 1
fi

echo "All tests passed"
```

## Test Data Analysis
- Expected packet count: 50+ packets per test run
- Protocol distribution: TCP (HTTP), ARP, ICMP
- No security anomalies in test environment

## Continuous Integration
For automated testing in CI/CD pipelines:
1. Use Docker-in-Docker setup
2. Run test suite with timeout
3. Collect logs and artifacts
4. Clean up resources

## Performance Benchmarks
- API response time: < 100ms
- Packet capture latency: < 10ms
- Memory usage: < 256MB
- CPU usage: < 10% idle system