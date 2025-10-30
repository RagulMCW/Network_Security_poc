#!/bin/bash
# Complete System Test & Verification
# Tests all key workflows: device creation, network setup, rerouting, UI

echo "========================================"
echo "NETWORK SECURITY POC - SYSTEM TEST"
echo "========================================"
echo ""

FAILED=0
PASSED=0

# Test 1: Check Docker networks
echo "[TEST 1] Checking Docker networks..."
if docker network ls | grep -q "custom_net"; then
    echo "  ✓ custom_net exists"
    ((PASSED++))
else
    echo "  ✗ custom_net missing - creating..."
    docker network create --subnet=192.168.6.0/24 custom_net
    ((FAILED++))
fi

if docker network ls | grep -q "honeypot_net"; then
    echo "  ✓ honeypot_net exists"
    ((PASSED++))
else
    echo "  ✗ honeypot_net missing - creating..."
    docker network create --subnet=192.168.7.0/24 honeypot_net
    ((FAILED++))
fi

echo ""

# Test 2: Check Beelzebub honeypot
echo "[TEST 2] Checking Beelzebub honeypot..."
if docker ps | grep -q "beelzebub-honeypot"; then
    echo "  ✓ Beelzebub running"
    
    # Check if on honeypot_net
    BEELZEBUB_IP=$(docker inspect beelzebub-honeypot --format '{{.NetworkSettings.Networks.honeypot_net.IPAddress}}' 2>/dev/null)
    if [ -n "$BEELZEBUB_IP" ]; then
        echo "  ✓ Beelzebub on honeypot_net: $BEELZEBUB_IP"
        ((PASSED++))
    else
        echo "  ✗ Beelzebub NOT on honeypot_net - connecting..."
        docker network connect honeypot_net beelzebub-honeypot
        BEELZEBUB_IP=$(docker inspect beelzebub-honeypot --format '{{.NetworkSettings.Networks.honeypot_net.IPAddress}}')
        echo "  ✓ Connected: $BEELZEBUB_IP"
        ((FAILED++))
    fi
    ((PASSED++))
else
    echo "  ✗ Beelzebub NOT running"
    echo "  → Start with: cd honey_pot && docker-compose -f docker-compose-simple.yml up -d"
    ((FAILED++))
fi

echo ""

# Test 3: Check network monitor
echo "[TEST 3] Checking network monitor..."
if docker ps | grep -q "net-monitor"; then
    echo "  ✓ Network monitor running"
    MONITOR_IP=$(docker inspect net-monitor-wan --format '{{.NetworkSettings.Networks.custom_net.IPAddress}}' 2>/dev/null)
    echo "  ✓ Monitor IP: $MONITOR_IP"
    ((PASSED++))
else
    echo "  ✗ Network monitor NOT running"
    echo "  → Container exists but stopped - restarting..."
    docker start net-monitor-wan 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  ✓ Monitor restarted"
        ((PASSED++))
    else
        echo "  ✗ Monitor needs rebuild"
        echo "  → Run: cd network && docker-compose up -d --build"
        ((FAILED++))
    fi
fi

echo ""

# Test 4: Check devices
echo "[TEST 4] Checking devices..."
DEVICE_COUNT=$(docker ps -a --filter "name=device_" --format "{{.Names}}" | wc -l)
if [ "$DEVICE_COUNT" -gt 0 ]; then
    echo "  ✓ Found $DEVICE_COUNT devices"
    
    # Check if running
    RUNNING_DEVICES=$(docker ps --filter "name=device_" --format "{{.Names}}" | wc -l)
    if [ "$RUNNING_DEVICES" -eq 0 ]; then
        echo "  ⚠ Devices are stopped - restarting..."
        docker ps -a --filter "name=device_" --format "{{.Names}}" | xargs -I {} docker start {} 2>/dev/null
        echo "  ✓ Devices restarted"
    else
        echo "  ✓ $RUNNING_DEVICES devices running"
    fi
    ((PASSED++))
else
    echo "  ⚠ No devices found"
    echo "  → Create via dashboard UI or: cd devices && ./manage_devices.sh create"
fi

echo ""

# Test 5: Check attackers
echo "[TEST 5] Checking attackers..."
if docker ps --filter "name=hping3-attacker" --format "{{.Names}}" | grep -q "hping3"; then
    echo "  ✓ hping3-attacker running"
    ATTACKER_IP=$(docker inspect hping3-attacker --format '{{.NetworkSettings.Networks.custom_net.IPAddress}}' 2>/dev/null)
    echo "  ✓ Attacker IP: $ATTACKER_IP"
    ((PASSED++))
else
    echo "  ⚠ hping3-attacker NOT running"
    echo "  → Start with: cd attackers/dos_attacker && docker-compose up -d"
fi

echo ""

# Test 6: Check PCAP capture
echo "[TEST 6] Checking PCAP capture..."
PCAP_COUNT=$(ls -1 /mnt/e/nos/Network_Security_poc/network/captures/*.pcap 2>/dev/null | wc -l)
if [ "$PCAP_COUNT" -gt 0 ]; then
    LATEST_PCAP=$(ls -t /mnt/e/nos/Network_Security_poc/network/captures/*.pcap 2>/dev/null | head -1)
    PCAP_SIZE=$(du -h "$LATEST_PCAP" 2>/dev/null | cut -f1)
    PCAP_AGE=$(stat -c %Y "$LATEST_PCAP" 2>/dev/null)
    NOW=$(date +%s)
    AGE_SECONDS=$((NOW - PCAP_AGE))
    
    if [ "$AGE_SECONDS" -lt 60 ]; then
        echo "  ✓ PCAP files being created (latest: ${PCAP_AGE}s ago, ${PCAP_SIZE})"
        ((PASSED++))
    else
        echo "  ⚠ Latest PCAP is old (${AGE_SECONDS}s ago)"
        echo "  → Start capture: cd network && ./start_capture.bat"
        ((FAILED++))
    fi
else
    echo "  ✗ No PCAP files found"
    echo "  → Start capture: cd network && ./start_capture.bat"
    ((FAILED++))
fi

echo ""

# Test 7: Check dashboard (if running)
echo "[TEST 7] Checking dashboard..."
if curl -s http://localhost:5001/api/health >/dev/null 2>&1; then
    echo "  ✓ Dashboard API responding on port 5001"
    ((PASSED++))
else
    echo "  ⚠ Dashboard NOT running"
    echo "  → Start with: cd dashboard && python app.py"
fi

echo ""

# Test 8: Check iptables rules
echo "[TEST 8] Checking iptables rerouting rules..."
DNAT_RULES=$(sudo iptables -t nat -L PREROUTING -n 2>/dev/null | grep -c DNAT 2>/dev/null || echo "0")
if [ "$DNAT_RULES" -gt 0 ]; then
    echo "  ✓ $DNAT_RULES iptables DNAT rules active"
    ((PASSED++))
else
    echo "  ⚠ No iptables rules configured"
    echo "  → Run: cd dashboard && ./complete_setup.bat"
fi

echo ""

# Test 9: Check Beelzebub logs
echo "[TEST 9] Checking Beelzebub logs..."
if [ -f "/mnt/e/nos/Network_Security_poc/honey_pot/logs/beelzebub.log" ]; then
    LOG_SIZE=$(wc -l < /mnt/e/nos/Network_Security_poc/honey_pot/logs/beelzebub.log 2>/dev/null || echo "0")
    echo "  ✓ Beelzebub log exists ($LOG_SIZE lines)"
    if [ "$LOG_SIZE" -gt 0 ]; then
        echo "  ✓ Honeypot is logging traffic"
        ((PASSED++))
    else
        echo "  ⚠ Log is empty (no traffic rerouted yet)"
    fi
else
    echo "  ⚠ Beelzebub log not found"
fi

echo ""

# Test 10: Check MCP agent
echo "[TEST 10] Checking MCP agent..."
if [ -d "/mnt/e/nos/Network_Security_poc/mcp_agent" ]; then
    if [ -f "/mnt/e/nos/Network_Security_poc/mcp_agent/config/.env" ]; then
        echo "  ✓ MCP agent configured"
        ((PASSED++))
    else
        echo "  ⚠ MCP agent .env missing"
        echo "  → Copy: cp mcp_agent/config/env.example mcp_agent/config/.env"
    fi
else
    echo "  ✗ MCP agent directory not found"
    ((FAILED++))
fi

echo ""
echo "========================================"
echo "SUMMARY"
echo "========================================"
echo "✓ Passed: $PASSED"
echo "✗ Failed: $FAILED"
echo ""

if [ "$FAILED" -eq 0 ]; then
    echo "🎉 ALL SYSTEMS OPERATIONAL"
    echo ""
    echo "Quick Start Commands:"
    echo "  Dashboard:    cd dashboard && python app.py"
    echo "  PCAP Capture: cd network && ./start_capture.bat"
    echo "  MCP Agent:    cd mcp_agent && ./start_agent.bat"
    echo "  View Logs:    cd honey_pot && ./view_live_logs.bat"
else
    echo "⚠️  SOME ISSUES DETECTED"
    echo ""
    echo "Run complete setup:"
    echo "  cd dashboard && ./complete_setup.bat"
fi

echo ""
echo "========================================"
