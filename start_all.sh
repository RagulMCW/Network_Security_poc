#!/bin/bash
# Complete System Startup - Start All Services

echo "========================================"
echo "STARTING NETWORK SECURITY POC"
echo "========================================"
echo ""

# Step 1: Ensure networks exist
echo "[1/7] Creating Docker networks..."
docker network create --subnet=192.168.6.0/24 custom_net 2>/dev/null && echo "  ✓ custom_net created" || echo "  ✓ custom_net already exists"
docker network create --subnet=192.168.7.0/24 honeypot_net 2>/dev/null && echo "  ✓ honeypot_net created" || echo "  ✓ honeypot_net already exists"

# Step 2: Start Beelzebub honeypot
echo ""
echo "[2/7] Starting Beelzebub honeypot..."
cd /mnt/e/nos/Network_Security_poc/honey_pot
if docker ps | grep -q "beelzebub-honeypot"; then
    echo "  ✓ Beelzebub already running"
else
    docker-compose -f docker-compose-simple.yml up -d
    sleep 2
    echo "  ✓ Beelzebub started"
fi

# Connect to honeypot_net
docker network connect honeypot_net beelzebub-honeypot 2>/dev/null && echo "  ✓ Connected to honeypot_net" || echo "  ✓ Already connected"
BEELZEBUB_IP=$(docker inspect beelzebub-honeypot --format '{{.NetworkSettings.Networks.honeypot_net.IPAddress}}')
echo "  ✓ Beelzebub IP: $BEELZEBUB_IP"

# Step 3: Start network monitor
echo ""
echo "[3/7] Starting network monitor..."
cd /mnt/e/nos/Network_Security_poc/network
if docker ps | grep -q "net-monitor"; then
    echo "  ✓ Monitor already running"
else
    docker start net-monitor-wan 2>/dev/null || docker-compose up -d --build
    sleep 2
    echo "  ✓ Monitor started"
fi
MONITOR_IP=$(docker inspect net-monitor-wan --format '{{.NetworkSettings.Networks.custom_net.IPAddress}}' 2>/dev/null)
echo "  ✓ Monitor IP: $MONITOR_IP"

# Step 4: Start devices
echo ""
echo "[4/7] Starting devices..."
DEVICE_COUNT=$(docker ps -a --filter "name=device_" --format "{{.Names}}" | wc -l)
if [ "$DEVICE_COUNT" -gt 0 ]; then
    docker ps -a --filter "name=device_" --format "{{.Names}}" | xargs -I {} docker start {} 2>/dev/null
    echo "  ✓ $DEVICE_COUNT devices started"
else
    echo "  ⚠ No devices found - create via dashboard UI"
fi

# Step 5: Start attacker
echo ""
echo "[5/7] Starting attacker..."
cd /mnt/e/nos/Network_Security_poc/attackers/dos_attacker
if docker ps | grep -q "hping3-attacker"; then
    echo "  ✓ Attacker already running"
else
    docker-compose up -d
    sleep 1
    echo "  ✓ Attacker started"
fi
ATTACKER_IP=$(docker inspect hping3-attacker --format '{{.NetworkSettings.Networks.custom_net.IPAddress}}' 2>/dev/null)
echo "  ✓ Attacker IP: $ATTACKER_IP"

# Step 6: Connect all containers to honeypot_net
echo ""
echo "[6/7] Ensuring all containers on honeypot_net..."
for CONTAINER in device_1 device_2 hping3-attacker; do
    if docker ps | grep -q "$CONTAINER"; then
        docker network connect honeypot_net $CONTAINER 2>/dev/null && echo "  ✓ $CONTAINER connected" || echo "  ✓ $CONTAINER already connected"
    fi
done

# Step 7: Display status
echo ""
echo "[7/7] System status..."
echo ""
echo "========================================"
echo "ALL SERVICES RUNNING"
echo "========================================"
echo ""
echo "Networks:"
echo "  custom_net:    192.168.6.0/24 (production)"
echo "  honeypot_net:  192.168.7.0/24 (honeypot)"
echo ""
echo "Containers:"
echo "  Beelzebub:     $BEELZEBUB_IP (honeypot)"
echo "  Monitor:       $MONITOR_IP (captures traffic)"
echo "  Attacker:      $ATTACKER_IP (DoS attack source)"
echo "  Devices:       $DEVICE_COUNT devices"
echo ""
echo "Endpoints:"
echo "  Dashboard:     http://localhost:5001 (start with: python dashboard/app.py)"
echo "  Monitor API:   http://$MONITOR_IP:5000"
echo "  Beelzebub SSH: telnet localhost 2222"
echo "  Beelzebub HTTP: http://localhost:8080"
echo ""
echo "Logs:"
echo "  Beelzebub:     honey_pot/logs/beelzebub.log"
echo "  PCAP:          network/captures/*.pcap"
echo "  Attacks:       honey_pot/logs/attacks.jsonl"
echo ""
echo "Next Steps:"
echo "  1. Start PCAP capture:  cd network && ./start_capture.bat"
echo "  2. Start dashboard:     cd dashboard && python app.py"
echo "  3. Start MCP agent:     cd mcp_agent && ./start_agent.bat"
echo "  4. View live logs:      cd honey_pot && ./view_live_logs.bat"
echo ""
echo "========================================"
