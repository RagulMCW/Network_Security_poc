# 🚀 Quick Start Guide

## Build & Run in 3 Steps

### 1️⃣ Build the Image
```bash
cd /mnt/e/nos/Network_Security_poc/network
docker build -t network-security-monitor .
```

### 2️⃣ Run the Container (Choose one option)

**🪟 WSL + Windows (Recommended for your setup):**
```bash
# Create network if needed
docker network create --driver bridge --subnet=192.168.6.0/24 custom_net

# Run with port mapping for Windows access
docker run -d --name net-monitor-wan \
  --net custom_net --ip 192.168.6.131 \
  -p 5002:5000 -p 8082:8080 -p 8415:8404 \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e SERVER_ID=net-monitor-wan \
  -v "$(pwd)/captures:/captures" \
  network-security-monitor

# Or use the interactive script:
./run_wsl_windows.sh
```

**Easy Mode (Host Network):**
```bash
docker run -d --name net-monitor --network host --cap-add=NET_RAW --cap-add=NET_ADMIN -v "$(pwd)/captures:/captures" network-security-monitor
```

**Secure Mode (Bridge Network):**
```bash
docker run -d --name net-monitor -p 8080:8080 -p 5000:5000 -p 8404:8404 --cap-add=NET_RAW --cap-add=NET_ADMIN -v "$(pwd)/captures:/captures" network-security-monitor
```

**Docker Compose:**
```bash
docker-compose up -d
```

### 3️⃣ Access Services

**For WSL + Windows setup:**
- 🌐 **Main Interface**: http://localhost:8082
- 🔧 **Flask API**: http://localhost:5002  
- 📊 **HAProxy Stats**: http://localhost:8415/stats

**For other setups:**
- 🌐 **Main Interface**: http://localhost:8080
- 🔧 **Flask API**: http://localhost:5000  
- 📊 **HAProxy Stats**: http://localhost:8404/stats

## 🛠️ Essential Commands

```bash
# View logs
docker logs -f net-monitor

# Check captures
docker exec net-monitor ls -la /captures/

# Test services
./test_container.bat  # Windows
./test_container.sh   # Linux/WSL

# Stop & cleanup
docker stop net-monitor && docker rm net-monitor
```

## 📦 What's Running?
- **tcpdump**: Captures network packets
- **HAProxy**: Load balancer and proxy
- **Flask**: Web API and interface

## 🔐 Security Notes
- Requires `NET_RAW` + `NET_ADMIN` capabilities for packet capture
- Host network mode = more access, less security
- Bridge network mode = more security, less access
- All captures saved to `./captures/` directory





# 1. Navigate to project
cd /mnt/e/nos/Network_Security_poc/network

# 2. Build image
docker build -f docker/Dockerfile -t network-security-monitor .

# 3. Create network
docker network create --driver bridge --subnet=192.168.6.0/24 custom_net

# 4. Run container (your command)
docker run -d --name net-monitor-wan \
  --net custom_net --ip 192.168.6.131 \
  -p 5002:5000 -p 8082:8080 -p 8415:8404 \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -e SERVER_ID=net-monitor-wan \
  -v "$(pwd)/captures:/captures" \
  network-security-monitor

# 5. Verify
docker ps
curl http://localhost:5002/health