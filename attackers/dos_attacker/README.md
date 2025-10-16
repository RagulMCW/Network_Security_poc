# Attacker Device - hping3 Container

A lightweight Docker container that uses **hping3** to send crafted network packets to your Flask server for security testing and network analysis.

## Features

- **Lightweight**: Based on Alpine Linux (~5MB base image)
- **Fast**: Minimal dependencies, quick startup
- **Configurable**: Environment variables for easy customization
- **Network Testing**: Sends TCP SYN packets to test server connectivity and security

## Building the Container

```bash
docker build -t hping3-attacker .
```

## Running the Container

### Basic usage (targets 192.168.6.131:5000):
```bash
docker run --rm --cap-add=NET_RAW hping3-attacker
```

### With custom target:
```bash
docker run --rm --cap-add=NET_RAW \
  -e TARGET_IP=192.168.1.100 \
  -e TARGET_PORT=8080 \
  hping3-attacker
```

### With custom packet settings:
```bash
docker run --rm --cap-add=NET_RAW \
  -e TARGET_IP=192.168.6.131 \
  -e TARGET_PORT=5000 \
  -e PACKET_COUNT=500 \
  -e PACKET_RATE=20 \
  hping3-attacker
```

## Using Docker Compose

```bash
docker-compose up --build
```

To modify the configuration, edit the environment variables in `docker-compose.yml`.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_IP` | `192.168.6.131` | IP address of the target Flask server |
| `TARGET_PORT` | `5000` | Port number of the target Flask server |
| `PACKET_COUNT` | `100` | Number of packets to send |
| `PACKET_RATE` | `10` | Packets per second to send |

## hping3 Options Used

- `--syn`: Send TCP SYN packets
- `-p`: Target port
- `-c`: Packet count
- `-i`: Packet interval (in microseconds)

## Requirements

- Docker
- Network access to the target Flask server
- The container needs `NET_RAW` capability to send raw packets

## Notes

- The container will exit after sending the specified number of packets
- Ensure the Flask server is running and accessible before running the container
- Network firewall rules may block the packets, depending on your setup
- This tool is for legitimate network security testing only

## HTTP (curl) sender

If you prefer application-layer traffic (HTTP) instead of raw packets, a simple `curl`-based sender is included.

Build the image as usual:

```bash
docker build -t hping3-attacker .
```

Run the curl sender on the same `custom_net` network:

```bash
# create network if needed
docker network create --driver bridge --subnet 192.168.6.0/24 custom_net

docker run --rm --network custom_net --ip 192.168.6.133 \
  -e TARGET_URL=http://192.168.6.131:5000/health \
  -e REQUESTS=20 -e DELAY=0.5 \
  hping3-attacker /app/curl_sender.sh
```

The curl sender prints the attacker container IP on startup and performs the requested number of HTTP GETs.


docker run --rm --network custom_net --ip 192.168.6.133 -e TARGET_URL=http://192.168.6.131:5000/health -e REQUESTS=200000 -e DELAY=0.1  hping3-attacker /app/curl_sender.sh