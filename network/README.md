# Network Security Monitoring Container

A comprehensive Docker-based network security monitoring solution that provides real-time packet capture, load balancing, and web-based monitoring interfaces.

## Features

- **Real-time Packet Capture**: Automated tcpdump with file rotation
- **Load Balancing**: HAProxy with statistics dashboard
- **REST API**: Flask-based web interface with monitoring endpoints
- **Health Monitoring**: Built-in health checks and status reporting
- **Cross-platform**: WSL/Linux support with Windows accessibility

## Quick Start

### Prerequisites

- Docker and Docker Compose
- WSL2 (for Windows users)
- Git

### Build and Run

```bash
# Clone and navigate to project
cd /path/to/Network_Security_poc/network

# Build the container
make build

# Run with default configuration
make run

# Access services
# Web Interface: http://localhost:8080
# API: http://localhost:5000
# Statistics: http://localhost:8404/stats
```

### For WSL + Windows Users

```bash
# Build and run with Windows port mapping
make run-wsl

# Access from Windows browser
# Web Interface: http://localhost:8082
# API: http://localhost:5002
# Statistics: http://localhost:8415/stats
```

## Project Structure

```
network/
├── src/                    # Source code
│   ├── app/               # Flask application
│   └── config/            # Configuration files
├── scripts/               # Deployment and utility scripts
├── docs/                  # Documentation
├── docker/                # Docker configuration
├── tests/                 # Test scripts
└── captures/              # Packet capture output
```

## Documentation

- [Installation Guide](docs/installation.md)
- [Configuration](docs/configuration.md)
- [API Documentation](docs/api.md)
- [Deployment Guide](docs/deployment.md)
- [Troubleshooting](docs/troubleshooting.md)

## Security Notes

- Requires NET_RAW and NET_ADMIN capabilities for packet capture
- Container runs as root for network access
- Packet captures are stored in mounted volumes
- Use appropriate network isolation in production



## Contributing

Please read CONTRIBUTING.md for details on our code of conduct and the process for submitting pull requests.



make quickstart

make down

make analyze

make health-check