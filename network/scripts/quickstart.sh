#!/bin/bash

# Network Security Monitor - Quick Start Script
# Professional deployment for Windows WSL environment

echo "Network Security Monitor - Quick Start"
echo "======================================"

# Check requirements
check_requirements() {
    echo "Checking requirements..."
    
    if ! command -v docker &> /dev/null; then
        echo "Error: Docker not installed"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        echo "Error: Docker Compose not installed" 
        exit 1
    fi
    
    echo "All requirements met"
}

# Build and start services
start_monitoring() {
    echo "Starting Network Security Monitor..."
    
    # Navigate to docker directory
    cd "$(dirname "$0")/../docker"
    
    # Build and start services
    docker-compose up -d --build
    
    if [ $? -eq 0 ]; then
        echo "Services started successfully"
        echo ""
        echo "Access URLs:"
        echo "  Flask API: http://localhost:5000"
        echo "  HAProxy Stats: http://localhost:8080/stats"
        echo ""
        echo "To check logs: docker-compose logs -f"
        echo "To stop: docker-compose down"
    else
        echo "Error starting services"
        exit 1
    fi
}

# Main execution
main() {
    check_requirements
    start_monitoring
}

# WSL-specific port forwarding
setup_wsl_forwarding() {
    if [[ -n "$WSL_DISTRO_NAME" ]]; then
        echo "WSL environment detected"
        echo "Setting up port forwarding..."
        
        # Forward ports for Windows access
        netsh.exe interface portproxy add v4tov4 listenport=5000 listenaddress=0.0.0.0 connectport=5000 connectaddress=localhost 2>/dev/null || true
        netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=8080 connectaddress=localhost 2>/dev/null || true
        
        echo "Port forwarding configured"
        echo "Access from Windows at:"
        echo "  http://localhost:5000 (Flask API)"
        echo "  http://localhost:8080/stats (HAProxy)"
    fi
}

# Parse command line arguments
if [[ "$1" == "--wsl" ]]; then
    setup_wsl_forwarding
fi

main