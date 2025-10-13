#!/bin/bash

# Network Security Monitor - Build and Run Script
# Professional deployment automation

set -e

PROJECT_NAME="network-security-monitor"
VERSION="1.0.0"
NETWORK_NAME="custom_net"
NETWORK_SUBNET="192.168.6.0/24"

show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  build         Build the Docker image"
    echo "  run           Run with standard configuration"
    echo "  run-wsl       Run with WSL + Windows port mapping"
    echo "  stop          Stop running containers"
    echo "  clean         Remove containers and images"
    echo "  test          Run connectivity tests"
    echo "  logs          Show container logs"
    echo "  help          Show this help message"
    echo ""
}

build_image() {
    echo "Building ${PROJECT_NAME} v${VERSION}..."
    docker build -f docker/Dockerfile -t ${PROJECT_NAME}:${VERSION} -t ${PROJECT_NAME}:latest .
    echo "Build complete."
}

create_network() {
    if ! docker network ls | grep -q ${NETWORK_NAME}; then
        echo "Creating network ${NETWORK_NAME}..."
        docker network create --driver bridge --subnet=${NETWORK_SUBNET} ${NETWORK_NAME}
    else
        echo "Network ${NETWORK_NAME} already exists."
    fi
}

run_standard() {
    echo "Starting ${PROJECT_NAME} in standard mode..."
    docker run -d \
        --name net-monitor \
        -p 8080:8080 \
        -p 5000:5000 \
        -p 8404:8404 \
        --cap-add=NET_RAW \
        --cap-add=NET_ADMIN \
        -e SERVER_ID=monitor-standard \
        -v "$(pwd)/captures:/captures" \
        ${PROJECT_NAME}:latest
    
    echo "Container started. Access at:"
    echo "  Web Interface: http://localhost:8080"
    echo "  API: http://localhost:5000"
    echo "  Statistics: http://localhost:8404/stats"
}

run_wsl() {
    echo "Starting ${PROJECT_NAME} in WSL + Windows mode..."
    create_network
    
    docker run -d \
        --name net-monitor-wsl \
        --net ${NETWORK_NAME} \
        --ip 192.168.6.131 \
        -p 5002:5000 \
        -p 8082:8080 \
        -p 8415:8404 \
        --cap-add=NET_RAW \
        --cap-add=NET_ADMIN \
        -e SERVER_ID=net-monitor-wsl \
        -v "$(pwd)/captures:/captures" \
        ${PROJECT_NAME}:latest
    
    echo "Container started. Access from Windows at:"
    echo "  Web Interface: http://localhost:8082"
    echo "  API: http://localhost:5002"
    echo "  Statistics: http://localhost:8415/stats"
}

stop_containers() {
    echo "Stopping containers..."
    docker stop net-monitor net-monitor-wsl 2>/dev/null || true
    docker rm net-monitor net-monitor-wsl 2>/dev/null || true
    echo "Containers stopped and removed."
}

clean_all() {
    stop_containers
    echo "Removing images..."
    docker rmi ${PROJECT_NAME}:latest ${PROJECT_NAME}:${VERSION} 2>/dev/null || true
    echo "Cleanup complete."
}

run_tests() {
    echo "Running connectivity tests..."
    
    # Test standard configuration
    if docker ps | grep -q net-monitor; then
        echo "Testing standard configuration..."
        curl -f http://localhost:8080/health && echo " - Health check: OK"
        curl -f http://localhost:5000/ && echo " - Flask API: OK"
    fi
    
    # Test WSL configuration
    if docker ps | grep -q net-monitor-wsl; then
        echo "Testing WSL configuration..."
        curl -f http://localhost:8082/health && echo " - Health check: OK"
        curl -f http://localhost:5002/ && echo " - Flask API: OK"
    fi
    
    echo "Tests complete."
}

show_logs() {
    if docker ps | grep -q net-monitor; then
        echo "=== Standard Container Logs ==="
        docker logs --tail 50 net-monitor
    fi
    
    if docker ps | grep -q net-monitor-wsl; then
        echo "=== WSL Container Logs ==="
        docker logs --tail 50 net-monitor-wsl
    fi
}

case "${1:-help}" in
    build)
        build_image
        ;;
    run)
        build_image
        run_standard
        ;;
    run-wsl)
        build_image
        run_wsl
        ;;
    stop)
        stop_containers
        ;;
    clean)
        clean_all
        ;;
    test)
        run_tests
        ;;
    logs)
        show_logs
        ;;
    help|*)
        show_usage
        ;;
esac