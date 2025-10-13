#!/bin/bash
# WSL Docker Management Script
# Quick commands for managing network monitor container
# =====================================================

PROJECT_DIR="/mnt/e/nos/Network_Security_poc/network"
IMAGE_NAME="network-security-monitor"
CONTAINER_NAME="net-monitor-wan"
NETWORK_NAME="custom_net"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}! $1${NC}"
}

# Navigate to project
cd "$PROJECT_DIR" || {
    print_error "Failed to navigate to $PROJECT_DIR"
    exit 1
}

# Main menu
show_menu() {
    print_header "Network Security Monitor - WSL Manager"
    echo ""
    echo "1. Build Docker image"
    echo "2. Start container"
    echo "3. Stop container"
    echo "4. Restart container"
    echo "5. View status"
    echo "6. View logs"
    echo "7. Test health"
    echo "8. View captures"
    echo "9. Shell into container"
    echo "10. Clean up"
    echo "11. Full setup (build + start)"
    echo "0. Exit"
    echo ""
}

# Build image
build_image() {
    print_header "Building Docker Image"
    docker build -f docker/Dockerfile -t "$IMAGE_NAME" .
    if [ $? -eq 0 ]; then
        print_success "Image built successfully"
    else
        print_error "Failed to build image"
        return 1
    fi
}

# Create network
create_network() {
    if ! docker network ls | grep -q "$NETWORK_NAME"; then
        print_warning "Creating network $NETWORK_NAME..."
        docker network create --driver bridge --subnet=192.168.6.0/24 "$NETWORK_NAME"
        print_success "Network created"
    else
        print_success "Network already exists"
    fi
}

# Start container
start_container() {
    print_header "Starting Container"
    
    create_network
    
    # Check if container exists
    if docker ps -a | grep -q "$CONTAINER_NAME"; then
        print_warning "Container exists, starting..."
        docker start "$CONTAINER_NAME"
    else
        print_warning "Creating new container..."
        docker run -d --name "$CONTAINER_NAME" \
            --net "$NETWORK_NAME" --ip 192.168.6.131 \
            -p 5002:5000 -p 8082:8080 -p 8415:8404 \
            --cap-add=NET_RAW --cap-add=NET_ADMIN \
            -e SERVER_ID="$CONTAINER_NAME" \
            -v "$(pwd)/captures:/captures" \
            "$IMAGE_NAME"
    fi
    
    if [ $? -eq 0 ]; then
        print_success "Container started"
        echo ""
        echo "Access URLs:"
        echo "  HAProxy Stats:  http://localhost:8082/"
        echo "  Monitoring:     http://localhost:8415/stats"
    else
        print_error "Failed to start container"
        return 1
    fi
}

# Stop container
stop_container() {
    print_header "Stopping Container"
    docker stop "$CONTAINER_NAME"
    if [ $? -eq 0 ]; then
        print_success "Container stopped"
    else
        print_error "Failed to stop container"
    fi
}

# Restart container
restart_container() {
    print_header "Restarting Container"
    docker restart "$CONTAINER_NAME"
    if [ $? -eq 0 ]; then
        print_success "Container restarted"
    else
        print_error "Failed to restart container"
    fi
}

# View status
view_status() {
    print_header "Container Status"
    docker ps -a | grep -E "$CONTAINER_NAME|CONTAINER"
    echo ""
    docker inspect "$CONTAINER_NAME" --format='Status: {{.State.Status}}' 2>/dev/null
}

# View logs
view_logs() {
    print_header "Container Logs"
    echo "Press Ctrl+C to exit"
    docker logs -f "$CONTAINER_NAME"
}

# Test health
test_health() {
    print_header "Health Check"
    
    echo ""
    echo "Testing Flask API..."
    if curl -f -s http://localhost:5002/health > /dev/null; then
        print_success "Flask API is healthy"
        curl -s http://localhost:5002/health | python3 -m json.tool 2>/dev/null || curl -s http://localhost:5002/health
    else
        print_error "Flask API not responding"
    fi
    
    echo ""
    echo "Testing HAProxy..."
    if curl -f -s http://localhost:8082/stats > /dev/null; then
        print_success "HAProxy is healthy"
    else
        print_error "HAProxy not responding"
    fi
}

# View captures
view_captures() {
    print_header "Captured Files"
    ls -lah captures/
}

# Shell into container
shell_container() {
    print_header "Container Shell"
    echo "Type 'exit' to return"
    docker exec -it "$CONTAINER_NAME" /bin/bash
}

# Clean up
cleanup() {
    print_header "Cleaning Up"
    
    echo "Stopping container..."
    docker stop "$CONTAINER_NAME" 2>/dev/null
    
    echo "Removing container..."
    docker rm "$CONTAINER_NAME" 2>/dev/null
    
    echo "Pruning images..."
    docker image prune -f
    
    print_success "Cleanup complete"
}

# Full setup
full_setup() {
    print_header "Full Setup"
    build_image
    echo ""
    start_container
    echo ""
    sleep 3
    test_health
}

# Interactive mode
if [ $# -eq 0 ]; then
    while true; do
        show_menu
        read -p "Enter your choice: " choice
        echo ""
        
        case $choice in
            1) build_image ;;
            2) start_container ;;
            3) stop_container ;;
            4) restart_container ;;
            5) view_status ;;
            6) view_logs ;;
            7) test_health ;;
            8) view_captures ;;
            9) shell_container ;;
            10) cleanup ;;
            11) full_setup ;;
            0) echo "Goodbye!"; exit 0 ;;
            *) print_error "Invalid choice" ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
    done
else
    # Command line mode
    case "$1" in
        build) build_image ;;
        start) start_container ;;
        stop) stop_container ;;
        restart) restart_container ;;
        status) view_status ;;
        logs) view_logs ;;
        health) test_health ;;
        captures) view_captures ;;
        shell) shell_container ;;
        clean) cleanup ;;
        setup) full_setup ;;
        *) 
            echo "Usage: $0 {build|start|stop|restart|status|logs|health|captures|shell|clean|setup}"
            echo "Or run without arguments for interactive menu"
            exit 1
            ;;
    esac
fi