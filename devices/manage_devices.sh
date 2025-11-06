#!/bin/bash
# Virtual Device Manager for Linux/WSL
# Creates and manages multiple virtual devices on the Docker network

set -e

NETWORK_NAME="custom_net"
DEVICE_IMAGE="virtual-device:latest"
DEVICE_BASE_IP="192.168.6"
DEVICE_START_IP=10
DEVICE_CONTAINER_PREFIX="vdevice"   

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Virtual Device Manager${NC}"
    echo -e "${BLUE}========================================${NC}"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Build the device Docker image
build_image() {
    print_info "Building device Docker image..."
    
    cd "$(dirname "$0")"
    
    if [ ! -f "Dockerfile" ]; then
        print_error "Dockerfile not found in devices directory"
        exit 1
    fi
    
    docker build -t "$DEVICE_IMAGE" .
    
    if [ $? -eq 0 ]; then
        print_success "Device image built successfully"
    else
        print_error "Failed to build device image"
        exit 1
    fi
}

# Create N virtual devices
create_devices() {
    local count=$1
    local device_type=${2:-"generic"}
    
    if [ -z "$count" ]; then
        print_error "Please specify number of devices to create"
        echo "Usage: $0 create <count> [device_type]"
        echo "Device types: iot_sensor, smartphone, laptop, camera, generic"
        exit 1
    fi
    
    print_header
    print_info "Creating $count virtual devices (type: $device_type)..."
    
    # Check if image exists
    if ! docker image inspect "$DEVICE_IMAGE" >/dev/null 2>&1; then
        print_info "Device image not found. Building..."
        build_image
    fi
    
    # Check if network exists
    if ! docker network inspect "$NETWORK_NAME" >/dev/null 2>&1; then
        print_error "Network '$NETWORK_NAME' not found. Please start the main server first."
        exit 1
    fi
    
    # Create devices
    for i in $(seq 1 $count); do
        local device_num=$(printf "%03d" $i)
        local device_id="device_${device_num}"
        local container_name="${DEVICE_CONTAINER_PREFIX}_${device_num}"
        local ip_address="${DEVICE_BASE_IP}.$((DEVICE_START_IP + i - 1))"
        
        # Check if container already exists
        if docker ps -a --format '{{.Names}}' | grep -q "^${container_name}$"; then
            print_info "Device ${device_id} already exists (${container_name})"
            continue
        fi
        
        # Create container
        docker run -d \
            --name "$container_name" \
            --network "$NETWORK_NAME" \
            --ip "$ip_address" \
            -e DEVICE_ID="$device_id" \
            -e DEVICE_TYPE="$device_type" \
            -e SERVER_URL="http://192.168.6.131:5000" \
            -e REQUEST_INTERVAL="5" \
            --restart unless-stopped \
            "$DEVICE_IMAGE"
        
        if [ $? -eq 0 ]; then
            print_success "Created device: ${device_id} at ${ip_address}"
        else
            print_error "Failed to create device: ${device_id}"
        fi
        
        # Small delay to avoid overwhelming the network
        sleep 0.5
    done
    
    print_success "Device creation completed"
    echo ""
    list_devices
}

# List all virtual devices
list_devices() {
    print_header
    print_info "Active Virtual Devices:"
    echo ""
    
    # Get all device containers
    local containers=$(docker ps --filter "name=${DEVICE_CONTAINER_PREFIX}_" --format "{{.Names}}")
    
    if [ -z "$containers" ]; then
        print_info "No active devices found"
        return
    fi
    
    echo -e "${BLUE}Device ID       IP Address      Status      Uptime${NC}"
    echo "--------------------------------------------------------"
    
    for container in $containers; do
        local device_id=$(docker exec "$container" printenv DEVICE_ID 2>/dev/null || echo "unknown")
        local ip_address=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$container")
        local status=$(docker inspect -f '{{.State.Status}}' "$container")
        local uptime=$(docker ps --filter "name=$container" --format "{{.RunningFor}}")
        
        echo -e "${device_id}     ${ip_address}    ${status}    ${uptime}"
    done
    
    echo ""
    local count=$(echo "$containers" | wc -l)
    print_success "Total devices: $count"
}

# Stop all virtual devices
stop_devices() {
    print_header
    print_info "Stopping all virtual devices..."
    
    local containers=$(docker ps --filter "name=${DEVICE_CONTAINER_PREFIX}_" --format "{{.Names}}")
    
    if [ -z "$containers" ]; then
        print_info "No active devices to stop"
        return
    fi
    
    echo "$containers" | xargs docker stop
    
    print_success "All devices stopped"
}

# Start stopped devices
start_devices() {
    print_header
    print_info "Starting virtual devices..."
    
    local containers=$(docker ps -a --filter "name=${DEVICE_CONTAINER_PREFIX}_" --format "{{.Names}}")
    
    if [ -z "$containers" ]; then
        print_info "No devices found"
        return
    fi
    
    echo "$containers" | xargs docker start
    
    print_success "Devices started"
}

# Remove all virtual devices
remove_devices() {
    print_header
    read -p "Are you sure you want to remove all virtual devices? (y/N): " confirm
    
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        print_info "Operation cancelled"
        return
    fi
    
    print_info "Removing all virtual devices..."
    
    # Stop and remove containers
    local containers=$(docker ps -a --filter "name=${DEVICE_CONTAINER_PREFIX}_" --format "{{.Names}}")
    
    if [ -z "$containers" ]; then
        print_info "No devices to remove"
        return
    fi
    
    echo "$containers" | xargs docker stop 2>/dev/null || true
    echo "$containers" | xargs docker rm 2>/dev/null || true
    
    print_success "All devices removed"
}

# View logs of a specific device
view_logs() {
    local device_num=$1
    
    if [ -z "$device_num" ]; then
        print_error "Please specify device number (e.g., 001, 002)"
        exit 1
    fi
    
    local container_name="${DEVICE_CONTAINER_PREFIX}_${device_num}"
    
    if ! docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
        print_error "Device ${device_num} not found or not running"
        exit 1
    fi
    
    print_info "Showing logs for device ${device_num} (Press Ctrl+C to exit)"
    echo ""
    docker logs -f "$container_name"
}

# Show device statistics
show_stats() {
    print_header
    print_info "Device Statistics:"
    echo ""
    
    local containers=$(docker ps --filter "name=${DEVICE_CONTAINER_PREFIX}_" --format "{{.Names}}")
    
    if [ -z "$containers" ]; then
        print_info "No active devices found"
        return
    fi
    
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" $containers
}

# Show usage information
show_usage() {
    print_header
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  build                      Build device Docker image"
    echo "  create <count> [type]      Create N virtual devices"
    echo "  list                       List all devices"
    echo "  start                      Start stopped devices"
    echo "  stop                       Stop all devices"
    echo "  remove                     Remove all devices"
    echo "  logs <device_num>          View device logs (e.g., logs 001)"
    echo "  stats                      Show device statistics"
    echo "  help                       Show this help message"
    echo ""
    echo "Device Types:"
    echo "  iot_sensor    - IoT sensor (temp, humidity, pressure)"
    echo "  smartphone    - Mobile device (location, battery)"
    echo "  laptop        - Computer (CPU, memory, disk)"
    echo "  camera        - Security camera (motion, recording)"
    echo "  generic       - Generic device (default)"
    echo ""
    echo "Examples:"
    echo "  $0 create 5                # Create 5 generic devices"
    echo "  $0 create 3 iot_sensor     # Create 3 IoT sensors"
    echo "  $0 list                    # List all devices"
    echo "  $0 logs 001                # View logs for device 001"
    echo "  $0 remove                  # Remove all devices"
    echo ""
}

# Main script
main() {
    local command=$1
    shift
    
    case "$command" in
        build)
            build_image
            ;;
        create)
            create_devices "$@"
            ;;
        list)
            list_devices
            ;;
        start)
            start_devices
            ;;
        stop)
            stop_devices
            ;;
        remove)
            remove_devices
            ;;
        logs)
            view_logs "$@"
            ;;
        stats)
            show_stats
            ;;
        help|--help|-h)
            show_usage
            ;;
        *)
            print_error "Unknown command: $command"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
if [ $# -eq 0 ]; then
    show_usage
    exit 1
fi

main "$@"
