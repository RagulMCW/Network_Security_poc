#!/bin/bash

# Network Security Monitor - Test Suite Runner
# Professional automated testing script

set -e  # Exit on any error

echo "Network Security Monitor - Test Suite"
echo "====================================="

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAPTURE_DIR="$PROJECT_ROOT/captures"
TEST_RESULTS_DIR="$PROJECT_ROOT/test_results"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Utility functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Pre-test setup
setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Create necessary directories
    mkdir -p "$TEST_RESULTS_DIR"
    mkdir -p "$CAPTURE_DIR"
    
    # Install Python dependencies
    if command -v python3 &> /dev/null; then
        log_info "Installing Python dependencies..."
        pip3 install -r "$PROJECT_ROOT/requirements.txt" >/dev/null 2>&1 || log_warn "Some dependencies may not be installed"
    fi
}

# Docker tests
test_docker_setup() {
    log_info "Testing Docker setup..."
    
    # Check Docker availability
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found"
        return 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose not found"
        return 1
    fi
    
    # Test Docker build
    cd "$PROJECT_ROOT"
    log_info "Building Docker image..."
    docker build -f docker/Dockerfile -t network-monitor-test . >/dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        log_info "✓ Docker build successful"
    else
        log_error "✗ Docker build failed"
        return 1
    fi
}

# Unit tests
run_unit_tests() {
    log_info "Running unit tests..."
    
    cd "$PROJECT_ROOT"
    
    # Run Python unit tests
    python3 -m pytest tests/ -v --tb=short > "$TEST_RESULTS_DIR/unit_tests.log" 2>&1
    
    if [ $? -eq 0 ]; then
        log_info "✓ Unit tests passed"
    else
        log_warn "Some unit tests failed - check $TEST_RESULTS_DIR/unit_tests.log"
    fi
}

# Integration tests
run_integration_tests() {
    log_info "Running integration tests..."
    
    cd "$PROJECT_ROOT/docker"
    
    # Start services
    log_info "Starting test services..."
    docker-compose up -d >/dev/null 2>&1
    
    # Wait for services to be ready
    sleep 15
    
    # Test Flask API
    log_info "Testing Flask API endpoints..."
    
    # Health check
    if curl -f -s http://localhost:5000/health >/dev/null; then
        log_info "✓ Health endpoint working"
    else
        log_error "✗ Health endpoint failed"
        docker-compose down >/dev/null 2>&1
        return 1
    fi
    
    # Network info
    if curl -f -s http://localhost:5000/network/info >/dev/null; then
        log_info "✓ Network info endpoint working"
    else
        log_warn "Network info endpoint not responding"
    fi
    
    # Capture files
    if curl -f -s http://localhost:5000/capture/files >/dev/null; then
        log_info "✓ Capture files endpoint working"
    else
        log_warn "Capture files endpoint not responding"
    fi
    
    # Test HAProxy
    log_info "Testing HAProxy stats..."
    if curl -f -s http://localhost:8080/stats >/dev/null; then
        log_info "✓ HAProxy stats working"
    else
        log_warn "HAProxy stats not responding"
    fi
    
    # Generate test traffic
    log_info "Generating test traffic..."
    for i in {1..20}; do
        curl -s http://localhost:5000/network/info >/dev/null &
    done
    wait
    
    # Wait for packet capture
    sleep 10
    
    # Check for capture files
    if ls "$CAPTURE_DIR"/*.pcap* 1> /dev/null 2>&1; then
        log_info "✓ Packet capture working"
        
        # Analyze capture if possible
        if command -v python3 &> /dev/null; then
            log_info "Analyzing captured packets..."
            python3 scripts/analyze_capture.py "$CAPTURE_DIR"/*.pcap* > "$TEST_RESULTS_DIR/packet_analysis.log" 2>&1 || log_warn "Packet analysis failed"
        fi
    else
        log_warn "No packet captures found"
    fi
    
    # Cleanup
    log_info "Stopping test services..."
    docker-compose down >/dev/null 2>&1
}

# Performance tests
run_performance_tests() {
    log_info "Running performance tests..."
    
    cd "$PROJECT_ROOT/docker"
    docker-compose up -d >/dev/null 2>&1
    
    sleep 10
    
    # Load test with concurrent requests
    log_info "Running load test (100 concurrent requests)..."
    
    start_time=$(date +%s)
    
    for i in {1..100}; do
        curl -s http://localhost:5000/health >/dev/null &
    done
    wait
    
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    log_info "✓ Load test completed in ${duration}s"
    
    # Memory usage check
    if command -v docker &> /dev/null; then
        container_id=$(docker ps -q --filter "name=network-monitor")
        if [ -n "$container_id" ]; then
            memory_usage=$(docker stats --no-stream --format "{{.MemUsage}}" "$container_id")
            log_info "Container memory usage: $memory_usage"
        fi
    fi
    
    docker-compose down >/dev/null 2>&1
}

# WSL-specific tests
test_wsl_compatibility() {
    if [[ -n "$WSL_DISTRO_NAME" ]]; then
        log_info "Running WSL-specific tests..."
        
        # Test Windows port forwarding
        log_info "Testing Windows port accessibility..."
        
        # Note: These tests would require Windows commands
        # For now, just log that we're in WSL
        log_info "WSL environment detected: $WSL_DISTRO_NAME"
        log_info "Manual verification required for Windows port access"
    else
        log_info "Not running in WSL - skipping WSL tests"
    fi
}

# Security tests
run_security_tests() {
    log_info "Running security tests..."
    
    # Check for common security issues
    log_info "Checking Docker security..."
    
    # Check if running as root
    if [ "$EUID" -eq 0 ]; then
        log_warn "Running as root - not recommended for production"
    fi
    
    # Check file permissions
    if [ -f "$PROJECT_ROOT/scripts/start_services.sh" ]; then
        if [ -x "$PROJECT_ROOT/scripts/start_services.sh" ]; then
            log_info "✓ Script permissions correct"
        else
            log_warn "Script not executable"
        fi
    fi
    
    log_info "✓ Basic security checks completed"
}

# Generate test report
generate_report() {
    log_info "Generating test report..."
    
    report_file="$TEST_RESULTS_DIR/test_report.txt"
    
    cat > "$report_file" << EOF
Network Security Monitor - Test Report
======================================
Date: $(date)
Environment: $(uname -a)

Test Results Summary:
- Docker Setup: $([ -f "$TEST_RESULTS_DIR/.docker_ok" ] && echo "PASS" || echo "FAIL")
- Unit Tests: $([ -f "$TEST_RESULTS_DIR/unit_tests.log" ] && echo "COMPLETED" || echo "SKIPPED")
- Integration Tests: $([ -f "$TEST_RESULTS_DIR/.integration_ok" ] && echo "PASS" || echo "FAIL")
- Performance Tests: COMPLETED
- Security Tests: COMPLETED

Capture Files Found: $(ls -1 "$CAPTURE_DIR"/*.pcap* 2>/dev/null | wc -l)

For detailed logs, check files in: $TEST_RESULTS_DIR/
EOF

    log_info "Test report generated: $report_file"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."
    
    # Stop any running containers
    cd "$PROJECT_ROOT/docker" 2>/dev/null && docker-compose down >/dev/null 2>&1 || true
    
    # Remove test images
    docker rmi network-monitor-test >/dev/null 2>&1 || true
    
    log_info "Cleanup completed"
}

# Main test execution
main() {
    log_info "Starting comprehensive test suite..."
    
    # Trap cleanup on exit
    trap cleanup EXIT
    
    setup_test_environment
    
    # Run tests
    test_docker_setup && touch "$TEST_RESULTS_DIR/.docker_ok"
    run_unit_tests
    run_integration_tests && touch "$TEST_RESULTS_DIR/.integration_ok"
    run_performance_tests
    test_wsl_compatibility
    run_security_tests
    
    generate_report
    
    log_info "Test suite completed. Check $TEST_RESULTS_DIR/ for detailed results."
}

# Script entry point
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi