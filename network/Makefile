# Network Security Monitor - Professional Makefile
# =================================================

# Configuration
PROJECT_NAME = network-security-monitor
DOCKER_IMAGE = $(PROJECT_NAME)
DOCKER_COMPOSE = docker/docker-compose.yml
PYTHON = python3
PIP = pip3

# Colors for output
BLUE = \033[34m
GREEN = \033[32m
YELLOW = \033[33m
RED = \033[31m
NC = \033[0m # No Color

# Default target
.PHONY: help
help: ## Show this help message
	@echo "$(BLUE)Network Security Monitor - Make Commands$(NC)"
	@echo "=============================================="
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

# Development commands
.PHONY: install
install: ## Install Python dependencies
	@echo "$(BLUE)Installing dependencies...$(NC)"
	$(PIP) install -r requirements.txt

.PHONY: install-dev
install-dev: install ## Install development dependencies
	@echo "$(BLUE)Installing development dependencies...$(NC)"
	$(PIP) install pytest pytest-cov black flake8 mypy

.PHONY: format
format: ## Format code with black
	@echo "$(BLUE)Formatting code...$(NC)"
	black src/ scripts/ tests/

.PHONY: lint
lint: ## Lint code with flake8
	@echo "$(BLUE)Linting code...$(NC)"
	flake8 src/ scripts/ tests/

.PHONY: type-check
type-check: ## Type check with mypy
	@echo "$(BLUE)Type checking...$(NC)"
	mypy src/ --ignore-missing-imports

# Testing commands
.PHONY: test
test: ## Run unit tests
	@echo "$(BLUE)Running unit tests...$(NC)"
	cd tests && $(PYTHON) -m pytest -v

.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	cd tests && $(PYTHON) -m pytest --cov=../src --cov-report=html --cov-report=term

.PHONY: test-integration
test-integration: ## Run integration tests
	@echo "$(BLUE)Running integration tests...$(NC)"
	./scripts/run_tests.sh

# Docker commands
.PHONY: build
build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(NC)"
	docker build -f docker/Dockerfile -t $(DOCKER_IMAGE) .

.PHONY: up
up: build ## Start services with docker-compose
	@echo "$(BLUE)Starting services...$(NC)"
	cd docker && docker-compose up -d
	@echo "$(GREEN)Services started successfully!$(NC)"
	@echo "Flask API: http://localhost:5000"
	@echo "HAProxy Stats: http://localhost:8080/stats"

.PHONY: down
down: ## Stop services
	@echo "$(BLUE)Stopping services...$(NC)"
	cd docker && docker-compose down

.PHONY: logs
logs: ## Show service logs
	@echo "$(BLUE)Showing service logs...$(NC)"
	cd docker && docker-compose logs -f

.PHONY: status
status: ## Show service status
	@echo "$(BLUE)Service status:$(NC)"
	cd docker && docker-compose ps

# WSL-specific commands
.PHONY: wsl-setup
wsl-setup: ## Setup WSL port forwarding
	@echo "$(BLUE)Setting up WSL port forwarding...$(NC)"
	@echo "$(YELLOW)Note: Run this from WSL terminal$(NC)"
	./scripts/quickstart.sh --wsl

.PHONY: wsl-test
wsl-test: ## Test WSL connectivity
	@echo "$(BLUE)Testing WSL connectivity...$(NC)"
	curl -f http://localhost:5000/health || echo "$(RED)Connection failed$(NC)"
	curl -f http://localhost:8080/stats || echo "$(RED)HAProxy stats failed$(NC)"

# Analysis commands
.PHONY: analyze
analyze: ## Analyze capture files
	@echo "$(BLUE)Analyzing capture files...$(NC)"
	@if ls captures/*.pcap* 1> /dev/null 2>&1; then \
		for file in captures/*.pcap*; do \
			echo "Analyzing $$file:"; \
			$(PYTHON) scripts/analyze_capture.py "$$file"; \
		done; \
	else \
		echo "$(YELLOW)No capture files found$(NC)"; \
	fi

.PHONY: capture-info
capture-info: ## Show capture file information
	@echo "$(BLUE)Capture file information:$(NC)"
	@ls -lah captures/ 2>/dev/null || echo "$(YELLOW)No captures directory found$(NC)"

# Deployment commands
.PHONY: deploy
deploy: ## Deploy with production settings
	@echo "$(BLUE)Deploying with production settings...$(NC)"
	./scripts/deploy.sh

.PHONY: deploy-wsl
deploy-wsl: ## Deploy for WSL environment
	@echo "$(BLUE)Deploying for WSL environment...$(NC)"
	./scripts/deploy.sh --wsl

# Maintenance commands
.PHONY: clean
clean: ## Clean up containers and images
	@echo "$(BLUE)Cleaning up...$(NC)"
	cd docker && docker-compose down --volumes --remove-orphans
	docker image prune -f
	docker volume prune -f

.PHONY: clean-all
clean-all: clean ## Clean everything including captures
	@echo "$(BLUE)Cleaning everything...$(NC)"
	rm -rf captures/*.pcap*
	rm -rf test_results/
	docker system prune -af

.PHONY: reset
reset: clean-all build up ## Full reset: clean, build, and start
	@echo "$(GREEN)Full reset completed$(NC)"

# Documentation commands
.PHONY: docs
docs: ## Open documentation
	@echo "$(BLUE)Available documentation:$(NC)"
	@echo "README.md - Main project documentation"
	@echo "docs/API.md - API documentation"
	@echo "docs/TESTING.md - Testing guide"
	@echo "QUICKSTART.md - Quick start guide"

.PHONY: health-check
health-check: ## Check service health
	@echo "$(BLUE)Checking service health...$(NC)"
	@curl -s http://localhost:5000/health | $(PYTHON) -m json.tool || echo "$(RED)Flask service not responding$(NC)"
	@curl -s http://localhost:8080/stats >/dev/null && echo "$(GREEN)HAProxy service healthy$(NC)" || echo "$(RED)HAProxy service not responding$(NC)"

# Quick start commands
.PHONY: quickstart
quickstart: install build up health-check ## Complete quickstart setup
	@echo "$(GREEN)Quickstart completed successfully!$(NC)"
	@echo "Next steps:"
	@echo "  make logs     - View service logs"
	@echo "  make analyze  - Analyze captured packets"
	@echo "  make test     - Run test suite"

.PHONY: dev
dev: install-dev format lint test ## Development workflow
	@echo "$(GREEN)Development workflow completed$(NC)"

# Version and info
.PHONY: version
version: ## Show version information
	@echo "$(BLUE)Network Security Monitor v1.0.0$(NC)"
	@echo "Docker: $$(docker --version 2>/dev/null || echo 'Not installed')"
	@echo "Docker Compose: $$(docker-compose --version 2>/dev/null || echo 'Not installed')"
	@echo "Python: $$($(PYTHON) --version 2>/dev/null || echo 'Not installed')"

# Make sure intermediate files are not deleted
.SECONDARY:python scripts\analyze_capture.py captures\capture.pcap