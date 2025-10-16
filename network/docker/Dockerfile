# Network Security Monitoring Container
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install essential network monitoring tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    haproxy \
    curl \
    tcpdump \
    tshark \
    iproute2 \
    iputils-ping \
    net-tools \
    libpcap0.8 \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy source code
COPY src/ /app/src/
COPY scripts/ /app/scripts/
COPY network-monitor.html /app/network-monitor.html

# Install Python dependencies
RUN pip3 install flask scapy

# Create python symlink for convenience
RUN ln -s /usr/bin/python3 /usr/bin/python

# Create captures directory
RUN mkdir -p /captures && chmod 755 /captures

# Make startup script executable
RUN chmod +x /app/scripts/start_services.sh

# Expose ports
EXPOSE 5000 8080 8404

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://127.0.0.1:8080/health || exit 1

# Start services
CMD ["/app/scripts/start_services.sh"]