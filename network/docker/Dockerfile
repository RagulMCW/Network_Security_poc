# Network Security Monitoring Container with Zeek
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install essential network monitoring tools + SSH server + Zeek dependencies
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
    openssh-server \
    wget \
    gnupg \
    lsb-release \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Zeek from official repository
RUN echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
    > /etc/apt/sources.list.d/security:zeek.list && \
    wget -qO - https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key \
    | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg && \
    apt-get update && \
    apt-get install -y --no-install-recommends zeek zeek-core zeekctl || \
    (apt-get install -y --fix-missing zeek zeek-core zeekctl || true) && \
    rm -rf /var/lib/apt/lists/*

# Add Zeek to PATH
ENV PATH="/opt/zeek/bin:${PATH}"

# Setup SSH
RUN mkdir -p /var/run/sshd && \
    mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh

# Create test users for SSH brute force testing
RUN useradd -m -s /bin/bash admin && echo "admin:admin123" | chpasswd && \
    useradd -m -s /bin/bash test && echo "test:test123" | chpasswd && \
    useradd -m -s /bin/bash user && echo "user:password" | chpasswd

# Configure SSH to allow password authentication and log all attempts
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config && \
    echo "root:rootpassword" | chpasswd

# Create app directory
WORKDIR /app

# Copy source code
COPY src/ /app/src/
COPY scripts/ /app/scripts/

# Copy ALL Zeek configuration files and scripts
COPY zeek/ /app/zeek/

# Install Python dependencies
RUN pip3 install flask scapy

# Create python symlink for convenience
RUN ln -s /usr/bin/python3 /usr/bin/python

# Create captures directory
RUN mkdir -p /captures && chmod 755 /captures

# Make scripts executable
RUN chmod +x /app/scripts/start_services.sh /app/zeek/monitor.sh

# Expose ports
EXPOSE 5000 8080 8404 22

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://127.0.0.1:8080/health || exit 1

# Start services
CMD ["/app/scripts/start_services.sh"]