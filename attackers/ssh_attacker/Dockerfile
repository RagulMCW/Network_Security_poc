# SSH Brute Force Attacker Container
# Purpose: Simulates SSH brute force attacks for security testing

FROM debian:bookworm-slim

# Install SSH client, sshpass (for password-based SSH), and tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    sshpass \
    bash \
    iproute2 \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy attack scripts
COPY ssh_bruteforce.sh .
COPY wordlists/ ./wordlists/

# Create logs directory
RUN mkdir -p /app/logs

# Make scripts executable
RUN chmod +x ssh_bruteforce.sh

# Environment variables
ENV TARGET_IP="192.168.6.131"
ENV TARGET_PORT="22"
ENV ATTACK_INTERVAL="5"
ENV LOG_INTERVAL="5"

# Run the SSH brute force script
CMD ["/app/ssh_bruteforce.sh"]
