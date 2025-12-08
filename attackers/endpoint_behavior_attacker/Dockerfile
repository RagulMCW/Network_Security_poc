FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    python3 \
    python3-pip \
    iputils-ping \
    netcat \
    net-tools \
    nmap \
    dnsutils \
    uuid-runtime \
    sshpass \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip3 install requests paramiko

WORKDIR /app

# Copy the endpoint behavior simulator
COPY endpoint_behavior_simulator.py /app/

# Fix line endings and make executable
RUN sed -i 's/\r$//' /app/endpoint_behavior_simulator.py && \
    chmod +x /app/endpoint_behavior_simulator.py

# Create logs directory
RUN mkdir -p /app/logs

# Run the simulator
CMD ["python3", "/app/endpoint_behavior_simulator.py"]
