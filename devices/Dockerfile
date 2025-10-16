# Lightweight Virtual Device Container
# Purpose: Simulates network devices that communicate with the monitoring server

FROM python:3.11-slim

# Install minimal dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip install --no-cache-dir requests

# Create app directory
WORKDIR /app

# Copy device simulator script
COPY device_simulator.py .

# Default device configuration (can be overridden)
ENV DEVICE_ID="device_001"
ENV DEVICE_TYPE="generic"
ENV SERVER_URL="http://192.168.6.131:5000"
ENV REQUEST_INTERVAL="5"

# Run the device simulator
CMD ["python", "-u", "device_simulator.py"]
