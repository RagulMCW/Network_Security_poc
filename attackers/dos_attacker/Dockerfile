# Lightweight Attacker Device Container using hping3
# Purpose: Sends crafted packets to the Flask server for security testing

FROM debian:bookworm-slim

# Install hping3 and minimal tools
# include bash and iproute2 so the script can detect the container IP
RUN apt-get update && apt-get install -y --no-install-recommends \
    hping3 \
    bash \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy the hping3 script
COPY hping3_sender.sh .
# Copy the curl-based HTTP sender
COPY curl_sender.sh .

# Make script executable
RUN chmod +x hping3_sender.sh
RUN chmod +x curl_sender.sh

# Environment variables
# NOTE: When using docker-compose we attach this container to `custom_net` and
# assign a static IP (192.168.6.132). If you run with `docker run`, use the
# `--network` flag to attach to the same network so TARGET_IP is reachable.
ENV TARGET_IP="192.168.6.131"
ENV TARGET_PORT="5000"
# sensible defaults (match docker-compose)
ENV PACKET_COUNT="1000000"
ENV PACKET_RATE="1000"

# Run the hping3 sender script
CMD ["/app/hping3_sender.sh"]
