#!/bin/bash

# Simple curl sender script
# Repeatedly sends HTTP requests to the Flask server to simulate application-layer traffic

TARGET_URL="${TARGET_URL:-http://192.168.6.131:5000/}"
REQUESTS="${REQUESTS:-1000000000}"
DELAY="${DELAY:-0.1}"

print_attacker_ip() {
  if command -v ip >/dev/null 2>&1; then
    ATTACKER_IP=$(ip -4 addr show scope global | awk '/inet/ {print $2}' | cut -d/ -f1 | head -n1)
  else
    ATTACKER_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  ATTACKER_IP=${ATTACKER_IP:-unknown}
  echo "Attacker container IP: $ATTACKER_IP"
}

echo "=========================================="
echo "Starting curl sender..."
echo "=========================================="
print_attacker_ip
echo "Target URL: $TARGET_URL"
echo "Requests: $REQUESTS, Delay between requests: ${DELAY}s"
echo "=========================================="

i=0
while [ "$i" -lt "$REQUESTS" ]; do
  ts=$(date +"%Y-%m-%dT%H:%M:%S%z")
  echo "[$ts] GET $TARGET_URL"
  curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL" || echo "curl failed"
  echo ""
  i=$((i+1))
  sleep "$DELAY"
done

echo "curl sender completed."
