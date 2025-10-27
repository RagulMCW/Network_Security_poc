#!/bin/bash
# Start Flask dashboard in WSL so devices can reach it on 192.168.6.1

echo "🚀 Starting Flask Dashboard in WSL..."
echo "📡 Dashboard will be accessible to Docker devices on 192.168.6.1:5000"
echo "🌐 Also accessible from Windows at http://localhost:5000"
echo ""

cd /mnt/e/nos/Network_Security_poc/dashboard

# Check if pip3 is available
if ! command -v pip3 &> /dev/null; then
    echo "❌ pip3 not found. Installing python3-pip..."
    sudo apt-get update && sudo apt-get install -y python3-pip
fi

# Install requirements if needed
echo "📦 Checking Python dependencies..."
if ! python3 -c "import flask" 2>/dev/null; then
    echo "📦 Installing Flask and dependencies..."
    pip3 install flask flask-cors python-dotenv requests --user
fi

if ! python3 -c "import anthropic" 2>/dev/null; then
    echo "📦 Installing Anthropic SDK..."
    pip3 install anthropic --user
fi

# Optional: Install scapy for PCAP parsing
if ! python3 -c "import scapy" 2>/dev/null; then
    echo "📦 Installing scapy for PCAP analysis..."
    pip3 install scapy --user
fi

# Run Flask
echo ""
echo "✅ Starting Flask server..."
echo "=================================================="
python3 app.py
