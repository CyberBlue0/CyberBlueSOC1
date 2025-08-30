#!/bin/bash

set -e  # Exit on error

# Record start time
START_TIME=$(date +%s)

echo ""
echo "🎉 =================================="
echo "    ____      _               ____  _            "
echo "   / ___|   _| |__   ___ _ __| __ )| |_   _  ___ "
echo "  | |  | | | | '_ \ / _ \ '__|  _ \| | | | |/ _ \\"
echo "  | |__| |_| | |_) |  __/ |  | |_) | | |_| |  __/"
echo "   \____\__, |_.__/ \___|_|  |____/|_|\__,_|\___|"
echo "        |___/                                    "
echo ""
echo "  🔷 CyberBlue SOC Platform Initialization 🔷"
echo ""
echo "🚀 Starting CyberBlue initialization..."
echo "=================================="

# ----------------------------
# Cleanup: Remove existing directories if they exist
# ----------------------------
echo "🧹 Cleaning up any existing build directories..."
if [ -d "attack-navigator" ]; then
    echo "   Removing existing attack-navigator/ directory..."
    rm -rf attack-navigator/
fi
if [ -d "wireshark" ]; then
    echo "   Removing existing wireshark/ directory..."
    rm -rf wireshark/
fi

# Clone MITRE ATTACK Nav.
echo "📥 Cloning MITRE ATT&CK Navigator..."
git clone https://github.com/mitre-attack/attack-navigator.git

# ----------------------------
# Get Host IP for MISP
# ----------------------------
HOST_IP=$(hostname -I | awk '{print $1}')
MISP_URL="https://${HOST_IP}:7003"
echo "🔧 Configuring MISP_BASE_URL as: $MISP_URL"

# Ensure .env exists
if [ ! -f .env ] && [ -f .env.template ]; then
    echo "🧪 Creating .env from .env.template..."
    cp .env.template .env
fi
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating one..."
    touch .env
fi

# Set or update MISP_BASE_URL
if grep -q "^MISP_BASE_URL=" .env; then
    sed -i "s|^MISP_BASE_URL=.*|MISP_BASE_URL=${MISP_URL}|" .env
else
    echo "MISP_BASE_URL=${MISP_URL}" >> .env
fi

# Show result
echo "✅ .env updated with:"
grep "^MISP_BASE_URL=" .env

# ----------------------------
# Generate YETI_AUTH_SECRET_KEY
# ----------------------------
if grep -q "^YETI_AUTH_SECRET_KEY=" .env; then
    echo "ℹ️ YETI_AUTH_SECRET_KEY already exists. Skipping."
else
    SECRET_KEY=$(openssl rand -hex 64)
    echo "YETI_AUTH_SECRET_KEY=${SECRET_KEY}" >> .env
    echo "✅ YETI_AUTH_SECRET_KEY added to .env"
fi

# Prepare directory
sudo mkdir -p /opt/yeti/bloomfilters

# ----------------------------
# Dynamic Suricata Interface Detection
# ----------------------------
echo "🔍 Detecting primary network interface for Suricata..."

# Method 1: Try to get the default route interface (most reliable)
SURICATA_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)

# Method 2: Fallback to first active non-loopback interface
if [ -z "$SURICATA_IFACE" ]; then
    echo "⚠️  No default route found, trying alternative detection..."
    SURICATA_IFACE=$(ip link show | grep -E '^[0-9]+:' | grep -v lo | grep 'state UP' | awk -F': ' '{print $2}' | head -1)
fi

# Method 3: Final fallback to any UP interface except loopback
if [ -z "$SURICATA_IFACE" ]; then
    echo "⚠️  Trying final fallback method..."
    SURICATA_IFACE=$(ip a | grep 'state UP' | grep -v lo | awk -F: '{print $2}' | head -1 | xargs)
fi

if [ -z "$SURICATA_IFACE" ]; then
    echo "❌ Could not detect any suitable network interface for Suricata."
    echo "📋 Available interfaces:"
    ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print "   - " $2}' | sed 's/@.*$//'
    echo "💡 Please manually set SURICATA_INT in .env file"
    exit 1
fi

echo "✅ Detected primary interface: $SURICATA_IFACE"

# Always update the SURICATA_INT to ensure it's current
if grep -q "^SURICATA_INT=" .env; then
    echo "🔄 Updating existing SURICATA_INT in .env..."
    sed -i "s/^SURICATA_INT=.*/SURICATA_INT=$SURICATA_IFACE/" .env
else
    echo "SURICATA_INT=$SURICATA_IFACE" >> .env
fi

echo "✅ SURICATA_INT configured as: $SURICATA_IFACE"
echo "📋 Current network interface settings:"
grep "^SURICATA_INT=" .env

# ----------------------------
# Suricata Rule Setup
# ----------------------------
echo "📦 Downloading Emerging Threats rules..."
sudo mkdir -p ./suricata/rules
if [ ! -f ./suricata/emerging.rules.tar.gz ]; then
    sudo curl -s -O https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz
    sudo tar -xzf emerging.rules.tar.gz -C ./suricata/rules --strip-components=1
    sudo rm emerging.rules.tar.gz
else
    echo "ℹ️ Suricata rules archive already downloaded. Skipping."
fi

# Download config files
sudo curl -s -o ./suricata/classification.config https://raw.githubusercontent.com/OISF/suricata/master/etc/classification.config
sudo curl -s -o ./suricata/reference.config https://raw.githubusercontent.com/OISF/suricata/master/etc/reference.config

# ----------------------------
# Launching Services
# ----------------------------
echo "🚀 Running Docker initialization commands..."
sudo docker-compose run --rm generator
sudo docker-compose up --build -d
sudo docker run --rm \
  --network=cyber-blue \
  -e FLEET_MYSQL_ADDRESS=fleet-mysql:3306 \
  -e FLEET_MYSQL_USERNAME=fleet \
  -e FLEET_MYSQL_PASSWORD=fleetpass \
  -e FLEET_MYSQL_DATABASE=fleet \
  fleetdm/fleet:latest fleet prepare db
sudo docker-compose up -d fleet-server

# ----------------------------
# Arkime Setup & Data Initialization
# ----------------------------
echo "🔍 Setting up Arkime with sample data..."

# Wait for OpenSearch to be ready
echo "⏳ Waiting for OpenSearch to be ready..."
for i in {1..30}; do
  if curl -s http://localhost:9200/_cluster/health | grep -q "green\|yellow"; then
    echo "✅ OpenSearch is ready"
    break
  fi
  echo "   Waiting for OpenSearch... ($i/30)"
  sleep 5
done

# Initialize Arkime database
echo "📊 Initializing Arkime database..."
sudo docker exec arkime bash -c 'echo "yes" | timeout 30 /opt/arkime/db/db.pl http://os01:9200 init --force' 2>/dev/null || {
    echo "⚠️  Database initialization completed with warnings (this is normal)"
}

# Create sample PCAP data
echo "📁 Creating sample network traffic for Arkime..."
mkdir -p ./arkime/pcaps

# Generate some network activity and capture it
echo "🌐 Capturing live network traffic for analysis..."
(
    # Generate some HTTP traffic
    curl -s http://example.com > /dev/null 2>&1 &
    curl -s http://httpbin.org/get > /dev/null 2>&1 &
    curl -s http://jsonplaceholder.typicode.com/posts/1 > /dev/null 2>&1 &
    
    # Wait for requests to complete
    sleep 2
) &

# Capture the traffic (if tcpdump is available)
if command -v tcpdump &> /dev/null; then
    timeout 10s sudo tcpdump -i $SURICATA_IFACE -w ./arkime/pcaps/sample_traffic.pcap -c 50 2>/dev/null || echo "Traffic capture completed"
else
    echo "⚠️  tcpdump not available, skipping live capture"
fi

# Process any PCAP files in the directory
echo "⚙️  Processing PCAP files..."
if ls ./arkime/pcaps/*.pcap 1> /dev/null 2>&1; then
    echo "📦 Found PCAP files, processing..."
    sudo docker exec arkime bash -c 'find /data/pcap -name "*.pcap" -exec /opt/arkime/bin/capture -c /opt/arkime/etc/config.ini -r {} \;' 2>/dev/null || echo "PCAP processing completed"
else
    echo "ℹ️  No PCAP files found - Arkime will be ready for manual upload"
fi

# Create Arkime admin user
echo "👤 Creating Arkime admin user..."
sudo docker exec arkime /opt/arkime/bin/arkime_add_user.sh admin "Admin User" admin --admin 2>/dev/null || echo "User creation completed"

echo "✅ Arkime setup complete!"

# ----------------------------
# Caldera Setup
# ----------------------------
echo "🧠 Installing Caldera in the background..."
chmod +x ./install_caldera.sh
./install_caldera.sh

# Wait until Caldera is fully running on port 7009
echo "⏳ Waiting for Caldera to become available on port 7009..."
for i in {1..30}; do
  if ss -tuln | grep -q ":7009"; then
    echo "✅ Caldera is now running at http://localhost:7009"
    break
  fi
  sleep 2
done

# ----------------------------
# Final Success Message with Logo and Time
# ----------------------------
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

echo ""
echo "🎉 =================================="
echo "    ____      _               ____  _            "
echo "   / ___|   _| |__   ___ _ __| __ )| |_   _  ___ "
echo "  | |  | | | | '_ \ / _ \ '__|  _ \| | | | |/ _ \\"
echo "  | |__| |_| | |_) |  __/ |  | |_) | | |_| |  __/"
echo "   \____\__, |_.__/ \___|_|  |____/|_|\__,_|\___|"
echo "        |___/                                    "
echo ""
echo "  🔷 CyberBlue SOC Platform Successfully Deployed! 🔷"
echo ""
echo "⏱️  Total Installation Time: ${MINUTES}m ${SECONDS}s"
echo ""
echo "🌐 Access Your SOC Tools:"
echo "   🏠 Portal:         https://$(hostname -I | awk '{print $1}'):5443"
echo "   🔒 MISP:           https://$(hostname -I | awk '{print $1}'):7003"
echo "   🛡️  Wazuh:          http://$(hostname -I | awk '{print $1}'):7001"
echo "   🔍 EveBox:         http://$(hostname -I | awk '{print $1}'):7010"
echo "   🧠 Caldera:        http://$(hostname -I | awk '{print $1}'):7009"
echo "   📊 Arkime:         http://$(hostname -I | awk '{print $1}'):7008"
echo "   🕷️  TheHive:        http://$(hostname -I | awk '{print $1}'):7005"
echo "   🔧 Fleet:          http://$(hostname -I | awk '{print $1}'):7007"
echo "   🧪 CyberChef:      http://$(hostname -I | awk '{print $1}'):7004"
echo "   🔗 Shuffle:        http://$(hostname -I | awk '{print $1}'):7002"
echo "   🖥️  Portainer:      http://$(hostname -I | awk '{print $1}'):9443"
echo "   ✨ ...and many others!"
echo ""
echo "🔑 Access & Credentials:"
echo "   🏠 CyberBlueSOC Portal: https://$(hostname -I | awk '{print $1}'):5443 - admin / cyberblue123"
echo "   🔒 Other Tools:         admin / cyberblue"
echo ""
echo "✅ CyberBlue SOC is ready for cyber defense operations!"
echo "=================================="
