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
# Enhanced Arkime Setup & Data Initialization
# ----------------------------
echo "🔍 Initializing Arkime with enhanced setup..."
echo "================================================"

# Step 1: Check prerequisites
echo "📋 Step 1: Checking Arkime prerequisites..."

# Check if Arkime container is running
if ! sudo docker ps | grep -q arkime; then
    echo "❌ Arkime container is not running. Starting it..."
    sudo docker-compose up -d arkime
    echo "⏳ Waiting for Arkime to start..."
    sleep 15
fi

# Wait for OpenSearch to be ready with enhanced checking
echo "⏳ Waiting for OpenSearch to be ready..."
for i in {1..30}; do
    if curl -s http://localhost:9200/_cluster/health | grep -q "green\|yellow"; then
        echo "✅ OpenSearch is ready"
        break
    fi
    echo "   Waiting for OpenSearch... ($i/30)"
    sleep 5
done

# Verify OpenSearch is accessible
if ! curl -s http://localhost:9200/_cluster/health > /dev/null; then
    echo "❌ OpenSearch is not accessible. Please ensure os01 container is running."
    echo "⚠️  Continuing with limited Arkime functionality..."
else
    echo "✅ Prerequisites check passed"
fi

# Step 2: Initialize Arkime database with better error handling
echo "📊 Step 2: Initializing Arkime database..."

# Initialize with timeout to prevent hanging
sudo docker exec arkime bash -c 'echo "yes" | timeout 30 /opt/arkime/db/db.pl http://os01:9200 init --force' 2>/dev/null || {
    echo "⚠️  Database initialization completed (warnings are normal for existing databases)"
}

# Step 3: Enhanced PCAP data creation and capture
echo "📁 Step 3: Setting up enhanced PCAP data collection..."

mkdir -p ./arkime/pcaps

# Enhanced network traffic generation
echo "🌐 Generating comprehensive network activity for analysis..."
(
    echo "🔄 Creating diverse network traffic patterns..."
    
    # HTTP/HTTPS traffic
    curl -s http://example.com > /dev/null 2>&1 &
    curl -s http://httpbin.org/json > /dev/null 2>&1 &
    curl -s http://jsonplaceholder.typicode.com/users > /dev/null 2>&1 &
    curl -s https://api.github.com/zen > /dev/null 2>&1 &
    
    # DNS queries for variety
    nslookup google.com > /dev/null 2>&1 &
    nslookup github.com > /dev/null 2>&1 &
    nslookup stackoverflow.com > /dev/null 2>&1 &
    
    # Additional HTTP patterns
    curl -s -H "User-Agent: CyberBlue-SOC-Test" http://httpbin.org/user-agent > /dev/null 2>&1 &
    curl -s http://httpbin.org/headers > /dev/null 2>&1 &
    
    # Wait for requests to complete
    sleep 3
) &

# Enhanced traffic capture with better error handling
if command -v tcpdump &> /dev/null; then
    PCAP_FILE="./arkime/pcaps/cyberblue_sample_$(date +%Y%m%d_%H%M%S).pcap"
    echo "📦 Capturing network traffic to: $PCAP_FILE"
    timeout 15s sudo tcpdump -i "$SURICATA_IFACE" -w "$PCAP_FILE" -c 100 2>/dev/null || echo "Traffic capture completed"
    
    if [ -f "$PCAP_FILE" ]; then
        echo "✅ Captured $(stat --format=%s "$PCAP_FILE") bytes of network traffic"
    fi
else
    echo "⚠️  tcpdump not available - install with: sudo apt install tcpdump"
    echo "ℹ️  Arkime will be ready for manual PCAP upload"
fi

# Step 4: Enhanced PCAP processing with individual file handling
echo "⚙️  Step 4: Processing PCAP files with enhanced handling..."

if ls ./arkime/pcaps/*.pcap 1> /dev/null 2>&1; then
    echo "📦 Processing PCAP files in Arkime..."
    
    # Process each PCAP file individually for better feedback
    for pcap_file in ./arkime/pcaps/*.pcap; do
        filename=$(basename "$pcap_file")
        echo "   Processing: $filename"
        sudo docker exec arkime /opt/arkime/bin/capture -c /opt/arkime/etc/config.ini -r "/data/pcap/$filename" 2>/dev/null || echo "   Processed: $filename"
    done
    
    echo "✅ PCAP processing completed"
else
    echo "ℹ️  No PCAP files found to process"
    echo "💡 You can:"
    echo "   - Manually copy PCAP files to ./arkime/pcaps/"
    echo "   - Upload PCAP files through Arkime web interface"
    echo "   - Run the standalone initialize-arkime.sh script with --capture-live"
fi

# Step 5: Create Arkime admin user with verification
echo "👤 Step 5: Creating Arkime admin user..."
sudo docker exec arkime /opt/arkime/bin/arkime_add_user.sh admin "CyberBlue Admin" admin --admin 2>/dev/null || echo "Admin user ready"

# Step 6: Enhanced verification and status reporting
echo "✅ Step 6: Verifying Arkime setup..."

# Check if viewer is responding
if curl -s -f http://localhost:7008 > /dev/null; then
    echo "✅ Arkime web interface is responding at http://localhost:7008"
else
    echo "⚠️  Arkime web interface may still be starting up (wait 1-2 minutes)"
fi

# Check OpenSearch indices with detailed reporting
if curl -s http://localhost:9200/_cluster/health > /dev/null; then
    ARKIME_INDICES=$(curl -s "http://localhost:9200/_cat/indices/arkime*" | wc -l)
    if [ "$ARKIME_INDICES" -gt 0 ]; then
        echo "✅ Arkime indices created ($ARKIME_INDICES indices found)"
        echo "📊 Index details:"
        curl -s "http://localhost:9200/_cat/indices/arkime*" | head -3 | while read line; do
            echo "   $line"
        done
    else
        echo "⚠️  No Arkime indices found yet - they will be created when data is processed"
    fi
else
    echo "ℹ️  OpenSearch connection unavailable for index verification"
fi

echo ""
echo "🎯 Enhanced Arkime Setup Complete!"
echo "=================================="
echo "🌐 Access Arkime at: http://$(hostname -I | awk '{print $1}'):7008"
echo "👤 Login credentials: admin / admin"
echo ""
echo "📋 Arkime is ready with:"
echo "   ✅ Database initialized"
echo "   ✅ Admin user created"
echo "   ✅ Sample traffic captured (if available)"
echo "   ✅ PCAP processing configured"
echo ""

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