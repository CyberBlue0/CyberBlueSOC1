# 🔍 Arkime Setup Guide for CyberBlueSOC

This guide explains how Arkime is integrated into CyberBlueSOC and how to use it effectively.

## 🎯 Overview

Arkime is a full packet capture and analysis tool that provides deep network visibility. In CyberBlueSOC, it's automatically configured to work with OpenSearch for data storage and analysis.

## 🚀 Automatic Setup

### During Initial Installation

When you run `./cyberblue_init.sh`, Arkime is automatically:

1. ✅ **Database Initialized** - OpenSearch indices created
2. ✅ **Sample Data Generated** - Live network traffic captured
3. ✅ **PCAP Processing** - Traffic analyzed and indexed
4. ✅ **Admin User Created** - Ready for immediate use
5. ✅ **Web Interface Started** - Accessible at port 7008

### Manual Initialization

If you need to reinitialize Arkime:

```bash
# Run the standalone initialization script
./scripts/initialize-arkime.sh

# With live traffic capture
./scripts/initialize-arkime.sh --capture-live

# Force reinitialization
./scripts/initialize-arkime.sh --force --capture-live
```

## 🌐 Access Information

### Web Interface
- **URL**: `http://YOUR_IP:7008`
- **Username**: `admin`
- **Password**: `admin`

### API Access
```bash
# Get session data
curl -u admin:admin "http://localhost:7008/api/sessions?length=10"

# Search for specific traffic
curl -u admin:admin "http://localhost:7008/api/sessions?expression=ip==192.168.1.1"
```

## 📁 Data Sources

### PCAP File Upload
1. **Manual Upload**: Use the web interface to upload PCAP files
2. **Directory Upload**: Copy files to `./arkime/pcaps/` and run processing script
3. **Live Capture**: Enable live packet capture (requires tcpdump)

### Processing PCAP Files
```bash
# Process all PCAP files in the directory
sudo docker exec arkime bash -c 'find /data/pcap -name "*.pcap" -exec /opt/arkime/bin/capture -c /opt/arkime/etc/config.ini -r {} \;'

# Process specific file
sudo docker exec arkime /opt/arkime/bin/capture -c /opt/arkime/etc/config.ini -r /data/pcap/your_file.pcap
```

## 🔧 Configuration

### OpenSearch Connection
Arkime is configured to connect to the `os01` OpenSearch container:
- **Host**: `os01:9200`
- **Indices**: `arkime_sessions3-*`
- **Health Check**: Available at `http://localhost:9200/_cluster/health`

### Data Retention
```bash
# Configure data retention (example)
sudo docker exec arkime /opt/arkime/db/db.pl http://os01:9200 expire daily 30
```

## 🔍 Usage Examples

### Basic Searches
- **All Traffic**: Leave search field empty
- **Specific IP**: `ip == 192.168.1.100`
- **HTTP Traffic**: `protocols == http`
- **Time Range**: Use the time picker in the interface
- **Port Filter**: `port == 80 || port == 443`

### Advanced Queries
```bash
# Find suspicious traffic
protocols == http && http.statuscode == [400..499]

# Large file transfers
bytes > 1000000

# External communications
ip.dst != 192.168.0.0/16 && ip.dst != 10.0.0.0/8
```

## 🛠️ Troubleshooting

### Common Issues

#### No Data Showing
```bash
# Check container status
sudo docker ps | grep arkime

# Check logs
sudo docker logs arkime

# Verify OpenSearch connection
curl http://localhost:9200/_cat/indices/arkime*

# Reinitialize if needed
./scripts/initialize-arkime.sh --force
```

#### Database Connection Issues
```bash
# Check OpenSearch health
curl http://localhost:9200/_cluster/health

# Restart OpenSearch if needed
sudo docker-compose restart os01

# Wait and retry Arkime initialization
sleep 30 && ./scripts/initialize-arkime.sh
```

#### PCAP Processing Errors
```bash
# Check PCAP file permissions
ls -la ./arkime/pcaps/

# Fix permissions if needed
sudo chown -R 1000:1000 ./arkime/pcaps/

# Reprocess files
sudo docker exec arkime bash -c 'find /data/pcap -name "*.pcap" -exec /opt/arkime/bin/capture -c /opt/arkime/etc/config.ini -r {} \;'
```

## 📊 Integration with Other Tools

### Suricata Integration
Arkime complements Suricata by providing:
- **Full packet details** for Suricata alerts
- **Deep protocol analysis** beyond what IDS rules detect
- **Historical packet data** for forensic analysis

### MISP Integration
Use Arkime data to:
- **Extract IOCs** from captured traffic
- **Validate threat intelligence** against real traffic
- **Create new indicators** from observed patterns

### Velociraptor Integration
Combine Arkime with Velociraptor for:
- **Network + endpoint correlation**
- **Complete attack timeline** reconstruction
- **Evidence collection** from multiple sources

## 🔄 Maintenance

### Regular Tasks
```bash
# Weekly: Clean old data (optional)
sudo docker exec arkime /opt/arkime/db/db.pl http://os01:9200 expire daily 30

# Monthly: Optimize indices
curl -X POST "localhost:9200/arkime_*/_forcemerge?max_num_segments=1"

# As needed: Add new users
sudo docker exec arkime /opt/arkime/bin/arkime_add_user.sh newuser "Full Name" password
```

### Performance Tuning
```ini
# Arkime config.ini optimizations
maxFileSizeG=12
magicMode=both
pcapWriteSize=262144
dbBulkSize=300000
```

## 📈 Advanced Features

### Custom Views
Create custom views in the Arkime interface:
1. **Security View**: Focus on suspicious traffic patterns
2. **Performance View**: Monitor bandwidth and top talkers
3. **Compliance View**: Track specific protocols and communications

### Automated Analysis
```bash
# Set up automated PCAP processing
# Add to crontab for regular processing
0 */6 * * * cd /home/ubuntu/CyberBlueSOC && ./scripts/initialize-arkime.sh --capture-live
```

## 🎯 Best Practices

1. **Regular Data Capture**: Set up automated traffic capture
2. **Storage Management**: Monitor disk usage and set retention policies
3. **User Management**: Create role-based users for different teams
4. **Integration**: Use with other CyberBlueSOC tools for comprehensive analysis
5. **Documentation**: Document custom queries and analysis procedures

---

**Arkime is now fully integrated into your CyberBlueSOC platform!** 🎉

For questions or issues, check the troubleshooting section above or review the Arkime logs.
