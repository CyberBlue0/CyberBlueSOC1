# 🛡️ CyberBlueSOC Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-20.10+-blue.svg)](https://www.docker.com/)
[![Docker Compose](https://img.shields.io/badge/Docker%20Compose-2.0+-blue.svg)](https://docs.docker.com/compose/)

> **Production-Ready Cybersecurity Lab** - Deploy 15+ integrated security tools with a single command

**CyberBlue** is a comprehensive, containerized cybersecurity platform that brings together industry-leading open-source tools for **SIEM**, **DFIR**, **CTI**, **SOAR**, and **Network Analysis**. Perfect for security teams, researchers, educators, and enthusiasts.

---

## 🎯 Overview

CyberBlue transforms Blue Teams cybersecurity tool deployment into a **one-command solution**. Built with Docker Compose and featuring a beautiful web portal, it provides enterprise-grade security capabilities in minutes, not days.

### 🌟 Why CyberBlue?

- **🚀 Instant Deployment**: Full security lab in under 30 minutes
- **🎨 Modern Interface**: Beautiful CyberBlue portal with enhanced dashboard
- **🔧 Lab Ready**: Pre-configured, optimized containers
- **📚 Documentation**: Step-by-step guides and tutorials (auto-generated for Beta version)
- **🌐 Community Driven**: Open source with active development!

---

## 🛡️ Security Tools Included

### 📊 **SIEM & Monitoring**
- **[Wazuh](https://wazuh.com/)** - Host-based intrusion detection and log analysis
- **[Suricata](https://suricata.io/)** - Network intrusion detection and prevention
- **[EveBox](https://evebox.org/)** - Suricata event and alert management

### 🕵️ **DFIR & Forensics**
- **[Velociraptor](https://docs.velociraptor.app/)** - Endpoint visibility and digital forensics
- **[Arkime](https://arkime.com/)** - Full packet capture and network analysis
- **[Wireshark](https://www.wireshark.org/)** - Network protocol analyzer

### 🧠 **Threat Intelligence**
- **[MISP](https://www.misp-project.org/)** - Threat intelligence platform
- **[MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)** - Threat modeling and visualization

### ⚡ **SOAR & Automation**
- **[Shuffle](https://shuffler.io/)** - Security orchestration and automation
- **[TheHive](https://thehive-project.org/)** - Incident response platform
- **[Cortex](https://github.com/TheHive-Project/Cortex)** - Observable analysis engine

### 🔧 **Utilities & Management**
- **[CyberChef](https://gchq.github.io/CyberChef/)** - Cyber Swiss Army knife
- **[Portainer](https://www.portainer.io/)** - Container management interface
- **[FleetDM](https://fleetdm.com/)** - Device management and osquery fleet manager
- **[Caldera](https://caldera.mitre.org/)** - Adversary emulation platform

---

## 🚀 Quick Start

### Prerequisites
- **Docker** 20.10+ and **Docker Compose** 2.0+
```bash
sudo apt update && \
sudo apt install -y ca-certificates curl gnupg lsb-release && \
sudo mkdir -p /etc/apt/keyrings && \
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null && \
sudo apt update && \
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin && \
sudo usermod -aG docker $USER && \
newgrp docker && \
sudo chown root:docker /var/run/docker.sock && \
cb@cb:~/CyberBlueSOC$ sudo chmod 660 /var/run/docker.sock && \
docker --version && docker compose version
```
- **RAM** (16+ GB recommended)
- **100GB+ free disk space**
- **Linux/Ubuntu** (tested only on Ubuntu 22.04.5 LTS & Ubuntu 24.04.2 LTS)

### ⚡ One-Command Installation

```bash
# Clone the repository
git clone https://github.com/CyberBlue0/CyberBlueSOC.git
cd CyberBlueSOC

# Run the quick start script 
chmod +x cyberblue_init.sh
chmod +x quick-start.sh
./quick-start.sh
```

The script will:
- ✅ Check system requirements
- ✅ Configure environment variables
- ✅ Deploy all security tools
- ✅ Start the CyberBlue portal
- ✅ Display access URLs

### 🌐 Access Your Security Lab

After deployment, access the **CyberBlue Portal** at:
```
http://YOUR_SERVER_IP:5500
```

Individual tools are available on ports **7000-7099**:
- **Velociraptor**: https://YOUR_SERVER_IP:7000
- **Wazuh**: https://YOUR_SERVER_IP:7001
- **Shuffle**: https://YOUR_SERVER_IP:7002
- **MISP**: https://YOUR_SERVER_IP:7003
- **And more...**

---

## 📖 Documentation

### 🚀 Quick Start
- **[Installation Guide](INSTALL.md)** - Detailed setup instructions
- **[Security Guide](SECURITY.md)** - Hardening and best practices

### 📚 Comprehensive Documentation
- **[📚 Documentation Hub](docs/README.md)** - Complete documentation index
- **[📖 User Guide](docs/USER_GUIDE.md)** - How to use all CyberBlue tools
- **[⚙️ Tool Configurations](docs/TOOL_CONFIGURATIONS.md)** - Advanced tool setup and customization
- **[🔌 API Reference](docs/API_REFERENCE.md)** - Portal API documentation
- **[🚀 Deployment Scenarios](docs/DEPLOYMENT_SCENARIOS.md)** - Development, staging, and production guides
- **[🔧 Maintenance Guide](docs/MAINTENANCE_GUIDE.md)** - Operational procedures and schedules
- **[💾 Backup & Recovery](docs/BACKUP_RECOVERY.md)** - Disaster recovery procedures
- **[🔧 Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions

---

## ⚙️ Configuration

### Environment Variables

Copy `.env.template` to `.env` and customize:

```bash
# Network Configuration
HOST_IP=10.0.0.40                    # Your server IP
NETWORK_SUBNET=172.18.0.0/16         # Docker network subnet

# Security Configuration
WAZUH_ADMIN_PASSWORD=SecurePass123!   # Wazuh admin password
OPENSEARCH_ADMIN_PASSWORD=SecurePass123!  # OpenSearch admin password
MISP_ADMIN_EMAIL=admin@cyberblue.local     # MISP admin email

# Portal Configuration
PORTAL_PORT=5500                      # CyberBlue portal port
```

### Advanced Configuration

For production deployments, see our [Advanced Configuration Guide](docs/ADVANCED.md).

---

## 🎨 CyberBlue Portal Features

The CyberBlue Portal provides a unified interface for managing your security lab:

### 📊 **Enhanced Dashboard**
- Real-time container status monitoring
- System resource utilization
- Security metrics and trends
- Activity logging and changelog

### 🔧 **Container Management**
- One-click start/stop/restart controls
- Health status indicators
- Resource usage monitoring
- Log viewing capabilities

### 🛡️ **Security Overview**
- Tool categorization (SIEM, DFIR, CTI, SOAR)
- Quick access to all security tools
- Integration status monitoring
- Security posture dashboard

### 🔍 **Search & Filter**
- Tool search functionality
- Category-based filtering
- Status-based filtering
- Organized tool layout

---

## 🐳 Architecture

CyberBlue uses a microservices architecture with Docker Compose:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CyberBlue     │    │   SIEM Stack    │    │   DFIR Stack    │
│     Portal      │    │                 │    │                 │
│   (Flask App)   │    │ • Wazuh         │    │ • Velociraptor  │
│                 │    │ • Suricata      │    │ • Arkime        │
│                 │    │ • EveBox        │    │ • Wireshark     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌─────────────────┐    ┌┴─────────────────┐    ┌─────────────────┐
         │   CTI Stack     │    │ Docker Network   │    │  SOAR Stack     │
         │                 │    │  (172.18.0.0/16) │    │                 │
         │ • MISP          │    │                  │    │ • Shuffle       │
         │ • MITRE ATT&CK  │    │                  │    │ • TheHive       │
         │                 │    │                  │    │ • Cortex        │
         └─────────────────┘    └──────────────────┘    └─────────────────┘
```

---


## 📋 System Requirements

### Recommended Requirements
- **CPU**: 8+ cores
- **RAM**: 16GB+
- **Storage**: 100GB+ SSD
- **Network**: Gigabit Ethernet

---

## 🔧 Troubleshooting

### Common Issues

**Portal not accessible:**
```bash
# Check portal status
docker ps | grep portal

# View portal logs
docker logs cyber-blue-portal
```

**Tools not starting:**
```bash
# Check all containers
docker ps -a

# Restart specific service
docker-compose restart [service-name]
```

**Resource issues:**
```bash
# Check system resources
docker stats

# Free up space
docker system prune -a
```

For more troubleshooting, see our [Troubleshooting Guide](docs/TROUBLESHOOTING.md).

---

## 📊 Monitoring & Metrics

CyberBlue includes built-in monitoring:

- **Container Health**: Real-time status monitoring
- **Resource Usage**: CPU, memory, disk utilization

---

## 🔒 Security Considerations

- **Network Isolation**: All tools run in isolated Docker networks
- **Access Control**: Configure authentication for LAB use
- **SSL/TLS**: Enable HTTPS for some web interfaces
- 

See our [Security Guide](SECURITY.md) for detailed hardening instructions. 

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **MITRE Corporation** for the ATT&CK framework
- **Elastic** for the ELK stack foundation
- **The Hive Project** for incident response tools
- **All open-source contributors** who make this possible


---

<div align="center">

**⭐ Star this repository if you find it useful for you!**

</div>
