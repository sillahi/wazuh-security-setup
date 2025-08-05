#!/bin/bash

# Wazuh Manager Setup Script for RHEL/CentOS
# This script installs and configures Wazuh Manager

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

# Check OS version
if [[ -f /etc/redhat-release ]]; then
    OS_VERSION=$(cat /etc/redhat-release)
    print_status "Detected OS: $OS_VERSION"
else
    print_error "This script is designed for RHEL/CentOS systems"
    exit 1
fi

# Variables
WAZUH_VERSION="4.7.0"
WAZUH_REPO_URL="https://packages.wazuh.com/4.x/yum/"
ELASTIC_VERSION="7.17.9"
KIBANA_VERSION="7.17.9"

print_status "Starting Wazuh Manager installation..."

# Update system
print_status "Updating system packages..."
yum update -y

# Install required packages
print_status "Installing required packages..."
yum install -y curl wget unzip java-11-openjdk-devel

# Add Wazuh repository
print_status "Adding Wazuh repository..."
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh_repo]
gpgcheck=1
enabled=1
name=Wazuh repository
baseurl=https://packages.wazuh.com/4.x/yum/
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
EOF

# Import GPG key
print_status "Importing Wazuh GPG key..."
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

# Install Wazuh Manager
print_status "Installing Wazuh Manager..."
yum install -y wazuh-manager

# Start and enable Wazuh Manager service
print_status "Starting Wazuh Manager service..."
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager

# Check service status
if systemctl is-active --quiet wazuh-manager; then
    print_status "Wazuh Manager is running successfully"
else
    print_error "Wazuh Manager failed to start"
    exit 1
fi

# Install Wazuh Indexer (Elasticsearch)
print_status "Installing Wazuh Indexer..."
cat > /etc/yum.repos.d/wazuh-indexer.repo << EOF
[wazuh-indexer]
name=Wazuh Indexer Repository
baseurl=https://artifacts.elastic.co/packages/7.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
EOF

# Install Elasticsearch
yum install -y elasticsearch-${ELASTIC_VERSION}

# Configure Elasticsearch
print_status "Configuring Elasticsearch..."
cat > /etc/elasticsearch/elasticsearch.yml << EOF
cluster.name: wazuh-cluster
node.name: node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch
network.host: localhost
http.port: 9200
discovery.type: single-node
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: elastic-certificates.p12
xpack.security.transport.ssl.truststore.path: elastic-certificates.p12
EOF

# Create certificates directory
mkdir -p /etc/elasticsearch/certs

# Generate certificates
print_status "Generating SSL certificates..."
if [[ ! -f /etc/elasticsearch/elastic-certificates.p12 ]]; then
    /usr/share/elasticsearch/bin/elasticsearch-certutil cert -out /etc/elasticsearch/elastic-certificates.p12 -pass ""
    chown elasticsearch:elasticsearch /etc/elasticsearch/elastic-certificates.p12
else
    print_warning "SSL certificate already exists at /etc/elasticsearch/elastic-certificates.p12 — skipping generation"
fi

# cd /etc/elasticsearch/certs
# /usr/share/elasticsearch/bin/elasticsearch-certutil cert -out elastic-certificates.p12 -pass ""

# Copy certificate to Elasticsearch config
# cp elastic-certificates.p12 /etc/elasticsearch/

# Start and enable Elasticsearch
print_status "Starting Elasticsearch..."
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

# Wait for Elasticsearch to be ready
print_status "Waiting for Elasticsearch to be ready..."
sleep 30

# Set Elasticsearch passwords
print_status "Setting Elasticsearch passwords..."
/usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto -u "https://localhost:9200" > /tmp/elastic_passwords.txt

# Install Kibana
print_status "Installing Kibana..."
yum install -y kibana-${KIBANA_VERSION}

# Configure Kibana
print_status "Configuring Kibana..."
cat > /etc/kibana/kibana.yml << EOF
server.port: 5601
server.host: "0.0.0.0"
elasticsearch.hosts: ["https://localhost:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "$(grep 'PASSWORD kibana_system' /tmp/elastic_passwords.txt | cut -d' ' -f4)"
elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/ca.crt"]
elasticsearch.ssl.certificate: "/etc/kibana/certs/kibana.crt"
elasticsearch.ssl.key: "/etc/kibana/certs/kibana.key"
xpack.security.enabled: true
xpack.security.encryptionKey: "$(openssl rand -hex 32)"
EOF

# Generate Kibana certificates
print_status "Generating Kibana certificates..."
cd /etc/kibana/certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout kibana.key -out kibana.crt -subj "/C=US/ST=State/L=City/O=Organization/CN=kibana"
cp kibana.crt ca.crt
chown kibana:kibana /etc/kibana/certs/*

# Start and enable Kibana
print_status "Starting Kibana..."
systemctl daemon-reload
systemctl enable kibana
systemctl start kibana

# Install Wazuh Dashboard
print_status "Installing Wazuh Dashboard..."
yum install -y wazuh-dashboard

# Configure Wazuh Dashboard
print_status "Configuring Wazuh Dashboard..."
cat > /etc/wazuh-dashboard/opensearch_dashboards.yml << EOF
server.port: 5601
server.host: "0.0.0.0"
opensearch.hosts: ["https://localhost:9200"]
opensearch.username: "kibana_system"
opensearch.password: "$(grep 'PASSWORD kibana_system' /tmp/elastic_passwords.txt | cut -d' ' -f4)"
opensearch.ssl.certificateAuthorities: ["/etc/wazuh-dashboard/certs/ca.crt"]
opensearch.ssl.certificate: "/etc/wazuh-dashboard/certs/dashboard.crt"
opensearch.ssl.key: "/etc/wazuh-dashboard/certs/dashboard.key"
opensearch_security.multitenancy.enabled: false
opensearch_security.readonly_mode.roles: ["kibana_read_only"]
EOF

# Generate Dashboard certificates
print_status "Generating Dashboard certificates..."
mkdir -p /etc/wazuh-dashboard/certs
cd /etc/wazuh-dashboard/certs
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout dashboard.key -out dashboard.crt -subj "/C=US/ST=State/L=City/O=Organization/CN=dashboard"
cp dashboard.crt ca.crt
chown wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs/*

# Start and enable Wazuh Dashboard
print_status "Starting Wazuh Dashboard..."
systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

# Configure firewall
print_status "Configuring firewall..."
firewall-cmd --permanent --add-port=1514/tcp
firewall-cmd --permanent --add-port=1515/tcp
firewall-cmd --permanent --add-port=514/udp
firewall-cmd --permanent --add-port=514/tcp
firewall-cmd --permanent --add-port=5601/tcp
firewall-cmd --permanent --add-port=9200/tcp
firewall-cmd --reload

# Get manager IP
MANAGER_IP=$(hostname -I | awk '{print $1}')

# Display installation summary
print_status "Installation completed successfully!"
echo ""
echo "=== WAZUH MANAGER INSTALLATION SUMMARY ==="
echo "Manager IP: $MANAGER_IP"
echo "Wazuh Manager: Running on port 1514"
echo "Elasticsearch: Running on port 9200"
echo "Kibana: Running on port 5601"
echo "Wazuh Dashboard: Running on port 5601"
echo ""
echo "=== NEXT STEPS ==="
echo "1. Access Kibana at: https://$MANAGER_IP:5601"
echo "2. Access Wazuh Dashboard at: https://$MANAGER_IP:5601"
echo "3. Use the elastic user password from: /tmp/elastic_passwords.txt"
echo "4. Install agents using the provided scripts:"
echo "   - RHEL: ./scripts/install-rhel-agent.sh $MANAGER_IP"
echo "   - Windows: .\\scripts\\install-windows-agent.ps1 -WazuhManagerIP $MANAGER_IP"
echo ""
echo "=== IMPORTANT FILES ==="
echo "Elasticsearch passwords: /tmp/elastic_passwords.txt"
echo "Wazuh Manager logs: /var/ossec/logs/"
echo "Elasticsearch logs: /var/log/elasticsearch/"
echo "Kibana logs: /var/log/kibana/"
echo ""

# Save manager IP for agent installation
echo "$MANAGER_IP" > /tmp/wazuh_manager_ip.txt
print_status "Manager IP saved to /tmp/wazuh_manager_ip.txt" 