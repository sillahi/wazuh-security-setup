#!/bin/bash

# Wazuh Agent Installation Script for RHEL/CentOS
# This script installs and configures Wazuh Agent on RHEL systems

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

# Function to show usage
show_usage() {
    echo "Usage: $0 <WAZUH_MANAGER_IP> [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -p, --port PORT     Manager port (default: 1514)"
    echo "  -n, --name NAME     Agent name (default: hostname)"
    echo "  -g, --group GROUP   Agent group (default: default)"
    echo ""
    echo "Example:"
    echo "  $0 192.168.1.100"
    echo "  $0 192.168.1.100 -n web-server -g web-servers"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

# Parse command line arguments
MANAGER_IP=""
MANAGER_PORT="1514"
AGENT_NAME=""
AGENT_GROUP="default"

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            ;;
        -p|--port)
            MANAGER_PORT="$2"
            shift 2
            ;;
        -n|--name)
            AGENT_NAME="$2"
            shift 2
            ;;
        -g|--group)
            AGENT_GROUP="$2"
            shift 2
            ;;
        *)
            if [[ -z "$MANAGER_IP" ]]; then
                MANAGER_IP="$1"
            else
                print_error "Unknown option: $1"
                show_usage
            fi
            shift
            ;;
    esac
done

# Check if manager IP is provided
if [[ -z "$MANAGER_IP" ]]; then
    print_error "Wazuh Manager IP is required"
    show_usage
fi

# Validate IP address format
if ! [[ $MANAGER_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    print_error "Invalid IP address format: $MANAGER_IP"
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

# Set agent name if not provided
if [[ -z "$AGENT_NAME" ]]; then
    AGENT_NAME=$(hostname)
fi

print_status "Starting Wazuh Agent installation..."
print_status "Manager IP: $MANAGER_IP"
print_status "Manager Port: $MANAGER_PORT"
print_status "Agent Name: $AGENT_NAME"
print_status "Agent Group: $AGENT_GROUP"

# Update system
print_status "Updating system packages..."
yum update -y

# Install required packages
print_status "Installing required packages..."
yum install -y curl wget

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

# Install Wazuh Agent
print_status "Installing Wazuh Agent..."
yum install -y wazuh-agent

# Configure Wazuh Agent
print_status "Configuring Wazuh Agent..."
cat > /var/ossec/etc/ossec.conf << EOF
<ossec_config>
  <client>
    <server>
      <address>$MANAGER_IP</address>
    </server>
    <config-profile>$AGENT_GROUP</config-profile>
  </client>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/maillog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/cron</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/boot.log</location>
  </localfile>

  <syscheck>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore>no</auto_ignore>
    <scan_timeout>0</scan_timeout>
    <scan_day>sunday</scan_day>
    <scan_time>02:00</scan_time>
  </syscheck>

  <rootcheck>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
  </rootcheck>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>50000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>
</ossec_config>
EOF

# Ensure ossec group exists before setting permissions
if ! getent group ossec >/dev/null; then
    print_warning "Group 'ossec' does not exist. Creating it..."
    groupadd ossec
fi

# Set proper permissions
chown root:ossec /var/ossec/etc/ossec.conf
chmod 640 /var/ossec/etc/ossec.conf

# Configure agent name
print_status "Setting agent name: $AGENT_NAME"
echo "$AGENT_NAME" > /var/ossec/etc/client.keys

# Start and enable Wazuh Agent service
print_status "Starting Wazuh Agent service..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent

# Check service status
if systemctl is-active --quiet wazuh-agent; then
    print_status "Wazuh Agent is running successfully"
else
    print_error "Wazuh Agent failed to start"
    exit 1
fi

# Configure firewall to allow outbound connections
print_status "Configuring firewall..."
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="$MANAGER_IP" port port="1514" protocol="tcp" accept'
firewall-cmd --reload

# Test connectivity to manager
print_status "Testing connectivity to Wazuh Manager..."
if nc -z -w5 $MANAGER_IP $MANAGER_PORT; then
    print_status "Successfully connected to Wazuh Manager"
else
    print_warning "Could not connect to Wazuh Manager. Please check network connectivity and firewall rules."
fi

# Get agent ID
AGENT_ID=$(/var/ossec/bin/agent_control -l | grep "$AGENT_NAME" | awk '{print $2}' 2>/dev/null || echo "Not registered yet")

# Display installation summary
print_status "Installation completed successfully!"
echo ""
echo "=== WAZUH AGENT INSTALLATION SUMMARY ==="
echo "Agent Name: $AGENT_NAME"
echo "Agent Group: $AGENT_GROUP"
echo "Manager IP: $MANAGER_IP"
echo "Manager Port: $MANAGER_PORT"
echo "Agent ID: $AGENT_ID"
echo "Agent Status: Running"
echo ""
echo "=== IMPORTANT FILES ==="
echo "Configuration: /var/ossec/etc/ossec.conf"
echo "Logs: /var/ossec/logs/"
echo "Agent Control: /var/ossec/bin/agent_control"
echo ""
echo "=== USEFUL COMMANDS ==="
echo "Check agent status: systemctl status wazuh-agent"
echo "View agent logs: tail -f /var/ossec/logs/ossec.log"
echo "List agents: /var/ossec/bin/agent_control -l"
echo "Restart agent: systemctl restart wazuh-agent"
echo ""

# Save configuration for reference
cat > /tmp/wazuh_agent_config.txt << EOF
Wazuh Agent Configuration
=========================
Agent Name: $AGENT_NAME
Agent Group: $AGENT_GROUP
Manager IP: $MANAGER_IP
Manager Port: $MANAGER_PORT
Installation Date: $(date)
EOF

print_status "Configuration saved to /tmp/wazuh_agent_config.txt" 