# RHEL Agent Setup Guide

This guide provides detailed instructions for setting up Wazuh agents on RHEL/CentOS systems.

## Prerequisites

- RHEL 7/8/9 or CentOS 7/8/9
- Root or sudo access
- Network connectivity to Wazuh manager
- Minimum 1GB RAM
- 5GB free disk space

## Installation Steps

### 1. Download and Run Installation Script

```bash
# Clone the repository (if not already done)
git clone <repository-url>
cd wazuh-security-setup

# Make script executable
chmod +x scripts/install-rhel-agent.sh

# Run installation with manager IP
sudo ./scripts/install-rhel-agent.sh <WAZUH_MANAGER_IP>
```

### 2. Advanced Installation Options

```bash
# Install with custom agent name and group
sudo ./scripts/install-rhel-agent.sh 192.168.1.100 -n web-server-01 -g web-servers

# Install with custom port
sudo ./scripts/install-rhel-agent.sh 192.168.1.100 -p 1515

# Show help
sudo ./scripts/install-rhel-agent.sh -h
```

## Configuration

### Agent Configuration File

The agent configuration is located at `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.1.100</address>
    </server>
    <config-profile>default</config-profile>
  </client>

  <!-- Log monitoring -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/messages</location>
  </localfile>

  <!-- File integrity monitoring -->
  <syscheck>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
  </syscheck>
</ossec_config>
```

### Custom Log Monitoring

Add custom log files to monitor:

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/application.log</location>
</localfile>

<localfile>
  <log_format>apache</log_format>
  <location>/var/log/httpd/access_log</location>
</localfile>
```

### File Integrity Monitoring

Configure directories to monitor:

```xml
<syscheck>
  <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
  <directories check_all="yes">/var/www/html</directories>
  <directories check_all="yes">/opt/webapp</directories>
  
  <!-- Exclude patterns -->
  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
</syscheck>
```

## Service Management

### Start/Stop Service

```bash
# Start service
sudo systemctl start wazuh-agent

# Stop service
sudo systemctl stop wazuh-agent

# Restart service
sudo systemctl restart wazuh-agent

# Check status
sudo systemctl status wazuh-agent
```

### Enable Auto-start

```bash
# Enable service to start on boot
sudo systemctl enable wazuh-agent

# Disable auto-start
sudo systemctl disable wazuh-agent
```

## Monitoring and Logs

### View Agent Logs

```bash
# View real-time logs
sudo tail -f /var/ossec/logs/ossec.log

# View alerts
sudo tail -f /var/ossec/logs/alerts/alerts.log

# View agent statistics
sudo tail -f /var/ossec/logs/ossec.log | grep "Agent statistics"
```

### Agent Control Commands

```bash
# List all agents
sudo /var/ossec/bin/agent_control -l

# Get agent information
sudo /var/ossec/bin/agent_control -i <agent_id>

# Restart agent
sudo /var/ossec/bin/agent_control -r <agent_id>

# Remove agent
sudo /var/ossec/bin/agent_control -r <agent_id>
```

## Security Hardening

### Firewall Configuration

```bash
# Allow outbound connections to manager
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="192.168.1.100" port port="1514" protocol="tcp" accept'
sudo firewall-cmd --reload
```

### SELinux Configuration

If SELinux is enabled:

```bash
# Check SELinux status
sestatus

# Allow Wazuh agent through SELinux
sudo setsebool -P wazuh_agent_can_network_connect 1
```

### File Permissions

```bash
# Set proper permissions on configuration
sudo chown root:ossec /var/ossec/etc/ossec.conf
sudo chmod 640 /var/ossec/etc/ossec.conf

# Set permissions on logs
sudo chown -R root:ossec /var/ossec/logs/
sudo chmod -R 750 /var/ossec/logs/
```

## Troubleshooting

### Common Issues

1. **Agent not connecting to manager**
   ```bash
   # Check network connectivity
   telnet <manager_ip> 1514
   
   # Check firewall rules
   sudo firewall-cmd --list-all
   
   # Check agent logs
   sudo tail -f /var/ossec/logs/ossec.log
   ```

2. **Service not starting**
   ```bash
   # Check service status
   sudo systemctl status wazuh-agent
   
   # Check configuration syntax
   sudo /var/ossec/bin/ossec-logtest -t
   
   # View detailed logs
   sudo journalctl -u wazuh-agent -f
   ```

3. **High CPU usage**
   ```bash
   # Check syscheck frequency
   grep "frequency" /var/ossec/etc/ossec.conf
   
   # Monitor agent processes
   ps aux | grep ossec
   ```

### Log Analysis

```bash
# Search for specific events
sudo grep "ERROR" /var/ossec/logs/ossec.log

# Search for connection issues
sudo grep "connection" /var/ossec/logs/ossec.log

# Search for authentication issues
sudo grep "auth" /var/ossec/logs/ossec.log
```

### Performance Tuning

```bash
# Adjust client buffer settings
# Edit /var/ossec/etc/ossec.conf
<client_buffer>
  <disabled>no</disabled>
  <queue_size>50000</queue_size>
  <events_per_second>500</events_per_second>
</client_buffer>

# Adjust syscheck frequency for large systems
<syscheck>
  <frequency>86400</frequency>  <!-- 24 hours -->
</syscheck>
```

## Integration with External Tools

### Log Forwarding

```bash
# Forward logs to external SIEM
sudo /var/ossec/bin/ossec-logtest -f /var/log/messages

# Send alerts via email
# Configure in manager ossec.conf
<email_alerts>
  <email_to>admin@company.com</email_to>
  <level>12</level>
</email_alerts>
```

### Custom Decoders

Create custom decoders in `/var/ossec/etc/decoders/local_decoder.xml`:

```xml
<decoder name="custom-app">
  <prematch>custom_app:</prematch>
</decoder>

<decoder name="custom-app-event">
  <parent>custom-app</parent>
  <regex>event: (\w+)</regex>
  <order>event</order>
</decoder>
```

## Backup and Recovery

### Backup Configuration

```bash
# Create backup directory
sudo mkdir -p /backup/wazuh

# Backup configuration
sudo cp -r /var/ossec/etc/ /backup/wazuh/

# Backup logs (optional)
sudo cp -r /var/ossec/logs/ /backup/wazuh/
```

### Restore Configuration

```bash
# Stop service
sudo systemctl stop wazuh-agent

# Restore configuration
sudo cp -r /backup/wazuh/etc/* /var/ossec/etc/

# Set permissions
sudo chown -R root:ossec /var/ossec/etc/
sudo chmod -R 640 /var/ossec/etc/

# Start service
sudo systemctl start wazuh-agent
```

## Monitoring Dashboard

Access the Wazuh dashboard to monitor your agents:

1. Open web browser
2. Navigate to `https://<manager_ip>:5601`
3. Login with credentials
4. Go to Agents section to view agent status

## Support

For additional support:

- Check Wazuh documentation: https://documentation.wazuh.com/
- Review troubleshooting guide in `docs/troubleshooting.md`
- Open an issue in this repository 