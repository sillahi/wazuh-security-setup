# Wazuh Troubleshooting Guide

This guide provides solutions for common issues encountered when setting up and running Wazuh agents and managers.

## Table of Contents

1. [Manager Issues](#manager-issues)
2. [RHEL Agent Issues](#rhel-agent-issues)
3. [Windows Agent Issues](#windows-agent-issues)
4. [Network Connectivity Issues](#network-connectivity-issues)
5. [Performance Issues](#performance-issues)
6. [Configuration Issues](#configuration-issues)
7. [Log Analysis](#log-analysis)

## Manager Issues

### Manager Service Not Starting

**Symptoms:**
- `systemctl status wazuh-manager` shows failed status
- Manager logs show startup errors

**Solutions:**

1. **Check system resources:**
   ```bash
   # Check available memory
   free -h
   
   # Check disk space
   df -h
   
   # Check CPU usage
   top
   ```

2. **Check configuration syntax:**
   ```bash
   # Validate configuration
   /var/ossec/bin/ossec-logtest -t
   
   # Check for syntax errors
   /var/ossec/bin/ossec-logtest -f /var/log/messages
   ```

3. **Check file permissions:**
   ```bash
   # Set correct permissions
   chown -R root:ossec /var/ossec/
   chmod -R 550 /var/ossec/
   chmod -R 770 /var/ossec/logs/
   chmod -R 770 /var/ossec/stats/
   chmod -R 770 /var/ossec/var/
   ```

4. **Check port conflicts:**
   ```bash
   # Check if port 1514 is in use
   netstat -tlnp | grep 1514
   
   # Kill conflicting process if needed
   kill -9 <PID>
   ```

### Elasticsearch Issues

**Symptoms:**
- Kibana shows connection errors
- Elasticsearch service not responding

**Solutions:**

1. **Check Elasticsearch status:**
   ```bash
   # Check service status
   systemctl status elasticsearch
   
   # Check Elasticsearch logs
   tail -f /var/log/elasticsearch/wazuh-cluster.log
   
   # Test Elasticsearch connection
   curl -X GET "localhost:9200/_cluster/health?pretty"
   ```

2. **Fix memory issues:**
   ```bash
   # Check JVM heap size
   grep "Xms\|Xmx" /etc/elasticsearch/jvm.options
   
   # Adjust heap size (should be 50% of available RAM)
   echo "-Xms2g" >> /etc/elasticsearch/jvm.options
   echo "-Xmx2g" >> /etc/elasticsearch/jvm.options
   ```

3. **Fix disk space issues:**
   ```bash
   # Check disk usage
   df -h /var/lib/elasticsearch
   
   # Clean old indices if needed
   curl -X DELETE "localhost:9200/wazuh-alerts-*"
   ```

### Kibana Issues

**Symptoms:**
- Kibana web interface not accessible
- Dashboard not loading

**Solutions:**

1. **Check Kibana service:**
   ```bash
   # Check service status
   systemctl status kibana
   
   # Check Kibana logs
   tail -f /var/log/kibana/kibana.log
   
   # Test Kibana connection
   curl -X GET "localhost:5601/api/status"
   ```

2. **Fix configuration issues:**
   ```bash
   # Check configuration file
   cat /etc/kibana/kibana.yml
   
   # Verify Elasticsearch connection
   grep "elasticsearch.hosts" /etc/kibana/kibana.yml
   ```

## RHEL Agent Issues

### Agent Not Connecting to Manager

**Symptoms:**
- Agent shows "disconnected" status in dashboard
- Agent logs show connection errors

**Solutions:**

1. **Check network connectivity:**
   ```bash
   # Test connectivity to manager
   telnet <manager_ip> 1514
   
   # Check DNS resolution
   nslookup <manager_hostname>
   
   # Check routing
   traceroute <manager_ip>
   ```

2. **Check firewall rules:**
   ```bash
   # Check firewall status
   firewall-cmd --state
   
   # List firewall rules
   firewall-cmd --list-all
   
   # Add firewall rule if missing
   firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="<manager_ip>" port port="1514" protocol="tcp" accept'
   firewall-cmd --reload
   ```

3. **Check agent configuration:**
   ```bash
   # Verify manager IP in config
   grep "address" /var/ossec/etc/ossec.conf
   
   # Check agent registration
   /var/ossec/bin/agent_control -l
   ```

### Agent Service Not Starting

**Symptoms:**
- `systemctl status wazuh-agent` shows failed status
- Agent processes not running

**Solutions:**

1. **Check system requirements:**
   ```bash
   # Check available memory
   free -h
   
   # Check disk space
   df -h /var/ossec
   ```

2. **Check configuration syntax:**
   ```bash
   # Validate configuration
   /var/ossec/bin/ossec-logtest -t
   
   # Check for syntax errors
   cat /var/ossec/etc/ossec.conf | xmllint --format -
   ```

3. **Check file permissions:**
   ```bash
   # Set correct permissions
   chown -R root:ossec /var/ossec/
   chmod 640 /var/ossec/etc/ossec.conf
   chmod -R 750 /var/ossec/logs/
   ```

### High CPU Usage

**Symptoms:**
- Agent consuming excessive CPU resources
- System performance degradation

**Solutions:**

1. **Adjust syscheck frequency:**
   ```bash
   # Edit configuration file
   vi /var/ossec/etc/ossec.conf
   
   # Change frequency from 43200 (12 hours) to 86400 (24 hours)
   <syscheck>
     <frequency>86400</frequency>
   </syscheck>
   ```

2. **Optimize monitored directories:**
   ```bash
   # Reduce number of monitored directories
   # Remove unnecessary directories from syscheck
   ```

3. **Check for malware scanning:**
   ```bash
   # Check if antivirus is scanning Wazuh files
   # Add exclusions to antivirus software
   ```

## Windows Agent Issues

### Agent Service Not Starting

**Symptoms:**
- Windows service shows "stopped" status
- Event logs show service errors

**Solutions:**

1. **Check service configuration:**
   ```powershell
   # Check service status
   Get-Service -Name "WazuhSvc"
   
   # Check service configuration
   Get-WmiObject -Class Win32_Service -Filter "Name='WazuhSvc'"
   
   # Check service dependencies
   Get-Service -Name "WazuhSvc" -DependentServices
   ```

2. **Check file permissions:**
   ```powershell
   # Check configuration file permissions
   Get-Acl "C:\Program Files (x86)\ossec-agent\ossec.conf"
   
   # Set proper permissions
   $ConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
   $Acl = Get-Acl $ConfigPath
   $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
   $Acl.SetAccessRule($AccessRule)
   Set-Acl $ConfigPath $Acl
   ```

3. **Check Windows Event Logs:**
   ```powershell
   # Check Application logs for Wazuh errors
   Get-EventLog -LogName Application -Source "Wazuh" -Newest 10
   
   # Check System logs for service errors
   Get-EventLog -LogName System -Newest 10 | Where-Object {$_.Message -like "*Wazuh*"}
   ```

### Agent Not Connecting to Manager

**Symptoms:**
- Agent shows disconnected status
- Connection timeout errors

**Solutions:**

1. **Check network connectivity:**
   ```powershell
   # Test connectivity to manager
   Test-NetConnection -ComputerName "<manager_ip>" -Port 1514
   
   # Check DNS resolution
   Resolve-DnsName "<manager_hostname>"
   
   # Check routing
   tracert <manager_ip>
   ```

2. **Check Windows Firewall:**
   ```powershell
   # Check firewall rules
   Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Wazuh*"}
   
   # Add firewall rule if missing
   New-NetFirewallRule -DisplayName "Wazuh Agent Outbound" -Direction Outbound -Protocol TCP -RemoteAddress "<manager_ip>" -RemotePort 1514 -Action Allow -Profile Any
   ```

3. **Check antivirus interference:**
   ```powershell
   # Add Wazuh to Windows Defender exclusions
   Add-MpPreference -ExclusionPath "C:\Program Files (x86)\ossec-agent"
   Add-MpPreference -ExclusionProcess "ossec-agent.exe"
   ```

## Network Connectivity Issues

### Port Blocking

**Symptoms:**
- Connection refused errors
- Timeout errors

**Solutions:**

1. **Check port availability:**
   ```bash
   # Check if port is open on manager
   netstat -tlnp | grep 1514
   
   # Test port from agent
   telnet <manager_ip> 1514
   ```

2. **Check intermediate firewalls:**
   ```bash
   # Check if corporate firewall is blocking
   # Contact network administrator
   ```

3. **Use different port:**
   ```bash
   # Configure manager to use different port
   # Update agent configuration accordingly
   ```

### DNS Resolution Issues

**Symptoms:**
- Cannot resolve manager hostname
- Connection errors with hostname

**Solutions:**

1. **Check DNS configuration:**
   ```bash
   # Check DNS servers
   cat /etc/resolv.conf
   
   # Test DNS resolution
   nslookup <manager_hostname>
   ```

2. **Use IP address instead:**
   ```bash
   # Update agent configuration to use IP address
   # Edit /var/ossec/etc/ossec.conf
   <server>
     <address>192.168.1.100</address>
   </server>
   ```

## Performance Issues

### High Memory Usage

**Symptoms:**
- System running out of memory
- Agent processes consuming excessive RAM

**Solutions:**

1. **Adjust client buffer settings:**
   ```bash
   # Edit agent configuration
   <client_buffer>
     <disabled>no</disabled>
     <queue_size>25000</queue_size>
     <events_per_second>250</events_per_second>
   </client_buffer>
   ```

2. **Reduce monitored files:**
   ```bash
   # Remove unnecessary directories from syscheck
   # Focus on critical system files only
   ```

3. **Increase system memory:**
   ```bash
   # Add more RAM to the system
   # Consider using swap space
   ```

### High CPU Usage

**Symptoms:**
- System CPU usage consistently high
- Agent processes consuming excessive CPU

**Solutions:**

1. **Adjust scan frequencies:**
   ```bash
   # Increase syscheck frequency
   <syscheck>
     <frequency>86400</frequency>  # 24 hours
   </syscheck>
   
   # Increase rootcheck frequency
   <rootcheck>
     <frequency>86400</frequency>  # 24 hours
   </rootcheck>
   ```

2. **Optimize log monitoring:**
   ```bash
   # Reduce number of monitored log files
   # Use more specific log patterns
   ```

3. **Check for malware:**
   ```bash
   # Run antivirus scan
   # Check for suspicious processes
   ```

## Configuration Issues

### Invalid Configuration Syntax

**Symptoms:**
- Service fails to start
- Configuration validation errors

**Solutions:**

1. **Validate XML syntax:**
   ```bash
   # Check XML syntax
   xmllint --format /var/ossec/etc/ossec.conf
   
   # Check for syntax errors
   xmllint --noout /var/ossec/etc/ossec.conf
   ```

2. **Use configuration templates:**
   ```bash
   # Use provided configuration templates
   # Copy from working installations
   ```

3. **Backup and restore:**
   ```bash
   # Restore from backup
   cp /backup/ossec.conf /var/ossec/etc/
   ```

### Missing Dependencies

**Symptoms:**
- Installation fails
- Service cannot start

**Solutions:**

1. **Install required packages:**
   ```bash
   # RHEL/CentOS
   yum install -y curl wget java-11-openjdk-devel
   
   # Ubuntu/Debian
   apt-get install -y curl wget openjdk-11-jdk
   ```

2. **Check system requirements:**
   ```bash
   # Check OS version
   cat /etc/os-release
   
   # Check available memory
   free -h
   
   # Check disk space
   df -h
   ```

## Log Analysis

### Understanding Log Messages

**Common log locations:**
```bash
# Manager logs
/var/ossec/logs/ossec.log
/var/ossec/logs/alerts/alerts.log

# Agent logs
/var/ossec/logs/ossec.log
/var/ossec/logs/alerts/alerts.log

# Windows agent logs
C:\Program Files (x86)\ossec-agent\ossec.log
C:\Program Files (x86)\ossec-agent\alerts\alerts.log
```

**Common log patterns:**
```bash
# Connection errors
grep "connection" /var/ossec/logs/ossec.log

# Authentication errors
grep "auth" /var/ossec/logs/ossec.log

# Configuration errors
grep "config" /var/ossec/logs/ossec.log

# Performance issues
grep "timeout" /var/ossec/logs/ossec.log
```

### Debug Mode

**Enable debug logging:**
```bash
# Edit configuration file
<global>
  <debug>2</debug>
</global>

# Restart service
systemctl restart wazuh-agent
```

### Log Rotation

**Configure log rotation:**
```bash
# Create logrotate configuration
cat > /etc/logrotate.d/wazuh << EOF
/var/ossec/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 root ossec
    postrotate
        systemctl reload wazuh-agent
    endscript
}
EOF
```

## Getting Help

### Collecting Diagnostic Information

```bash
# Create diagnostic script
cat > /tmp/wazuh-diagnostics.sh << 'EOF'
#!/bin/bash
echo "=== Wazuh Diagnostics Report ===" > /tmp/wazuh-diagnostics.txt
echo "Date: $(date)" >> /tmp/wazuh-diagnostics.txt
echo "" >> /tmp/wazuh-diagnostics.txt

echo "=== System Information ===" >> /tmp/wazuh-diagnostics.txt
uname -a >> /tmp/wazuh-diagnostics.txt
cat /etc/os-release >> /tmp/wazuh-diagnostics.txt
echo "" >> /tmp/wazuh-diagnostics.txt

echo "=== Service Status ===" >> /tmp/wazuh-diagnostics.txt
systemctl status wazuh-agent >> /tmp/wazuh-diagnostics.txt
echo "" >> /tmp/wazuh-diagnostics.txt

echo "=== Configuration ===" >> /tmp/wazuh-diagnostics.txt
cat /var/ossec/etc/ossec.conf >> /tmp/wazuh-diagnostics.txt
echo "" >> /tmp/wazuh-diagnostics.txt

echo "=== Recent Logs ===" >> /tmp/wazuh-diagnostics.txt
tail -50 /var/ossec/logs/ossec.log >> /tmp/wazuh-diagnostics.txt
echo "" >> /tmp/wazuh-diagnostics.txt

echo "=== Network Connectivity ===" >> /tmp/wazuh-diagnostics.txt
netstat -tlnp | grep 1514 >> /tmp/wazuh-diagnostics.txt
echo "" >> /tmp/wazuh-diagnostics.txt

echo "Diagnostics saved to /tmp/wazuh-diagnostics.txt"
EOF

chmod +x /tmp/wazuh-diagnostics.sh
./tmp/wazuh-diagnostics.sh
```

### Support Resources

- **Wazuh Documentation:** https://documentation.wazuh.com/
- **Wazuh Community:** https://wazuh.com/community/
- **GitHub Issues:** https://github.com/wazuh/wazuh/issues
- **Stack Overflow:** https://stackoverflow.com/questions/tagged/wazuh 