# Wazuh Security Setup - Quick Start Guide

This guide will help you quickly set up Wazuh security agents for both RHEL and Windows VMs.

## Prerequisites

### For Wazuh Manager (RHEL/CentOS):
- RHEL 8/9 or CentOS 8/9
- Minimum 4GB RAM, 20GB disk space
- Root access
- Internet connectivity

### For RHEL Agents:
- RHEL 7/8/9 or CentOS 7/8/9
- Root access
- Network connectivity to manager

### For Windows Agents:
- Windows Server 2016/2019/2022 or Windows 10/11
- Administrator access
- Network connectivity to manager

## Step 1: Setup Wazuh Manager

**On your RHEL/CentOS manager server:**

```bash
# Clone this repository
git clone <repository-url>
cd wazuh-security-setup

# Make scripts executable
chmod +x scripts/*.sh

# Run the manager setup script
sudo ./scripts/setup-wazuh-manager.sh
```

**The script will:**
- Install Wazuh Manager, Elasticsearch, and Kibana
- Configure SSL certificates
- Set up firewall rules
- Start all services

**After completion, note the manager IP address displayed.**

## Step 2: Install RHEL Agents

**On each RHEL VM:**

```bash
# Copy the installation script to the VM
scp scripts/install-rhel-agent.sh user@rhel-vm:/tmp/

# SSH to the VM and run installation
ssh user@rhel-vm
sudo /tmp/install-rhel-agent.sh <MANAGER_IP>
```

**Example:**
```bash
sudo /tmp/install-rhel-agent.sh 192.168.1.100 -n web-server-01 -g web-servers
```

## Step 3: Install Windows Agents

**On each Windows VM:**

```powershell
# Copy the installation script to the VM
# Then run PowerShell as Administrator and execute:

# Set execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Run installation
.\scripts\install-windows-agent.ps1 -WazuhManagerIP <MANAGER_IP>
```

**Example:**
```powershell
.\scripts\install-windows-agent.ps1 -WazuhManagerIP 192.168.1.100 -AgentName "WEB-SERVER-01" -AgentGroup "web-servers"
```

## Step 4: Access the Dashboard

1. **Open web browser**
2. **Navigate to:** `https://<MANAGER_IP>:5601`
3. **Login with:**
   - Username: `elastic`
   - Password: Check `/tmp/elastic_passwords.txt` on the manager

## Step 5: Verify Installation

### Check Manager Status:
```bash
# On manager server
sudo systemctl status wazuh-manager
sudo systemctl status elasticsearch
sudo systemctl status kibana
```

### Check Agent Status:
```bash
# On RHEL agents
sudo systemctl status wazuh-agent

# On Windows agents (PowerShell)
Get-Service -Name "WazuhSvc"
```

### View Connected Agents:
1. Access the Wazuh dashboard
2. Go to "Management" → "Agents"
3. Verify all agents show "Active" status

## Common Commands

### Manager Commands:
```bash
# List all agents
sudo /var/ossec/bin/agent_control -l

# Get agent information
sudo /var/ossec/bin/agent_control -i <agent_id>

# Restart agent
sudo /var/ossec/bin/agent_control -r <agent_id>
```

### RHEL Agent Commands:
```bash
# Check agent status
sudo systemctl status wazuh-agent

# View logs
sudo tail -f /var/ossec/logs/ossec.log

# Restart agent
sudo systemctl restart wazuh-agent
```

### Windows Agent Commands:
```powershell
# Check service status
Get-Service -Name "WazuhSvc"

# View logs
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Wait

# Restart service
Restart-Service -Name "WazuhSvc"
```

## Security Features Enabled

### File Integrity Monitoring:
- Critical system files
- Configuration files
- Web application files
- Database files

### Log Analysis:
- System logs
- Security logs
- Application logs
- Web server logs

### Threat Detection:
- Brute force attacks
- SQL injection attempts
- XSS attacks
- Suspicious processes
- Unauthorized file changes

### Active Response:
- Automatic firewall blocking
- Account disabling
- Process termination

## Troubleshooting

### If agents don't connect:
1. Check network connectivity: `telnet <manager_ip> 1514`
2. Verify firewall rules
3. Check agent logs for errors

### If dashboard doesn't load:
1. Verify all services are running
2. Check Elasticsearch health: `curl localhost:9200/_cluster/health`
3. Check Kibana logs: `tail -f /var/log/kibana/kibana.log`

### For detailed troubleshooting:
- See `docs/troubleshooting.md`
- Check Wazuh documentation: https://documentation.wazuh.com/

## Next Steps

1. **Configure email alerts** in `/var/ossec/etc/ossec.conf`
2. **Set up custom rules** in `config/local_rules.xml`
3. **Configure external integrations** (Slack, Jira, etc.)
4. **Set up log forwarding** to external SIEM
5. **Create custom dashboards** in Kibana

## Support

- **Documentation:** Check `docs/` directory
- **Troubleshooting:** See `docs/troubleshooting.md`
- **Wazuh Community:** https://wazuh.com/community/
- **GitHub Issues:** Open an issue in this repository

## Security Notes

- All communication is encrypted
- Agents authenticate using pre-shared keys
- Firewall rules are automatically configured
- Regular security updates are recommended
- Monitor logs regularly for security events 