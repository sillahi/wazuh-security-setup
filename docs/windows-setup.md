# Windows Agent Setup Guide

This guide provides detailed instructions for setting up Wazuh agents on Windows systems.

## Prerequisites

- Windows Server 2016/2019/2022 or Windows 10/11
- Administrator access
- Network connectivity to Wazuh manager
- Minimum 2GB RAM
- 5GB free disk space
- PowerShell 5.0 or later

## Installation Steps

### 1. Download and Run Installation Script

```powershell
# Clone the repository (if not already done)
git clone <repository-url>
cd wazuh-security-setup

# Set execution policy to allow script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Run installation with manager IP
.\scripts\install-windows-agent.ps1 -WazuhManagerIP <WAZUH_MANAGER_IP>
```

### 2. Advanced Installation Options

```powershell
# Install with custom agent name and group
.\scripts\install-windows-agent.ps1 -WazuhManagerIP 192.168.1.100 -AgentName "WEB-SERVER-01" -AgentGroup "web-servers"

# Install with custom port
.\scripts\install-windows-agent.ps1 -WazuhManagerIP 192.168.1.100 -WazuhManagerPort 1515

# Show help
.\scripts\install-windows-agent.ps1 -Help
```

## Configuration

### Agent Configuration File

The agent configuration is located at `C:\Program Files (x86)\ossec-agent\ossec.conf`:

```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.1.100</address>
    </server>
    <config-profile>default</config-profile>
  </client>

  <!-- Windows Event Logs -->
  <localfile>
    <log_format>eventlog</log_format>
    <location>Application</location>
  </localfile>

  <localfile>
    <log_format>eventlog</log_format>
    <location>Security</location>
  </localfile>

  <localfile>
    <log_format>eventlog</log_format>
    <location>System</location>
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
  <location>C:\logs\application.log</location>
</localfile>

<localfile>
  <log_format>iis</log_format>
  <location>C:\inetpub\logs\LogFiles\W3SVC1\*.log</location>
</localfile>
```

### File Integrity Monitoring

Configure directories to monitor:

```xml
<syscheck>
  <!-- System directories -->
  <directories check_all="yes">C:\Windows\System32</directories>
  <directories check_all="yes">C:\Windows\SysWOW64</directories>
  
  <!-- Application directories -->
  <directories check_all="yes">C:\Program Files</directories>
  <directories check_all="yes">C:\Program Files (x86)</directories>
  
  <!-- Web application directories -->
  <directories check_all="yes">C:\inetpub\wwwroot</directories>
  <directories check_all="yes">C:\webapp</directories>
  
  <!-- Exclude patterns -->
  <ignore>C:\Windows\Temp</ignore>
  <ignore>C:\Users\*\AppData\Local\Temp</ignore>
</syscheck>
```

## Service Management

### Start/Stop Service

```powershell
# Start service
Start-Service -Name "WazuhSvc"

# Stop service
Stop-Service -Name "WazuhSvc"

# Restart service
Restart-Service -Name "WazuhSvc"

# Check status
Get-Service -Name "WazuhSvc"
```

### Enable Auto-start

```powershell
# Enable service to start on boot
Set-Service -Name "WazuhSvc" -StartupType Automatic

# Disable auto-start
Set-Service -Name "WazuhSvc" -StartupType Manual
```

## Monitoring and Logs

### View Agent Logs

```powershell
# View real-time logs
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Wait

# View alerts
Get-Content "C:\Program Files (x86)\ossec-agent\alerts\alerts.log" -Wait

# View agent statistics
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" | Select-String "Agent statistics"
```

### Agent Control Commands

```powershell
# Navigate to agent directory
cd "C:\Program Files (x86)\ossec-agent"

# List all agents
.\agent_control.exe -l

# Get agent information
.\agent_control.exe -i <agent_id>

# Restart agent
.\agent_control.exe -r <agent_id>

# Remove agent
.\agent_control.exe -r <agent_id>
```

## Security Hardening

### Windows Firewall Configuration

```powershell
# Allow outbound connections to manager
New-NetFirewallRule -DisplayName "Wazuh Agent Outbound" -Direction Outbound -Protocol TCP -RemoteAddress "192.168.1.100" -RemotePort 1514 -Action Allow -Profile Any

# Remove rule if needed
Remove-NetFirewallRule -DisplayName "Wazuh Agent Outbound"
```

### Registry Permissions

```powershell
# Set proper permissions on configuration
$ConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$Acl = Get-Acl $ConfigPath
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
$Acl.SetAccessRule($AccessRule)
Set-Acl $ConfigPath $Acl
```

### Windows Defender Exclusion

```powershell
# Add Wazuh directories to Windows Defender exclusions
Add-MpPreference -ExclusionPath "C:\Program Files (x86)\ossec-agent"
Add-MpPreference -ExclusionProcess "ossec-agent.exe"
```

## Troubleshooting

### Common Issues

1. **Agent not connecting to manager**
   ```powershell
   # Check network connectivity
   Test-NetConnection -ComputerName "192.168.1.100" -Port 1514
   
   # Check firewall rules
   Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Wazuh*"}
   
   # Check agent logs
   Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 50
   ```

2. **Service not starting**
   ```powershell
   # Check service status
   Get-Service -Name "WazuhSvc"
   
   # Check service configuration
   Get-WmiObject -Class Win32_Service -Filter "Name='WazuhSvc'"
   
   # View detailed logs
   Get-EventLog -LogName Application -Source "Wazuh" -Newest 10
   ```

3. **High CPU usage**
   ```powershell
   # Check syscheck frequency
   Select-String "frequency" "C:\Program Files (x86)\ossec-agent\ossec.conf"
   
   # Monitor agent processes
   Get-Process | Where-Object {$_.ProcessName -like "*ossec*"}
   ```

### Log Analysis

```powershell
# Search for specific events
Select-String "ERROR" "C:\Program Files (x86)\ossec-agent\ossec.log"

# Search for connection issues
Select-String "connection" "C:\Program Files (x86)\ossec-agent\ossec.log"

# Search for authentication issues
Select-String "auth" "C:\Program Files (x86)\ossec-agent\ossec.log"
```

### Performance Tuning

```powershell
# Adjust client buffer settings
# Edit C:\Program Files (x86)\ossec-agent\ossec.conf
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

## Windows Event Log Monitoring

### Custom Event Log Sources

```xml
<localfile>
  <log_format>eventlog</log_format>
  <location>Application</location>
</localfile>

<localfile>
  <log_format>eventlog</log_format>
  <location>Security</location>
</localfile>

<localfile>
  <log_format>eventlog</log_format>
  <location>System</location>
</localfile>

<!-- Custom application logs -->
<localfile>
  <log_format>eventlog</log_format>
  <location>CustomApp</location>
</localfile>
```

### PowerShell Script Monitoring

```powershell
# Monitor PowerShell execution
Get-WinEvent -FilterHashtable @{LogName='Windows PowerShell'; ID=4103,4104,4105,4106} | Format-List

# Monitor command execution
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} | Format-List
```

## Integration with External Tools

### Windows Event Forwarding

```powershell
# Configure Windows Event Forwarding
wecutil qc /q

# Create subscription
wecutil cs "WazuhEvents" /cm:custom /cf:"C:\subscription.xml" /rf:PT1M /rd:PT1M /ru:domain\username /rp:password
```

### Custom PowerShell Scripts

```powershell
# Create custom monitoring script
$Script = @"
# Monitor specific Windows events
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} | 
ForEach-Object {
    $Event = $_
    $Message = "$($Event.TimeCreated): $($Event.Message)"
    Add-Content -Path "C:\logs\security_events.log" -Value $Message
}
"@

Set-Content -Path "C:\Scripts\Monitor-SecurityEvents.ps1" -Value $Script
```

## Backup and Recovery

### Backup Configuration

```powershell
# Create backup directory
New-Item -ItemType Directory -Path "C:\backup\wazuh" -Force

# Backup configuration
Copy-Item -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Destination "C:\backup\wazuh\"

# Backup logs (optional)
Copy-Item -Path "C:\Program Files (x86)\ossec-agent\logs" -Destination "C:\backup\wazuh\" -Recurse
```

### Restore Configuration

```powershell
# Stop service
Stop-Service -Name "WazuhSvc"

# Restore configuration
Copy-Item -Path "C:\backup\wazuh\ossec.conf" -Destination "C:\Program Files (x86)\ossec-agent\"

# Set permissions
$ConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$Acl = Get-Acl $ConfigPath
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
$Acl.SetAccessRule($AccessRule)
Set-Acl $ConfigPath $Acl

# Start service
Start-Service -Name "WazuhSvc"
```

## Group Policy Integration

### Deploy via Group Policy

1. Create a Group Policy Object (GPO)
2. Add the Wazuh agent installation script
3. Configure startup scripts
4. Deploy to target computers

```powershell
# Example GPO script
$ManagerIP = "192.168.1.100"
$ScriptPath = "\\domain\share\scripts\install-windows-agent.ps1"

# Run installation
& $ScriptPath -WazuhManagerIP $ManagerIP -AgentName $env:COMPUTERNAME
```

## Monitoring Dashboard

Access the Wazuh dashboard to monitor your Windows agents:

1. Open web browser
2. Navigate to `https://<manager_ip>:5601`
3. Login with credentials
4. Go to Agents section to view agent status
5. Filter by Windows agents

## Support

For additional support:

- Check Wazuh documentation: https://documentation.wazuh.com/
- Review troubleshooting guide in `docs/troubleshooting.md`
- Open an issue in this repository
- Check Windows Event Viewer for system errors 