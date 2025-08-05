# Wazuh Agent Installation Script for Windows
# This script installs and configures Wazuh Agent on Windows systems

param(
    [Parameter(Mandatory=$true)]
    [string]$WazuhManagerIP,
    
    [Parameter(Mandatory=$false)]
    [int]$WazuhManagerPort = 1514,
    
    [Parameter(Mandatory=$false)]
    [string]$AgentName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory=$false)]
    [string]$AgentGroup = "default",
    
    [Parameter(Mandatory=$false)]
    [switch]$Help
)

# Function to show usage
function Show-Usage {
    Write-Host "Usage: .\install-windows-agent.ps1 -WazuhManagerIP <IP> [OPTIONS]" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Parameters:" -ForegroundColor Yellow
    Write-Host "  -WazuhManagerIP <IP>     Wazuh Manager IP address (required)" -ForegroundColor White
    Write-Host "  -WazuhManagerPort <PORT> Manager port (default: 1514)" -ForegroundColor White
    Write-Host "  -AgentName <NAME>        Agent name (default: hostname)" -ForegroundColor White
    Write-Host "  -AgentGroup <GROUP>      Agent group (default: default)" -ForegroundColor White
    Write-Host "  -Help                    Show this help message" -ForegroundColor White
    Write-Host ""
    Write-Host "Example:" -ForegroundColor Yellow
    Write-Host "  .\install-windows-agent.ps1 -WazuhManagerIP 192.168.1.100" -ForegroundColor White
    Write-Host "  .\install-windows-agent.ps1 -WazuhManagerIP 192.168.1.100 -AgentName web-server -AgentGroup web-servers" -ForegroundColor White
    exit 1
}

# Function to write colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Check if help is requested
if ($Help) {
    Show-Usage
}

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Validate IP address format
if ($WazuhManagerIP -notmatch '^(\d{1,3}\.){3}\d{1,3}$') {
    Write-Error "Invalid IP address format: $WazuhManagerIP"
    exit 1
}

# Validate port number
if ($WazuhManagerPort -lt 1 -or $WazuhManagerPort -gt 65535) {
    Write-Error "Invalid port number: $WazuhManagerPort"
    exit 1
}

Write-Status "Starting Wazuh Agent installation..."
Write-Status "Manager IP: $WazuhManagerIP"
Write-Status "Manager Port: $WazuhManagerPort"
Write-Status "Agent Name: $AgentName"
Write-Status "Agent Group: $AgentGroup"

# Check Windows version
$OSVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
Write-Status "Detected OS: $OSVersion"

# Set execution policy to allow script execution
Write-Status "Setting execution policy..."
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

# Create temporary directory
$TempDir = "C:\temp\wazuh-install"
if (!(Test-Path $TempDir)) {
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
}

# Download Wazuh Agent
Write-Status "Downloading Wazuh Agent..."
$WazuhVersion = "4.7.0"
$DownloadURL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion-1.msi"
$InstallerPath = "$TempDir\wazuh-agent-$WazuhVersion-1.msi"

try {
    Invoke-WebRequest -Uri $DownloadURL -OutFile $InstallerPath -UseBasicParsing
    Write-Status "Download completed successfully"
} catch {
    Write-Error "Failed to download Wazuh Agent: $($_.Exception.Message)"
    exit 1
}

# Install Wazuh Agent
Write-Status "Installing Wazuh Agent..."
try {
    $InstallArgs = @(
        "/i", $InstallerPath,
        "/quiet",
        "/norestart",
        "WZUH_MANAGER=$WazuhManagerIP",
        "WZUH_MANAGER_PORT=$WazuhManagerPort",
        "WZUH_REGISTRATION_SERVER=$WazuhManagerIP",
        "WZUH_REGISTRATION_PORT=$WazuhManagerPort"
    )
    
    Start-Process -FilePath "msiexec.exe" -ArgumentList $InstallArgs -Wait -NoNewWindow
    Write-Status "Installation completed successfully"
} catch {
    Write-Error "Failed to install Wazuh Agent: $($_.Exception.Message)"
    exit 1
}

# Wait for service to be installed
Write-Status "Waiting for service installation..."
Start-Sleep -Seconds 10

# Check if service exists
$ServiceName = "WazuhSvc"
if (!(Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    Write-Error "Wazuh service not found after installation"
    exit 1
}

# Configure Wazuh Agent
Write-Status "Configuring Wazuh Agent..."
$OssecConfigPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

# Create configuration content
$ConfigContent = @"
<ossec_config>
  <client>
    <server>
      <address>$WazuhManagerIP</address>
    </server>
    <config-profile>$AgentGroup</config-profile>
  </client>

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
"@

# Write configuration file
try {
    $ConfigContent | Out-File -FilePath $OssecConfigPath -Encoding UTF8 -Force
    Write-Status "Configuration file created successfully"
} catch {
    Write-Error "Failed to create configuration file: $($_.Exception.Message)"
    exit 1
}

# Set proper permissions on configuration file
try {
    $Acl = Get-Acl $OssecConfigPath
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow")
    $Acl.SetAccessRule($AccessRule)
    Set-Acl $OssecConfigPath $Acl
    Write-Status "Configuration file permissions set"
} catch {
    Write-Warning "Failed to set configuration file permissions: $($_.Exception.Message)"
}

# Start Wazuh Agent service
Write-Status "Starting Wazuh Agent service..."
try {
    Start-Service -Name $ServiceName
    Set-Service -Name $ServiceName -StartupType Automatic
    Write-Status "Service started and set to auto-start"
} catch {
    Write-Error "Failed to start Wazuh Agent service: $($_.Exception.Message)"
    exit 1
}

# Check service status
if ((Get-Service -Name $ServiceName).Status -eq "Running") {
    Write-Status "Wazuh Agent is running successfully"
} else {
    Write-Error "Wazuh Agent failed to start"
    exit 1
}

# Configure Windows Firewall
Write-Status "Configuring Windows Firewall..."
try {
    New-NetFirewallRule -DisplayName "Wazuh Agent Outbound" -Direction Outbound -Protocol TCP -RemoteAddress $WazuhManagerIP -RemotePort $WazuhManagerPort -Action Allow -Profile Any | Out-Null
    Write-Status "Firewall rule created successfully"
} catch {
    Write-Warning "Failed to create firewall rule: $($_.Exception.Message)"
}

# Test connectivity to manager
Write-Status "Testing connectivity to Wazuh Manager..."
try {
    $TestConnection = Test-NetConnection -ComputerName $WazuhManagerIP -Port $WazuhManagerPort -InformationLevel Quiet
    if ($TestConnection) {
        Write-Status "Successfully connected to Wazuh Manager"
    } else {
        Write-Warning "Could not connect to Wazuh Manager. Please check network connectivity and firewall rules."
    }
} catch {
    Write-Warning "Could not test connectivity: $($_.Exception.Message)"
}

# Get agent information
$AgentInfo = Get-Service -Name $ServiceName
$InstallDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Display installation summary
Write-Status "Installation completed successfully!"
Write-Host ""
Write-Host "=== WAZUH AGENT INSTALLATION SUMMARY ===" -ForegroundColor Cyan
Write-Host "Agent Name: $AgentName" -ForegroundColor White
Write-Host "Agent Group: $AgentGroup" -ForegroundColor White
Write-Host "Manager IP: $WazuhManagerIP" -ForegroundColor White
Write-Host "Manager Port: $WazuhManagerPort" -ForegroundColor White
Write-Host "Service Status: $($AgentInfo.Status)" -ForegroundColor White
Write-Host "Installation Date: $InstallDate" -ForegroundColor White
Write-Host ""
Write-Host "=== IMPORTANT FILES ===" -ForegroundColor Cyan
Write-Host "Configuration: $OssecConfigPath" -ForegroundColor White
Write-Host "Logs: C:\Program Files (x86)\ossec-agent\ossec.log" -ForegroundColor White
Write-Host "Agent Control: C:\Program Files (x86)\ossec-agent\agent_control.exe" -ForegroundColor White
Write-Host ""
Write-Host "=== USEFUL COMMANDS ===" -ForegroundColor Cyan
Write-Host "Check service status: Get-Service WazuhSvc" -ForegroundColor White
Write-Host "View service logs: Get-EventLog -LogName Application -Source Wazuh" -ForegroundColor White
Write-Host "Restart service: Restart-Service WazuhSvc" -ForegroundColor White
Write-Host "Stop service: Stop-Service WazuhSvc" -ForegroundColor White
Write-Host ""

# Save configuration for reference
$ConfigSummary = @"
Wazuh Agent Configuration
=========================
Agent Name: $AgentName
Agent Group: $AgentGroup
Manager IP: $WazuhManagerIP
Manager Port: $WazuhManagerPort
Installation Date: $InstallDate
Configuration Path: $OssecConfigPath
"@

$ConfigSummary | Out-File -FilePath "$TempDir\wazuh_agent_config.txt" -Encoding UTF8
Write-Status "Configuration saved to $TempDir\wazuh_agent_config.txt"

# Clean up installer
if (Test-Path $InstallerPath) {
    Remove-Item $InstallerPath -Force
    Write-Status "Installer cleaned up"
}

Write-Status "Installation process completed!" 