<# 
==============================================
 SNMP Agent Auto-Setup Script for Windows
 For Prometheus / SNMP Monitoring
----------------------------------------------
 Requirements:
   - Run as Administrator
   - Windows 10/11/Server (2016+)
==============================================
#>

param(
    [string]$Community = "public",
    [string]$ManagerIP = "192.168.0.154"
)

Write-Host "=== Installing SNMP service ===" -ForegroundColor Cyan

# Install SNMP components
Add-WindowsCapability -Online -Name "SNMP.Client~~~~0.0.1.0" -ErrorAction SilentlyContinue
Add-WindowsCapability -Online -Name "WMI-SNMP-Provider.Client~~~~0.0.1.0" -ErrorAction SilentlyContinue

# Enable SNMP service startup
Set-Service -Name SNMP -StartupType Automatic

# Registry path for SNMP settings
$snmpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters"

Write-Host "=== Configuring SNMP Community and Manager Access ===" -ForegroundColor Cyan

# Create Community subkey if not exists
if (-not (Test-Path "$snmpRegPath\ValidCommunities")) {
    New-Item -Path "$snmpRegPath" -Name "ValidCommunities" | Out-Null
}

# Add or update community string (read-only = 4)
New-ItemProperty -Path "$snmpRegPath\ValidCommunities" -Name $Community -PropertyType DWord -Value 4 -Force | Out-Null

# Create Permitted Managers list if not exists
if (-not (Test-Path "$snmpRegPath\PermittedManagers")) {
    New-Item -Path "$snmpRegPath" -Name "PermittedManagers" | Out-Null
}

# Remove any old entries and add new one
Remove-Item -Path "$snmpRegPath\PermittedManagers" -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path "$snmpRegPath" -Name "PermittedManagers" | Out-Null
New-ItemProperty -Path "$snmpRegPath\PermittedManagers" -Name "1" -Value $ManagerIP -PropertyType String | Out-Null

# Optional system info
Set-ItemProperty -Path "$snmpRegPath" -Name "sysContact" -Value "admin@local" -Force
Set-ItemProperty -Path "$snmpRegPath" -Name "sysLocation" -Value "Auto-Discovered Node" -Force

Write-Host "=== Restarting SNMP Service ===" -ForegroundColor Cyan
Restart-Service SNMP

Write-Host "`n✅ SNMP successfully configured!"
Write-Host "   Community: $Community"
Write-Host "   Manager:   $ManagerIP"
Write-Host "SNMP service is now running and set to start automatically." -ForegroundColor Green
