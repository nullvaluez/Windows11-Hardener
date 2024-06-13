# Comprehensive Windows Hardening PowerShell Script - Enhanced

# Ensure running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Warning "You do not have Administrator rights to run this script! Please run as Administrator."
    break
}

# System Update
Write-Output "Checking for and installing Windows Updates..."
Install-Module -Name PSWindowsUpdate -Force
Import-Module -Name PSWindowsUpdate
Get-WindowsUpdate -Install -AcceptAll -AutoReboot

# Firewall Rules
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -LogFileName 'C:\Windows\System32\LogFiles\Firewall\pfirewall.log' -LogAllowed $true

# Disable SMBv1
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# PowerShell Restriction
Set-ExecutionPolicy Restricted -Force

# Account Policies
Get-LocalUser -Name "Guest" | Disable-LocalUser
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\Current Version\Winlogon' -Name 'AccountLockoutThreshold' -Value 5

# UAC Configuration
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2

# Remove SMB Shares
Get-SmbShare | Where-Object { $_.Name -ne 'ADMIN$' -and $_.Name -ne 'C$' -and $_.Name -ne 'IPC$' } | Remove-SmbShare -Force

# Driver Access Restriction
$driverPath = "C:\Windows\System32\drivers\cldflt.sys"
if (Test-Path $driverPath) {
    icacls $driverPath /grant:r "SYSTEM:(F)" /inheritance:r
}

# ASP.NET Security Enhancements
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location 'Default Web Site' -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping" -value $false

# Auditing Settings
auditpol /set /category:* /success:enable /failure:enable

# Disable Unnecessary Windows Features
$featuresToRemove = @("TelnetClient", "TFTP", "MediaPlayback", "WindowsMediaPlayer", "HelloFace", "XPS-Viewer", "WorkFolders-Client", "Microsoft-Windows-Subsystem-Linux")
foreach ($feature in $featuresToRemove) {
    Disable-WindowsOptionalFeature -Online -FeatureName $feature
}

# Application Control Policies
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Name "DefaultLevel" -Value "0x10000" -PropertyType DWORD
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Name "TransparentEnabled" -Value 1 -PropertyType DWORD

# Network Isolation
$criticalServices = @("C:\Program Files\ImportantApp\app.exe", "C:\Program Files\AnotherApp\app.exe")
foreach ($service in $criticalServices) {
    New-NetFirewallRule -DisplayName "Allow Critical App" -Direction Inbound -Program $service -Action Allow
    New-NetFirewallRule -DisplayName "Block Internet for Critical App" -Direction Outbound -Program $service -Action Block
}

# Fetch and block malicious IPs from Project Honey Pot
Write-Output "Fetching and blocking malicious IPs from Project Honey Pot..."
$maliciousIPs = (Invoke-WebRequest -Uri 'https://www.projecthoneypot.org/list_of_ips.php' -UseBasicParsing).Content -split "`n" | Where-Object { $_ -match "\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b" }
foreach ($ip in $maliciousIPs) {
    if (![string]::IsNullOrWhiteSpace($ip)) {
        New-NetFirewallRule -DisplayName "Block Malicious IP $ip" -Direction Inbound -Action Block -RemoteAddress $ip
    }
}

# Mitigation for CVE-2023-35641 (ICS RCE)
# Ensure ICS (Internet Connection Sharing) is disabled
Set-Service 'SharedAccess' -StartupartupType Disabled
Stop-Service 'SharedAccess'

# Mitigation for CVE-2023-35708 (SQL Injection Vulnerability)
# Note: Implement secure coding practices in your database interactions
Write-Output "Ensure your applications use parameterized queries to mitigate SQL Injection vulnerabilities."

# Log actions to file
$LogPath = "C:\HardeningLog_Enhanced.txt"
"Comprehensive hardening completed at $(Get-Date)" | Out-File -FilePath $LogPath -Append

Write-Output "Enhanced comprehensive system hardening is completed. Please check the log at $LogPath for details."
