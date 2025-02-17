# Comprehensive Windows 11 Hardening Script
# Enhanced with security best practices and additional protections

#region Initialization
# Ensure running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "You do not have Administrator rights to run this script!`nPlease restart PowerShell as Administrator."
    exit
}

# Ensure necessary directories exist
if (-not (Test-Path "C:\Temp")) {
    New-Item -Path "C:\Temp" -ItemType Directory | Out-Null
}

# Configure script parameters
$LogPath = "C:\WindowsHardeningLog_$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
$ErrorActionPreference = "Stop"
$TranscriptPath = "C:\Temp\HardeningTranscript_$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

# Start logging
Start-Transcript -Path $TranscriptPath -Append
#endregion

#region System Updates
try {
    Write-Output "[*] Configuring Windows Update settings..." | Tee-Object -FilePath $LogPath -Append
    # Ensure registry paths exist before setting properties
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 1 -Type DWord

    if (-not (Get-Module -Name PSWindowsUpdate -ListAvailable)) {
        Install-Module -Name PSWindowsUpdate -Force -Confirm:$false
    }
    Import-Module PSWindowsUpdate
    Write-Output "[*] Checking for and installing Windows Updates..." | Tee-Object -FilePath $LogPath -Append
    Get-WindowsUpdate -Install -AcceptAll -AutoReboot:$false -IgnoreUserInput -Confirm:$false
}
catch {
    Write-Warning "Windows Update configuration failed: $_" | Tee-Object -FilePath $LogPath -Append
}
#endregion

#region Network Security
try {
    Write-Output "[*] Configuring network security settings..." | Tee-Object -FilePath $LogPath -Append
    
    # Firewall Configuration
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen True -AllowUnicastResponseToMulticast False -LogFileName "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" -LogMaxSizeKilobytes 32767 -LogAllowed True -LogBlocked True
    
    # Disable legacy protocols and features
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Type DWord -Value 0
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -WarningAction SilentlyContinue
    Set-NetTCPSetting -SettingName InternetCustom -AutoTuningLevelLocal Disabled
    Set-NetTCPSetting -SettingName DatacenterCustom -AutoTuningLevelLocal Disabled
    
    # Disable LLMNR and WPAD
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMulticast" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" -Name "Start" -Type DWord -Value 4
    
    # Disable IPv6 privacy extensions
    Set-NetIPv6Protocol -RandomizeIdentifiers Disabled -UseTemporaryAddresses Disabled

    # Disable NetBIOS over TCP/IP for all active adapters
    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" | ForEach-Object {
        if ($_.TcpipNetbiosOptions -ne 2) {
            Write-Output "[*] Disabling NetBIOS for adapter: $($_.Description)" | Tee-Object -FilePath $LogPath -Append
            $_.SetTcpipNetbios(2) | Out-Null
        }
    }
    
    # Optional: Disable Remote Desktop (Uncomment if RDP is not needed)
    # Write-Output "[*] Disabling Remote Desktop..." | Tee-Object -FilePath $LogPath -Append
    # Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
    
    # Optional: Disable Windows Remote Management (WinRM) (Uncomment if not required)
    # Write-Output "[*] Disabling Windows Remote Management (WinRM)..." | Tee-Object -FilePath $LogPath -Append
    # Set-Service -Name WinRM -StartupType Disabled
    # Stop-Service -Name WinRM -Force
}
catch {
    Write-Warning "Network security configuration failed: $_" | Tee-Object -FilePath $LogPath -Append
}
#endregion

#region Account Security
try {
    Write-Output "[*] Configuring account security policies..." | Tee-Object -FilePath $LogPath -Append
    
    # Account lockout policy using secedit
    secedit /configure /cfg "$env:windir\inf\defltbase.inf" /db defltbase.sdb /verbose
    $secpol = @"
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 12
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 15
LockoutDuration = 15
[Registry Values]
MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,0
"@
    $secpol | Out-File -FilePath "$env:TEMP\secpol.inf" -Encoding ASCII
    secedit /configure /db "$env:TEMP\secedit.sdb" /cfg "$env:TEMP\secpol.inf" /areas SECURITYPOLICY
    
    # Disable Guest and built-in Administrator account (Ensure you have an alternative admin account)
    if (Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue) {
        Disable-LocalUser -Name "Guest"
    }
    if (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue) {
        Disable-LocalUser -Name "Administrator"
    }
    
    # Configure UAC
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1

    # Configure audit policies for account logon events
    Write-Output "[*] Configuring audit policies for logon and account lockout events..." | Tee-Object -FilePath $LogPath -Append
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable | Out-Null
}
catch {
    Write-Warning "Account security configuration failed: $_" | Tee-Object -FilePath $LogPath -Append
}
#endregion

#region System Hardening
try {
    Write-Output "[*] Applying system hardening configurations..." | Tee-Object -FilePath $LogPath -Append
    
    # Remove non-default SMB shares
    Get-SmbShare | Where-Object { $_.Name -notin @('ADMIN$', 'C$', 'IPC$') } | ForEach-Object {
        Write-Output "[*] Removing SMB share: $($_.Name)" | Tee-Object -FilePath $LogPath -Append
        Remove-SmbShare -Name $_.Name -Force -ErrorAction SilentlyContinue
    }
    
    # Disable unnecessary services
    $servicesToDisable = @(
        "SSDPSRV", "upnphost", "RemoteRegistry", "WpnService",
        "XboxGipSvc", "XblAuthManager", "XboxNetApiSvc"
    )
    foreach ($service in $servicesToDisable) {
        Write-Output "[*] Disabling service: $service" | Tee-Object -FilePath $LogPath -Append
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
    }
    
    # Disable unnecessary Windows features
    $featuresToDisable = @(
        "MicrosoftWindowsPowerShellV2Root", "MicrosoftWindowsPowershellV2",
        "SMB1Protocol", "WorkFolders-Client", "WindowsMediaPlayer",
        "Printing-Foundation-Features", "Printing-PrintToPDFServices-Features"
    )
    foreach ($feature in $featuresToDisable) {
        Write-Output "[*] Disabling Windows feature: $feature" | Tee-Object -FilePath $LogPath -Append
        Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -WarningAction SilentlyContinue
    }
    
    # Configure memory protections
    Write-Output "[*] Configuring memory protections..." | Tee-Object -FilePath $LogPath -Append
    Set-ProcessMitigation -System -Enable DEP,TerminateOnError
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Type DWord -Value 3
    
    # Enable LSA Protection
    Write-Output "[*] Enabling LSA Protection..." | Tee-Object -FilePath $LogPath -Append
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Type DWord -Value 1
    
    # Disable AutoRun for all drives
    Write-Output "[*] Disabling AutoRun on all drives..." | Tee-Object -FilePath $LogPath -Append
    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord
    
    # Disable Remote Assistance
    Write-Output "[*] Disabling Remote Assistance..." | Tee-Object -FilePath $LogPath -Append
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord

    # Optional: Disable Windows Script Host (Uncomment if not required)
    # Write-Output "[*] Disabling Windows Script Host..." | Tee-Object -FilePath $LogPath -Append
    # if (-not (Test-Path "HKLM:\Software\Microsoft\Windows Script Host\Settings")) {
    #     New-Item -Path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -Force | Out-Null
    # }
    # Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord
}
catch {
    Write-Warning "System hardening configuration failed: $_" | Tee-Object -FilePath $LogPath -Append
}
#endregion

#region Application Security
try {
    Write-Output "[*] Configuring application security settings..." | Tee-Object -FilePath $LogPath -Append
    
    # Enable Windows Defender
    Write-Output "[*] Ensuring Windows Defender real-time monitoring is enabled..." | Tee-Object -FilePath $LogPath -Append
    Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableBlockAtFirstSeen $false
    Set-MpPreference -SubmitSamplesConsent 2 -MAPSReporting 2 -HighThreatDefaultAction 2 -ModerateThreatDefaultAction 2
    
    # Configure AppLocker
    if (Get-Command -Name Get-AppLockerPolicy -ErrorAction SilentlyContinue) {
        Write-Output "[*] Configuring AppLocker policies..." | Tee-Object -FilePath $LogPath -Append
        $appLockerPolicy = @"
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePublisherRule Id="a9e18c21-ff8f-43cf-b9fc-db1ad9c6be64" Name="Allow All Signed EXEs" Description="" UserOrGroupSid="S-1-1-0" Action="Allow">
      <Conditions>
        <FilePublisherCondition PublisherName="*" ProductName="*" BinaryName="*">
          <BinaryVersionRange LowSection="0.0.0.0" HighSection="*" />
        </FilePublisherCondition>
      </Conditions>
    </FilePublisherRule>
  </RuleCollection>
</AppLockerPolicy>
"@
        $appLockerPolicy | Out-File -FilePath "$env:TEMP\AppLockerPolicy.xml" -Encoding ASCII
        Set-AppLockerPolicy -XmlPolicy "$env:TEMP\AppLockerPolicy.xml" -Merge
    }
    
    # Restrict PowerShell execution and enhance logging
    Write-Output "[*] Configuring PowerShell execution policy and logging..." | Tee-Object -FilePath $LogPath -Append
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" -Name "ExecutionPolicy" -Value "RemoteSigned"
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -Force | Out-Null
    }
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Type DWord -Value 1
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Type DWord -Value 1
}
catch {
    Write-Warning "Application security configuration failed: $_" | Tee-Object -FilePath $LogPath -Append
}
#endregion

#region Privacy & Telemetry
try {
    Write-Output "[*] Configuring privacy settings..." | Tee-Object -FilePath $LogPath -Append
    
    # Disable telemetry
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 1
    
    # Disable Cortana
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
    
    # Disable activity history
    if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0

    # Disable location services
    Write-Output "[*] Disabling location services..." | Tee-Object -FilePath $LogPath -Append
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
    
    # Disable Windows Error Reporting
    Write-Output "[*] Disabling Windows Error Reporting..." | Tee-Object -FilePath $LogPath -Append
    if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1

    # Optional: Disable OneDrive integration (Uncomment if not used)
    # Write-Output "[*] Disabling OneDrive integration..." | Tee-Object -FilePath $LogPath -Append
    # if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
    #     New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Force | Out-Null
    # }
    # Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
}
catch {
    Write-Warning "Privacy configuration failed: $_" | Tee-Object -FilePath $LogPath -Append
}
#endregion

#region Finalization
Write-Output "[*] Hardening process completed. Review logs at $LogPath and $TranscriptPath"
Write-Output "[!] A system reboot may be required for some changes to take effect."
Stop-Transcript
#endregion