# Windows 11 Hardener

## Overview
This PowerShell script is designed to enhance the security of Windows systems by applying a series of hardening measures. It addresses numerous known vulnerabilities, disables unnecessary Windows features, and configures system settings to reduce the attack surface. This script is suitable for administrators looking to secure Windows servers and desktops in a corporate environment.

## Features
- **Windows Updates**: Automatically checks for and installs available Windows updates to mitigate known vulnerabilities.
- **Firewall Configuration**: Sets strict firewall rules to block unsolicited inbound traffic while allowing necessary outbound communications.
- **Feature Disablement**: Disables legacy and unnecessary Windows features such as SMBv1, Telnet, TFTP, Media Playback, and more.
- **Security Policies**: Implements strict user account and User Account Control (UAC) settings to prevent unauthorized access.
- **Auditing Enhancements**: Configures auditing settings to log successful and failed security events, providing a trail for forensic analysis.
- **CVE Mitigations**: Specifically addresses vulnerabilities such as CVE-2023-35641 and CVE-2023-35708 by disabling affected components and recommending secure coding practices.

## Script Actions
1. **System Updates**: Installs all critical and security-related updates from Windows Update.
2. **Firewall Rules**: Configures the firewall to default-deny all inbound connections not explicitly allowed.
3. **Disable Unnecessary Features**: Removes features that are commonly exploited or unnecessary for a secured environment.
4. **Account and Security Policy Configuration**: Sets policies to enhance the security posture, like disabling the guest account and enforcing UAC prompts.
5. **Network Isolation for Critical Applications**: Applies firewall rules to limit network access to critical applications, reducing potential exposure.
6. **Application Control Policies**: Enforces application whitelisting to ensure only authorized applications are allowed to execute.
7. **Driver and Service Restrictions**: Places strict access controls on sensitive system files and services to prevent privilege escalation.

## Usage
```powershell
# Run the script with administrative privileges
# Right-click on PowerShell and select 'Run as Administrator'
.\WindowsHardeningScript.ps1
```

## Prerequisites
- Powershell 5.1 or higher
- Admin privs on the system to execute

## Security Considerations
Before deploying this script:

- Test thoroughly in a non-production environment.
- Review each setting to ensure it does not interfere with necessary business functions.
- Customize the script to fit organizational policies and specific system roles.

## Contributing
Contributions to this script are welcome. Please submit pull requests with suggested changes or enhancements. Ensure any contributions are tested and include updates to documentation as needed. I will actively maintain this with the latest CVE and vectors.

## License
This script is provided under the MIT License. See the LICENSE file for full details.
