# Zentryc DNS Agent — Installation Guide

## Prerequisites

- Windows Server 2016, 2019, 2022, or 2025 (64-bit)
- DNS Server role installed and running
- Network connectivity to your Zentryc SIEM server on UDP port 514
- Administrator privileges for installation

## Quick Install (Interactive)

1. Copy `ZentrycDnsAgent.msi` to the target Windows Server
2. Double-click to launch the installer
3. Enter your Zentryc SIEM server IP and port (default: 514)
4. Click Install — the service starts automatically

## Silent Install (Command Line)

```powershell
msiexec /i ZentrycDnsAgent.msi /qn ZENTRYC_HOST=10.0.0.100 ZENTRYC_PORT=514
```

### All MSI Properties

| Property | Default | Description |
|----------|---------|-------------|
| `ZENTRYC_HOST` | `127.0.0.1` | Zentryc SIEM server IP or hostname |
| `ZENTRYC_PORT` | `514` | Syslog UDP port |
| `ZENTRYC_APIKEY` | (empty) | API key for HTTPS transport |
| `ZENTRYC_PROTOCOL` | `udp` | Transport protocol: `udp` or `https` |

### Example with logging

```powershell
msiexec /i ZentrycDnsAgent.msi /qn /l*v C:\temp\zentryc-install.log ZENTRYC_HOST=siem.corp.local ZENTRYC_PORT=514
```

## GPO Deployment

1. Place the MSI on a network share accessible to all DNS servers
2. Create a Group Policy Object linked to the DNS Servers OU
3. Navigate to: Computer Configuration > Policies > Software Settings > Software Installation
4. Add the MSI package from the network share
5. Set properties via MSI Transform (.mst) or use `ZENTRYC_HOST` in the deployment options

## Post-Install Verification

### Check service status
```powershell
Get-Service ZentrycDnsAgent
```

### View agent logs
```powershell
Get-Content "C:\ProgramData\Zentryc\Logs\agent-*.log" -Tail 50
```

### Check Windows Event Log
```powershell
Get-EventLog -LogName Application -Source ZentrycDnsAgent -Newest 10
```

### Test syslog connectivity
```powershell
# Verify UDP packets reach the server (from Zentryc server)
# Check the Zentryc log viewer for logs with vendor="windows-dns"
```

## Configuration

Config file: `C:\ProgramData\Zentryc\appsettings.json`

Edit this file to change settings after installation. Restart the service after changes:

```powershell
Restart-Service ZentrycDnsAgent
```

### Exclude noisy internal DNS queries

Edit `appsettings.json` and add patterns to the exclude list:

```json
{
  "Collection": {
    "ExcludePatterns": [
      "*.in-addr.arpa",
      "*.ip6.arpa",
      "_ldap._tcp.*",
      "_kerberos._tcp.*",
      "_gc._tcp.*",
      "wpad.*",
      "isatap.*"
    ]
  }
}
```

### Filter specific query types only

```json
{
  "Collection": {
    "QueryTypes": ["A", "AAAA", "MX", "CNAME", "TXT"]
  }
}
```

## File Locations

| Path | Contents |
|------|----------|
| `C:\Program Files\Zentryc\DNS Agent\` | Service executable |
| `C:\ProgramData\Zentryc\appsettings.json` | Configuration |
| `C:\ProgramData\Zentryc\buffer.db` | Offline message buffer |
| `C:\ProgramData\Zentryc\Logs\` | Agent log files (30-day retention) |

## Uninstall

```powershell
# Via command line
msiexec /x ZentrycDnsAgent.msi /qn

# Via Settings
# Settings > Apps > Zentryc DNS Agent > Uninstall
```

Note: Uninstall removes the service and program files but preserves logs in `C:\ProgramData\Zentryc\Logs\`.

## Troubleshooting

### Service won't start

1. Check the DNS Server role is installed: `Get-WindowsFeature DNS`
2. Verify the DNS Server service is running: `Get-Service DNS`
3. Check agent logs: `C:\ProgramData\Zentryc\Logs\`
4. ETW requires admin rights — ensure the service runs as LocalSystem

### No logs appearing in Zentryc

1. Verify network connectivity: `Test-NetConnection -ComputerName <siem-ip> -Port 514`
2. Check firewall rules: `Get-NetFirewallRule | Where DisplayName -like "*Zentryc*"`
3. Verify the agent heartbeat in Zentryc (check for `vendor=windows-dns` logs)
4. Check buffer count in agent logs — if growing, the server is unreachable

### DNS Analytical log not enabled

The agent auto-enables it, but if it fails:
```powershell
wevtutil sl "Microsoft-Windows-DNS-Server/Analytical" /e:true
```

## Building from Source

Requirements: .NET 8 SDK, WiX Toolset v5

```powershell
# On a Windows machine with .NET 8 SDK
cd agent\windows-dns
.\build.ps1

# Debug build
.\build.ps1 -Configuration Debug

# Skip tests
.\build.ps1 -SkipTests
```
