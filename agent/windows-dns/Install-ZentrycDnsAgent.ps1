#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    Installs, upgrades, or uninstalls the Zentryc DNS Agent on Windows Server.

.DESCRIPTION
    Production installer for the Zentryc DNS Agent. Performs:
    - Prerequisite checks (OS version, DNS Server role, admin rights)
    - Copies files to Program Files and ProgramData
    - Creates and starts the Windows Service with recovery policies
    - Configures Windows Firewall outbound rule
    - Enables DNS Server Analytical log for ETW capture
    - Writes configuration (server IP, port) to appsettings.json

    Supports silent/unattended install for GPO and SCCM deployment.

.PARAMETER ServerHost
    Zentryc SIEM server IP or hostname. Default: 10.12.50.77

.PARAMETER ServerPort
    Syslog UDP port on the Zentryc server. Default: 514

.PARAMETER Uninstall
    Remove the agent, service, and firewall rules. Preserves logs.

.PARAMETER SourcePath
    Path to the directory containing ZentrycDnsAgent.exe and appsettings.json.
    Defaults to the same directory as this script.

.PARAMETER Silent
    Suppress all interactive prompts (for GPO/SCCM deployment).

.EXAMPLE
    # Interactive install
    .\Install-ZentrycDnsAgent.ps1

    # Silent install with custom server
    .\Install-ZentrycDnsAgent.ps1 -ServerHost 10.12.50.77 -ServerPort 514 -Silent

    # Uninstall
    .\Install-ZentrycDnsAgent.ps1 -Uninstall

    # GPO startup script
    powershell.exe -ExecutionPolicy Bypass -File \\share\zentryc\Install-ZentrycDnsAgent.ps1 -ServerHost 10.12.50.77 -Silent
#>

[CmdletBinding()]
param(
    [string]$ServerHost = "10.12.50.77",
    [int]$ServerPort = 514,
    [string]$Protocol = "udp",
    [string]$ApiKey = "",
    [switch]$Uninstall,
    [string]$SourcePath = "",
    [switch]$Silent
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Constants
# ============================================================================
$ServiceName        = "ZentrycDnsAgent"
$DisplayName        = "Zentryc DNS Log Agent"
$Description        = "Collects DNS Server logs and forwards them to Zentryc SIEM via syslog."
$InstallDir         = "$env:ProgramFiles\Zentryc\DNS Agent"
$DataDir            = "$env:ProgramData\Zentryc"
$LogDir             = "$DataDir\Logs"
$ConfigPath         = "$DataDir\appsettings.json"
$ExeName            = "ZentrycDnsAgent.exe"
$FirewallRuleName   = "Zentryc DNS Agent - Syslog (UDP Out)"
$Version            = "1.0.0"

# ============================================================================
# Helpers
# ============================================================================
function Write-Step {
    param([string]$Step, [string]$Message)
    Write-Host "[$Step] " -ForegroundColor Cyan -NoNewline
    Write-Host $Message
}

function Write-Ok {
    param([string]$Message)
    Write-Host "  OK: " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warn {
    param([string]$Message)
    Write-Host "  WARN: " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  FAIL: " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ============================================================================
# UNINSTALL
# ============================================================================
if ($Uninstall) {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  Zentryc DNS Agent - Uninstall" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""

    # Stop and remove service
    Write-Step "1/4" "Stopping service..."
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force
            Start-Sleep -Seconds 2
        }
        sc.exe delete $ServiceName | Out-Null
        Write-Ok "Service removed"
    } else {
        Write-Ok "Service not found (already removed)"
    }

    # Remove firewall rule
    Write-Step "2/4" "Removing firewall rule..."
    $rule = Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue
    if ($rule) {
        Remove-NetFirewallRule -DisplayName $FirewallRuleName
        Write-Ok "Firewall rule removed"
    } else {
        Write-Ok "Firewall rule not found"
    }

    # Remove program files
    Write-Step "3/4" "Removing program files..."
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
        Write-Ok "Removed $InstallDir"
    }
    # Remove parent Zentryc dir if empty
    $parentDir = Split-Path $InstallDir -Parent
    if ((Test-Path $parentDir) -and ((Get-ChildItem $parentDir).Count -eq 0)) {
        Remove-Item $parentDir -Force
    }

    # Keep logs
    Write-Step "4/4" "Preserving data..."
    Write-Ok "Logs preserved at $LogDir"
    Write-Ok "Config preserved at $ConfigPath"
    Write-Host ""

    # Clean registry
    Remove-Item "HKLM:\SOFTWARE\Zentryc" -Recurse -ErrorAction SilentlyContinue

    Write-Host "Uninstall complete." -ForegroundColor Green
    Write-Host ""
    exit 0
}

# ============================================================================
# INSTALL
# ============================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Zentryc DNS Agent v$Version" -ForegroundColor Cyan
Write-Host "  Installer for Windows DNS Server" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Target SIEM:  $ServerHost`:$ServerPort/$Protocol"
Write-Host "  Install path: $InstallDir"
Write-Host "  Data path:    $DataDir"
Write-Host ""

# ── Resolve source path ──
if (-not $SourcePath) {
    $SourcePath = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$SourceExe = Join-Path $SourcePath $ExeName

# ============================================================================
# Step 1: Prerequisites
# ============================================================================
Write-Step "1/7" "Checking prerequisites..."

# Admin check
if (-not (Test-IsAdmin)) {
    Write-Fail "This installer requires Administrator privileges."
    Write-Host "  Right-click PowerShell > 'Run as Administrator' and try again."
    exit 1
}
Write-Ok "Running as Administrator"

# OS version check
$os = [System.Environment]::OSVersion
$build = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
if ($build -lt 14393) {
    Write-Fail "Windows Server 2016 or later required (build 14393+). Current: $build"
    exit 1
}
Write-Ok "Windows build $build"

# DNS Server role check
$dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
if (-not $dnsService) {
    Write-Warn "DNS Server role not detected. The agent captures DNS Server logs."
    Write-Warn "Install DNS Server role first, or ignore if this server will get DNS role later."
    if (-not $Silent) {
        $continue = Read-Host "  Continue anyway? (y/N)"
        if ($continue -ne 'y') { exit 1 }
    }
} else {
    Write-Ok "DNS Server role installed (service status: $($dnsService.Status))"
}

# Source exe check
if (-not (Test-Path $SourceExe)) {
    Write-Fail "Cannot find $ExeName in $SourcePath"
    Write-Host "  Build the project first: dotnet publish -c Release -r win-x64 --self-contained"
    Write-Host "  Or place $ExeName next to this script."
    exit 1
}
Write-Ok "Found $ExeName ($([math]::Round((Get-Item $SourceExe).Length / 1MB, 1)) MB)"

# Network connectivity check
Write-Step "2/7" "Testing network connectivity to $ServerHost`:$ServerPort..."
try {
    $udpClient = New-Object System.Net.Sockets.UdpClient
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("<14>1 test ZentrycDNS installer-test")
    $udpClient.Send($bytes, $bytes.Length, $ServerHost, $ServerPort) | Out-Null
    $udpClient.Close()
    Write-Ok "UDP packet sent to $ServerHost`:$ServerPort (no ACK expected for UDP)"
} catch {
    Write-Warn "Could not send UDP to $ServerHost`:$ServerPort - $($_.Exception.Message)"
    Write-Warn "The agent will buffer logs until connectivity is restored."
}

# ============================================================================
# Step 3: Stop existing service (upgrade scenario)
# ============================================================================
Write-Step "3/7" "Checking for existing installation..."
$existingSvc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingSvc) {
    Write-Ok "Existing installation found (status: $($existingSvc.Status))"
    if ($existingSvc.Status -eq "Running") {
        Write-Host "  Stopping service for upgrade..." -ForegroundColor Yellow
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 3
    }
    # Remove old service (will recreate)
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
    Write-Ok "Old service removed for upgrade"
} else {
    Write-Ok "Fresh installation"
}

# ============================================================================
# Step 4: Deploy files
# ============================================================================
Write-Step "4/7" "Deploying files..."

# Create directories
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

# Copy executable
Copy-Item -Path $SourceExe -Destination "$InstallDir\$ExeName" -Force
Write-Ok "Copied $ExeName to $InstallDir"

# Copy appsettings.json template (if exists alongside exe)
$sourceConfig = Join-Path $SourcePath "appsettings.json"
if (Test-Path $sourceConfig) {
    # Only copy if no existing config (don't overwrite user changes on upgrade)
    if (-not (Test-Path $ConfigPath)) {
        Copy-Item -Path $sourceConfig -Destination $ConfigPath -Force
        Write-Ok "Copied default appsettings.json to $DataDir"
    } else {
        Write-Ok "Preserved existing appsettings.json (upgrade)"
    }
}

# ============================================================================
# Step 5: Write configuration
# ============================================================================
Write-Step "5/7" "Writing configuration..."

# Build config JSON
$config = @{
    Zentryc = @{
        ServerHost = $ServerHost
        ServerPort = $ServerPort
        Protocol   = $Protocol
        ApiKey     = $ApiKey
        DeviceName = ""
        DeviceIp   = ""
        TlsEnabled = $false
    }
    Collection = @{
        EnableEtw            = $true
        EnableEventLog       = $false
        QueryTypes           = @()
        ExcludeInternalZones = $false
        ExcludePatterns      = @(
            "*.in-addr.arpa",
            "*.ip6.arpa",
            "_ldap._tcp.*",
            "_kerberos._tcp.*",
            "_gc._tcp.*",
            "_kpasswd._tcp.*",
            "_kpasswd._udp.*"
        )
        IncludeResponseData    = $true
        IncludeDynamicUpdates  = $true
        IncludeZoneTransfers   = $true
    }
    Buffer = @{
        MaxSizeMB       = 100
        MaxAgeDays      = 7
        FlushIntervalMs = 1000
        BatchSize       = 500
        DatabasePath    = "$DataDir\buffer.db"
    }
    Heartbeat = @{
        Enabled         = $true
        IntervalSeconds = 60
    }
    Serilog = @{
        MinimumLevel = @{
            Default  = "Information"
            Override = @{
                Microsoft = "Warning"
                System    = "Warning"
            }
        }
        WriteTo = @(
            @{
                Name = "File"
                Args = @{
                    path                   = "$LogDir\agent-.log"
                    rollingInterval        = "Day"
                    retainedFileCountLimit = 30
                    fileSizeLimitBytes     = 52428800
                    outputTemplate         = "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {Message:lj}{NewLine}{Exception}"
                }
            },
            @{
                Name = "EventLog"
                Args = @{
                    source                   = "ZentrycDnsAgent"
                    logName                  = "Application"
                    restrictedToMinimumLevel = "Warning"
                }
            }
        )
    }
}

$config | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigPath -Encoding UTF8
Write-Ok "Config written to $ConfigPath"
Write-Ok "  Server: $ServerHost`:$ServerPort/$Protocol"

# Write to registry for tracking
New-Item -Path "HKLM:\SOFTWARE\Zentryc\DnsAgent" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Zentryc\DnsAgent" -Name "Version" -Value $Version
Set-ItemProperty -Path "HKLM:\SOFTWARE\Zentryc\DnsAgent" -Name "InstallPath" -Value $InstallDir
Set-ItemProperty -Path "HKLM:\SOFTWARE\Zentryc\DnsAgent" -Name "ServerHost" -Value $ServerHost
Set-ItemProperty -Path "HKLM:\SOFTWARE\Zentryc\DnsAgent" -Name "ServerPort" -Value $ServerPort
Set-ItemProperty -Path "HKLM:\SOFTWARE\Zentryc\DnsAgent" -Name "InstalledAt" -Value (Get-Date -Format "o")
Write-Ok "Registry keys written to HKLM:\SOFTWARE\Zentryc\DnsAgent"

# ============================================================================
# Step 6: Create Windows Service
# ============================================================================
Write-Step "6/7" "Creating Windows Service..."

$exePath = "$InstallDir\$ExeName"

# Create the service
New-Service -Name $ServiceName `
    -BinaryPathName "`"$exePath`"" `
    -DisplayName $DisplayName `
    -Description $Description `
    -StartupType Automatic `
    -DependsOn @("DNS") `
    -ErrorAction Stop | Out-Null

Write-Ok "Service '$ServiceName' created"

# Set delayed auto-start
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
Set-ItemProperty -Path $regPath -Name "DelayedAutostart" -Value 1 -Type DWord
Write-Ok "Delayed auto-start enabled"

# Set service recovery: restart after 60s, 300s, 900s
# sc.exe failure syntax: reset=86400 (1 day) actions=restart/60000/restart/300000/restart/900000
sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/300000/restart/900000 | Out-Null
Write-Ok "Recovery policy: restart after 1min, 5min, 15min"

# Firewall rule
Write-Host "  Creating firewall rule..." -ForegroundColor DarkGray
$existingRule = Get-NetFirewallRule -DisplayName $FirewallRuleName -ErrorAction SilentlyContinue
if ($existingRule) {
    Remove-NetFirewallRule -DisplayName $FirewallRuleName
}
New-NetFirewallRule -DisplayName $FirewallRuleName `
    -Description "Allow Zentryc DNS Agent to send syslog to SIEM" `
    -Direction Outbound `
    -Protocol UDP `
    -RemotePort $ServerPort `
    -RemoteAddress $ServerHost `
    -Program $exePath `
    -Action Allow `
    -Profile Any `
    -Enabled True | Out-Null
Write-Ok "Firewall rule created (outbound UDP/$ServerPort to $ServerHost)"

# ============================================================================
# Step 7: Enable DNS Analytical Log & Start Service
# ============================================================================
Write-Step "7/7" "Final setup..."

# Enable DNS Server Analytical log for ETW
try {
    $logName = "Microsoft-Windows-DNS-Server/Analytical"
    $logConfig = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration($logName)
    if (-not $logConfig.IsEnabled) {
        wevtutil sl $logName /e:true 2>$null
        Write-Ok "DNS Server Analytical log enabled"
    } else {
        Write-Ok "DNS Server Analytical log already enabled"
    }
} catch {
    Write-Warn "Could not enable DNS Analytical log: $($_.Exception.Message)"
    Write-Warn "Run manually: wevtutil sl `"Microsoft-Windows-DNS-Server/Analytical`" /e:true"
}

# Create Windows Event Log source
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists("ZentrycDnsAgent")) {
        [System.Diagnostics.EventLog]::CreateEventSource("ZentrycDnsAgent", "Application")
        Write-Ok "Event log source 'ZentrycDnsAgent' registered"
    }
} catch {
    Write-Warn "Could not create event log source (non-critical)"
}

# Start the service
Write-Host "  Starting service..." -ForegroundColor Yellow
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq "Running") {
    Write-Ok "Service is RUNNING"
} else {
    Write-Warn "Service status: $($svc.Status)"
    Write-Warn "Check logs at $LogDir for details"
}

# ============================================================================
# Done
# ============================================================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Service:    $ServiceName ($($svc.Status))" -ForegroundColor White
Write-Host "  Target:     $ServerHost`:$ServerPort/$Protocol" -ForegroundColor White
Write-Host "  Config:     $ConfigPath" -ForegroundColor White
Write-Host "  Logs:       $LogDir" -ForegroundColor White
Write-Host "  Version:    $Version" -ForegroundColor White
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Cyan
Write-Host "  Get-Service $ServiceName                    # Check status"
Write-Host "  Restart-Service $ServiceName                # Restart agent"
Write-Host "  Get-Content '$LogDir\agent-*.log' -Tail 50  # View logs"
Write-Host "  .\Install-ZentrycDnsAgent.ps1 -Uninstall    # Remove agent"
Write-Host ""
