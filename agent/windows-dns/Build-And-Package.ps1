#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    One-click build and package script for the Zentryc DNS Agent.
    Run this on ANY Windows machine — it installs .NET SDK if needed,
    builds the agent, and creates a deployable ZIP package.

.DESCRIPTION
    This script:
    1. Checks for / installs .NET 8 SDK
    2. Restores NuGet packages
    3. Builds in Release mode
    4. Runs unit tests
    5. Publishes as self-contained single-file executable
    6. Packages everything into ZentrycDnsAgent-v1.0.0.zip

    The output ZIP contains:
    - ZentrycDnsAgent.exe      (self-contained, no runtime needed)
    - appsettings.json         (pre-configured for your SIEM)
    - Install-ZentrycDnsAgent.ps1  (production installer)
    - INSTALL.md               (documentation)

.PARAMETER SkipTests
    Skip unit tests for faster builds.

.PARAMETER ServerHost
    Bake this server IP into the default config. Default: 10.12.50.77

.EXAMPLE
    .\Build-And-Package.ps1
    .\Build-And-Package.ps1 -SkipTests -ServerHost 10.12.50.77
#>

[CmdletBinding()]
param(
    [switch]$SkipTests,
    [string]$ServerHost = "10.12.50.77",
    [int]$ServerPort = 514
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Version = "1.0.0"
$OutputDir = "$ScriptDir\dist"
$PublishDir = "$ScriptDir\publish"
$PackageName = "ZentrycDnsAgent-v$Version"

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Zentryc DNS Agent — Build & Package" -ForegroundColor Cyan
Write-Host "  Version: $Version" -ForegroundColor Cyan
Write-Host "  Target SIEM: $ServerHost`:$ServerPort" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# Step 1: Ensure .NET 8 SDK
# ============================================================================
Write-Host "[1/6] Checking .NET 8 SDK..." -ForegroundColor Yellow

$dotnetVersion = $null
try {
    $dotnetVersion = & dotnet --version 2>$null
} catch {}

$hasDotnet8 = $false
if ($dotnetVersion -and $dotnetVersion.StartsWith("8.")) {
    $hasDotnet8 = $true
    Write-Host "  Found .NET SDK $dotnetVersion" -ForegroundColor Green
} else {
    # Check if any 8.x SDK is installed
    try {
        $sdks = & dotnet --list-sdks 2>$null
        if ($sdks -match "^8\.") {
            $hasDotnet8 = $true
            Write-Host "  Found .NET 8 SDK" -ForegroundColor Green
        }
    } catch {}
}

if (-not $hasDotnet8) {
    Write-Host "  .NET 8 SDK not found. Installing..." -ForegroundColor Yellow

    $installerUrl = "https://dot.net/v1/dotnet-install.ps1"
    $installerPath = "$env:TEMP\dotnet-install.ps1"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
        & $installerPath -Channel 8.0 -InstallDir "$env:ProgramFiles\dotnet"

        # Add to PATH for this session
        $env:PATH = "$env:ProgramFiles\dotnet;$env:PATH"

        $installedVersion = & dotnet --version
        Write-Host "  Installed .NET SDK $installedVersion" -ForegroundColor Green
    } catch {
        Write-Host "  FAILED to install .NET SDK: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Please install manually from: https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
        exit 1
    }
}

# ============================================================================
# Step 2: Restore packages
# ============================================================================
Write-Host "[2/6] Restoring NuGet packages..." -ForegroundColor Yellow
& dotnet restore "$ScriptDir\ZentrycDnsAgent.sln" --verbosity quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Package restore failed!" -ForegroundColor Red
    exit 1
}
Write-Host "  Packages restored" -ForegroundColor Green

# ============================================================================
# Step 3: Build
# ============================================================================
Write-Host "[3/6] Building solution (Release)..." -ForegroundColor Yellow
& dotnet build "$ScriptDir\ZentrycDnsAgent.sln" -c Release --no-restore --verbosity quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "  Build successful" -ForegroundColor Green

# ============================================================================
# Step 4: Test
# ============================================================================
if (-not $SkipTests) {
    Write-Host "[4/6] Running unit tests..." -ForegroundColor Yellow
    & dotnet test "$ScriptDir\tests\ZentrycDnsAgent.Tests\ZentrycDnsAgent.Tests.csproj" `
        -c Release --no-build --verbosity normal
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  Tests failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "  All tests passed" -ForegroundColor Green
} else {
    Write-Host "[4/6] Skipping tests (-SkipTests)" -ForegroundColor DarkGray
}

# ============================================================================
# Step 5: Publish (self-contained single-file)
# ============================================================================
Write-Host "[5/6] Publishing self-contained executable..." -ForegroundColor Yellow

if (Test-Path $PublishDir) { Remove-Item -Recurse -Force $PublishDir }

& dotnet publish "$ScriptDir\src\ZentrycDnsAgent\ZentrycDnsAgent.csproj" `
    -c Release `
    -r win-x64 `
    --self-contained `
    -p:PublishSingleFile=true `
    -p:EnableCompressionInSingleFile=true `
    -p:DebugType=none `
    -p:DebugSymbols=false `
    -o $PublishDir `
    --verbosity quiet

if ($LASTEXITCODE -ne 0) {
    Write-Host "  Publish failed!" -ForegroundColor Red
    exit 1
}

$exeSize = [math]::Round((Get-Item "$PublishDir\ZentrycDnsAgent.exe").Length / 1MB, 1)
Write-Host "  Published: ZentrycDnsAgent.exe ($exeSize MB)" -ForegroundColor Green

# ============================================================================
# Step 6: Package into deployable ZIP
# ============================================================================
Write-Host "[6/6] Creating deployment package..." -ForegroundColor Yellow

if (Test-Path $OutputDir) { Remove-Item -Recurse -Force $OutputDir }
$stageDir = "$OutputDir\$PackageName"
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

# Copy artifacts
Copy-Item "$PublishDir\ZentrycDnsAgent.exe" "$stageDir\" -Force
Copy-Item "$PublishDir\appsettings.json" "$stageDir\" -Force
Copy-Item "$ScriptDir\Install-ZentrycDnsAgent.ps1" "$stageDir\" -Force
Copy-Item "$ScriptDir\INSTALL.md" "$stageDir\" -Force

# Update the config in the package with the target server
$configContent = Get-Content "$stageDir\appsettings.json" -Raw | ConvertFrom-Json
$configContent.Zentryc.ServerHost = $ServerHost
$configContent.Zentryc.ServerPort = $ServerPort
$configContent | ConvertTo-Json -Depth 10 | Set-Content "$stageDir\appsettings.json" -Encoding UTF8

# Create ZIP
$zipPath = "$OutputDir\$PackageName.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$stageDir\*" -DestinationPath $zipPath -CompressionLevel Optimal

$zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 1)

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Build Complete!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Package: $zipPath ($zipSize MB)" -ForegroundColor White
Write-Host ""
Write-Host "  Contents:" -ForegroundColor Cyan
Get-ChildItem $stageDir | ForEach-Object {
    $size = if ($_.Length -gt 1MB) { "$([math]::Round($_.Length/1MB,1)) MB" } else { "$([math]::Round($_.Length/1KB,1)) KB" }
    Write-Host "    $($_.Name)  ($size)"
}
Write-Host ""
Write-Host "  Deploy to Windows DNS Server:" -ForegroundColor Cyan
Write-Host "    1. Copy $PackageName.zip to the target server"
Write-Host "    2. Extract the ZIP"
Write-Host "    3. Run as Admin: .\Install-ZentrycDnsAgent.ps1 -ServerHost $ServerHost"
Write-Host ""
Write-Host "  Silent install (GPO/SCCM):" -ForegroundColor Cyan
Write-Host "    powershell -ExecutionPolicy Bypass -File Install-ZentrycDnsAgent.ps1 -ServerHost $ServerHost -Silent"
Write-Host ""
