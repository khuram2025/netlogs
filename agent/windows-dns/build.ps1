#Requires -Version 5.1
<#
.SYNOPSIS
    Build script for the Zentryc DNS Agent MSI installer.

.DESCRIPTION
    Builds the .NET service, runs tests, publishes as self-contained single-file,
    and packages into an MSI via WiX v5.

.PARAMETER Configuration
    Build configuration: Debug or Release (default: Release)

.PARAMETER SkipTests
    Skip running unit tests

.PARAMETER SignCert
    Path to code-signing certificate (.pfx) for MSI signing

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Configuration Debug
    .\build.ps1 -SignCert "C:\certs\zentryc.pfx"
#>

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",

    [switch]$SkipTests,

    [string]$SignCert = ""
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Zentryc DNS Agent Build" -ForegroundColor Cyan
Write-Host "  Configuration: $Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ── Step 1: Restore ──
Write-Host "[1/5] Restoring packages..." -ForegroundColor Yellow
dotnet restore "$ScriptDir\ZentrycDnsAgent.sln"
if ($LASTEXITCODE -ne 0) { throw "Restore failed" }

# ── Step 2: Build ──
Write-Host "[2/5] Building solution..." -ForegroundColor Yellow
dotnet build "$ScriptDir\ZentrycDnsAgent.sln" -c $Configuration --no-restore
if ($LASTEXITCODE -ne 0) { throw "Build failed" }

# ── Step 3: Test ──
if (-not $SkipTests) {
    Write-Host "[3/5] Running tests..." -ForegroundColor Yellow
    dotnet test "$ScriptDir\tests\ZentrycDnsAgent.Tests\ZentrycDnsAgent.Tests.csproj" `
        -c $Configuration --no-build --verbosity normal
    if ($LASTEXITCODE -ne 0) { throw "Tests failed" }
} else {
    Write-Host "[3/5] Skipping tests..." -ForegroundColor DarkGray
}

# ── Step 4: Publish (self-contained single-file) ──
Write-Host "[4/5] Publishing self-contained executable..." -ForegroundColor Yellow
$PublishDir = "$ScriptDir\publish"
if (Test-Path $PublishDir) { Remove-Item -Recurse -Force $PublishDir }

dotnet publish "$ScriptDir\src\ZentrycDnsAgent\ZentrycDnsAgent.csproj" `
    -c $Configuration `
    -r win-x64 `
    --self-contained `
    -p:PublishSingleFile=true `
    -p:EnableCompressionInSingleFile=true `
    -o $PublishDir
if ($LASTEXITCODE -ne 0) { throw "Publish failed" }

Write-Host "  Published to: $PublishDir" -ForegroundColor Green
$exeSize = (Get-Item "$PublishDir\ZentrycDnsAgent.exe").Length / 1MB
Write-Host "  Executable size: $([math]::Round($exeSize, 1)) MB" -ForegroundColor Green

# ── Step 5: Build MSI ──
Write-Host "[5/5] Building MSI installer..." -ForegroundColor Yellow

# Check if WiX is available
$wixAvailable = $null -ne (Get-Command "wix" -ErrorAction SilentlyContinue)
if (-not $wixAvailable) {
    # Try dotnet tool
    dotnet tool list -g | Select-String "wix" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  WiX Toolset not found. Install with: dotnet tool install --global wix" -ForegroundColor Red
        Write-Host "  Then run: wix extension add WixToolset.UI.wixext WixToolset.Util.wixext WixToolset.Firewall.wixext" -ForegroundColor Red
        Write-Host "  Skipping MSI build." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Build completed (without MSI)." -ForegroundColor Green
        exit 0
    }
}

dotnet build "$ScriptDir\src\ZentrycDnsAgent.Installer\ZentrycDnsAgent.Installer.wixproj" `
    -c $Configuration
if ($LASTEXITCODE -ne 0) {
    Write-Host "  MSI build failed. Executable is still available in $PublishDir" -ForegroundColor Yellow
} else {
    $msiPath = Get-ChildItem "$ScriptDir\src\ZentrycDnsAgent.Installer\bin\$Configuration" -Filter "*.msi" -Recurse | Select-Object -First 1
    if ($msiPath) {
        $outputMsi = "$ScriptDir\ZentrycDnsAgent.msi"
        Copy-Item $msiPath.FullName $outputMsi -Force
        Write-Host "  MSI created: $outputMsi" -ForegroundColor Green

        # Sign if certificate provided
        if ($SignCert -and (Test-Path $SignCert)) {
            Write-Host "  Signing MSI..." -ForegroundColor Yellow
            signtool sign /f $SignCert /tr http://timestamp.digicert.com /td sha256 /fd sha256 $outputMsi
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  MSI signed successfully." -ForegroundColor Green
            } else {
                Write-Host "  MSI signing failed (non-critical)." -ForegroundColor Yellow
            }
        }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Build Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Artifacts:" -ForegroundColor Cyan
Write-Host "  Executable: $PublishDir\ZentrycDnsAgent.exe"
Write-Host "  MSI:        $ScriptDir\ZentrycDnsAgent.msi"
Write-Host ""
Write-Host "Silent install:" -ForegroundColor Cyan
Write-Host '  msiexec /i ZentrycDnsAgent.msi /qn ZENTRYC_HOST=<your-siem-ip> ZENTRYC_PORT=514'
Write-Host ""
