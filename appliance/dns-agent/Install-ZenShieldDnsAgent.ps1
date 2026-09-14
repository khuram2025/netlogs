#Requires -RunAsAdministrator
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$PackagePath,
 [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedSha256,
 [Parameter(Mandatory=$true)][string]$ConfigPath
)
$ErrorActionPreference='Stop'
if (-not (Get-Service DNS -ErrorAction SilentlyContinue)) { throw 'Install this service on a Windows DNS server.' }
if ((Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash -ne $ExpectedSha256) { throw 'Agent binary hash does not match the verified release.' }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if ($config.endpoint -notmatch '^https://[^/]+/api/dns/ingest$' -or $config.token.Length -lt 32 -or $config.certificate_sha256 -notmatch '^[a-fA-F0-9]{64}$') { throw 'The source configuration is invalid.' }
$install=Join-Path $env:ProgramFiles 'ZenShield\DnsAgent'
$data=Join-Path $env:ProgramData 'ZenShield\DnsAgent'
New-Item -ItemType Directory -Force -Path $install,$data,(Join-Path $data 'spool'),(Join-Path $data 'runtime') | Out-Null
& icacls.exe $data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
& icacls.exe (Join-Path $data '*') /reset /T /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not protect the agent data directory.' }
$existing=Get-Service ZenShieldDnsAgent -ErrorAction SilentlyContinue
if ($existing) { Stop-Service ZenShieldDnsAgent; $existing.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(35)) }
$target=Join-Path $install 'ZenShield.DnsAgent.exe'
if (Test-Path -LiteralPath $target) { Copy-Item -LiteralPath $target -Destination ($target+'.previous') -Force }
Copy-Item -LiteralPath $PackagePath -Destination $target -Force
$configTarget=Join-Path $data 'config.json'
if ([IO.Path]::GetFullPath($ConfigPath) -ne [IO.Path]::GetFullPath($configTarget)) { Copy-Item -LiteralPath $ConfigPath -Destination $configTarget -Force }
if (-not $existing) { New-Service -Name ZenShieldDnsAgent -BinaryPathName ('"'+$target+'"') -DisplayName 'ZenShield DNS Forwarder' -Description 'Streams Windows DNS ETW events to a verified ZenShield appliance over HTTPS with a persistent disk buffer.' -StartupType Automatic | Out-Null }
& sc.exe config ZenShieldDnsAgent start= delayed-auto | Out-Null
& sc.exe failure ZenShieldDnsAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
& sc.exe failureflag ZenShieldDnsAgent 1 | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\ZenShieldDnsAgent' -Name Environment -PropertyType MultiString -Value @('DOTNET_BUNDLE_EXTRACT_BASE_DIR='+ (Join-Path $data 'runtime')) -Force | Out-Null
Start-Service ZenShieldDnsAgent
(Get-Service ZenShieldDnsAgent).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
Write-Output 'ZenShield DNS Forwarder installed and running. Check status.json and Devices > Windows DNS sources for delivery health.'
