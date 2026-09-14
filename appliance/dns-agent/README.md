# ZenShield Windows DNS Forwarder

The forwarder collects native Windows DNS Server ETW query, response and recursion events and sends batches to ZenShield over HTTPS. It runs as the `ZenShieldDnsAgent` Windows service. It does not change DNS zones, forwarding rules, client DNS settings or enable DNS debug-file logging.

## Install

Use an elevated PowerShell session on Windows Server 2019 or later with the DNS Server role. Windows Server 2025 is the initial verified platform. No separate .NET runtime is needed; the distribution includes the runtime.

1. In ZenShield, open **Devices → Add Windows DNS source**. Enter the actual server IP address and name, then enroll it. Save the source ID and one-time token privately. Enrollment is limited to administrators.
2. Download the agent package and its SHA-256 manifest from your trusted ZenShield appliance. Extract them into a staging directory. Do not use a package with a mismatching hash.
3. Obtain the appliance certificate’s SHA-256 fingerprint through your authenticated administrative channel. Set the HTTPS endpoint to an address reachable from the DNS server. Certificate pinning authenticates that exact certificate, including its validity dates; an appliance certificate replacement requires updating this pin.
4. Create `config.json` in a directory accessible only to Administrators and SYSTEM:

```json
{
  "endpoint": "https://APPLIANCE-IP/api/dns/ingest",
  "source_id": "SOURCE-UUID-FROM-ENROLLMENT",
  "token": "ONE-TIME-SOURCE-TOKEN",
  "certificate_sha256": "64-CHARACTER-CERTIFICATE-SHA256",
  "spool_limit_bytes": 1073741824
}
```

5. Run the installer using the executable hash listed in `SHA256SUMS.txt`:

```powershell
.\Install-ZenShieldDnsAgent.ps1 `
  -PackagePath .\ZenShield.DnsAgent.exe `
  -ExpectedSha256 'SHA256-FROM-TRUSTED-MANIFEST' `
  -ConfigPath .\config.json
```

The installer verifies the executable hash, protects the configuration and disk buffer, installs the service, enables automatic startup and restart recovery, then starts collection. No domain administrator password is stored in the agent. The service runs as LocalSystem to create the ETW session; its network credential grants DNS intake for one enrolled source only, not UI or administrative access.

Delete the staging copy of `config.json` after confirming successful installation. The active protected configuration is `%ProgramData%\ZenShield\DnsAgent\config.json`.

## Check operation

```powershell
Get-Service ZenShieldDnsAgent
Get-Content "$env:ProgramData\ZenShield\DnsAgent\status.json"
Get-Process ZenShield.DnsAgent | Select-Object CPU,WorkingSet64
Resolve-DnsName -Server YOUR-DNS-SERVER-IP -Name YOUR-EXISTING-DNS-NAME
```

Open **Devices → Windows DNS sources**. Confirm the source is connected, accepted event count increases and **Last DNS log received** advances. The separate **Last agent contact** field includes 30-second heartbeats, which never inflate DNS event counts or update the last-log timestamp.

Open **URL & DNS → DNS traffic**. Filter by source server, client/resolver address, domain, record type, response code, event type, transport, answer IP, action and time range. Domain matching supports contains, exact and domain/subdomains. The details drawer shows event time, receipt time, transaction ID and original event fields. CSV exports contain the current page and current filters, up to 500 rows.

Windows event 256 represents an incoming query. Events 257 and 258 represent responses, 259 ignored queries, and 260–262 recursion. A query and its response are separate events, not duplicate log entries. NXDOMAIN means a name does not exist; it is not automatically malicious. Answer IP extraction covers A and AAAA records present in the bounded packet data.

## Reliability and sizing

- The collector uses a 32 MiB ETW buffer and a bounded 50,000-event memory queue. Batches contain up to 250 events, with approximately 200 ms coalescing before disk persistence. A separate thread delivers persisted batches.
- The default persistent buffer is 1 GiB. Connection failures retain queued batches and retry with exponential backoff up to about 60 seconds. Backlog survives service restarts. Acknowledgements are sent only after ClickHouse commits the batch; repeated batch IDs are idempotent. Event IDs also deduplicate ambiguous database commits when querying before background merges complete.
- ETW is a best-effort source. A process crash or power loss can lose events still in ETW/memory before persistence. When the configured buffer is full, new events are counted as dropped; existing queued batches remain. Watch `dropped`, `etw_lost`, `parse_errors` and `spool_bytes`. Counters are per service process.
- The intake accepts batches up to 500 events/2 MiB and 600 requests per minute per source. These are protective limits, not a throughput rating. The intake window is 30 days, with at most five minutes of future clock skew. Keep Windows and appliance clocks synchronized.
- Search time ranges are capped at 31 days per request. Queries use parameterized filters, partition pruning, bounded memory (256 MiB), two query threads and a 10-second execution limit. Pagination stops at 10,000 results; narrow filters to continue investigating. Distinct client/domain statistics are approximate.
- Retention is set when an event is ingested. Changing the device’s retention affects future events; it does not retroactively rewrite existing expiry times. A zero-day retention setting retains new events indefinitely and requires storage monitoring.
- Monitor actual DNS throughput and service resource use before expanding deployment. This release’s acceptance tests do not certify unlimited QPS or every Windows Server version.

## Maintenance and troubleshooting

```powershell
Restart-Service ZenShieldDnsAgent
Stop-Service ZenShieldDnsAgent
Start-Service ZenShieldDnsAgent
```

`status.json` reports the latest delivery error and successful send time. HTTP 401 indicates a wrong/rotated token; 403 indicates a disabled/blocked source; 429 indicates intake throttling. Certificate or network errors leave batches on disk. An invalid batch (422), invalid file, or event older than the intake window requires administrator inspection; do not delete a buffer without reviewing its contents. Source health becomes degraded when capture drops/errors are reported or its backlog exceeds 5 MiB.

To rotate a source credential, use the administrator-only `POST /api/dns/sources/{source_id}/rotate` API with the UI’s authenticated CSRF protection, update the protected agent configuration and restart the service. Old credentials are invalid immediately. Do not put tokens in URLs, command arguments, scripts, logs or tickets.

To update the agent, stop its service and rerun the installer with the verified new executable and current configuration. The previous executable is retained as `.previous`. Existing disk buffers remain in place. To uninstall, stop the service and run `sc.exe delete ZenShieldDnsAgent`; preserve the protected data directory until its queued logs and configuration are no longer needed.

For routed or bridged installations, permit outbound TCP 443 from the DNS server to the selected appliance address. The agent opens no listening port. If using DHCP, reserve the appliance collection address or use a stable DNS name. A source token authenticates the source identity; its configured IP is an inventory identifier, so routed/NAT delivery is supported.

## Build and supply chain

The agent is built from the source alongside this guide using .NET 10 and Microsoft’s MIT-licensed `Microsoft.Diagnostics.Tracing.TraceEvent` package. NuGet versions are locked in `packages.lock.json`. The executable is not Authenticode-signed; distribution integrity relies on the trusted appliance channel and the published SHA-256 manifest. Do not represent it as a Microsoft-signed or NXLog binary.

```powershell
dotnet restore .\ZenShield.DnsAgent.csproj --locked-mode
dotnet publish .\ZenShield.DnsAgent.csproj -c Release --no-restore -o .\publish
```

References: [Microsoft DNS logging and diagnostics](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics), [Microsoft TraceEvent](https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent/3.2.6), [NXLog Windows DNS collection comparison](https://docs.nxlog.co/integrations/dns/dns-monitoring-windows.html).
