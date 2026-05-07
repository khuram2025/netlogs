using System.Net;
using System.Threading.Channels;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Options;
using Serilog;
using ZentrycDnsAgent.Config;

namespace ZentrycDnsAgent.Collection;

/// <summary>
/// Real-time ETW consumer for the Microsoft-Windows-DNSServer provider.
/// Captures DNS query/response events and normalizes them into DnsEvent objects.
/// Requires Administrator privileges to create an ETW session.
/// </summary>
public sealed class DnsEtwCollector : IDisposable
{
    private const string SessionName = "ZentrycDnsCapture";
    private const string DnsServerProviderName = "Microsoft-Windows-DNSServer";

    // Microsoft-Windows-DNSServer provider GUID
    private static readonly Guid DnsServerProviderGuid =
        new("EB79061A-A566-4698-9119-3ED2807060E7");

    private readonly CollectionConfig _config;
    private readonly string _deviceName;
    private readonly string _deviceIp;
    private readonly Channel<DnsEvent> _outputChannel;
    private readonly ILogger _logger;
    private readonly HashSet<string> _excludePatterns;
    private readonly HashSet<string> _queryTypeFilter;

    private TraceEventSession? _session;
    private ETWTraceEventSource? _source;
    private long _eventsProcessed;
    private long _eventsDropped;

    public DnsEtwCollector(
        IOptions<CollectionConfig> collectionConfig,
        IOptions<ZentrycConfig> zentrycConfig,
        Channel<DnsEvent> outputChannel)
    {
        _config = collectionConfig.Value;
        _outputChannel = outputChannel;
        _logger = Log.ForContext<DnsEtwCollector>();

        _deviceName = string.IsNullOrEmpty(zentrycConfig.Value.DeviceName)
            ? Environment.MachineName
            : zentrycConfig.Value.DeviceName;

        _deviceIp = string.IsNullOrEmpty(zentrycConfig.Value.DeviceIp)
            ? GetPrimaryIpAddress()
            : zentrycConfig.Value.DeviceIp;

        _excludePatterns = new HashSet<string>(
            _config.ExcludePatterns ?? Array.Empty<string>(),
            StringComparer.OrdinalIgnoreCase);

        _queryTypeFilter = _config.QueryTypes?.Length > 0
            ? new HashSet<string>(_config.QueryTypes, StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>();
    }

    public long EventsProcessed => Interlocked.Read(ref _eventsProcessed);
    public long EventsDropped => Interlocked.Read(ref _eventsDropped);

    /// <summary>
    /// Start the ETW real-time session. Blocks until cancellation.
    /// Must be called on a dedicated thread.
    /// </summary>
    public Task StartAsync(CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                // Kill any orphaned session from a previous crash
                KillOrphanedSession();

                _session = new TraceEventSession(SessionName, TraceEventSessionOptions.Create)
                {
                    StopOnDispose = true
                };

                // Enable DNS Server provider with all keywords (query, response, etc.)
                _session.EnableProvider(
                    DnsServerProviderGuid,
                    TraceEventLevel.Verbose,
                    ulong.MaxValue // All keywords — captures queries, responses, updates, transfers
                );

                _source = _session.Source;

                // Register callback for all DNS events
                _source.Dynamic.All += OnDnsEvent;

                _logger.Information(
                    "ETW session '{SessionName}' started for {Provider} on {DeviceName} ({DeviceIp})",
                    SessionName, DnsServerProviderName, _deviceName, _deviceIp);

                // Register cancellation to stop the session
                ct.Register(() =>
                {
                    _logger.Information("Stopping ETW session...");
                    _session?.Stop();
                });

                // Process() blocks until the session is stopped
                _source.Process();

                _logger.Information("ETW session ended. Processed={Processed}, Dropped={Dropped}",
                    _eventsProcessed, _eventsDropped);
            }
            catch (UnauthorizedAccessException)
            {
                _logger.Error("ETW session requires Administrator privileges. " +
                    "Ensure the service account has 'Manage auditing and security log' rights.");
                throw;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _logger.Error(ex, "ETW session failed unexpectedly");
                throw;
            }
        }, ct);
    }

    private void OnDnsEvent(TraceEvent evt)
    {
        try
        {
            var dnsEvent = evt.ID switch
            {
                (TraceEventID)DnsEventIds.QueryReceived => ParseQueryReceived(evt),
                (TraceEventID)DnsEventIds.ResponseSuccess => ParseResponse(evt, DnsAction.Allow),
                (TraceEventID)DnsEventIds.ResponseFailure => ParseResponseFailure(evt),
                (TraceEventID)DnsEventIds.IgnoredQuery => ParseQueryReceived(evt, DnsAction.Ignore),
                (TraceEventID)DnsEventIds.RecurseQueryOut => ParseRecurseOut(evt),
                (TraceEventID)DnsEventIds.RecurseResponseIn => ParseResponse(evt, DnsAction.Recurse),
                (TraceEventID)DnsEventIds.RecurseQueryTimeout => ParseQueryReceived(evt, DnsAction.Timeout),
                (TraceEventID)DnsEventIds.DynamicUpdateReceived when _config.IncludeDynamicUpdates
                    => ParseDynamicUpdate(evt),
                (TraceEventID)DnsEventIds.ZoneTransferRequest when _config.IncludeZoneTransfers
                    => ParseZoneTransfer(evt),
                _ => null
            };

            if (dnsEvent is null)
                return;

            // Apply filters
            if (ShouldExclude(dnsEvent))
                return;

            // Non-blocking write to channel
            if (!_outputChannel.Writer.TryWrite(dnsEvent))
            {
                Interlocked.Increment(ref _eventsDropped);
            }
            else
            {
                Interlocked.Increment(ref _eventsProcessed);
            }
        }
        catch (Exception ex)
        {
            Interlocked.Increment(ref _eventsDropped);
            _logger.Debug(ex, "Failed to parse ETW event {EventId}", (int)evt.ID);
        }
    }

    private DnsEvent ParseQueryReceived(TraceEvent evt, DnsAction action = DnsAction.Allow)
    {
        var qname = GetPayloadString(evt, "QNAME");
        var qtypeNum = GetPayloadInt(evt, "QTYPE");
        var sourceIp = GetPayloadString(evt, "Source");
        var sourcePort = GetPayloadInt(evt, "Port");
        var tcp = GetPayloadBool(evt, "TCP");

        return new DnsEvent
        {
            Timestamp = evt.TimeStamp.ToUniversalTime(),
            DeviceIp = _deviceIp,
            DeviceName = _deviceName,
            Action = action,
            SrcIp = sourceIp,
            SrcPort = (ushort)sourcePort,
            Transport = tcp ? "TCP" : "UDP",
            QName = NormalizeQName(qname),
            QType = DnsEventIds.QTypeToString(qtypeNum),
            EventType = "dns-query",
            EtwEventId = (int)evt.ID,
            Message = $"DNS query from {sourceIp} for {qname} ({DnsEventIds.QTypeToString(qtypeNum)})"
        };
    }

    private DnsEvent ParseResponse(TraceEvent evt, DnsAction action)
    {
        var qname = GetPayloadString(evt, "QNAME");
        var qtypeNum = GetPayloadInt(evt, "QTYPE");
        var sourceIp = GetPayloadString(evt, "Source");
        var rdata = GetPayloadString(evt, "RDATA");

        return new DnsEvent
        {
            Timestamp = evt.TimeStamp.ToUniversalTime(),
            DeviceIp = _deviceIp,
            DeviceName = _deviceName,
            Action = action,
            SrcIp = sourceIp,
            Transport = GetPayloadBool(evt, "TCP") ? "TCP" : "UDP",
            QName = NormalizeQName(qname),
            QType = DnsEventIds.QTypeToString(qtypeNum),
            ResolvedIp = ExtractFirstIp(rdata),
            EventType = "dns-response",
            EtwEventId = (int)evt.ID,
            Message = $"DNS response for {qname}: {rdata}"
        };
    }

    private DnsEvent ParseResponseFailure(TraceEvent evt)
    {
        var qname = GetPayloadString(evt, "QNAME");
        var rcode = GetPayloadInt(evt, "RCODE");

        var dnsEvent = ParseQueryReceived(evt, DnsEventIds.RCodeToAction(rcode));
        dnsEvent.EventType = "dns-response";
        dnsEvent.Severity = rcode == 3 ? "informational" : "warning";
        dnsEvent.Message = $"DNS response failure for {qname}: RCODE={rcode}";
        return dnsEvent;
    }

    private DnsEvent ParseRecurseOut(TraceEvent evt)
    {
        var qname = GetPayloadString(evt, "QNAME");
        var forwarder = GetPayloadString(evt, "InterfaceIP");

        return new DnsEvent
        {
            Timestamp = evt.TimeStamp.ToUniversalTime(),
            DeviceIp = _deviceIp,
            DeviceName = _deviceName,
            Action = DnsAction.Recurse,
            DstIp = forwarder,
            DstPort = 53,
            Direction = "outbound",
            QName = NormalizeQName(qname),
            QType = DnsEventIds.QTypeToString(GetPayloadInt(evt, "QTYPE")),
            EventType = "dns-recurse",
            EtwEventId = (int)evt.ID,
            Message = $"Recursive query for {qname} to {forwarder}"
        };
    }

    private DnsEvent ParseDynamicUpdate(TraceEvent evt)
    {
        var zoneName = GetPayloadString(evt, "ZoneName");
        var sourceIp = GetPayloadString(evt, "Source");

        return new DnsEvent
        {
            Timestamp = evt.TimeStamp.ToUniversalTime(),
            DeviceIp = _deviceIp,
            DeviceName = _deviceName,
            Action = DnsAction.Update,
            SrcIp = sourceIp,
            QName = zoneName,
            EventType = "dns-update",
            EtwEventId = (int)evt.ID,
            Message = $"Dynamic DNS update for zone {zoneName} from {sourceIp}"
        };
    }

    private DnsEvent ParseZoneTransfer(TraceEvent evt)
    {
        var zoneName = GetPayloadString(evt, "ZoneName");
        var sourceIp = GetPayloadString(evt, "Source");

        return new DnsEvent
        {
            Timestamp = evt.TimeStamp.ToUniversalTime(),
            DeviceIp = _deviceIp,
            DeviceName = _deviceName,
            Action = DnsAction.ZoneTransfer,
            SrcIp = sourceIp,
            QName = zoneName,
            EventType = "dns-zone-transfer",
            Severity = "notice",
            EtwEventId = (int)evt.ID,
            Message = $"Zone transfer request for {zoneName} from {sourceIp}"
        };
    }

    private bool ShouldExclude(DnsEvent evt)
    {
        // Filter by query type
        if (_queryTypeFilter.Count > 0 && !_queryTypeFilter.Contains(evt.QType))
            return true;

        // Filter by exclude patterns
        if (_excludePatterns.Count > 0 && !string.IsNullOrEmpty(evt.QName))
        {
            foreach (var pattern in _excludePatterns)
            {
                if (MatchesGlob(evt.QName, pattern))
                    return true;
            }
        }

        return false;
    }

    private static bool MatchesGlob(string input, string pattern)
    {
        // Simple glob: *.example.com or _ldap._tcp.*
        if (pattern.StartsWith("*."))
            return input.EndsWith(pattern[1..], StringComparison.OrdinalIgnoreCase);

        if (pattern.EndsWith(".*"))
            return input.StartsWith(pattern[..^2], StringComparison.OrdinalIgnoreCase);

        return string.Equals(input, pattern, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeQName(string qname)
    {
        if (string.IsNullOrEmpty(qname)) return string.Empty;
        // Remove trailing dot if present
        return qname.TrimEnd('.');
    }

    private static string ExtractFirstIp(string rdata)
    {
        if (string.IsNullOrEmpty(rdata)) return string.Empty;

        // RDATA may contain multiple answers separated by semicolons or spaces
        var parts = rdata.Split(new[] { ';', ' ', ',' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            if (IPAddress.TryParse(part.Trim(), out _))
                return part.Trim();
        }
        return rdata.Split(';', ' ', ',')[0].Trim();
    }

    private static string GetPayloadString(TraceEvent evt, string name)
    {
        try
        {
            var idx = evt.PayloadIndex(name);
            return idx >= 0 ? evt.PayloadString(idx) : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    private static int GetPayloadInt(TraceEvent evt, string name)
    {
        try
        {
            var idx = evt.PayloadIndex(name);
            if (idx < 0) return 0;
            var val = evt.PayloadValue(idx);
            return val is int i ? i : Convert.ToInt32(val);
        }
        catch
        {
            return 0;
        }
    }

    private static bool GetPayloadBool(TraceEvent evt, string name)
    {
        try
        {
            var idx = evt.PayloadIndex(name);
            if (idx < 0) return false;
            var val = evt.PayloadValue(idx);
            return val is bool b ? b : Convert.ToInt32(val) != 0;
        }
        catch
        {
            return false;
        }
    }

    private static string GetPrimaryIpAddress()
    {
        try
        {
            var host = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in host.AddressList)
            {
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    return ip.ToString();
            }
        }
        catch { }
        return "127.0.0.1";
    }

    private static void KillOrphanedSession()
    {
        try
        {
            // If a previous instance crashed, the ETW session may still exist
            var existing = TraceEventSession.GetActiveSession(SessionName);
            if (existing is not null)
            {
                existing.Stop(true);
                existing.Dispose();
            }
        }
        catch { }
    }

    public void Dispose()
    {
        _outputChannel.Writer.TryComplete();
        _source?.Dispose();
        _session?.Dispose();
    }
}
