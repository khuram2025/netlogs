using System.Diagnostics.Eventing.Reader;
using System.Threading.Channels;
using Microsoft.Extensions.Options;
using Serilog;
using ZentrycDnsAgent.Config;

namespace ZentrycDnsAgent.Collection;

/// <summary>
/// Fallback DNS event collector using Windows Event Log subscription.
/// Slower than ETW but works without creating a custom ETW session.
/// Reads from "Microsoft-Windows-DNS-Server/Analytical" event log channel.
/// </summary>
public sealed class DnsEventLogCollector : IDisposable
{
    private const string DnsAnalyticalLog = "Microsoft-Windows-DNS-Server/Analytical";
    private const string DnsAuditLog = "Microsoft-Windows-DNS-Server/Audit";

    private readonly CollectionConfig _config;
    private readonly string _deviceName;
    private readonly string _deviceIp;
    private readonly Channel<DnsEvent> _outputChannel;
    private readonly ILogger _logger;

    private EventLogWatcher? _analyticalWatcher;
    private EventLogWatcher? _auditWatcher;
    private long _eventsProcessed;

    public DnsEventLogCollector(
        IOptions<CollectionConfig> collectionConfig,
        IOptions<ZentrycConfig> zentrycConfig,
        Channel<DnsEvent> outputChannel)
    {
        _config = collectionConfig.Value;
        _outputChannel = outputChannel;
        _logger = Log.ForContext<DnsEventLogCollector>();

        _deviceName = string.IsNullOrEmpty(zentrycConfig.Value.DeviceName)
            ? Environment.MachineName
            : zentrycConfig.Value.DeviceName;

        _deviceIp = string.IsNullOrEmpty(zentrycConfig.Value.DeviceIp)
            ? GetPrimaryIp()
            : zentrycConfig.Value.DeviceIp;
    }

    public long EventsProcessed => Interlocked.Read(ref _eventsProcessed);

    /// <summary>
    /// Start watching DNS event logs. The Analytical log must be enabled first:
    /// wevtutil sl "Microsoft-Windows-DNS-Server/Analytical" /e:true
    /// </summary>
    public Task StartAsync(CancellationToken ct)
    {
        return Task.Run(() =>
        {
            try
            {
                EnableAnalyticalLog();

                // Query for DNS query events (Event IDs 256-282)
                var analyticalQuery = new EventLogQuery(
                    DnsAnalyticalLog,
                    PathType.LogName,
                    "*[System[(EventID >= 256 and EventID <= 282)]]");

                _analyticalWatcher = new EventLogWatcher(analyticalQuery);
                _analyticalWatcher.EventRecordWritten += OnEventRecordWritten;
                _analyticalWatcher.Enabled = true;

                _logger.Information("DNS Event Log watcher started on {Channel}", DnsAnalyticalLog);

                // Block until cancelled
                ct.WaitHandle.WaitOne();

                _analyticalWatcher.Enabled = false;
                _logger.Information("DNS Event Log watcher stopped. Events processed: {Count}",
                    _eventsProcessed);
            }
            catch (EventLogNotFoundException)
            {
                _logger.Error(
                    "DNS Server Analytical log not found. Ensure the DNS Server role is installed " +
                    "and the Analytical log is enabled: " +
                    "wevtutil sl \"Microsoft-Windows-DNS-Server/Analytical\" /e:true");
                throw;
            }
            catch (Exception ex) when (!ct.IsCancellationRequested)
            {
                _logger.Error(ex, "DNS Event Log watcher failed");
                throw;
            }
        }, ct);
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs e)
    {
        if (e.EventRecord is null) return;

        try
        {
            var record = e.EventRecord;
            var eventId = record.Id;

            var dnsEvent = new DnsEvent
            {
                Timestamp = (record.TimeCreated ?? DateTime.UtcNow).ToUniversalTime(),
                DeviceIp = _deviceIp,
                DeviceName = _deviceName,
                EtwEventId = eventId,
            };

            // Extract properties from event record
            var props = record.Properties;
            if (props.Count == 0) return;

            switch (eventId)
            {
                case DnsEventIds.QueryReceived:
                case DnsEventIds.IgnoredQuery:
                    dnsEvent.EventType = "dns-query";
                    dnsEvent.Action = eventId == DnsEventIds.IgnoredQuery
                        ? DnsAction.Ignore : DnsAction.Allow;
                    ExtractQueryFields(props, dnsEvent);
                    break;

                case DnsEventIds.ResponseSuccess:
                    dnsEvent.EventType = "dns-response";
                    dnsEvent.Action = DnsAction.Allow;
                    ExtractQueryFields(props, dnsEvent);
                    ExtractResponseFields(props, dnsEvent);
                    break;

                case DnsEventIds.ResponseFailure:
                    dnsEvent.EventType = "dns-response";
                    ExtractQueryFields(props, dnsEvent);
                    var rcode = SafeGetInt(props, 4);
                    dnsEvent.Action = DnsEventIds.RCodeToAction(rcode);
                    break;

                case DnsEventIds.RecurseQueryOut:
                    dnsEvent.EventType = "dns-recurse";
                    dnsEvent.Action = DnsAction.Recurse;
                    dnsEvent.Direction = "outbound";
                    ExtractQueryFields(props, dnsEvent);
                    break;

                case DnsEventIds.RecurseQueryTimeout:
                    dnsEvent.EventType = "dns-recurse";
                    dnsEvent.Action = DnsAction.Timeout;
                    ExtractQueryFields(props, dnsEvent);
                    break;

                default:
                    return; // Skip unhandled events
            }

            dnsEvent.Message = record.FormatDescription() ?? $"DNS event {eventId}";

            _outputChannel.Writer.TryWrite(dnsEvent);
            Interlocked.Increment(ref _eventsProcessed);
        }
        catch (Exception ex)
        {
            _logger.Debug(ex, "Failed to parse event log record {EventId}", e.EventRecord.Id);
        }
    }

    private static void ExtractQueryFields(IList<EventProperty> props, DnsEvent evt)
    {
        // Standard DNS analytical event layout:
        // [0]=QNAME, [1]=QTYPE, [2]=Source, [3]=Port, [4]=protocol/rcode
        if (props.Count > 0) evt.QName = SafeGetString(props, 0).TrimEnd('.');
        if (props.Count > 1) evt.QType = DnsEventIds.QTypeToString(SafeGetInt(props, 1));
        if (props.Count > 2) evt.SrcIp = SafeGetString(props, 2);
        if (props.Count > 3) evt.SrcPort = (ushort)SafeGetInt(props, 3);
    }

    private static void ExtractResponseFields(IList<EventProperty> props, DnsEvent evt)
    {
        // Response events may have RDATA at index 5+
        if (props.Count > 5)
        {
            var rdata = SafeGetString(props, 5);
            if (!string.IsNullOrEmpty(rdata) && System.Net.IPAddress.TryParse(rdata, out _))
                evt.ResolvedIp = rdata;
        }
    }

    private static string SafeGetString(IList<EventProperty> props, int index)
    {
        if (index >= props.Count) return string.Empty;
        return props[index].Value?.ToString() ?? string.Empty;
    }

    private static int SafeGetInt(IList<EventProperty> props, int index)
    {
        if (index >= props.Count) return 0;
        try { return Convert.ToInt32(props[index].Value); }
        catch { return 0; }
    }

    private void EnableAnalyticalLog()
    {
        try
        {
            // Attempt to enable the analytical log if not already enabled
            using var session = new EventLogSession();
            var config = new EventLogConfiguration(DnsAnalyticalLog, session);
            if (!config.IsEnabled)
            {
                config.IsEnabled = true;
                config.SaveChanges();
                _logger.Information("Enabled DNS Server Analytical log");
            }
        }
        catch (Exception ex)
        {
            _logger.Warning(ex, "Could not auto-enable DNS Analytical log. " +
                "Run manually: wevtutil sl \"Microsoft-Windows-DNS-Server/Analytical\" /e:true");
        }
    }

    private static string GetPrimaryIp()
    {
        try
        {
            var host = System.Net.Dns.GetHostEntry(System.Net.Dns.GetHostName());
            foreach (var ip in host.AddressList)
                if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    return ip.ToString();
        }
        catch { }
        return "127.0.0.1";
    }

    public void Dispose()
    {
        _analyticalWatcher?.Dispose();
        _auditWatcher?.Dispose();
    }
}
