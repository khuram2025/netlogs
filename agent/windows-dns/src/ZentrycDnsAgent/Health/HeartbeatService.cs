using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Serilog;
using ZentrycDnsAgent.Collection;
using ZentrycDnsAgent.Config;
using ZentrycDnsAgent.Transport;

namespace ZentrycDnsAgent.Health;

/// <summary>
/// Sends periodic heartbeat messages to the Zentryc server via syslog.
/// The heartbeat includes agent version, uptime, and event metrics.
/// Zentryc can use these to track agent health and detect offline agents.
/// </summary>
public sealed class HeartbeatService
{
    private readonly HeartbeatConfig _config;
    private readonly ZentrycConfig _zentrycConfig;
    private readonly ILogger _logger;
    private readonly DnsEtwCollector? _etwCollector;
    private readonly SyslogSender? _syslogSender;
    private readonly DiskBuffer? _diskBuffer;
    private readonly DateTime _startTime = DateTime.UtcNow;

    public HeartbeatService(
        IOptions<HeartbeatConfig> config,
        IOptions<ZentrycConfig> zentrycConfig,
        IServiceProvider services)
    {
        _config = config.Value;
        _zentrycConfig = zentrycConfig.Value;
        _logger = Log.ForContext<HeartbeatService>();
        _etwCollector = services.GetService<DnsEtwCollector>();
        _syslogSender = services.GetService<SyslogSender>();
        _diskBuffer = services.GetService<DiskBuffer>();
    }

    public async Task RunAsync(CancellationToken ct)
    {
        if (!_config.Enabled)
        {
            _logger.Debug("Heartbeat disabled");
            return;
        }

        _logger.Information("Heartbeat service started (interval: {Interval}s)", _config.IntervalSeconds);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(_config.IntervalSeconds), ct);
                await SendHeartbeatAsync(ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Heartbeat send failed");
            }
        }
    }

    private async Task SendHeartbeatAsync(CancellationToken ct)
    {
        var uptime = DateTime.UtcNow - _startTime;
        var deviceName = string.IsNullOrEmpty(_zentrycConfig.DeviceName)
            ? Environment.MachineName
            : _zentrycConfig.DeviceName;

        var heartbeat = new
        {
            type = "agent-heartbeat",
            agent = "zentryc-dns-agent",
            version = typeof(HeartbeatService).Assembly.GetName().Version?.ToString() ?? "1.0.0",
            hostname = Environment.MachineName,
            os_version = Environment.OSVersion.ToString(),
            uptime_seconds = (long)uptime.TotalSeconds,
            events_processed = _etwCollector?.EventsProcessed ?? 0,
            events_dropped = _etwCollector?.EventsDropped ?? 0,
            messages_sent = _syslogSender?.MessagesSent ?? 0,
            buffer_count = _diskBuffer?.Count ?? 0,
            server_reachable = _syslogSender?.ServerReachable ?? false,
            timestamp = DateTime.UtcNow.ToString("o")
        };

        // Send as syslog structured data
        var message = $"<14>1 {DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss.fffZ} " +
            $"{deviceName} ZentrycDNS - agent-heartbeat " +
            $"[heartbeat@zentryc " +
            $"version=\"{heartbeat.version}\" " +
            $"hostname=\"{heartbeat.hostname}\" " +
            $"uptime=\"{heartbeat.uptime_seconds}\" " +
            $"events_processed=\"{heartbeat.events_processed}\" " +
            $"events_dropped=\"{heartbeat.events_dropped}\" " +
            $"messages_sent=\"{heartbeat.messages_sent}\" " +
            $"buffer_count=\"{heartbeat.buffer_count}\" " +
            $"server_reachable=\"{heartbeat.server_reachable}\"] " +
            $"Agent heartbeat: up {uptime.Days}d {uptime.Hours}h, " +
            $"{heartbeat.events_processed} events processed";

        try
        {
            using var udp = new UdpClient();
            var bytes = Encoding.UTF8.GetBytes(message);
            await udp.SendAsync(
                bytes, bytes.Length,
                _zentrycConfig.ServerHost,
                _zentrycConfig.ServerPort);

            _logger.Debug("Heartbeat sent: uptime={Uptime}, events={Events}",
                $"{uptime.Days}d {uptime.Hours}h", heartbeat.events_processed);
        }
        catch (SocketException ex)
        {
            _logger.Debug("Heartbeat send failed: {Error}", ex.SocketErrorCode);
        }
    }
}
