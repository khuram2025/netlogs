using System.Threading.Channels;
using Microsoft.Extensions.Options;
using Serilog;
using ZentrycDnsAgent.Collection;
using ZentrycDnsAgent.Config;
using ZentrycDnsAgent.Transport;

namespace ZentrycDnsAgent;

/// <summary>
/// Main background service that orchestrates the DNS log collection pipeline:
/// ETW/EventLog collector → Channel → SyslogSender → Zentryc SIEM
///
/// Pipeline architecture:
/// [DnsEtwCollector] ──▶ Channel&lt;DnsEvent&gt; ──▶ [SyslogSender] ──▶ UDP/514
///                                                    │
///                                              [DiskBuffer] (overflow/retry)
/// </summary>
public sealed class Worker : BackgroundService
{
    private readonly IServiceProvider _services;
    private readonly CollectionConfig _collectionConfig;
    private readonly Channel<DnsEvent> _eventChannel;
    private readonly ILogger _logger;

    // Metrics
    private readonly System.Timers.Timer _metricsTimer;

    public Worker(
        IServiceProvider services,
        IOptions<CollectionConfig> collectionConfig,
        Channel<DnsEvent> eventChannel)
    {
        _services = services;
        _collectionConfig = collectionConfig.Value;
        _eventChannel = eventChannel;
        _logger = Log.ForContext<Worker>();

        _metricsTimer = new System.Timers.Timer(30_000); // 30s metrics
        _metricsTimer.Elapsed += LogMetrics;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.Information(
            "Zentryc DNS Agent v{Version} starting on {Host}",
            GetVersion(), Environment.MachineName);

        // Initialize disk buffer
        var diskBuffer = _services.GetRequiredService<DiskBuffer>();
        diskBuffer.Initialize();

        // Start metrics reporting
        _metricsTimer.Start();

        // Build task list based on configuration
        var tasks = new List<Task>();

        // Start collector (ETW or Event Log)
        if (_collectionConfig.EnableEtw)
        {
            var etwCollector = _services.GetRequiredService<DnsEtwCollector>();
            tasks.Add(RunWithRestart("ETW Collector", () => etwCollector.StartAsync(stoppingToken), stoppingToken));
        }
        else if (_collectionConfig.EnableEventLog)
        {
            var eventLogCollector = _services.GetRequiredService<DnsEventLogCollector>();
            tasks.Add(RunWithRestart("EventLog Collector",
                () => eventLogCollector.StartAsync(stoppingToken), stoppingToken));
        }
        else
        {
            _logger.Error("No collection method enabled. Set EnableEtw or EnableEventLog to true.");
            return;
        }

        // Start syslog sender
        var sender = _services.GetRequiredService<SyslogSender>();
        tasks.Add(RunWithRestart("Syslog Sender", () => sender.RunAsync(stoppingToken), stoppingToken));

        // Start heartbeat (if enabled)
        var heartbeatService = _services.GetRequiredService<Health.HeartbeatService>();
        tasks.Add(heartbeatService.RunAsync(stoppingToken));

        // Schedule periodic buffer cleanup
        tasks.Add(RunBufferCleanup(diskBuffer, stoppingToken));

        _logger.Information("All pipeline components started");

        try
        {
            // Wait for any task to complete (or fail)
            var completedTask = await Task.WhenAny(tasks);

            if (completedTask.IsFaulted)
            {
                _logger.Error(completedTask.Exception?.InnerException,
                    "Pipeline component failed. Service will restart via recovery policy.");
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            _logger.Information("Service shutdown requested");
        }

        _metricsTimer.Stop();
        _logger.Information("Zentryc DNS Agent stopped");
    }

    /// <summary>
    /// Wraps a task with automatic restart on failure (up to 5 retries with backoff).
    /// </summary>
    private async Task RunWithRestart(string name, Func<Task> taskFactory, CancellationToken ct)
    {
        const int maxRetries = 5;
        var retryDelay = TimeSpan.FromSeconds(5);

        for (int attempt = 1; attempt <= maxRetries && !ct.IsCancellationRequested; attempt++)
        {
            try
            {
                _logger.Debug("Starting {Component} (attempt {Attempt})", name, attempt);
                await taskFactory();
                return; // Clean exit
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "{Component} failed (attempt {Attempt}/{Max}). Restarting in {Delay}s...",
                    name, attempt, maxRetries, retryDelay.TotalSeconds);

                if (attempt < maxRetries)
                    await Task.Delay(retryDelay, ct);

                retryDelay *= 2; // Exponential backoff
            }
        }

        _logger.Error("{Component} exhausted all retry attempts. Giving up.", name);
        throw new InvalidOperationException($"{name} failed after {maxRetries} attempts");
    }

    private async Task RunBufferCleanup(DiskBuffer buffer, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromHours(1), ct);
                buffer.Cleanup();
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Debug(ex, "Buffer cleanup error");
            }
        }
    }

    private void LogMetrics(object? sender, System.Timers.ElapsedEventArgs e)
    {
        try
        {
            var etwCollector = _services.GetService<DnsEtwCollector>();
            var syslogSender = _services.GetService<SyslogSender>();
            var diskBuffer = _services.GetService<DiskBuffer>();

            _logger.Information(
                "Metrics: ETW={EtwProcessed}/{EtwDropped} (proc/drop), " +
                "Sent={Sent}, Buffered={Buffered}, SendErrors={Errors}, " +
                "DiskQueue={DiskQueue}, ServerReachable={Reachable}",
                etwCollector?.EventsProcessed ?? 0,
                etwCollector?.EventsDropped ?? 0,
                syslogSender?.MessagesSent ?? 0,
                syslogSender?.MessagesBuffered ?? 0,
                syslogSender?.SendErrors ?? 0,
                diskBuffer?.Count ?? 0,
                syslogSender?.ServerReachable ?? false);
        }
        catch { }
    }

    private static string GetVersion()
    {
        return typeof(Worker).Assembly.GetName().Version?.ToString() ?? "1.0.0";
    }

    public override void Dispose()
    {
        _metricsTimer.Dispose();
        base.Dispose();
    }
}
