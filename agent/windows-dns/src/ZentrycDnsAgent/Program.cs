using System.Threading.Channels;
using Microsoft.Extensions.Options;
using Serilog;
using ZentrycDnsAgent;
using ZentrycDnsAgent.Collection;
using ZentrycDnsAgent.Config;
using ZentrycDnsAgent.Health;
using ZentrycDnsAgent.Transport;

// Bootstrap Serilog for early startup logging
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File(
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Zentryc", "Logs", "agent-.log"),
        rollingInterval: RollingInterval.Day)
    .CreateBootstrapLogger();

try
{
    Log.Information("Zentryc DNS Agent starting...");

    var builder = Host.CreateDefaultBuilder(args)
        .UseWindowsService(options =>
        {
            options.ServiceName = "ZentrycDnsAgent";
        })
        .UseSerilog((context, services, loggerConfig) =>
        {
            loggerConfig.ReadFrom.Configuration(context.Configuration);
        })
        .ConfigureAppConfiguration((context, config) =>
        {
            // Load from standard locations
            config.SetBasePath(AppContext.BaseDirectory);
            config.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true);

            // Override with ProgramData config (written by installer)
            var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            var overridePath = Path.Combine(programData, "Zentryc", "appsettings.json");
            config.AddJsonFile(overridePath, optional: true, reloadOnChange: true);

            // Environment variables override everything (for containerized/CI testing)
            config.AddEnvironmentVariables("ZENTRYC_");
        })
        .ConfigureServices((context, services) =>
        {
            // Bind configuration sections
            services.Configure<ZentrycConfig>(context.Configuration.GetSection(ZentrycConfig.SectionName));
            services.Configure<CollectionConfig>(context.Configuration.GetSection(CollectionConfig.SectionName));
            services.Configure<BufferConfig>(context.Configuration.GetSection(BufferConfig.SectionName));
            services.Configure<HeartbeatConfig>(context.Configuration.GetSection(HeartbeatConfig.SectionName));

            // Bounded channel: backpressure at 50,000 events
            var channel = Channel.CreateBounded<DnsEvent>(new BoundedChannelOptions(50_000)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = false,
                SingleWriter = false
            });
            services.AddSingleton(channel);

            // Collection
            services.AddSingleton<DnsEtwCollector>();
            services.AddSingleton<DnsEventLogCollector>();

            // Transport
            services.AddSingleton<DiskBuffer>();
            services.AddSingleton<SyslogSender>();

            // Health
            services.AddSingleton<HeartbeatService>();

            // Main worker
            services.AddHostedService<Worker>();
        });

    var host = builder.Build();

    // Validate configuration on startup
    var zentrycConfig = host.Services.GetRequiredService<IOptions<ZentrycConfig>>().Value;
    if (string.IsNullOrEmpty(zentrycConfig.ServerHost) || zentrycConfig.ServerHost == "127.0.0.1")
    {
        Log.Warning("Zentryc server is set to {Host}. Update appsettings.json with your SIEM server address.",
            zentrycConfig.ServerHost);
    }

    Log.Information("Configuration: Server={Host}:{Port}/{Protocol}, ETW={Etw}, EventLog={EvtLog}",
        zentrycConfig.ServerHost,
        zentrycConfig.ServerPort,
        zentrycConfig.Protocol,
        host.Services.GetRequiredService<IOptions<CollectionConfig>>().Value.EnableEtw,
        host.Services.GetRequiredService<IOptions<CollectionConfig>>().Value.EnableEventLog);

    await host.RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Zentryc DNS Agent terminated unexpectedly");
    Environment.ExitCode = 1;
}
finally
{
    Log.CloseAndFlush();
}
