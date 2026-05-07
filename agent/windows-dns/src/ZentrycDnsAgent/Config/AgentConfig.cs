namespace ZentrycDnsAgent.Config;

/// <summary>
/// Strongly-typed configuration for the Zentryc DNS Agent.
/// Bound from appsettings.json and overridable via environment variables.
/// </summary>
public sealed class ZentrycConfig
{
    public const string SectionName = "Zentryc";

    /// <summary>Zentryc SIEM server hostname or IP.</summary>
    public string ServerHost { get; set; } = "10.12.50.77";

    /// <summary>Syslog UDP port on the Zentryc server.</summary>
    public int ServerPort { get; set; } = 514;

    /// <summary>Transport protocol: "udp" or "https".</summary>
    public string Protocol { get; set; } = "udp";

    /// <summary>API key for HTTPS transport (optional for UDP).</summary>
    public string ApiKey { get; set; } = string.Empty;

    /// <summary>Override device name (defaults to hostname).</summary>
    public string DeviceName { get; set; } = string.Empty;

    /// <summary>Override device IP sent in logs (defaults to primary adapter IP).</summary>
    public string DeviceIp { get; set; } = string.Empty;

    /// <summary>Enable TLS for syslog (RFC5425 TLS transport).</summary>
    public bool TlsEnabled { get; set; } = false;
}

public sealed class CollectionConfig
{
    public const string SectionName = "Collection";

    /// <summary>Use ETW real-time session for DNS Server events.</summary>
    public bool EnableEtw { get; set; } = true;

    /// <summary>Fallback: use Windows Event Log (slower, but works without admin ETW rights).</summary>
    public bool EnableEventLog { get; set; } = false;

    /// <summary>DNS query types to capture. Empty = all types.</summary>
    public string[] QueryTypes { get; set; } = Array.Empty<string>();

    /// <summary>Exclude internal reverse-lookup and AD service records.</summary>
    public bool ExcludeInternalZones { get; set; } = false;

    /// <summary>Glob patterns for qnames to exclude (e.g., "*.in-addr.arpa").</summary>
    public string[] ExcludePatterns { get; set; } = Array.Empty<string>();

    /// <summary>Include resolved IP addresses from response events.</summary>
    public bool IncludeResponseData { get; set; } = true;

    /// <summary>Include dynamic DNS update events.</summary>
    public bool IncludeDynamicUpdates { get; set; } = true;

    /// <summary>Include zone transfer events.</summary>
    public bool IncludeZoneTransfers { get; set; } = true;
}

public sealed class BufferConfig
{
    public const string SectionName = "Buffer";

    /// <summary>Maximum disk buffer size in MB before oldest entries are purged.</summary>
    public int MaxSizeMB { get; set; } = 100;

    /// <summary>Maximum age of buffered events in days.</summary>
    public int MaxAgeDays { get; set; } = 7;

    /// <summary>How often to flush buffered events (ms).</summary>
    public int FlushIntervalMs { get; set; } = 1000;

    /// <summary>Maximum events per flush batch.</summary>
    public int BatchSize { get; set; } = 500;

    /// <summary>Path to the SQLite buffer database.</summary>
    public string DatabasePath { get; set; } = @"C:\ProgramData\Zentryc\buffer.db";
}

public sealed class HeartbeatConfig
{
    public const string SectionName = "Heartbeat";

    /// <summary>Enable periodic heartbeat to Zentryc server.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Heartbeat interval in seconds.</summary>
    public int IntervalSeconds { get; set; } = 60;
}
