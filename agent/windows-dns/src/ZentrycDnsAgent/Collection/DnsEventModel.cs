namespace ZentrycDnsAgent.Collection;

/// <summary>
/// Normalized DNS event extracted from Windows ETW or Event Log sources.
/// Maps directly to Zentryc dns_logs ClickHouse schema.
/// </summary>
public sealed class DnsEvent
{
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    // Source identification
    public string Vendor { get; set; } = "windows-dns";
    public string DeviceIp { get; set; } = string.Empty;
    public string DeviceName { get; set; } = string.Empty;

    // Action
    public DnsAction Action { get; set; } = DnsAction.Allow;

    // Network 5-tuple
    public string SrcIp { get; set; } = string.Empty;
    public string DstIp { get; set; } = string.Empty;
    public ushort SrcPort { get; set; }
    public ushort DstPort { get; set; } = 53;
    public string Transport { get; set; } = "UDP";

    // Identity
    public string SrcUser { get; set; } = string.Empty;

    // DNS fields
    public string QName { get; set; } = string.Empty;
    public string QType { get; set; } = string.Empty;
    public string QClass { get; set; } = "IN";
    public string ResolvedIp { get; set; } = string.Empty;

    // Classification
    public string Category { get; set; } = string.Empty;
    public string Severity { get; set; } = "informational";
    public string Direction { get; set; } = "inbound";

    // Event metadata
    public string EventType { get; set; } = "dns-query";
    public string Message { get; set; } = string.Empty;

    // Raw ETW event ID for debugging
    public int EtwEventId { get; set; }

    /// <summary>
    /// Compute syslog severity from DNS action.
    /// RFC5424: 0=Emergency ... 6=Informational, 7=Debug
    /// </summary>
    public int SyslogSeverity => Action switch
    {
        DnsAction.Deny => 4,      // Warning
        DnsAction.Drop => 4,      // Warning
        DnsAction.NxDomain => 6,  // Informational
        DnsAction.ServFail => 3,  // Error
        DnsAction.Timeout => 3,   // Error
        DnsAction.Refused => 4,   // Warning
        _ => 6                    // Informational
    };

    /// <summary>Syslog facility 1 = user-level messages.</summary>
    public int SyslogFacility => 1;
}

public enum DnsAction
{
    Allow,
    Deny,
    Drop,
    NxDomain,
    ServFail,
    Timeout,
    Refused,
    Ignore,
    Recurse,
    Update,
    ZoneTransfer
}

/// <summary>
/// Maps Windows DNS Server ETW event IDs to human-readable names and actions.
/// </summary>
public static class DnsEventIds
{
    // Analytical channel event IDs (Windows Server 2012+)
    public const int QueryReceived = 256;
    public const int ResponseSuccess = 257;
    public const int ResponseFailure = 258;
    public const int IgnoredQuery = 259;
    public const int RecurseQueryOut = 260;
    public const int RecurseResponseIn = 261;
    public const int RecurseQueryTimeout = 262;
    public const int DynamicUpdateReceived = 270;
    public const int DynamicUpdateCompleted = 271;
    public const int DynamicUpdateRejected = 272;
    public const int ZoneTransferRequest = 280;
    public const int ZoneTransferComplete = 281;
    public const int NotifyReceived = 282;

    // RCODEs
    public static DnsAction RCodeToAction(int rcode) => rcode switch
    {
        0 => DnsAction.Allow,     // NOERROR
        2 => DnsAction.ServFail,  // SERVFAIL
        3 => DnsAction.NxDomain,  // NXDOMAIN
        5 => DnsAction.Refused,   // REFUSED
        _ => DnsAction.Allow
    };

    // QTYPE numeric to string
    public static string QTypeToString(int qtype) => qtype switch
    {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        43 => "DS",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        52 => "TLSA",
        65 => "HTTPS",
        255 => "ANY",
        _ => $"TYPE{qtype}"
    };
}
