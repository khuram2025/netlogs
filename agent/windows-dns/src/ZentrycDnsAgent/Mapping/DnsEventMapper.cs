using System.Text;
using ZentrycDnsAgent.Collection;

namespace ZentrycDnsAgent.Mapping;

/// <summary>
/// Maps normalized DnsEvent objects to RFC5424 syslog messages with
/// Zentryc-specific structured data for the WindowsDNSParser on the server.
/// </summary>
public static class DnsEventMapper
{
    // Zentryc structured data enterprise number (private use)
    private const string StructuredDataId = "dns@zentryc";
    private const string AppName = "ZentrycDNS";
    private const int MaxMessageLength = 8192; // UDP safe limit

    /// <summary>
    /// Format a DnsEvent as an RFC5424 syslog message.
    ///
    /// Format:
    /// &lt;PRI&gt;1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID params...] MSG
    ///
    /// Example:
    /// &lt;14&gt;1 2026-03-31T10:15:30.123Z WIN-DNS01 ZentrycDNS - dns-query
    ///   [dns@zentryc qname="mail.example.com" qtype="A" src_ip="192.168.1.50"
    ///    action="allow"] DNS query from 192.168.1.50 for mail.example.com (A)
    /// </summary>
    public static string ToSyslogMessage(DnsEvent evt)
    {
        var sb = new StringBuilder(512);

        // PRI = facility * 8 + severity
        int pri = evt.SyslogFacility * 8 + evt.SyslogSeverity;
        sb.Append($"<{pri}>");

        // VERSION
        sb.Append("1 ");

        // TIMESTAMP (RFC5424 format)
        sb.Append(evt.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
        sb.Append(' ');

        // HOSTNAME
        sb.Append(SanitizeSyslogField(evt.DeviceName));
        sb.Append(' ');

        // APP-NAME
        sb.Append(AppName);
        sb.Append(' ');

        // PROCID (nil)
        sb.Append("- ");

        // MSGID (event type)
        sb.Append(SanitizeSyslogField(evt.EventType));
        sb.Append(' ');

        // STRUCTURED-DATA
        sb.Append('[');
        sb.Append(StructuredDataId);
        AppendParam(sb, "vendor", evt.Vendor);
        AppendParam(sb, "device_ip", evt.DeviceIp);
        AppendParam(sb, "device_name", evt.DeviceName);
        AppendParam(sb, "action", ActionToString(evt.Action));
        AppendParam(sb, "src_ip", evt.SrcIp);
        AppendParam(sb, "dst_ip", evt.DstIp);
        AppendParam(sb, "src_port", evt.SrcPort.ToString());
        AppendParam(sb, "dst_port", evt.DstPort.ToString());
        AppendParam(sb, "transport", evt.Transport);
        AppendParam(sb, "src_user", evt.SrcUser);
        AppendParam(sb, "qname", evt.QName);
        AppendParam(sb, "qtype", evt.QType);
        AppendParam(sb, "qclass", evt.QClass);
        AppendParam(sb, "resolved_ip", evt.ResolvedIp);
        AppendParam(sb, "category", evt.Category);
        AppendParam(sb, "severity", evt.Severity);
        AppendParam(sb, "direction", evt.Direction);
        AppendParam(sb, "event_type", evt.EventType);
        AppendParam(sb, "etw_event_id", evt.EtwEventId.ToString());
        sb.Append(']');

        // MSG
        sb.Append(' ');
        sb.Append(evt.Message);

        // Truncate if over UDP safe limit
        if (sb.Length > MaxMessageLength)
            sb.Length = MaxMessageLength;

        return sb.ToString();
    }

    /// <summary>
    /// Format a DnsEvent as a compact JSON message (for HTTPS transport).
    /// </summary>
    public static string ToJsonMessage(DnsEvent evt)
    {
        return System.Text.Json.JsonSerializer.Serialize(new
        {
            timestamp = evt.Timestamp.ToString("o"),
            vendor = evt.Vendor,
            device_ip = evt.DeviceIp,
            device_name = evt.DeviceName,
            action = ActionToString(evt.Action),
            src_ip = evt.SrcIp,
            dst_ip = evt.DstIp,
            src_port = evt.SrcPort,
            dst_port = evt.DstPort,
            transport = evt.Transport,
            src_user = evt.SrcUser,
            qname = evt.QName,
            qtype = evt.QType,
            qclass = evt.QClass,
            resolved_ip = evt.ResolvedIp,
            category = evt.Category,
            severity = evt.Severity,
            direction = evt.Direction,
            event_type = evt.EventType,
            msg = evt.Message
        });
    }

    public static string ActionToString(DnsAction action) => action switch
    {
        DnsAction.Allow => "allow",
        DnsAction.Deny => "deny",
        DnsAction.Drop => "drop",
        DnsAction.NxDomain => "nxdomain",
        DnsAction.ServFail => "servfail",
        DnsAction.Timeout => "timeout",
        DnsAction.Refused => "refused",
        DnsAction.Ignore => "ignore",
        DnsAction.Recurse => "recurse",
        DnsAction.Update => "update",
        DnsAction.ZoneTransfer => "zone-transfer",
        _ => "unknown"
    };

    private static void AppendParam(StringBuilder sb, string name, string value)
    {
        if (string.IsNullOrEmpty(value) || value == "0")
            return;

        sb.Append(' ');
        sb.Append(name);
        sb.Append("=\"");
        // Escape per RFC5424: \, ", ]
        foreach (char c in value)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '"': sb.Append("\\\""); break;
                case ']': sb.Append("\\]"); break;
                default: sb.Append(c); break;
            }
        }
        sb.Append('"');
    }

    private static string SanitizeSyslogField(string value)
    {
        if (string.IsNullOrEmpty(value)) return "-";
        // RFC5424: printable US-ASCII, no spaces
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
            if (c >= 33 && c <= 126)
                sb.Append(c);
            else
                sb.Append('_');
        }
        return sb.Length > 0 ? sb.ToString() : "-";
    }
}
