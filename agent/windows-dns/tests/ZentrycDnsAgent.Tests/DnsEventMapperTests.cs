using Xunit;
using ZentrycDnsAgent.Collection;
using ZentrycDnsAgent.Mapping;

namespace ZentrycDnsAgent.Tests;

public class DnsEventMapperTests
{
    [Fact]
    public void ToSyslogMessage_BasicQuery_ProducesValidRfc5424()
    {
        var evt = new DnsEvent
        {
            Timestamp = new DateTime(2026, 3, 31, 10, 15, 30, 123, DateTimeKind.Utc),
            DeviceName = "WIN-DNS01",
            DeviceIp = "192.168.1.10",
            Action = DnsAction.Allow,
            SrcIp = "192.168.1.50",
            SrcPort = 54321,
            Transport = "UDP",
            QName = "mail.example.com",
            QType = "A",
            EventType = "dns-query",
            Message = "DNS query from 192.168.1.50 for mail.example.com (A)"
        };

        var result = DnsEventMapper.ToSyslogMessage(evt);

        // Check RFC5424 PRI
        Assert.StartsWith("<14>1 ", result); // facility=1 * 8 + severity=6 = 14

        // Check timestamp
        Assert.Contains("2026-03-31T10:15:30.123Z", result);

        // Check hostname and app name
        Assert.Contains("WIN-DNS01 ZentrycDNS", result);

        // Check structured data
        Assert.Contains("[dns@zentryc", result);
        Assert.Contains("qname=\"mail.example.com\"", result);
        Assert.Contains("qtype=\"A\"", result);
        Assert.Contains("src_ip=\"192.168.1.50\"", result);
        Assert.Contains("action=\"allow\"", result);
        Assert.Contains("src_port=\"54321\"", result);
        Assert.Contains("transport=\"UDP\"", result);

        // Check message at end
        Assert.Contains("DNS query from 192.168.1.50 for mail.example.com (A)", result);
    }

    [Fact]
    public void ToSyslogMessage_NxDomainResponse_HasCorrectSeverity()
    {
        var evt = new DnsEvent
        {
            Timestamp = DateTime.UtcNow,
            DeviceName = "DNS01",
            Action = DnsAction.NxDomain,
            QName = "nonexistent.example.com",
            QType = "A",
            EventType = "dns-response"
        };

        var result = DnsEventMapper.ToSyslogMessage(evt);

        // NxDomain = severity 6 (informational), facility 1 → PRI = 14
        Assert.StartsWith("<14>1 ", result);
        Assert.Contains("action=\"nxdomain\"", result);
    }

    [Fact]
    public void ToSyslogMessage_ServFail_HasWarningSeverity()
    {
        var evt = new DnsEvent
        {
            Timestamp = DateTime.UtcNow,
            DeviceName = "DNS01",
            Action = DnsAction.ServFail,
            QName = "broken.example.com",
            QType = "A",
            EventType = "dns-response"
        };

        var result = DnsEventMapper.ToSyslogMessage(evt);

        // ServFail = severity 3 (error), facility 1 → PRI = 11
        Assert.StartsWith("<11>1 ", result);
    }

    [Fact]
    public void ToSyslogMessage_EmptyFields_AreOmitted()
    {
        var evt = new DnsEvent
        {
            Timestamp = DateTime.UtcNow,
            DeviceName = "DNS01",
            QName = "test.com",
            QType = "A",
            EventType = "dns-query"
        };

        var result = DnsEventMapper.ToSyslogMessage(evt);

        // Empty src_user should not appear
        Assert.DoesNotContain("src_user=", result);
        // Empty resolved_ip should not appear
        Assert.DoesNotContain("resolved_ip=", result);
        // Port 0 should not appear
        Assert.DoesNotContain("src_port=\"0\"", result);
    }

    [Fact]
    public void ToSyslogMessage_SpecialCharacters_AreEscaped()
    {
        var evt = new DnsEvent
        {
            Timestamp = DateTime.UtcNow,
            DeviceName = "DNS01",
            QName = "test\"evil].com",
            QType = "A",
            EventType = "dns-query"
        };

        var result = DnsEventMapper.ToSyslogMessage(evt);

        // RFC5424 escaping: " → \", ] → \]
        Assert.Contains("qname=\"test\\\"evil\\].com\"", result);
    }

    [Fact]
    public void ToSyslogMessage_WithResolvedIp_IncludesIt()
    {
        var evt = new DnsEvent
        {
            Timestamp = DateTime.UtcNow,
            DeviceName = "DNS01",
            Action = DnsAction.Allow,
            QName = "www.example.com",
            QType = "A",
            ResolvedIp = "93.184.216.34",
            EventType = "dns-response"
        };

        var result = DnsEventMapper.ToSyslogMessage(evt);

        Assert.Contains("resolved_ip=\"93.184.216.34\"", result);
    }

    [Theory]
    [InlineData(DnsAction.Allow, "allow")]
    [InlineData(DnsAction.Deny, "deny")]
    [InlineData(DnsAction.NxDomain, "nxdomain")]
    [InlineData(DnsAction.ServFail, "servfail")]
    [InlineData(DnsAction.Timeout, "timeout")]
    [InlineData(DnsAction.Refused, "refused")]
    [InlineData(DnsAction.Recurse, "recurse")]
    [InlineData(DnsAction.Update, "update")]
    [InlineData(DnsAction.ZoneTransfer, "zone-transfer")]
    public void ActionToString_AllActions_MapCorrectly(DnsAction action, string expected)
    {
        Assert.Equal(expected, DnsEventMapper.ActionToString(action));
    }

    [Fact]
    public void ToJsonMessage_ProducesValidJson()
    {
        var evt = new DnsEvent
        {
            Timestamp = new DateTime(2026, 3, 31, 10, 0, 0, DateTimeKind.Utc),
            DeviceName = "DNS01",
            DeviceIp = "10.0.0.1",
            QName = "example.com",
            QType = "A",
            Action = DnsAction.Allow
        };

        var json = DnsEventMapper.ToJsonMessage(evt);

        Assert.Contains("\"qname\":\"example.com\"", json);
        Assert.Contains("\"action\":\"allow\"", json);
        Assert.Contains("\"vendor\":\"windows-dns\"", json);

        // Should be valid JSON
        var doc = System.Text.Json.JsonDocument.Parse(json);
        Assert.NotNull(doc);
    }
}

public class DnsEventModelTests
{
    [Theory]
    [InlineData(1, "A")]
    [InlineData(5, "CNAME")]
    [InlineData(15, "MX")]
    [InlineData(28, "AAAA")]
    [InlineData(33, "SRV")]
    [InlineData(255, "ANY")]
    [InlineData(999, "TYPE999")]
    public void QTypeToString_MapsCorrectly(int qtype, string expected)
    {
        Assert.Equal(expected, DnsEventIds.QTypeToString(qtype));
    }

    [Theory]
    [InlineData(0, DnsAction.Allow)]
    [InlineData(2, DnsAction.ServFail)]
    [InlineData(3, DnsAction.NxDomain)]
    [InlineData(5, DnsAction.Refused)]
    public void RCodeToAction_MapsCorrectly(int rcode, DnsAction expected)
    {
        Assert.Equal(expected, DnsEventIds.RCodeToAction(rcode));
    }

    [Fact]
    public void SyslogSeverity_Allow_IsInformational()
    {
        var evt = new DnsEvent { Action = DnsAction.Allow };
        Assert.Equal(6, evt.SyslogSeverity); // Informational
    }

    [Fact]
    public void SyslogSeverity_ServFail_IsError()
    {
        var evt = new DnsEvent { Action = DnsAction.ServFail };
        Assert.Equal(3, evt.SyslogSeverity); // Error
    }

    [Fact]
    public void SyslogSeverity_Deny_IsWarning()
    {
        var evt = new DnsEvent { Action = DnsAction.Deny };
        Assert.Equal(4, evt.SyslogSeverity); // Warning
    }
}
