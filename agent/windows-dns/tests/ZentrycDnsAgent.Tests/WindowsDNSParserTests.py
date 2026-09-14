"""
Tests for the server-side WindowsDNSParser.
Run with: pytest tests/ZentrycDnsAgent.Tests/WindowsDNSParserTests.py -v
"""
import sys
import os
import pytest

# Add fastapi_app to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'fastapi_app'))

from services.parsers import WindowsDNSParser, get_parser


class TestWindowsDNSParser:
    """Tests for WindowsDNSParser structured data extraction."""

    def setup_method(self):
        self.parser = WindowsDNSParser()

    def test_parse_basic_dns_query(self):
        message = (
            '<14>1 2026-03-31T10:15:30.123Z WIN-DNS01 ZentrycDNS - dns-query '
            '[dns@zentryc vendor="windows-dns" device_ip="192.168.1.10" '
            'device_name="WIN-DNS01" action="allow" src_ip="192.168.1.50" '
            'src_port="54321" transport="UDP" qname="mail.example.com" '
            'qtype="A" qclass="IN" event_type="dns-query"] '
            'DNS query from 192.168.1.50 for mail.example.com (A)'
        )
        result = self.parser.parse(message)

        assert result['vendor'] == 'windows-dns'
        assert result['device_ip'] == '192.168.1.10'
        assert result['device_name'] == 'WIN-DNS01'
        assert result['action'] == 'allow'
        assert result['src_ip'] == '192.168.1.50'
        assert result['src_port'] == '54321'
        assert result['transport'] == 'UDP'
        assert result['qname'] == 'mail.example.com'
        assert result['qtype'] == 'A'
        assert result['qclass'] == 'IN'
        assert result['event_type'] == 'dns-query'
        assert result['log_type'] == 'windows-dns'

    def test_parse_dns_response_with_resolved_ip(self):
        message = (
            '<14>1 2026-03-31T10:15:31.000Z WIN-DNS01 ZentrycDNS - dns-response '
            '[dns@zentryc qname="www.example.com" qtype="A" action="allow" '
            'resolved_ip="93.184.216.34" event_type="dns-response" '
            'src_ip="192.168.1.50"] DNS response for www.example.com: 93.184.216.34'
        )
        result = self.parser.parse(message)

        assert result['qname'] == 'www.example.com'
        assert result['resolved_ip'] == '93.184.216.34'
        assert result['action'] == 'allow'
        assert result['event_type'] == 'dns-response'

    def test_parse_nxdomain_response(self):
        message = (
            '<14>1 2026-03-31T10:16:00.000Z WIN-DNS01 ZentrycDNS - dns-response '
            '[dns@zentryc qname="nonexistent.example.com" qtype="A" '
            'action="nxdomain" event_type="dns-response" severity="informational"] '
            'DNS response failure for nonexistent.example.com: RCODE=3'
        )
        result = self.parser.parse(message)

        assert result['action'] == 'nxdomain'
        assert result['severity'] == 'informational'
        assert result['log_type'] == 'windows-dns'

    def test_parse_recursive_query(self):
        message = (
            '<14>1 2026-03-31T10:16:01.000Z WIN-DNS01 ZentrycDNS - dns-recurse '
            '[dns@zentryc qname="external.com" qtype="A" action="recurse" '
            'dst_ip="8.8.8.8" dst_port="53" direction="outbound" '
            'event_type="dns-recurse"] Recursive query for external.com to 8.8.8.8'
        )
        result = self.parser.parse(message)

        assert result['action'] == 'recurse'
        assert result['dst_ip'] == '8.8.8.8'
        assert result['direction'] == 'outbound'

    def test_parse_heartbeat(self):
        message = (
            '<14>1 2026-03-31T10:20:00.000Z WIN-DNS01 ZentrycDNS - agent-heartbeat '
            '[heartbeat@zentryc version="1.0.0" hostname="WIN-DNS01" uptime="3600" '
            'events_processed="15000"] Agent heartbeat: up 0d 1h, 15000 events processed'
        )
        result = self.parser.parse(message)

        assert result['version'] == '1.0.0'
        assert result['hostname'] == 'WIN-DNS01'
        assert result['uptime'] == '3600'
        assert result['log_type'] == 'agent-heartbeat'

    def test_parse_escaped_characters(self):
        message = (
            '<14>1 2026-03-31T10:15:30.000Z DNS01 ZentrycDNS - dns-query '
            '[dns@zentryc qname="test\\"evil\\].com" qtype="A" '
            'event_type="dns-query"] test'
        )
        result = self.parser.parse(message)

        assert result['qname'] == 'test"evil].com'

    def test_parse_empty_message_returns_empty(self):
        result = self.parser.parse('some random syslog message without structured data')
        assert result == {}

    def test_get_parser_returns_windows_dns(self):
        parser = get_parser('WINDOWS_DNS')
        assert isinstance(parser, WindowsDNSParser)

    def test_parse_with_user_field(self):
        message = (
            '<14>1 2026-03-31T10:15:30.000Z DNS01 ZentrycDNS - dns-query '
            '[dns@zentryc qname="intranet.corp.local" qtype="A" '
            'src_ip="10.0.0.50" src_user="CORP\\\\jsmith" '
            'event_type="dns-query" action="allow"] DNS query'
        )
        result = self.parser.parse(message)

        assert result['src_user'] == 'CORP\\jsmith'
        assert result['qname'] == 'intranet.corp.local'
