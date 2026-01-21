"""
Log parsers for different firewall vendors.

Supports:
- Fortinet FortiGate (FortiOS 7.x) - Full field extraction per official documentation
- Palo Alto Networks (CSV, CEF, LEEF, Key-Value formats)
- Generic syslog

Reference: https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/357866/log-message-fields
"""

import re
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
from datetime import datetime


class BaseParser(ABC):
    """Base class for log parsers."""

    @abstractmethod
    def parse(self, message: str) -> Dict[str, Any]:
        """
        Parse the message and return a dictionary of key-value pairs.

        Args:
            message: Raw log message

        Returns:
            Dictionary of parsed fields
        """
        pass


class GenericParser(BaseParser):
    """Generic parser that returns empty dict (pass-through)."""

    def parse(self, message: str) -> Dict[str, Any]:
        return {}


class FortinetParser(BaseParser):
    """
    Parser for Fortinet FortiGate firewall logs (FortiOS 7.x).

    Based on official Fortinet Log Message Reference documentation.
    Reference: https://docs.fortinet.com/document/fortigate/7.6.4/fortios-log-message-reference/357866/log-message-fields

    Log Types Supported:
    - traffic (forward, local, multicast, sniffer)
    - utm (virus, webfilter, ips, dlp, app-ctrl, etc.)
    - event (system, user, router, vpn, wad, endpoint, etc.)
    - anomaly

    Format: key=value or key="value with spaces"

    Example:
        date=2025-11-30 time=14:19:23 devname="FGT-FW01" devid="FGVM2VTM24005376"
        eventtime=1764501563610106094 tz="+0300" logid="0000000020" type="traffic"
        subtype="forward" level="notice" vd="root" srcip=172.20.7.32 srcport=61556
        dstip=10.11.50.43 dstport=8027 action="accept" policyid=3
    """

    # Compile regex once for performance
    _KV_PATTERN = re.compile(r'([a-zA-Z0-9_]+)=("(?:[^"\\]|\\.)*"|[^ ]+)')

    # =========================================================================
    # FIELD DEFINITIONS BY CATEGORY (Based on FortiOS 7.x Log Reference)
    # =========================================================================

    # Header fields (common to all log types)
    HEADER_FIELDS = {
        'date', 'time', 'devname', 'devid', 'eventtime', 'tz', 'logid',
        'type', 'subtype', 'level', 'vd', 'logdesc', 'logver'
    }

    # Traffic log fields
    TRAFFIC_FIELDS = {
        # Source/Destination
        'srcip', 'dstip', 'srcport', 'dstport', 'srcintf', 'dstintf',
        'srcintfrole', 'dstintfrole', 'srcname', 'dstname', 'srcmac', 'dstmac',
        'srccountry', 'dstcountry', 'srcserver', 'dstserver',
        'srcfamily', 'dstfamily', 'srchwvendor', 'dsthwvendor',
        'srchwversion', 'dsthwversion', 'srcswversion', 'dstswversion',
        'srcosname', 'dstosname', 'srcdevtype', 'dstdevtype',

        # Session info
        'sessionid', 'proto', 'action', 'policyid', 'policytype', 'policyname',
        'poluuid', 'service', 'duration', 'trandisp', 'transip', 'transport',
        'natsrcip', 'natsrcport', 'natdstip', 'natdstport',

        # Bytes/Packets
        'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt',
        'sentdelta', 'rcvddelta', 'sentpktdelta', 'rcvdpktdelta', 'durationdelta',

        # Application
        'app', 'appcat', 'apprisk', 'applist', 'appid', 'appact',

        # VPN
        'vpntype', 'tunneltype', 'tunnelid', 'vwlid', 'vwlname', 'vwlquality',

        # Device/User info
        'devtype', 'osname', 'osversion', 'mastersrcmac', 'masterdstmac',
        'srcuuid', 'dstuuid', 'unauthuser', 'unauthusersource',

        # Reputation/UTM
        'crscore', 'craction', 'crlevel', 'dstreputation', 'srcreputation',
        'dstinetsvc', 'srcinetsvc',

        # GeoIP
        'srcregion', 'dstregion', 'srccity', 'dstcity',
        'srcserver', 'dstserver',

        # Misc
        'msg', 'wanin', 'wanout', 'lanin', 'lanout', 'collectedemail',
    }

    # UTM/Security log fields
    UTM_FIELDS = {
        # Common UTM
        'utmaction', 'utmref', 'countips', 'countweb', 'countav',

        # Web Filter
        'urltype', 'urlcat', 'urlcatscore', 'urlcatrisk',
        'hostname', 'url', 'referralurl', 'httpmethod',
        'sentbyte', 'rcvdbyte', 'direction',

        # IPS/IDS
        'attack', 'attackid', 'severity', 'signature', 'ref',
        'incidentserialno', 'msg', 'cve',

        # Antivirus
        'virus', 'virusid', 'dtype', 'filename', 'filesize', 'filetype',
        'filehash', 'quarskip', 'scantime',

        # Application Control
        'appcat', 'app', 'applist', 'appid', 'apprisk', 'appact',

        # DLP
        'dlpextra', 'filteridx', 'filtername', 'filtertype', 'filtercat',

        # Email Filter
        'from', 'to', 'subject', 'recipient',

        # DNS
        'qname', 'qtype', 'qclass', 'ipaddr', 'botnetdomain', 'botnetip',

        # SSL/SSH
        'sslaction', 'ssllocaction', 'issuer', 'serial', 'fingerprint',
    }

    # Event log fields
    EVENT_FIELDS = {
        # System events
        'action', 'status', 'reason', 'msg', 'logdesc',
        'cpu', 'mem', 'disk', 'setuprate', 'totalsession',

        # User events
        'user', 'srcuser', 'dstuser', 'group', 'authproto',
        'authserver', 'policyid', 'assignip',

        # VPN events
        'tunneltype', 'tunnelid', 'remip', 'locip',
        'vpntunnel', 'xauthuser', 'xauthgroup', 'phase1name',
        'initspi', 'respspi', 'cookies', 'outintf',

        # HA events
        'sn', 'state', 'role', 'hagroup', 'priority',

        # Config events
        'cfgpath', 'cfgobj', 'cfgattr', 'admin', 'ui',
    }

    # Integer fields (for type conversion)
    INTEGER_FIELDS = {
        'srcport', 'dstport', 'sessionid', 'proto', 'policyid',
        'duration', 'sentbyte', 'rcvdbyte', 'sentpkt', 'rcvdpkt',
        'sentdelta', 'rcvddelta', 'sentpktdelta', 'rcvdpktdelta', 'durationdelta',
        'natsrcport', 'natdstport', 'severity', 'crscore', 'craction',
        'cpu', 'mem', 'disk', 'appid', 'attackid', 'virusid',
        'filesize', 'wanin', 'wanout', 'lanin', 'lanout',
    }

    # Low cardinality fields (for optimized storage)
    LOW_CARDINALITY_FIELDS = {
        'type', 'subtype', 'level', 'action', 'proto', 'policytype',
        'trandisp', 'vpntype', 'tunneltype', 'devtype', 'osname',
        'appcat', 'apprisk', 'urlcat', 'direction', 'status',
    }

    # Fields that should always be extracted for indexing
    INDEXED_FIELDS = {
        'srcip', 'dstip', 'srcport', 'dstport', 'action', 'policyid',
        'proto', 'type', 'subtype', 'sessionid', 'app', 'appcat',
        'srcintf', 'dstintf', 'service', 'user', 'srcuser', 'dstuser',
    }

    def parse(self, message: str) -> Dict[str, Any]:
        """
        Parse FortiGate log message into structured fields.

        Args:
            message: Raw syslog message

        Returns:
            Dictionary with all parsed fields
        """
        data = {}

        # Extract all key=value pairs
        matches = self._KV_PATTERN.findall(message)

        for key, value in matches:
            # Strip quotes from quoted values
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]

            # Store all values as strings (ClickHouse Map requires String,String)
            data[key] = value

        # Create combined log_datetime from date and time fields
        if 'date' in data and 'time' in data:
            data['log_datetime'] = f"{data['date']} {data['time']}"

        # Handle eventtime (nanosecond epoch) - convert to readable timestamp
        if 'eventtime' in data:
            try:
                # FortiGate eventtime is in nanoseconds (10^9)
                eventtime_ns = int(data['eventtime'])
                # Convert to seconds
                eventtime_s = eventtime_ns / 1_000_000_000
                dt = datetime.fromtimestamp(eventtime_s)
                data['eventtime_formatted'] = dt.strftime('%Y-%m-%d %H:%M:%S')
            except (ValueError, OSError):
                pass

        return data

    def get_log_type(self, parsed: Dict[str, Any]) -> str:
        """Get the log type from parsed data."""
        log_type = parsed.get('type', 'unknown')
        subtype = parsed.get('subtype', '')
        if subtype:
            return f"{log_type}/{subtype}"
        return log_type

    def get_severity_level(self, parsed: Dict[str, Any]) -> int:
        """
        Map FortiGate level to syslog severity.

        FortiGate levels: emergency, alert, critical, error, warning, notice, information, debug
        Syslog severity: 0=Emergency, 1=Alert, 2=Critical, 3=Error, 4=Warning, 5=Notice, 6=Info, 7=Debug
        """
        level_map = {
            'emergency': 0,
            'alert': 1,
            'critical': 2,
            'error': 3,
            'warning': 4,
            'notice': 5,
            'notification': 5,
            'information': 6,
            'informational': 6,
            'debug': 7,
        }
        level = parsed.get('level', 'notice').lower()
        return level_map.get(level, 6)


class PaloAltoParser(BaseParser):
    """
    Parser for Palo Alto Networks firewall logs.

    Supports all major log types in CSV, CEF, and key=value formats:
    - TRAFFIC: Network traffic logs (sessions, bytes, packets)
    - THREAT: Security threat detection (virus, spyware, vulnerability)
    - URL: URL filtering logs
    - WILDFIRE: WildFire malware analysis logs
    - DATA: Data filtering logs
    - SYSTEM: System events (auth, dhcp, general, globalprotect)
    - CONFIG: Configuration change logs
    - HIP-MATCH: GlobalProtect Host Information Profile match logs
    - CORRELATION: Correlated event logs
    - USERID: User-ID logs
    - GLOBALPROTECT: GlobalProtect logs
    - AUTHENTICATION: Authentication logs
    - SCTP: SCTP protocol logs
    - DECRYPTION: Decryption logs
    """

    # TRAFFIC log fields (PAN-OS 10.x/11.x)
    TRAFFIC_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'src_ip', 'dst_ip', 'nat_src_ip',
        'nat_dst_ip', 'rule', 'src_user', 'dst_user', 'application',
        'vsys', 'src_zone', 'dst_zone', 'inbound_if', 'outbound_if',
        'log_action', 'future_use_3', 'session_id', 'repeat_count', 'src_port',
        'dst_port', 'nat_src_port', 'nat_dst_port', 'flags', 'protocol',
        'action', 'bytes', 'bytes_sent', 'bytes_recv', 'packets',
        'start_time', 'elapsed_time', 'category', 'future_use_4', 'seq_no',
        'action_flags', 'src_location', 'dst_location', 'future_use_5', 'packets_sent',
        'packets_recv', 'session_end_reason', 'dg_hierarchy_l1', 'dg_hierarchy_l2', 'dg_hierarchy_l3',
        'dg_hierarchy_l4', 'vsys_name', 'device_name', 'action_source', 'src_vm_uuid',
        'dst_vm_uuid', 'tunnel_id', 'monitor_tag', 'parent_session_id', 'parent_start_time',
        'tunnel_type', 'sctp_assoc_id', 'sctp_chunks', 'sctp_chunks_sent', 'sctp_chunks_recv',
        'rule_uuid', 'http2_connection', 'link_change_count', 'policy_id', 'link_switches',
        'sdwan_cluster', 'sdwan_device_type', 'sdwan_cluster_type', 'sdwan_site', 'dynusergroup_name',
        'xff_ip', 'src_dvc_category', 'src_dvc_profile', 'src_dvc_model', 'src_dvc_vendor',
        'src_dvc_os_family', 'src_dvc_os_version', 'src_hostname', 'src_mac', 'dst_dvc_category',
        'dst_dvc_profile', 'dst_dvc_model', 'dst_dvc_vendor', 'dst_dvc_os_family', 'dst_dvc_os_version',
        'dst_hostname', 'dst_mac', 'container_id', 'pod_namespace', 'pod_name',
        'src_edl', 'dst_edl', 'hostid', 'serial_number', 'src_dag',
        'dst_dag', 'session_owner', 'high_res_timestamp', 'nsdsai_sst', 'nsdsai_sd',
        'subcategory_of_app', 'category_of_app', 'tech_of_app', 'risk_of_app', 'characteristic_of_app',
        'container_of_app', 'tunneled_app', 'is_saas_of_app', 'sanctioned_state_of_app'
    ]

    # THREAT log fields
    THREAT_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'src_ip', 'dst_ip', 'nat_src_ip',
        'nat_dst_ip', 'rule', 'src_user', 'dst_user', 'application',
        'vsys', 'src_zone', 'dst_zone', 'inbound_if', 'outbound_if',
        'log_action', 'future_use_3', 'session_id', 'repeat_count', 'src_port',
        'dst_port', 'nat_src_port', 'nat_dst_port', 'flags', 'protocol',
        'action', 'misc', 'threat_id', 'category', 'severity',
        'direction', 'seq_no', 'action_flags', 'src_location', 'dst_location',
        'future_use_4', 'content_type', 'pcap_id', 'file_digest', 'cloud',
        'url_index', 'user_agent', 'file_type', 'xff', 'referer',
        'sender', 'subject', 'recipient', 'report_id', 'dg_hierarchy_l1',
        'dg_hierarchy_l2', 'dg_hierarchy_l3', 'dg_hierarchy_l4', 'vsys_name', 'device_name',
        'future_use_5', 'src_vm_uuid', 'dst_vm_uuid', 'http_method', 'tunnel_id',
        'monitor_tag', 'parent_session_id', 'parent_start_time', 'tunnel_type', 'threat_category',
        'content_ver', 'future_use_6', 'sctp_assoc_id', 'payload_protocol_id', 'http_headers',
        'url_category_list', 'rule_uuid', 'http2_connection', 'dynusergroup_name', 'xff_ip',
        'src_dvc_category', 'src_dvc_profile', 'src_dvc_model', 'src_dvc_vendor', 'src_dvc_os_family',
        'src_dvc_os_version', 'src_hostname', 'src_mac', 'dst_dvc_category', 'dst_dvc_profile',
        'dst_dvc_model', 'dst_dvc_vendor', 'dst_dvc_os_family', 'dst_dvc_os_version', 'dst_hostname',
        'dst_mac', 'container_id', 'pod_namespace', 'pod_name', 'src_edl',
        'dst_edl', 'hostid', 'serial_number', 'domain_edl', 'src_dag',
        'dst_dag', 'partial_hash', 'high_res_timestamp', 'reason', 'justification',
        'nsdsai_sst', 'nsdsai_sd', 'subcategory_of_app', 'category_of_app', 'tech_of_app',
        'risk_of_app', 'characteristic_of_app', 'container_of_app', 'tunneled_app', 'is_saas_of_app',
        'sanctioned_state_of_app'
    ]

    # SYSTEM log fields
    SYSTEM_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'vsys', 'event_id', 'object',
        'future_use_3', 'future_use_4', 'module', 'severity', 'description',
        'seq_no', 'action_flags', 'dg_hierarchy_l1', 'dg_hierarchy_l2', 'dg_hierarchy_l3',
        'dg_hierarchy_l4', 'vsys_name', 'device_name', 'future_use_5', 'future_use_6',
        'high_res_timestamp'
    ]

    # CONFIG log fields
    CONFIG_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'host', 'vsys', 'cmd',
        'admin', 'client', 'result', 'config_path', 'before_change_detail',
        'after_change_detail', 'seq_no', 'action_flags', 'dg_hierarchy_l1', 'dg_hierarchy_l2',
        'dg_hierarchy_l3', 'dg_hierarchy_l4', 'vsys_name', 'device_name', 'future_use_3',
        'future_use_4', 'high_res_timestamp'
    ]

    # HIP-MATCH log fields
    HIPMATCH_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'src_user', 'vsys', 'machine_name',
        'os', 'src_ip', 'hip_match_name', 'repeat_count', 'hip_match_type',
        'future_use_3', 'future_use_4', 'seq_no', 'action_flags', 'dg_hierarchy_l1',
        'dg_hierarchy_l2', 'dg_hierarchy_l3', 'dg_hierarchy_l4', 'vsys_name', 'device_name',
        'vsys_id', 'ipv6', 'hostid', 'serial_number', 'mac',
        'high_res_timestamp', 'endpoint_serial_number'
    ]

    # CORRELATION log fields
    CORRELATION_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'src_ip', 'src_user', 'vsys',
        'category', 'severity', 'dg_hierarchy_l1', 'dg_hierarchy_l2', 'dg_hierarchy_l3',
        'dg_hierarchy_l4', 'vsys_name', 'device_name', 'vsys_id', 'object_name',
        'object_id', 'evidence', 'future_use_3', 'high_res_timestamp'
    ]

    # USERID log fields
    USERID_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'vsys', 'src_ip', 'source_name',
        'event_id', 'repeat_count', 'timeout_threshold', 'src_port', 'dst_port',
        'data_source', 'data_source_name', 'data_source_type', 'seq_no', 'action_flags',
        'dg_hierarchy_l1', 'dg_hierarchy_l2', 'dg_hierarchy_l3', 'dg_hierarchy_l4', 'vsys_name',
        'device_name', 'vsys_id', 'factor_type', 'factor_completion_time', 'factor_no',
        'ugflags', 'user_by_source', 'high_res_timestamp', 'tag_name'
    ]

    # URL log fields
    URL_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'src_ip', 'dst_ip', 'nat_src_ip',
        'nat_dst_ip', 'rule', 'src_user', 'dst_user', 'application',
        'vsys', 'src_zone', 'dst_zone', 'inbound_if', 'outbound_if',
        'log_action', 'future_use_3', 'session_id', 'repeat_count', 'src_port',
        'dst_port', 'nat_src_port', 'nat_dst_port', 'flags', 'protocol',
        'action', 'url', 'threat_id', 'category', 'severity',
        'direction', 'seq_no', 'action_flags', 'src_location', 'dst_location',
        'future_use_4', 'content_type', 'pcap_id', 'file_digest', 'cloud',
        'url_index', 'user_agent', 'file_type', 'xff', 'referer',
        'sender', 'subject', 'recipient', 'report_id', 'dg_hierarchy_l1',
        'dg_hierarchy_l2', 'dg_hierarchy_l3', 'dg_hierarchy_l4', 'vsys_name', 'device_name',
        'future_use_5', 'src_vm_uuid', 'dst_vm_uuid', 'http_method', 'tunnel_id',
        'monitor_tag', 'parent_session_id', 'parent_start_time', 'tunnel_type', 'threat_category',
        'content_ver', 'future_use_6', 'http_headers', 'url_category_list', 'rule_uuid',
        'http2_connection', 'dynusergroup_name', 'xff_ip', 'src_dvc_category', 'src_dvc_profile',
        'src_dvc_model', 'src_dvc_vendor', 'src_dvc_os_family', 'src_dvc_os_version', 'src_hostname',
        'src_mac', 'dst_dvc_category', 'dst_dvc_profile', 'dst_dvc_model', 'dst_dvc_vendor',
        'dst_dvc_os_family', 'dst_dvc_os_version', 'dst_hostname', 'dst_mac', 'container_id',
        'pod_namespace', 'pod_name', 'src_edl', 'dst_edl', 'hostid',
        'serial_number', 'src_dag', 'dst_dag', 'partial_hash', 'high_res_timestamp',
        'nsdsai_sst', 'nsdsai_sd'
    ]

    # WILDFIRE log fields
    WILDFIRE_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'src_ip', 'dst_ip', 'nat_src_ip',
        'nat_dst_ip', 'rule', 'src_user', 'dst_user', 'application',
        'vsys', 'src_zone', 'dst_zone', 'inbound_if', 'outbound_if',
        'log_action', 'future_use_3', 'session_id', 'repeat_count', 'src_port',
        'dst_port', 'nat_src_port', 'nat_dst_port', 'flags', 'protocol',
        'action', 'misc', 'threat_id', 'category', 'severity',
        'direction', 'seq_no', 'action_flags', 'src_location', 'dst_location',
        'future_use_4', 'content_type', 'pcap_id', 'file_digest', 'cloud',
        'url_index', 'user_agent', 'file_type', 'xff', 'referer',
        'sender', 'subject', 'recipient', 'report_id', 'dg_hierarchy_l1',
        'dg_hierarchy_l2', 'dg_hierarchy_l3', 'dg_hierarchy_l4', 'vsys_name', 'device_name',
        'future_use_5', 'src_vm_uuid', 'dst_vm_uuid', 'http_method', 'tunnel_id',
        'monitor_tag', 'parent_session_id', 'parent_start_time', 'tunnel_type', 'threat_category',
        'content_ver', 'future_use_6', 'sctp_assoc_id', 'payload_protocol_id', 'http_headers',
        'url_category_list', 'rule_uuid', 'http2_connection', 'dynusergroup_name', 'xff_ip',
        'src_dvc_category', 'src_dvc_profile', 'src_dvc_model', 'src_dvc_vendor', 'src_dvc_os_family',
        'src_dvc_os_version', 'src_hostname', 'src_mac', 'dst_dvc_category', 'dst_dvc_profile',
        'dst_dvc_model', 'dst_dvc_vendor', 'dst_dvc_os_family', 'dst_dvc_os_version', 'dst_hostname',
        'dst_mac', 'container_id', 'pod_namespace', 'pod_name', 'src_edl',
        'dst_edl', 'hostid', 'serial_number', 'domain_edl', 'src_dag',
        'dst_dag', 'partial_hash', 'high_res_timestamp', 'reason', 'justification'
    ]

    # DATA log fields
    DATA_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'src_ip', 'dst_ip', 'nat_src_ip',
        'nat_dst_ip', 'rule', 'src_user', 'dst_user', 'application',
        'vsys', 'src_zone', 'dst_zone', 'inbound_if', 'outbound_if',
        'log_action', 'future_use_3', 'session_id', 'repeat_count', 'src_port',
        'dst_port', 'nat_src_port', 'nat_dst_port', 'flags', 'protocol',
        'action', 'misc', 'threat_id', 'category', 'severity',
        'direction', 'seq_no', 'action_flags', 'src_location', 'dst_location',
        'future_use_4', 'content_type', 'pcap_id', 'file_digest', 'cloud',
        'url_index', 'user_agent', 'file_type', 'xff', 'referer',
        'sender', 'subject', 'recipient', 'report_id', 'dg_hierarchy_l1',
        'dg_hierarchy_l2', 'dg_hierarchy_l3', 'dg_hierarchy_l4', 'vsys_name', 'device_name',
        'future_use_5', 'src_vm_uuid', 'dst_vm_uuid', 'tunnel_id', 'monitor_tag',
        'parent_session_id', 'parent_start_time', 'tunnel_type', 'threat_category', 'content_ver',
        'future_use_6', 'rule_uuid', 'data_id', 'data_profile', 'data_pattern_name'
    ]

    # AUTHENTICATION log fields
    AUTHENTICATION_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'vsys', 'src_ip', 'normalize_user',
        'object', 'auth_policy', 'repeat_count', 'auth_id', 'vendor',
        'log_action', 'server_profile', 'description', 'client_type', 'event_type',
        'factor_no', 'seq_no', 'action_flags', 'dg_hierarchy_l1', 'dg_hierarchy_l2',
        'dg_hierarchy_l3', 'dg_hierarchy_l4', 'vsys_name', 'device_name', 'vsys_id',
        'auth_protocol', 'rule_uuid', 'high_res_timestamp', 'src_dvc_category', 'src_dvc_profile',
        'src_dvc_model', 'src_dvc_vendor', 'src_dvc_os_family', 'src_dvc_os_version', 'src_hostname',
        'src_mac', 'src_osfp', 'src_category', 'user_agent', 'session_id'
    ]

    # GLOBALPROTECT log fields
    GLOBALPROTECT_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'vsys', 'event_id', 'stage',
        'auth_method', 'tunnel_type', 'src_user', 'src_region', 'machine_name',
        'public_ip', 'public_ipv6', 'private_ip', 'private_ipv6', 'hostid',
        'serial_number', 'client_ver', 'client_os', 'client_os_ver', 'repeat_count',
        'reason', 'error', 'opaque', 'status', 'location',
        'login_duration', 'connect_method', 'error_code', 'portal', 'seq_no',
        'action_flags', 'dg_hierarchy_l1', 'dg_hierarchy_l2', 'dg_hierarchy_l3', 'dg_hierarchy_l4',
        'vsys_name', 'device_name', 'vsys_id', 'high_res_timestamp', 'selection_type',
        'response_time', 'priority', 'attempted_gateways', 'gateway', 'future_use_3'
    ]

    # DECRYPTION log fields
    DECRYPTION_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'src_ip', 'dst_ip', 'nat_src_ip',
        'nat_dst_ip', 'rule', 'src_user', 'dst_user', 'application',
        'vsys', 'src_zone', 'dst_zone', 'inbound_if', 'outbound_if',
        'log_action', 'future_use_3', 'session_id', 'repeat_count', 'src_port',
        'dst_port', 'nat_src_port', 'nat_dst_port', 'flags', 'protocol',
        'action', 'tunnel_id', 'monitor_tag', 'parent_session_id', 'parent_start_time',
        'tunnel_type', 'action_flags', 'dg_hierarchy_l1', 'dg_hierarchy_l2', 'dg_hierarchy_l3',
        'dg_hierarchy_l4', 'vsys_name', 'device_name', 'future_use_4', 'src_vm_uuid',
        'dst_vm_uuid', 'policy_name', 'elliptic_curve', 'error_index', 'root_cn',
        'root_serial', 'chain_status', 'proxy_type', 'cert_serial_num', 'fingerprint',
        'timestamp_not_before', 'timestamp_not_after', 'cert_version', 'cert_size', 'issuer_cn',
        'root_status', 'issuer_name', 'subject_name', 'altsubj_name', 'seq_no',
        'tls_version', 'tls_keyexchange', 'tls_encryption', 'tls_auth', 'rule_uuid',
        'container_id', 'pod_namespace', 'pod_name', 'src_edl', 'dst_edl',
        'src_dag', 'dst_dag', 'high_res_timestamp', 'src_dvc_category', 'src_dvc_profile',
        'src_dvc_model', 'src_dvc_vendor', 'src_dvc_os_family', 'src_dvc_os_version', 'src_hostname',
        'src_mac', 'dst_dvc_category', 'dst_dvc_profile', 'dst_dvc_model', 'dst_dvc_vendor',
        'dst_dvc_os_family', 'dst_dvc_os_version', 'dst_hostname', 'dst_mac'
    ]

    # SCTP log fields
    SCTP_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'src_ip', 'dst_ip', 'nat_src_ip',
        'nat_dst_ip', 'rule', 'src_user', 'dst_user', 'application',
        'vsys', 'src_zone', 'dst_zone', 'inbound_if', 'outbound_if',
        'log_action', 'future_use_3', 'session_id', 'repeat_count', 'src_port',
        'dst_port', 'nat_src_port', 'nat_dst_port', 'flags', 'protocol',
        'action', 'dg_hierarchy_l1', 'dg_hierarchy_l2', 'dg_hierarchy_l3', 'dg_hierarchy_l4',
        'vsys_name', 'device_name', 'seq_no', 'assoc_id', 'ppid',
        'severity', 'sctp_chunk_type', 'sctp_event_type', 'verif_tag_1', 'verif_tag_2',
        'sctp_cause_code', 'diam_app_id', 'diam_cmd_code', 'diam_avp_code', 'stream_id',
        'assoc_end_reason', 'op_code', 'sccp_calling_party_ssn', 'sccp_calling_party_gt',
        'sctp_filter', 'sctp_chunks', 'sctp_chunks_sent', 'sctp_chunks_recv', 'rule_uuid',
        'high_res_timestamp'
    ]

    # Mapping of log types to their field definitions
    LOG_TYPE_FIELDS = {
        'TRAFFIC': TRAFFIC_FIELDS,
        'THREAT': THREAT_FIELDS,
        'SYSTEM': SYSTEM_FIELDS,
        'CONFIG': CONFIG_FIELDS,
        'HIPMATCH': HIPMATCH_FIELDS,
        'HIP-MATCH': HIPMATCH_FIELDS,
        'CORRELATION': CORRELATION_FIELDS,
        'USERID': USERID_FIELDS,
        'URL': URL_FIELDS,
        'WILDFIRE': WILDFIRE_FIELDS,
        'DATA': DATA_FIELDS,
        'AUTHENTICATION': AUTHENTICATION_FIELDS,
        'GLOBALPROTECT': GLOBALPROTECT_FIELDS,
        'DECRYPTION': DECRYPTION_FIELDS,
        'SCTP': SCTP_FIELDS,
    }

    # Field name normalization map - maps Palo Alto fields to common/Fortinet-style fields
    FIELD_NORMALIZATION = {
        # IP addresses
        'src_ip': 'srcip',
        'dst_ip': 'dstip',
        'nat_src_ip': 'nat_srcip',
        'nat_dst_ip': 'nat_dstip',
        # Ports
        'src_port': 'srcport',
        'dst_port': 'dstport',
        'nat_src_port': 'natsrcport',
        'nat_dst_port': 'natdstport',
        # Zones
        'src_zone': 'srczone',
        'dst_zone': 'dstzone',
        # Users
        'src_user': 'srcuser',
        'dst_user': 'dstuser',
        # Interfaces
        'inbound_if': 'srcintf',
        'outbound_if': 'dstintf',
        # Protocol and Application
        'protocol': 'proto',
        'application': 'app',
        # Bytes - map to Fortinet-style names
        'bytes_sent': 'sentbyte',
        'bytes_recv': 'rcvdbyte',
        'bytes': 'totalbyte',
        # Packets
        'packets_sent': 'sentpkt',
        'packets_recv': 'rcvdpkt',
        'packets': 'totalpkt',
        # Session info
        'session_id': 'sessionid',
        'elapsed_time': 'duration',
        'session_end_reason': 'session_end_reason',
        # Location
        'src_location': 'srccountry',
        'dst_location': 'dstcountry',
        # Rule/Policy
        'rule': 'policyname',
        # Device info
        'device_name': 'device_name',
        'vsys_name': 'vsys_name',
        # Time fields
        'receive_time': 'receive_time',
        'generated_time': 'generated_time',
        'start_time': 'start_time',
        # Category
        'category': 'category',
        # Device category/profile info (for endpoint identification)
        'src_dvc_category': 'src_device_category',
        'dst_dvc_category': 'dst_device_category',
        'src_hostname': 'src_hostname',
        'dst_hostname': 'dst_hostname',
        'src_mac': 'srcmac',
        'dst_mac': 'dstmac',
        # Threat-specific
        'threat_id': 'threat_id',
        'severity': 'threat_severity',
        # App classification
        'category_of_app': 'appcat',
        'subcategory_of_app': 'app_subcat',
        'risk_of_app': 'apprisk',
        'tech_of_app': 'app_tech',
        'characteristic_of_app': 'app_characteristic',
    }

    def parse(self, message: str) -> Dict[str, Any]:
        """Parse a Palo Alto log message."""
        if not message:
            return {}

        # Extract syslog header timestamp before stripping (this is the correct timestamp)
        syslog_timestamp = self._extract_syslog_timestamp(message)

        # Strip syslog header if present
        message = self._strip_syslog_header(message)

        # Check for CEF format
        if message.startswith('CEF:'):
            result = self._parse_cef(message)
        # Check for LEEF format
        elif message.startswith('LEEF:'):
            result = self._parse_leef(message)
        # Try key=value format
        elif '=' in message and message.count('=') > message.count(',') / 3:
            result = self._parse_kv(message)
        # Default: CSV format
        else:
            result = self._parse_csv(message)

        # Use syslog header timestamp as log_datetime (more accurate than CSV timestamp)
        if syslog_timestamp:
            result['log_datetime'] = syslog_timestamp
            result['syslog_timestamp'] = syslog_timestamp

        return result

    def _extract_syslog_timestamp(self, message: str) -> Optional[str]:
        """
        Extract timestamp from RFC 3164 syslog header.

        Format: <PRI>Mon DD HH:MM:SS hostname ...
        Example: <14>Jan  8 15:43:53 VID-PA-01 ...

        Returns timestamp in format: YYYY-MM-DD HH:MM:SS
        """
        if not message.startswith('<'):
            return None

        pri_end = message.find('>')
        if pri_end == -1 or pri_end >= 5:
            return None

        after_pri = message[pri_end + 1:].lstrip()

        # Match RFC 3164 timestamp: Mon DD HH:MM:SS or Mon  D HH:MM:SS
        rfc3164_ts_pattern = r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})'
        match = re.match(rfc3164_ts_pattern, after_pri)

        if match:
            month_str, day, hour, minute, second = match.groups()

            # Convert month name to number
            months = {
                'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
                'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
                'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
            }
            month = months.get(month_str, '01')

            # Use current year (syslog RFC 3164 doesn't include year)
            year = datetime.now().year

            # Format: YYYY-MM-DD HH:MM:SS
            return f"{year}-{month}-{day.zfill(2)} {hour}:{minute}:{second}"

        return None

    def _strip_syslog_header(self, message: str) -> str:
        """Strip RFC 3164/5424 syslog header if present."""
        if message.startswith('<'):
            pri_end = message.find('>')
            if pri_end != -1 and pri_end < 5:
                message = message[pri_end + 1:].lstrip()
                rfc3164_pattern = r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+'
                match = re.match(rfc3164_pattern, message)
                if match:
                    message = message[match.end():]
        return message

    def _parse_csv(self, message: str) -> Dict[str, Any]:
        """Parse Palo Alto CSV format logs."""
        data = {}
        fields = self._split_csv(message)

        if len(fields) < 4:
            return data

        log_type = fields[3].upper() if len(fields) > 3 else 'UNKNOWN'
        data['log_type'] = log_type

        field_names = self.LOG_TYPE_FIELDS.get(log_type)
        if not field_names:
            field_names = [f'field_{i}' for i in range(len(fields))]

        for i, value in enumerate(fields):
            if i < len(field_names):
                field_name = field_names[i]
            else:
                field_name = f'field_{i}'

            if value and not field_name.startswith('future_use'):
                data[field_name] = value

        normalized_data = self._normalize_fields(data)

        if 'receive_time' in data:
            normalized_data['log_datetime'] = data['receive_time']
        elif 'generated_time' in data:
            normalized_data['log_datetime'] = data['generated_time']

        return normalized_data

    def _split_csv(self, message: str) -> List[str]:
        """Split CSV handling quoted fields correctly."""
        fields = []
        current_field = []
        in_quotes = False

        for char in message:
            if char == '"':
                in_quotes = not in_quotes
            elif char == ',' and not in_quotes:
                fields.append(''.join(current_field).strip())
                current_field = []
            else:
                current_field.append(char)

        fields.append(''.join(current_field).strip())
        return fields

    def _normalize_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize Palo Alto field names to common field names."""
        normalized = dict(data)
        for pa_field, common_field in self.FIELD_NORMALIZATION.items():
            if pa_field in data:
                normalized[common_field] = data[pa_field]
        return normalized

    def _parse_kv(self, message: str) -> Dict[str, Any]:
        """Parse key=value format."""
        data = {}
        pattern = r'([a-zA-Z0-9_-]+)=("(?:[^"\\]|\\.)*"|[^\s,]+)'
        matches = re.findall(pattern, message)

        for key, value in matches:
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1].replace('\\"', '"')
            data[key.lower()] = value

        if 'type' in data:
            data['log_type'] = data['type'].upper()

        return self._normalize_fields(data)

    def _parse_cef(self, message: str) -> Dict[str, Any]:
        """Parse CEF (Common Event Format) logs."""
        data = {'log_format': 'CEF'}
        parts = message.split('|', 7)

        if len(parts) >= 7:
            data['cef_version'] = parts[0].replace('CEF:', '')
            data['device_vendor'] = parts[1]
            data['device_product'] = parts[2]
            data['device_version'] = parts[3]
            data['signature_id'] = parts[4]
            data['name'] = parts[5]
            data['cef_severity'] = parts[6]

            sig_id = parts[4].upper()
            if 'TRAFFIC' in sig_id or 'TRAFFIC' in parts[5].upper():
                data['log_type'] = 'TRAFFIC'
            elif 'THREAT' in sig_id or 'THREAT' in parts[5].upper():
                data['log_type'] = 'THREAT'
            elif 'CONFIG' in sig_id or 'CONFIG' in parts[5].upper():
                data['log_type'] = 'CONFIG'
            elif 'SYSTEM' in sig_id or 'SYSTEM' in parts[5].upper():
                data['log_type'] = 'SYSTEM'
            else:
                data['log_type'] = sig_id

            if len(parts) > 7:
                ext_data = self._parse_cef_extension(parts[7])
                data.update(ext_data)

        return self._normalize_fields(data)

    def _parse_cef_extension(self, extension: str) -> Dict[str, Any]:
        """Parse CEF extension field."""
        data = {}
        pattern = r'(\w+)=((?:[^=](?!(?:\s\w+=)))*[^=\s]?)'
        matches = re.findall(pattern, extension)

        cef_mapping = {
            'src': 'src_ip',
            'dst': 'dst_ip',
            'spt': 'src_port',
            'dpt': 'dst_port',
            'act': 'action',
            'proto': 'protocol',
            'app': 'application',
            'duser': 'dst_user',
            'suser': 'src_user',
            'sourceTranslatedAddress': 'nat_src_ip',
            'destinationTranslatedAddress': 'nat_dst_ip',
            'sourceTranslatedPort': 'nat_src_port',
            'destinationTranslatedPort': 'nat_dst_port',
        }

        for key, value in matches:
            value = value.strip()
            if key in cef_mapping:
                data[cef_mapping[key]] = value
            data[key] = value

        return data

    def _parse_leef(self, message: str) -> Dict[str, Any]:
        """Parse LEEF (Log Event Extended Format) logs."""
        data = {'log_format': 'LEEF'}
        parts = message.split('|', 5)

        if len(parts) >= 5:
            leef_header = parts[0]
            data['leef_version'] = leef_header.replace('LEEF:', '').split(':')[0]
            data['device_vendor'] = parts[1]
            data['device_product'] = parts[2]
            data['device_version'] = parts[3]
            data['event_id'] = parts[4]

            event_id = parts[4].upper()
            if 'TRAFFIC' in event_id:
                data['log_type'] = 'TRAFFIC'
            elif 'THREAT' in event_id:
                data['log_type'] = 'THREAT'
            else:
                data['log_type'] = event_id

            if len(parts) > 5:
                delimiter = '\t'
                if ':' in leef_header and len(leef_header.split(':')) > 2:
                    delimiter = leef_header.split(':')[2]
                ext_data = self._parse_leef_extension(parts[5], delimiter)
                data.update(ext_data)

        return self._normalize_fields(data)

    def _parse_leef_extension(self, extension: str, delimiter: str = '\t') -> Dict[str, Any]:
        """Parse LEEF extension with specified delimiter."""
        data = {}
        pairs = extension.split(delimiter)

        for pair in pairs:
            if '=' in pair:
                key, _, value = pair.partition('=')
                key = key.strip()
                value = value.strip()
                if key:
                    data[key.lower()] = value

        return data


# Parser registry
PARSER_MAP: Dict[str, BaseParser] = {
    'GENERIC': GenericParser(),
    'FORTINET': FortinetParser(),
    'PALOALTO': PaloAltoParser(),
}


def get_parser(parser_name: str) -> BaseParser:
    """Get parser by name."""
    return PARSER_MAP.get(parser_name, GenericParser())
