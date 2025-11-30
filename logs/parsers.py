import re

class BaseParser:
    def parse(self, message):
        """
        Parses the message and returns a dictionary of key-value pairs.
        """
        return {}


class GenericParser(BaseParser):
    def parse(self, message):
        return {}


class FortinetParser(BaseParser):
    """
    Parser for Fortinet FortiGate firewall logs.
    Format: key=value or key="value with spaces"
    Example: date=2023-10-11 time=22:14:15 devname="FG100D" devid="FG100D3G16804432"
             logid="0000000013" type="traffic" subtype="forward" level="notice"
             srcip=10.1.100.199 dstip=142.250.185.69 srcport=62293 dstport=443
             action="accept" app="Gmail"
    """
    def parse(self, message):
        data = {}
        pattern = r'([a-zA-Z0-9_]+)=(".*?"|[^ ]+)'
        matches = re.findall(pattern, message)

        for key, value in matches:
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            data[key] = value

        # Create combined log_datetime from date and time fields
        if 'date' in data and 'time' in data:
            data['log_datetime'] = f"{data['date']} {data['time']}"

        return data


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

    CSV Format structure (varies by log type):
    Field 0: FUTURE_USE (always empty)
    Field 1: Receive Time
    Field 2: Serial Number
    Field 3: Type (log type identifier)
    Field 4: Subtype/Content Type
    Field 5+: Type-specific fields

    Reference: https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-admin/monitoring/use-syslog-for-monitoring/syslog-field-descriptions
    """

    # TRAFFIC log fields (PAN-OS 10.x/11.x) - Network session information
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

    # THREAT log fields (PAN-OS 10.x/11.x) - Security threats (virus, spyware, vulnerability, etc.)
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

    # SYSTEM log fields - System events, authentication, DHCP, GlobalProtect events
    SYSTEM_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'vsys', 'event_id', 'object',
        'future_use_3', 'future_use_4', 'module', 'severity', 'description',
        'seq_no', 'action_flags', 'dg_hierarchy_l1', 'dg_hierarchy_l2', 'dg_hierarchy_l3',
        'dg_hierarchy_l4', 'vsys_name', 'device_name', 'future_use_5', 'future_use_6',
        'high_res_timestamp'
    ]

    # CONFIG log fields - Configuration changes
    CONFIG_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'host', 'vsys', 'cmd',
        'admin', 'client', 'result', 'config_path', 'before_change_detail',
        'after_change_detail', 'seq_no', 'action_flags', 'dg_hierarchy_l1', 'dg_hierarchy_l2',
        'dg_hierarchy_l3', 'dg_hierarchy_l4', 'vsys_name', 'device_name', 'future_use_3',
        'future_use_4', 'high_res_timestamp'
    ]

    # HIP-MATCH log fields - GlobalProtect Host Information Profile
    HIPMATCH_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'src_user', 'vsys', 'machine_name',
        'os', 'src_ip', 'hip_match_name', 'repeat_count', 'hip_match_type',
        'future_use_3', 'future_use_4', 'seq_no', 'action_flags', 'dg_hierarchy_l1',
        'dg_hierarchy_l2', 'dg_hierarchy_l3', 'dg_hierarchy_l4', 'vsys_name', 'device_name',
        'vsys_id', 'ipv6', 'hostid', 'serial_number', 'mac',
        'high_res_timestamp', 'endpoint_serial_number'
    ]

    # CORRELATION log fields - Correlated security events
    CORRELATION_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'src_ip', 'src_user', 'vsys',
        'category', 'severity', 'dg_hierarchy_l1', 'dg_hierarchy_l2', 'dg_hierarchy_l3',
        'dg_hierarchy_l4', 'vsys_name', 'device_name', 'vsys_id', 'object_name',
        'object_id', 'evidence', 'future_use_3', 'high_res_timestamp'
    ]

    # USERID log fields - User identification events
    USERID_FIELDS = [
        'future_use_1', 'receive_time', 'serial', 'type', 'subtype',
        'future_use_2', 'generated_time', 'vsys', 'src_ip', 'source_name',
        'event_id', 'repeat_count', 'timeout_threshold', 'src_port', 'dst_port',
        'data_source', 'data_source_name', 'data_source_type', 'seq_no', 'action_flags',
        'dg_hierarchy_l1', 'dg_hierarchy_l2', 'dg_hierarchy_l3', 'dg_hierarchy_l4', 'vsys_name',
        'device_name', 'vsys_id', 'factor_type', 'factor_completion_time', 'factor_no',
        'ugflags', 'user_by_source', 'high_res_timestamp', 'tag_name'
    ]

    # URL log fields - URL filtering events
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

    # WILDFIRE log fields - Malware analysis results
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

    # DATA log fields - Data filtering/DLP events
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

    # AUTHENTICATION log fields - Authentication events
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

    # GLOBALPROTECT log fields - GlobalProtect VPN events
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

    # DECRYPTION log fields - SSL/TLS decryption events
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

    # SCTP log fields - SCTP protocol events
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
        'HIP-MATCH': HIPMATCH_FIELDS,  # Alternative format
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

    # Field name normalization map - maps Palo Alto fields to common field names
    # Used for ClickHouse materialized columns and consistent querying
    FIELD_NORMALIZATION = {
        # Source/Destination IP normalization
        'src_ip': 'srcip',
        'dst_ip': 'dstip',
        'nat_src_ip': 'nat_srcip',
        'nat_dst_ip': 'nat_dstip',
        # Port normalization
        'src_port': 'srcport',
        'dst_port': 'dstport',
        # Zone normalization
        'src_zone': 'srczone',
        'dst_zone': 'dstzone',
        # User normalization
        'src_user': 'srcuser',
        'dst_user': 'dstuser',
        # Interface normalization
        'inbound_if': 'srcintf',
        'outbound_if': 'dstintf',
        # Other common fields
        'protocol': 'proto',
        'application': 'app',
    }

    def parse(self, message):
        """
        Parse a Palo Alto log message.

        Supports three formats:
        1. CEF (Common Event Format) - starts with "CEF:"
        2. Key-Value format - contains "=" but fewer commas
        3. CSV format (default) - comma-separated fields

        Returns:
            dict: Parsed fields with normalized field names
        """
        if not message:
            return {}

        # Strip syslog header if present (e.g., "<14>Oct 25 12:00:00 hostname ")
        message = self._strip_syslog_header(message)

        # Check for CEF format first (Common Event Format)
        if message.startswith('CEF:'):
            return self._parse_cef(message)

        # Check for LEEF format (Log Event Extended Format)
        if message.startswith('LEEF:'):
            return self._parse_leef(message)

        # Try to detect if it's a key=value format (some PA configs use this)
        # Key=value format has many = signs and typically doesn't start with a comma-heavy structure
        if '=' in message and message.count('=') > message.count(',') / 3:
            return self._parse_kv(message)

        # Default: CSV format (most common for Palo Alto syslog)
        return self._parse_csv(message)

    def _strip_syslog_header(self, message):
        """Strip RFC 3164/5424 syslog header if present."""
        # Pattern for RFC 3164: <PRI>Mmm DD HH:MM:SS hostname
        # Pattern for RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
        import re

        # Check for PRI at start
        if message.startswith('<'):
            # Find the end of PRI
            pri_end = message.find('>')
            if pri_end != -1 and pri_end < 5:
                message = message[pri_end + 1:].lstrip()

                # Try to skip timestamp and hostname for RFC 3164
                # Format: "Oct 25 12:00:00 hostname "
                rfc3164_pattern = r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+'
                match = re.match(rfc3164_pattern, message)
                if match:
                    message = message[match.end():]

        # Also handle if message starts directly with timestamp (no PRI)
        # PAN-OS often sends: "1,YYYY/MM/DD HH:MM:SS,serial,..."
        return message

    def _parse_csv(self, message):
        """
        Parse Palo Alto CSV format logs.

        CSV structure:
        - Field 0: FUTURE_USE (empty or "1")
        - Field 1: Receive Time (YYYY/MM/DD HH:MM:SS)
        - Field 2: Serial Number
        - Field 3: Type (TRAFFIC, THREAT, SYSTEM, etc.)
        - Field 4+: Type-specific fields
        """
        data = {}

        # Split by comma, handling quoted fields
        fields = self._split_csv(message)

        if len(fields) < 4:
            return data

        # Determine log type from field 3
        log_type = fields[3].upper() if len(fields) > 3 else 'UNKNOWN'
        data['log_type'] = log_type

        # Get field mapping for this log type
        field_names = self.LOG_TYPE_FIELDS.get(log_type)

        if not field_names:
            # Unknown log type - create generic field mapping
            field_names = [f'field_{i}' for i in range(len(fields))]

        # Map fields to names
        for i, value in enumerate(fields):
            if i < len(field_names):
                field_name = field_names[i]
            else:
                field_name = f'field_{i}'

            # Skip empty or future_use fields
            if value and not field_name.startswith('future_use'):
                # Store original field
                data[field_name] = value

        # Normalize field names for consistency with other parsers
        normalized_data = self._normalize_fields(data)

        # Create combined datetime field for easier querying
        if 'receive_time' in data:
            normalized_data['log_datetime'] = data['receive_time']
        elif 'generated_time' in data:
            normalized_data['log_datetime'] = data['generated_time']

        return normalized_data

    def _split_csv(self, message):
        """
        Split CSV handling quoted fields correctly.

        Handles:
        - Standard comma separation
        - Double-quoted fields with embedded commas
        - Empty fields (consecutive commas)
        """
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

        # Don't forget the last field
        fields.append(''.join(current_field).strip())
        return fields

    def _normalize_fields(self, data):
        """
        Normalize Palo Alto field names to common field names.

        This ensures consistency with other parser outputs and allows
        ClickHouse materialized columns to work across different vendors.
        """
        normalized = dict(data)  # Keep original fields

        for pa_field, common_field in self.FIELD_NORMALIZATION.items():
            if pa_field in data:
                normalized[common_field] = data[pa_field]

        return normalized

    def _parse_kv(self, message):
        """
        Parse key=value format.

        Some Palo Alto configurations output in key=value pairs:
        type=TRAFFIC src=192.168.1.1 dst=10.0.0.1 action=allow
        """
        data = {}
        pattern = r'([a-zA-Z0-9_-]+)=("(?:[^"\\]|\\.)*"|[^\s,]+)'
        matches = re.findall(pattern, message)

        for key, value in matches:
            # Remove surrounding quotes
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
                # Unescape escaped quotes
                value = value.replace('\\"', '"')
            data[key.lower()] = value

        # Try to determine log type
        if 'type' in data:
            data['log_type'] = data['type'].upper()

        return self._normalize_fields(data)

    def _parse_cef(self, message):
        """
        Parse CEF (Common Event Format) logs.

        CEF Format:
        CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

        Example:
        CEF:0|Palo Alto Networks|PAN-OS|10.0.0|traffic|TRAFFIC|3|src=192.168.1.1 dst=10.0.0.1
        """
        data = {}
        data['log_format'] = 'CEF'

        # Split header from extension
        parts = message.split('|', 7)

        if len(parts) >= 7:
            data['cef_version'] = parts[0].replace('CEF:', '')
            data['device_vendor'] = parts[1]
            data['device_product'] = parts[2]
            data['device_version'] = parts[3]
            data['signature_id'] = parts[4]
            data['name'] = parts[5]
            data['cef_severity'] = parts[6]

            # Determine log type from signature_id or name
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

            # Parse extension (key=value pairs after the 7th |)
            if len(parts) > 7:
                extension = parts[7]
                ext_data = self._parse_cef_extension(extension)
                data.update(ext_data)

        return self._normalize_fields(data)

    def _parse_cef_extension(self, extension):
        """
        Parse CEF extension field (space-separated key=value pairs).

        CEF extensions use specific key names:
        - src: Source IP
        - dst: Destination IP
        - spt: Source Port
        - dpt: Destination Port
        - act: Action
        - cs1-cs6: Custom strings
        """
        data = {}

        # CEF extension pattern - handles spaces in values followed by known keys
        # Known CEF keys for proper parsing
        cef_keys = {
            'src', 'dst', 'spt', 'dpt', 'act', 'proto', 'app', 'deviceExternalId',
            'duser', 'suser', 'fname', 'msg', 'rt', 'cat', 'dvc', 'dvchost',
            'cs1', 'cs2', 'cs3', 'cs4', 'cs5', 'cs6',
            'cs1Label', 'cs2Label', 'cs3Label', 'cs4Label', 'cs5Label', 'cs6Label',
            'cn1', 'cn2', 'cn3', 'cn1Label', 'cn2Label', 'cn3Label',
            'deviceInboundInterface', 'deviceOutboundInterface',
            'sourceTranslatedAddress', 'destinationTranslatedAddress',
            'sourceTranslatedPort', 'destinationTranslatedPort',
            'flexString1', 'flexString2', 'PanOSSourceLocation', 'PanOSDestinationLocation'
        }

        pattern = r'(\w+)=((?:[^=](?!(?:\s\w+=)))*[^=\s]?)'
        matches = re.findall(pattern, extension)

        # CEF to common field mapping
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
            # Map to common field name if known
            if key in cef_mapping:
                data[cef_mapping[key]] = value
            data[key] = value

        return data

    def _parse_leef(self, message):
        """
        Parse LEEF (Log Event Extended Format) logs.

        LEEF Format (IBM QRadar):
        LEEF:Version|Vendor|Product|Version|EventID|Extension

        Extension uses tab or specified delimiter for key=value pairs.
        """
        data = {}
        data['log_format'] = 'LEEF'

        parts = message.split('|', 5)

        if len(parts) >= 5:
            leef_header = parts[0]  # LEEF:Version or LEEF:Version:Delimiter
            data['leef_version'] = leef_header.replace('LEEF:', '').split(':')[0]
            data['device_vendor'] = parts[1]
            data['device_product'] = parts[2]
            data['device_version'] = parts[3]
            data['event_id'] = parts[4]

            # Determine log type from event_id
            event_id = parts[4].upper()
            if 'TRAFFIC' in event_id:
                data['log_type'] = 'TRAFFIC'
            elif 'THREAT' in event_id:
                data['log_type'] = 'THREAT'
            else:
                data['log_type'] = event_id

            # Parse extension (key=value pairs with tab or custom delimiter)
            if len(parts) > 5:
                extension = parts[5]
                # LEEF 2.0 can specify custom delimiter in header
                delimiter = '\t'  # Default tab
                if ':' in leef_header and len(leef_header.split(':')) > 2:
                    delimiter = leef_header.split(':')[2]

                ext_data = self._parse_leef_extension(extension, delimiter)
                data.update(ext_data)

        return self._normalize_fields(data)

    def _parse_leef_extension(self, extension, delimiter='\t'):
        """Parse LEEF extension with specified delimiter."""
        data = {}

        # Split by delimiter
        pairs = extension.split(delimiter)

        for pair in pairs:
            if '=' in pair:
                key, _, value = pair.partition('=')
                key = key.strip()
                value = value.strip()
                if key:
                    data[key.lower()] = value

        return data


PARSER_MAP = {
    'GENERIC': GenericParser(),
    'FORTINET': FortinetParser(),
    'PALOALTO': PaloAltoParser(),
}


def get_parser(parser_name):
    return PARSER_MAP.get(parser_name, GenericParser())
