"""
MITRE ATT&CK Framework reference data for firewall/network detections.
Enterprise ATT&CK v14 - focused on techniques detectable via network/firewall logs.
"""

# All 14 Enterprise ATT&CK Tactics in kill-chain order
TACTICS = [
    {"id": "TA0043", "name": "Reconnaissance", "description": "Gathering information to plan future operations."},
    {"id": "TA0042", "name": "Resource Development", "description": "Establishing resources to support operations."},
    {"id": "TA0001", "name": "Initial Access", "description": "Trying to get into your network."},
    {"id": "TA0002", "name": "Execution", "description": "Trying to run malicious code."},
    {"id": "TA0003", "name": "Persistence", "description": "Trying to maintain their foothold."},
    {"id": "TA0004", "name": "Privilege Escalation", "description": "Trying to gain higher-level permissions."},
    {"id": "TA0005", "name": "Defense Evasion", "description": "Trying to avoid being detected."},
    {"id": "TA0006", "name": "Credential Access", "description": "Trying to steal account names and passwords."},
    {"id": "TA0007", "name": "Discovery", "description": "Trying to figure out your environment."},
    {"id": "TA0008", "name": "Lateral Movement", "description": "Trying to move through your environment."},
    {"id": "TA0009", "name": "Collection", "description": "Trying to gather data of interest."},
    {"id": "TA0011", "name": "Command and Control", "description": "Trying to communicate with compromised systems."},
    {"id": "TA0010", "name": "Exfiltration", "description": "Trying to steal data."},
    {"id": "TA0040", "name": "Impact", "description": "Trying to manipulate, interrupt, or destroy systems and data."},
]

# Network/firewall-detectable techniques organized by tactic
# Each technique: id, name, description, detectable (bool - can we detect via firewall logs)
TECHNIQUES = {
    "Reconnaissance": [
        {"id": "T1595", "name": "Active Scanning", "description": "Scanning IP blocks to gather victim network info.", "detectable": True},
        {"id": "T1595.001", "name": "Scanning IP Blocks", "description": "Scanning IP ranges to find active hosts.", "detectable": True},
        {"id": "T1595.002", "name": "Vulnerability Scanning", "description": "Scanning for software vulnerabilities.", "detectable": True},
        {"id": "T1590", "name": "Gather Victim Network Info", "description": "Gathering info about victim network.", "detectable": False},
        {"id": "T1592", "name": "Gather Victim Host Info", "description": "Gathering info about victim hosts.", "detectable": False},
    ],
    "Resource Development": [
        {"id": "T1583", "name": "Acquire Infrastructure", "description": "Buying/renting infrastructure for attacks.", "detectable": False},
        {"id": "T1584", "name": "Compromise Infrastructure", "description": "Compromising third-party infrastructure.", "detectable": False},
        {"id": "T1587", "name": "Develop Capabilities", "description": "Building malware and tools.", "detectable": False},
    ],
    "Initial Access": [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "description": "Exploiting vulnerabilities in internet-facing apps.", "detectable": True},
        {"id": "T1133", "name": "External Remote Services", "description": "Leveraging VPNs, Citrix, and other remote services.", "detectable": True},
        {"id": "T1078", "name": "Valid Accounts", "description": "Using stolen or leaked credentials.", "detectable": True},
        {"id": "T1566", "name": "Phishing", "description": "Sending phishing messages to gain access.", "detectable": False},
        {"id": "T1199", "name": "Trusted Relationship", "description": "Abusing trusted third-party access.", "detectable": True},
    ],
    "Execution": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "description": "Abusing command-line interpreters.", "detectable": False},
        {"id": "T1203", "name": "Exploitation for Client Execution", "description": "Exploiting software vulnerabilities for execution.", "detectable": False},
    ],
    "Persistence": [
        {"id": "T1133", "name": "External Remote Services", "description": "Maintaining access via remote services.", "detectable": True},
        {"id": "T1078", "name": "Valid Accounts", "description": "Using valid accounts for persistent access.", "detectable": True},
    ],
    "Privilege Escalation": [
        {"id": "T1078", "name": "Valid Accounts", "description": "Using valid accounts to escalate privileges.", "detectable": True},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation", "description": "Exploiting vulnerabilities for privilege escalation.", "detectable": False},
    ],
    "Defense Evasion": [
        {"id": "T1562", "name": "Impair Defenses", "description": "Disabling or modifying security tools.", "detectable": True},
        {"id": "T1562.004", "name": "Disable or Modify System Firewall", "description": "Disabling firewall rules.", "detectable": True},
        {"id": "T1090", "name": "Proxy", "description": "Using proxies to hide C2 traffic.", "detectable": True},
        {"id": "T1090.002", "name": "External Proxy", "description": "Using external proxy services.", "detectable": True},
        {"id": "T1027", "name": "Obfuscated Files or Information", "description": "Encoding data to evade detection.", "detectable": False},
    ],
    "Credential Access": [
        {"id": "T1110", "name": "Brute Force", "description": "Attempting many passwords to gain access.", "detectable": True},
        {"id": "T1110.001", "name": "Password Guessing", "description": "Guessing passwords for accounts.", "detectable": True},
        {"id": "T1110.003", "name": "Password Spraying", "description": "Trying one password across many accounts.", "detectable": True},
        {"id": "T1040", "name": "Network Sniffing", "description": "Sniffing network traffic for credentials.", "detectable": False},
    ],
    "Discovery": [
        {"id": "T1046", "name": "Network Service Scanning", "description": "Scanning for running network services.", "detectable": True},
        {"id": "T1018", "name": "Remote System Discovery", "description": "Discovering remote systems on network.", "detectable": True},
        {"id": "T1049", "name": "System Network Connections Discovery", "description": "Listing network connections.", "detectable": False},
        {"id": "T1135", "name": "Network Share Discovery", "description": "Discovering shared network resources.", "detectable": True},
    ],
    "Lateral Movement": [
        {"id": "T1021", "name": "Remote Services", "description": "Using remote services to move laterally.", "detectable": True},
        {"id": "T1021.001", "name": "Remote Desktop Protocol", "description": "Using RDP to move between systems.", "detectable": True},
        {"id": "T1021.004", "name": "SSH", "description": "Using SSH to move between systems.", "detectable": True},
        {"id": "T1080", "name": "Taint Shared Content", "description": "Delivering payloads through shared storage.", "detectable": False},
    ],
    "Collection": [
        {"id": "T1560", "name": "Archive Collected Data", "description": "Compressing collected data before exfil.", "detectable": False},
        {"id": "T1039", "name": "Data from Network Shared Drive", "description": "Accessing data from network shares.", "detectable": True},
    ],
    "Command and Control": [
        {"id": "T1071", "name": "Application Layer Protocol", "description": "Using app protocols for C2.", "detectable": True},
        {"id": "T1071.001", "name": "Web Protocols", "description": "Using HTTP/HTTPS for C2.", "detectable": True},
        {"id": "T1071.004", "name": "DNS", "description": "Using DNS for C2 communications.", "detectable": True},
        {"id": "T1573", "name": "Encrypted Channel", "description": "Using encryption for C2.", "detectable": True},
        {"id": "T1572", "name": "Protocol Tunneling", "description": "Tunneling within allowed protocols.", "detectable": True},
        {"id": "T1095", "name": "Non-Application Layer Protocol", "description": "Using non-app protocols for C2.", "detectable": True},
        {"id": "T1219", "name": "Remote Access Software", "description": "Using remote access tools for C2.", "detectable": True},
    ],
    "Exfiltration": [
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "description": "Using non-standard protocols for data theft.", "detectable": True},
        {"id": "T1048.001", "name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol", "description": "Encrypted exfiltration.", "detectable": True},
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "description": "Exfiltrating data over existing C2.", "detectable": True},
        {"id": "T1567", "name": "Exfiltration Over Web Service", "description": "Exfiltrating data to cloud services.", "detectable": True},
        {"id": "T1020", "name": "Automated Exfiltration", "description": "Automated data exfiltration.", "detectable": True},
    ],
    "Impact": [
        {"id": "T1498", "name": "Network Denial of Service", "description": "Performing DoS to disrupt availability.", "detectable": True},
        {"id": "T1498.001", "name": "Direct Network Flood", "description": "Flooding network with traffic.", "detectable": True},
        {"id": "T1499", "name": "Endpoint Denial of Service", "description": "Exhausting endpoint resources.", "detectable": True},
        {"id": "T1499.004", "name": "Application or System Exploitation", "description": "Exploiting apps to cause DoS.", "detectable": True},
        {"id": "T1489", "name": "Service Stop", "description": "Stopping services to impact availability.", "detectable": True},
        {"id": "T1529", "name": "System Shutdown/Reboot", "description": "Shutting down systems.", "detectable": True},
    ],
}


def get_tactic_names():
    """Return list of tactic names in kill-chain order."""
    return [t["name"] for t in TACTICS]


def get_techniques_for_tactic(tactic_name: str):
    """Return techniques for a given tactic."""
    return TECHNIQUES.get(tactic_name, [])


def get_all_technique_ids():
    """Return set of all technique IDs."""
    ids = set()
    for techniques in TECHNIQUES.values():
        for t in techniques:
            ids.add(t["id"])
    return ids


def get_detectable_technique_ids():
    """Return set of technique IDs that are detectable via firewall logs."""
    ids = set()
    for techniques in TECHNIQUES.values():
        for t in techniques:
            if t.get("detectable"):
                ids.add(t["id"])
    return ids
