"""
Curated correlation rule templates (Phase 6).

A template is a ready-to-use rule definition an analyst can load into the
builder as a starting point. Each declares the data sources it needs so the
UI can flag templates that are not usable on this deployment ("data-aware
discovery"). Templates are MITRE-mapped, grouped by tactic.

This is a starter library; templates can be extended freely — each is just a
dict whose ``rule`` body matches the create-rule payload.
"""

TEMPLATES = [
    # ── Reconnaissance ───────────────────────────────────────────────
    {
        "id": "port-scan",
        "name": "Port Scan Detection",
        "description": "A single source IP denied on many ports in a short window — classic active scanning.",
        "category": "Reconnaissance",
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1595 - Active Scanning",
        "required_sources": ["syslogs"],
        "rule": {
            "severity": "medium", "ordering": "sequence", "match_mode": "discrete",
            "suppress_window": 3600, "join_keys": ["ip"],
            "stages": [
                {"name": "Many Denied Ports", "source": "syslogs",
                 "filter": {"action": "deny", "group_by": "srcip"},
                 "threshold": 15, "window": 300},
            ],
        },
    },
    {
        "id": "recon-then-access",
        "name": "Reconnaissance then Access",
        "description": "Port scan from an IP followed by an allowed connection from the same IP.",
        "category": "Reconnaissance",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "required_sources": ["syslogs"],
        "rule": {
            "severity": "high", "ordering": "sequence", "match_mode": "discrete",
            "suppress_window": 3600, "join_keys": ["ip"],
            "stages": [
                {"name": "Port Scan", "source": "syslogs",
                 "filter": {"action": "deny", "group_by": "srcip"},
                 "threshold": 10, "window": 300},
                {"name": "Successful Access", "source": "syslogs",
                 "filter": {"action": "allow"}, "threshold": 1, "window": 600},
            ],
        },
    },
    # ── Credential Access ────────────────────────────────────────────
    {
        "id": "brute-force-then-login",
        "name": "Brute Force then Login",
        "description": "Many denied connections followed by an allowed one from the same source — a likely successful brute force.",
        "category": "Credential Access",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110 - Brute Force",
        "required_sources": ["syslogs"],
        "rule": {
            "severity": "critical", "ordering": "sequence", "match_mode": "discrete",
            "suppress_window": 3600, "join_keys": ["ip"],
            "stages": [
                {"name": "Repeated Denials", "source": "syslogs",
                 "filter": {"action": "deny", "group_by": "srcip"},
                 "threshold": 20, "window": 300},
                {"name": "Successful Login", "source": "syslogs",
                 "filter": {"action": "allow"}, "threshold": 1, "window": 600},
            ],
        },
    },
    # ── Command and Control ──────────────────────────────────────────
    {
        "id": "ioc-then-traffic",
        "name": "Threat-Intel Source then Traffic",
        "description": "An IP flagged by a threat-intel feed is still seen in firewall traffic — known-bad infrastructure.",
        "category": "Command and Control",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071 - Application Layer Protocol",
        "required_sources": ["ioc_matches", "syslogs"],
        "rule": {
            "severity": "high", "ordering": "any_order", "match_mode": "discrete",
            "suppress_window": 7200, "join_keys": ["ip"],
            "stages": [
                {"name": "Threat-Intel IOC Hit", "source": "ioc_matches",
                 "filter": {"group_by": "ip"}, "threshold": 1, "window": 86400},
                {"name": "Firewall Traffic", "source": "syslogs",
                 "filter": {"action": "deny"}, "threshold": 5, "window": 86400},
            ],
        },
    },
    {
        "id": "suspicious-dns",
        "name": "Suspicious DNS Category Spike",
        "description": "A host making many DNS queries in a security-related category.",
        "category": "Command and Control",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071.004 - DNS",
        "required_sources": ["dns_logs"],
        "rule": {
            "severity": "medium", "ordering": "sequence", "match_mode": "discrete",
            "suppress_window": 3600, "join_keys": ["ip"],
            "stages": [
                {"name": "Security-Category DNS", "source": "dns_logs",
                 "filter": {"category": "Information and Computer Security",
                            "group_by": "ip"},
                 "threshold": 5, "window": 600},
            ],
        },
    },
    # ── Exfiltration ─────────────────────────────────────────────────
    {
        "id": "high-outbound",
        "name": "High Outbound Volume",
        "description": "A single internal IP generating an unusually high volume of allowed outbound traffic.",
        "category": "Exfiltration",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
        "required_sources": ["syslogs"],
        "rule": {
            "severity": "high", "ordering": "sequence", "match_mode": "discrete",
            "suppress_window": 3600, "join_keys": ["ip"],
            "stages": [
                {"name": "High Outbound Volume", "source": "syslogs",
                 "filter": {"action": "allow", "group_by": "srcip"},
                 "threshold": 500, "window": 300},
            ],
        },
    },
    {
        "id": "dns-then-exfil",
        "name": "Suspicious DNS then High Volume",
        "description": "A security-category DNS lookup followed by a high-volume outbound connection from the same host.",
        "category": "Exfiltration",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
        "required_sources": ["dns_logs", "syslogs"],
        "rule": {
            "severity": "high", "ordering": "any_order", "match_mode": "discrete",
            "suppress_window": 3600, "join_keys": ["ip"],
            "stages": [
                {"name": "Security-Category DNS", "source": "dns_logs",
                 "filter": {"category": "Information and Computer Security",
                            "group_by": "ip"},
                 "threshold": 1, "window": 3600},
                {"name": "High Outbound Volume", "source": "syslogs",
                 "filter": {"action": "allow"}, "threshold": 300, "window": 3600},
            ],
        },
    },
    # ── Defense Evasion ──────────────────────────────────────────────
    {
        "id": "denied-then-allowed",
        "name": "Denied then Allowed - Policy Bypass",
        "description": "A source denied repeatedly then allowed through — possible policy bypass or misconfiguration.",
        "category": "Defense Evasion",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562 - Impair Defenses",
        "required_sources": ["syslogs"],
        "rule": {
            "severity": "medium", "ordering": "sequence", "match_mode": "discrete",
            "suppress_window": 3600, "join_keys": ["ip"],
            "stages": [
                {"name": "Repeated Denials", "source": "syslogs",
                 "filter": {"action": "deny", "group_by": "srcip"},
                 "threshold": 5, "window": 600},
                {"name": "Access Granted", "source": "syslogs",
                 "filter": {"action": "allow"}, "threshold": 1, "window": 900},
            ],
        },
    },
    # ── Initial Access ───────────────────────────────────────────────
    {
        "id": "pa-threat-then-allow",
        "name": "Threat Alert then Allowed Traffic",
        "description": "A Palo Alto threat alert for a host that also has allowed firewall traffic.",
        "category": "Initial Access",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "required_sources": ["pa_threat_logs", "syslogs"],
        "rule": {
            "severity": "high", "ordering": "any_order", "match_mode": "discrete",
            "suppress_window": 3600, "join_keys": ["ip"],
            "stages": [
                {"name": "PA Threat Alert", "source": "pa_threat_logs",
                 "filter": {"severity": "high", "group_by": "ip"},
                 "threshold": 1, "window": 3600},
                {"name": "Allowed Firewall Traffic", "source": "syslogs",
                 "filter": {"action": "allow"}, "threshold": 1, "window": 3600},
            ],
        },
    },
    # ── Discovery ────────────────────────────────────────────────────
    {
        "id": "multi-device-scan",
        "name": "Multi-Firewall Scan",
        "description": "The same source IP denied across many firewall events — broad network discovery.",
        "category": "Discovery",
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1046 - Network Service Discovery",
        "required_sources": ["syslogs"],
        "rule": {
            "severity": "high", "ordering": "sequence", "match_mode": "discrete",
            "suppress_window": 3600, "join_keys": ["ip"],
            "stages": [
                {"name": "Multi-Device Denials", "source": "syslogs",
                 "filter": {"action": "deny", "group_by": "srcip"},
                 "threshold": 15, "window": 300},
            ],
        },
    },
    # ── Impact ───────────────────────────────────────────────────────
    {
        "id": "malware-url-access",
        "name": "Malware / Phishing URL Access",
        "description": "A host accessing URLs in a high-risk web category.",
        "category": "Impact",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071.001 - Web Protocols",
        "required_sources": ["url_logs"],
        "rule": {
            "severity": "high", "ordering": "sequence", "match_mode": "discrete",
            "suppress_window": 3600, "join_keys": ["ip"],
            "stages": [
                {"name": "High-Risk URL Access", "source": "url_logs",
                 "filter": {"url_category": "Malware", "group_by": "ip"},
                 "threshold": 1, "window": 600},
            ],
        },
    },
    {
        "id": "audit-config-change",
        "name": "Burst of Admin Config Changes",
        "description": "A platform user making many configuration changes in a short window.",
        "category": "Defense Evasion",
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1562 - Impair Defenses",
        "required_sources": ["audit_logs"],
        "rule": {
            "severity": "medium", "ordering": "sequence", "match_mode": "discrete",
            "suppress_window": 3600, "join_keys": ["user"],
            "stages": [
                {"name": "Config Change Burst", "source": "audit_logs",
                 "filter": {"group_by": "user"}, "threshold": 10, "window": 600},
            ],
        },
    },
]
