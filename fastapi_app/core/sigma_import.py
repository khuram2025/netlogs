"""
Sigma rule import (Phase 6).

Best-effort conversion of a single-source Sigma detection rule (the open
detection format) into a Zentryc correlation-rule draft. The draft is loaded
into the builder for the analyst to review and adjust — Sigma uses generic
field names, so a field map covers the common ones and the rest pass through
for the analyst to correct before saving.
"""

import yaml

# Sigma / generic field name -> Zentryc syslogs column.
_FIELD_MAP = {
    "src_ip": "srcip", "source_ip": "srcip", "sourceip": "srcip", "src": "srcip",
    "srcip": "srcip",
    "dst_ip": "dstip", "destination_ip": "dstip", "dest_ip": "dstip", "dst": "dstip",
    "dstip": "dstip",
    "dst_port": "dstport", "destination_port": "dstport", "dest_port": "dstport",
    "dstport": "dstport",
    "src_port": "srcport", "source_port": "srcport", "srcport": "srcport",
    "action": "action", "protocol": "proto", "proto": "proto",
    "application": "application", "app": "application",
}

_SEVERITY_MAP = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "informational": "low", "info": "low",
}


def parse_sigma(yaml_text: str):
    """Convert Sigma YAML into a correlation-rule draft.

    Returns ``(rule_dict, warnings)``. Raises ``ValueError`` if the document
    is not a usable single-selection Sigma rule.
    """
    warnings = []
    doc = yaml.safe_load(yaml_text)
    if not isinstance(doc, dict):
        raise ValueError("not a valid Sigma YAML document")

    title = (doc.get("title") or "Imported Sigma Rule").strip()
    description = (doc.get("description") or "").strip()
    level = _SEVERITY_MAP.get(str(doc.get("level", "medium")).lower(), "medium")

    # MITRE ATT&CK from tags (e.g. attack.t1110, attack.credential_access).
    tactic, technique = "", ""
    for tag in (doc.get("tags") or []):
        t = str(tag).lower()
        if t.startswith("attack.t") and not technique:
            technique = tag.split(".")[-1].upper()
        elif t.startswith("attack.") and not tactic:
            tactic = tag.split(".", 1)[1].replace("_", " ").title()

    detection = doc.get("detection") or {}
    if not isinstance(detection, dict):
        raise ValueError("Sigma 'detection' section is missing or malformed")

    # Use the first selection-style block (a dict that is not 'condition').
    selection = None
    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict):
            selection = value
            break
    if selection is None:
        raise ValueError("Sigma 'detection' has no usable selection block")

    filt = {}
    for field, value in selection.items():
        base = str(field).split("|")[0].lower()
        if "|" in str(field):
            warnings.append(f"field modifier on '{field}' dropped — using equality")
        mapped = _FIELD_MAP.get(base, base)
        if mapped not in _FIELD_MAP.values():
            warnings.append(f"field '{base}' has no known mapping — review before saving")
        if isinstance(value, list):
            warnings.append(f"'{field}' had multiple values — using the first")
            value = value[0] if value else ""
        filt[mapped] = value

    if not filt:
        raise ValueError("Sigma selection produced no usable conditions")

    condition = str(detection.get("condition", "")).strip()
    if condition and condition not in ("selection",) and not condition.startswith("selection"):
        warnings.append(
            f"Sigma condition '{condition}' simplified to a single-stage rule")

    rule = {
        "name": title[:200],
        "description": description[:2000],
        "severity": level,
        "mitre_tactic": tactic[:100],
        "mitre_technique": technique[:100],
        "ordering": "sequence",
        "match_mode": "discrete",
        "suppress_window": 3600,
        "join_keys": ["ip"],
        "stages": [{
            "name": title[:120],
            "source": "syslogs",
            "filter": {**filt, "group_by": "srcip"},
            "threshold": 1,
            "window": 300,
        }],
    }
    return rule, warnings
