"""API routes for Address Objects management."""

import csv
import io
import json
import re
import ipaddress
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, Request, Form, UploadFile, File, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, func

from fastapi_app.core.auth import get_current_user
from fastapi_app.db.database import get_db
from fastapi_app.models.address_object import AddressObject

router = APIRouter()
templates = Jinja2Templates(directory="fastapi_app/templates")


# =====================================================================
#  PARSERS  —  Import from firewall configs
# =====================================================================

def parse_fortigate(config_text: str) -> List[dict]:
    """Parse FortiGate 'config firewall address' and 'config firewall addrgrp' blocks."""
    objects = []
    current = None
    in_group = False

    for line in config_text.splitlines():
        line = line.strip()

        # Detect address-group section
        if line == "config firewall addrgrp":
            in_group = True
            continue
        elif line == "config firewall address":
            in_group = False
            continue

        if line.startswith('edit "') or line.startswith("edit '") or line.startswith("edit "):
            match = re.match(r'edit\s+["\']?(.+?)["\']?\s*$', line)
            if match:
                if in_group:
                    current = {"name": match.group(1), "obj_type": "group", "value": "group", "members": "", "description": ""}
                else:
                    current = {"name": match.group(1), "obj_type": "subnet", "value": "", "description": ""}

        elif line == "next" or line == "end":
            if current and current.get("value"):
                objects.append(current)
            if line == "end":
                in_group = False
            current = None

        elif current:
            if line.startswith("set subnet "):
                parts = line.replace("set subnet ", "").strip().split()
                if len(parts) == 2:
                    ip_addr, mask = parts[0], parts[1]
                    try:
                        prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                        if prefix_len == 32:
                            current["obj_type"] = "host"
                            current["value"] = ip_addr
                        else:
                            current["obj_type"] = "subnet"
                            current["value"] = f"{ip_addr}/{prefix_len}"
                    except (ValueError, TypeError):
                        current["value"] = f"{ip_addr} {mask}"
                elif len(parts) == 1:
                    current["value"] = parts[0]

            elif line.startswith("set type fqdn"):
                current["obj_type"] = "fqdn"

            elif line.startswith("set type iprange"):
                current["obj_type"] = "range"

            elif line.startswith("set type geography"):
                current["obj_type"] = "host"

            elif line.startswith("set fqdn "):
                val = line.replace("set fqdn ", "").strip().strip('"').strip("'")
                current["value"] = val
                current["obj_type"] = "fqdn"

            elif line.startswith("set start-ip "):
                current["_start_ip"] = line.replace("set start-ip ", "").strip()

            elif line.startswith("set end-ip "):
                current["_end_ip"] = line.replace("set end-ip ", "").strip()
                if current.get("_start_ip"):
                    current["value"] = f"{current['_start_ip']}-{current['_end_ip']}"
                    current["obj_type"] = "range"

            elif line.startswith("set comment "):
                current["description"] = line.replace("set comment ", "").strip().strip('"').strip("'")

            elif line.startswith("set member "):
                # Address group members
                members_str = line.replace("set member ", "").strip()
                members = [m.strip().strip('"').strip("'") for m in re.split(r'\s+', members_str) if m.strip().strip('"').strip("'")]
                current["members"] = ",".join(members)
                current["value"] = "group"

            elif line.startswith("set country "):
                current["value"] = line.replace("set country ", "").strip().strip('"')

    if current and current.get("value"):
        objects.append(current)

    for obj in objects:
        obj.pop("_start_ip", None)
        obj.pop("_end_ip", None)

    return objects


def parse_paloalto(config_text: str) -> List[dict]:
    """Parse Palo Alto 'set address' commands."""
    objects = []
    descriptions = {}

    for line in config_text.splitlines():
        line = line.strip()
        if not line.startswith("set address "):
            continue

        # Description line
        desc_match = re.match(r'set address\s+(\S+)\s+description\s+"?(.+?)"?\s*$', line)
        if desc_match:
            descriptions[desc_match.group(1)] = desc_match.group(2)
            continue

        # Tag line
        if re.match(r'set address\s+\S+\s+tag\s+', line):
            continue

        match = re.match(r'set address\s+(\S+)\s+(ip-netmask|fqdn|ip-range|ip-wildcard)\s+(.+)', line)
        if match:
            name = match.group(1)
            addr_type = match.group(2)
            value = match.group(3).strip().strip('"').strip("'")

            obj = {"name": name, "value": value, "description": ""}

            if addr_type == "ip-netmask":
                try:
                    net = ipaddress.ip_network(value, strict=False)
                    if net.prefixlen == 32:
                        obj["obj_type"] = "host"
                        obj["value"] = str(net.network_address)
                    else:
                        obj["obj_type"] = "subnet"
                except ValueError:
                    obj["obj_type"] = "subnet"
            elif addr_type == "fqdn":
                obj["obj_type"] = "fqdn"
            elif addr_type == "ip-range":
                obj["obj_type"] = "range"
            elif addr_type == "ip-wildcard":
                obj["obj_type"] = "subnet"

            objects.append(obj)

    # Apply collected descriptions
    for obj in objects:
        if obj["name"] in descriptions:
            obj["description"] = descriptions[obj["name"]]

    return objects


def parse_cisco(config_text: str) -> List[dict]:
    """Parse Cisco ASA/IOS 'object network' and 'object-group network' blocks."""
    objects = []
    current = None

    for line in config_text.splitlines():
        stripped = line.strip()

        if line.startswith("object network "):
            if current and current.get("value"):
                objects.append(current)
            name = line.replace("object network ", "").strip()
            current = {"name": name, "obj_type": "host", "value": "", "description": ""}

        elif line.startswith("object-group network "):
            if current and current.get("value"):
                objects.append(current)
            name = line.replace("object-group network ", "").strip()
            current = {"name": name, "obj_type": "group", "value": "group", "members": "", "description": ""}

        elif current:
            if stripped.startswith("host "):
                ip = stripped.replace("host ", "").strip()
                current["obj_type"] = "host"
                current["value"] = ip

            elif stripped.startswith("subnet "):
                parts = stripped.replace("subnet ", "").strip().split()
                if len(parts) == 2:
                    try:
                        prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{parts[1]}").prefixlen
                        current["obj_type"] = "subnet"
                        current["value"] = f"{parts[0]}/{prefix_len}"
                    except (ValueError, TypeError):
                        current["value"] = f"{parts[0]} {parts[1]}"
                        current["obj_type"] = "subnet"

            elif stripped.startswith("range "):
                parts = stripped.replace("range ", "").strip().split()
                if len(parts) == 2:
                    current["obj_type"] = "range"
                    current["value"] = f"{parts[0]}-{parts[1]}"

            elif stripped.startswith("fqdn ") and not stripped.startswith("fqdn v"):
                val = stripped.replace("fqdn ", "").strip()
                current["obj_type"] = "fqdn"
                current["value"] = val

            elif stripped.startswith("description "):
                current["description"] = stripped.replace("description ", "").strip()

            elif stripped.startswith("network-object host "):
                member = stripped.replace("network-object host ", "").strip()
                if current.get("members"):
                    current["members"] += f",{member}"
                else:
                    current["members"] = member
                if not current.get("value") or current["value"] == "group":
                    current["value"] = "group"

            elif stripped.startswith("network-object object "):
                member = stripped.replace("network-object object ", "").strip()
                if current.get("members"):
                    current["members"] += f",{member}"
                else:
                    current["members"] = member
                if not current.get("value") or current["value"] == "group":
                    current["value"] = "group"

            elif stripped.startswith("network-object "):
                member = stripped.replace("network-object ", "").strip()
                if current.get("members"):
                    current["members"] += f",{member}"
                else:
                    current["members"] = member
                if not current.get("value") or current["value"] == "group":
                    current["value"] = "group"

            elif stripped.startswith("group-object "):
                member = stripped.replace("group-object ", "").strip()
                if current.get("members"):
                    current["members"] += f",{member}"
                else:
                    current["members"] = member
                if not current.get("value") or current["value"] == "group":
                    current["value"] = "group"

        # New top-level line that isn't part of current object
        if not line.startswith(" ") and not line.startswith("\t") and current and not line.startswith("object"):
            if current.get("value"):
                objects.append(current)
            current = None

    if current and current.get("value"):
        objects.append(current)

    return objects


def parse_juniper(config_text: str) -> List[dict]:
    """Parse Juniper SRX/JunOS address book entries.

    Handles:
      set security zones security-zone ZONE address-book address NAME A.B.C.D/N
      set security address-book global address NAME A.B.C.D/N
      set security address-book global address NAME dns-name FQDN
      set security address-book global address-set GRPNAME address NAME
    """
    objects = []
    group_members = {}  # group_name -> [member_names]
    descriptions = {}

    for line in config_text.splitlines():
        line = line.strip()

        # Global or zone address-book address
        m = re.match(
            r'set security (?:zones security-zone \S+ )?address-book (?:\S+ )?address (\S+)\s+(.+)', line
        )
        if m:
            name = m.group(1)
            rest = m.group(2).strip()

            if rest.startswith("description "):
                descriptions[name] = rest.replace("description ", "").strip().strip('"')
                continue

            if rest.startswith("dns-name "):
                val = rest.replace("dns-name ", "").strip().strip('"')
                objects.append({"name": name, "obj_type": "fqdn", "value": val, "description": ""})
            elif rest.startswith("range-address "):
                parts = rest.replace("range-address ", "").strip().split()
                if len(parts) >= 3 and parts[1] == "to":
                    objects.append({"name": name, "obj_type": "range", "value": f"{parts[0]}-{parts[2]}", "description": ""})
            elif rest.startswith("wildcard-address "):
                val = rest.replace("wildcard-address ", "").strip()
                objects.append({"name": name, "obj_type": "subnet", "value": val, "description": ""})
            else:
                # ip/prefix
                val = rest.strip().strip('"')
                try:
                    net = ipaddress.ip_network(val, strict=False)
                    if net.prefixlen == 32:
                        objects.append({"name": name, "obj_type": "host", "value": str(net.network_address), "description": ""})
                    else:
                        objects.append({"name": name, "obj_type": "subnet", "value": str(net), "description": ""})
                except ValueError:
                    objects.append({"name": name, "obj_type": "host", "value": val, "description": ""})
            continue

        # Address-set (group)
        m2 = re.match(
            r'set security (?:zones security-zone \S+ )?address-book (?:\S+ )?address-set (\S+)\s+address\s+(\S+)', line
        )
        if m2:
            grp = m2.group(1)
            member = m2.group(2)
            group_members.setdefault(grp, []).append(member)

    # Add groups
    for grp_name, members in group_members.items():
        objects.append({
            "name": grp_name,
            "obj_type": "group",
            "value": "group",
            "members": ",".join(members),
            "description": descriptions.get(grp_name, ""),
        })

    # Apply descriptions
    for obj in objects:
        if obj["name"] in descriptions and not obj.get("description"):
            obj["description"] = descriptions[obj["name"]]

    return objects


def parse_checkpoint(config_text: str) -> List[dict]:
    """Parse Check Point SmartConsole / dbedit / mgmt_cli style output.

    Handles multiple styles:
      mgmt_cli add host name X ip-address Y
      mgmt_cli add network name X subnet A.B.C.D subnet-mask M.M.M.M
      mgmt_cli add address-range name X ip-address-first A ip-address-last B
      dbedit style: create host_plain NAME; modify ... ; update ...
    """
    objects = []

    for line in config_text.splitlines():
        line = line.strip()

        # mgmt_cli host
        m = re.match(r'(?:mgmt_cli )?add (?:host|simple-gateway)\s+.*?name\s+"?(\S+?)"?\s+ip-address\s+"?([0-9.]+)"?', line)
        if m:
            objects.append({"name": m.group(1), "obj_type": "host", "value": m.group(2), "description": ""})
            continue

        # mgmt_cli network
        m = re.match(r'(?:mgmt_cli )?add network\s+.*?name\s+"?(\S+?)"?\s+subnet\s+"?([0-9.]+)"?\s+(?:subnet-mask|mask-length)\s+"?([0-9.]+)"?', line)
        if m:
            name, subnet, mask = m.group(1), m.group(2), m.group(3)
            try:
                if '.' in mask:
                    prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                else:
                    prefix_len = int(mask)
                objects.append({"name": name, "obj_type": "subnet", "value": f"{subnet}/{prefix_len}", "description": ""})
            except (ValueError, TypeError):
                objects.append({"name": name, "obj_type": "subnet", "value": f"{subnet} {mask}", "description": ""})
            continue

        # mgmt_cli address-range
        m = re.match(r'(?:mgmt_cli )?add address-range\s+.*?name\s+"?(\S+?)"?\s+ip-address-first\s+"?([0-9.]+)"?\s+ip-address-last\s+"?([0-9.]+)"?', line)
        if m:
            objects.append({"name": m.group(1), "obj_type": "range", "value": f"{m.group(2)}-{m.group(3)}", "description": ""})
            continue

        # mgmt_cli group
        m = re.match(r'(?:mgmt_cli )?add group\s+.*?name\s+"?(\S+?)"?\s+members(?:\.?\d*)?\s+"?(.+?)"?\s*$', line)
        if m:
            members = [x.strip().strip('"') for x in re.split(r'[,\s]+', m.group(2)) if x.strip().strip('"')]
            objects.append({"name": m.group(1), "obj_type": "group", "value": "group", "members": ",".join(members), "description": ""})
            continue

    return objects


def parse_sophos(config_text: str) -> List[dict]:
    """Parse Sophos XG/UTM style definitions.

    Handles:
      IPHost NAME IPAddress X.X.X.X
      IPHost NAME Network X.X.X.X/N  or  X.X.X.X Subnet M.M.M.M
      IPHost NAME IPRange X.X.X.X-Y.Y.Y.Y
      FQDNHost NAME FQDN domain.com
      IPHostGroup NAME HostList "H1,H2,H3"
    """
    objects = []

    for line in config_text.splitlines():
        line = line.strip()
        if not line:
            continue

        # IPHost
        m = re.match(r'(?:define\s+)?IPHost\s+"?(\S+?)"?\s+IPAddress\s+"?([0-9.]+)"?', line, re.IGNORECASE)
        if m:
            objects.append({"name": m.group(1), "obj_type": "host", "value": m.group(2), "description": ""})
            continue

        m = re.match(r'(?:define\s+)?IPHost\s+"?(\S+?)"?\s+Network\s+"?([0-9./]+)"?', line, re.IGNORECASE)
        if m:
            val = m.group(2)
            try:
                net = ipaddress.ip_network(val, strict=False)
                objects.append({"name": m.group(1), "obj_type": "subnet", "value": str(net), "description": ""})
            except ValueError:
                objects.append({"name": m.group(1), "obj_type": "subnet", "value": val, "description": ""})
            continue

        m = re.match(r'(?:define\s+)?IPHost\s+"?(\S+?)"?\s+IPRange\s+"?([0-9.-]+)"?', line, re.IGNORECASE)
        if m:
            objects.append({"name": m.group(1), "obj_type": "range", "value": m.group(2), "description": ""})
            continue

        # FQDNHost
        m = re.match(r'(?:define\s+)?FQDNHost\s+"?(\S+?)"?\s+FQDN\s+"?(\S+)"?', line, re.IGNORECASE)
        if m:
            objects.append({"name": m.group(1), "obj_type": "fqdn", "value": m.group(2), "description": ""})
            continue

        # IPHostGroup
        m = re.match(r'(?:define\s+)?IPHostGroup\s+"?(\S+?)"?\s+HostList\s+"(.+?)"', line, re.IGNORECASE)
        if m:
            members = [x.strip() for x in m.group(2).split(",") if x.strip()]
            objects.append({"name": m.group(1), "obj_type": "group", "value": "group", "members": ",".join(members), "description": ""})
            continue

    return objects


def parse_csv_objects(csv_text: str) -> List[dict]:
    """Parse CSV with columns: name, type, value, description."""
    objects = []
    reader = csv.reader(io.StringIO(csv_text))

    for i, row in enumerate(reader):
        if not row or len(row) < 3:
            continue
        # Skip header row
        if i == 0 and row[0].lower().strip() in ('name', 'object_name', 'object name'):
            continue

        name = row[0].strip()
        obj_type = row[1].strip().lower()
        value = row[2].strip()
        description = row[3].strip() if len(row) > 3 else ""

        if not name or not value:
            continue

        # Normalize type
        if obj_type not in ('host', 'subnet', 'range', 'fqdn', 'group'):
            if obj_type in ('ip', 'ip-host', 'iphost', 'address'):
                obj_type = 'host'
            elif obj_type in ('network', 'net', 'cidr', 'ip-netmask', 'ip-network'):
                obj_type = 'subnet'
            elif obj_type in ('ip-range', 'iprange'):
                obj_type = 'range'
            elif obj_type in ('domain', 'dns', 'hostname'):
                obj_type = 'fqdn'
            else:
                obj_type = 'host'

        objects.append({
            "name": name,
            "obj_type": obj_type,
            "value": value,
            "description": description,
        })

    return objects


def parse_plain_ips(text: str) -> List[dict]:
    """Parse plain list of IPs/CIDRs/ranges/FQDNs — one per line. Auto-detect type and auto-name."""
    objects = []
    seen = set()

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        # Optional: "name value" or "name,value" on one line
        parts_comma = line.split(",", 1)
        parts_space = line.split(None, 1)

        name = None
        value = line

        # If comma-separated with just 2 parts and second part looks like IP
        if len(parts_comma) == 2:
            candidate = parts_comma[1].strip()
            if re.match(r'^[\d./:a-fA-F-]+$', candidate) or re.match(r'^[\w.\-]+\.\w{2,}$', candidate):
                name = parts_comma[0].strip()
                value = candidate

        value = value.strip()
        if value in seen:
            continue
        seen.add(value)

        # Detect type
        obj_type = "host"
        if "/" in value:
            try:
                net = ipaddress.ip_network(value, strict=False)
                if net.prefixlen == 32:
                    obj_type = "host"
                    value = str(net.network_address)
                else:
                    obj_type = "subnet"
                    value = str(net)
            except ValueError:
                obj_type = "subnet"
        elif "-" in value:
            parts = value.split("-")
            if len(parts) == 2:
                try:
                    ipaddress.ip_address(parts[0].strip())
                    ipaddress.ip_address(parts[1].strip())
                    obj_type = "range"
                except ValueError:
                    obj_type = "fqdn"
        elif re.match(r'^[\w.\-]+\.\w{2,}$', value) and not re.match(r'^\d+\.\d+\.\d+\.\d+$', value):
            obj_type = "fqdn"
        else:
            try:
                ipaddress.ip_address(value)
                obj_type = "host"
            except ValueError:
                obj_type = "fqdn"

        # Auto-generate name if not provided
        if not name:
            safe_val = re.sub(r'[^a-zA-Z0-9_.-]', '_', value)
            if obj_type == "host":
                name = f"H_{safe_val}"
            elif obj_type == "subnet":
                name = f"N_{safe_val}"
            elif obj_type == "range":
                name = f"R_{safe_val}"
            elif obj_type == "fqdn":
                name = f"FQDN_{safe_val}"
            else:
                name = f"OBJ_{safe_val}"

        objects.append({"name": name, "obj_type": obj_type, "value": value, "description": ""})

    return objects


def parse_json_objects(json_text: str) -> List[dict]:
    """Parse JSON array of address objects."""
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError:
        return []

    objects = []
    items = data if isinstance(data, list) else data.get("objects", data.get("address_objects", []))

    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name", "").strip()
        value = item.get("value", item.get("ip", item.get("address", ""))).strip()
        obj_type = item.get("obj_type", item.get("type", "host")).strip().lower()
        if not name or not value:
            continue
        if obj_type not in ('host', 'subnet', 'range', 'fqdn', 'group'):
            obj_type = 'host'
        objects.append({
            "name": name,
            "obj_type": obj_type,
            "value": value,
            "description": item.get("description", ""),
            "members": item.get("members", ""),
        })
    return objects


PARSERS = {
    "fortigate": parse_fortigate,
    "paloalto": parse_paloalto,
    "cisco": parse_cisco,
    "juniper": parse_juniper,
    "checkpoint": parse_checkpoint,
    "sophos": parse_sophos,
    "csv": parse_csv_objects,
    "plain": parse_plain_ips,
    "json": parse_json_objects,
}


# =====================================================================
#  EXPORTERS  —  Generate firewall config from objects
# =====================================================================

def export_fortigate(objects: list) -> str:
    """Export as FortiGate 'config firewall address' config."""
    lines = ["config firewall address"]
    for o in objects:
        if o.obj_type == "group":
            continue
        lines.append(f'    edit "{o.name}"')
        if o.obj_type == "host":
            lines.append(f"        set subnet {o.value} 255.255.255.255")
        elif o.obj_type == "subnet":
            try:
                net = ipaddress.ip_network(o.value, strict=False)
                lines.append(f"        set subnet {net.network_address} {net.netmask}")
            except ValueError:
                lines.append(f"        set subnet {o.value}")
        elif o.obj_type == "range":
            lines.append("        set type iprange")
            if "-" in o.value:
                start, end = o.value.split("-", 1)
                lines.append(f"        set start-ip {start.strip()}")
                lines.append(f"        set end-ip {end.strip()}")
        elif o.obj_type == "fqdn":
            lines.append("        set type fqdn")
            lines.append(f'        set fqdn "{o.value}"')
        if o.description:
            lines.append(f'        set comment "{o.description}"')
        lines.append("    next")
    lines.append("end")

    # Groups
    groups = [o for o in objects if o.obj_type == "group"]
    if groups:
        lines.append("")
        lines.append("config firewall addrgrp")
        for g in groups:
            lines.append(f'    edit "{g.name}"')
            if g.members:
                member_list = " ".join(f'"{m.strip()}"' for m in g.members.split(",") if m.strip())
                lines.append(f"        set member {member_list}")
            if g.description:
                lines.append(f'        set comment "{g.description}"')
            lines.append("    next")
        lines.append("end")

    return "\n".join(lines)


def export_paloalto(objects: list) -> str:
    """Export as Palo Alto 'set address' commands."""
    lines = []
    for o in objects:
        if o.obj_type == "group":
            continue
        if o.obj_type == "host":
            lines.append(f"set address {o.name} ip-netmask {o.value}/32")
        elif o.obj_type == "subnet":
            val = o.value
            if "/" not in val:
                val += "/24"
            lines.append(f"set address {o.name} ip-netmask {val}")
        elif o.obj_type == "range":
            lines.append(f"set address {o.name} ip-range {o.value}")
        elif o.obj_type == "fqdn":
            lines.append(f"set address {o.name} fqdn {o.value}")
        if o.description:
            lines.append(f'set address {o.name} description "{o.description}"')

    groups = [o for o in objects if o.obj_type == "group"]
    for g in groups:
        if g.members:
            for member in g.members.split(","):
                member = member.strip()
                if member:
                    lines.append(f"set address-group {g.name} static {member}")

    return "\n".join(lines)


def export_cisco(objects: list) -> str:
    """Export as Cisco ASA 'object network' config."""
    lines = []
    for o in objects:
        if o.obj_type == "group":
            continue
        lines.append(f"object network {o.name}")
        if o.description:
            lines.append(f" description {o.description}")
        if o.obj_type == "host":
            lines.append(f" host {o.value}")
        elif o.obj_type == "subnet":
            try:
                net = ipaddress.ip_network(o.value, strict=False)
                lines.append(f" subnet {net.network_address} {net.netmask}")
            except ValueError:
                lines.append(f" subnet {o.value}")
        elif o.obj_type == "range":
            if "-" in o.value:
                start, end = o.value.split("-", 1)
                lines.append(f" range {start.strip()} {end.strip()}")
        elif o.obj_type == "fqdn":
            lines.append(f" fqdn {o.value}")

    groups = [o for o in objects if o.obj_type == "group"]
    for g in groups:
        lines.append(f"object-group network {g.name}")
        if g.description:
            lines.append(f" description {g.description}")
        if g.members:
            for member in g.members.split(","):
                member = member.strip()
                if member:
                    lines.append(f" network-object object {member}")

    return "\n".join(lines)


def export_juniper(objects: list) -> str:
    """Export as Juniper SRX address-book commands."""
    lines = []
    for o in objects:
        if o.obj_type == "group":
            continue
        if o.obj_type == "host":
            lines.append(f"set security address-book global address {o.name} {o.value}/32")
        elif o.obj_type == "subnet":
            val = o.value
            if "/" not in val:
                val += "/24"
            lines.append(f"set security address-book global address {o.name} {val}")
        elif o.obj_type == "range":
            if "-" in o.value:
                start, end = o.value.split("-", 1)
                lines.append(f"set security address-book global address {o.name} range-address {start.strip()} to {end.strip()}")
        elif o.obj_type == "fqdn":
            lines.append(f"set security address-book global address {o.name} dns-name {o.value}")
        if o.description:
            lines.append(f'set security address-book global address {o.name} description "{o.description}"')

    groups = [o for o in objects if o.obj_type == "group"]
    for g in groups:
        if g.members:
            for member in g.members.split(","):
                member = member.strip()
                if member:
                    lines.append(f"set security address-book global address-set {g.name} address {member}")

    return "\n".join(lines)


def export_checkpoint(objects: list) -> str:
    """Export as Check Point mgmt_cli commands."""
    lines = []
    for o in objects:
        if o.obj_type == "group":
            continue
        if o.obj_type == "host":
            lines.append(f'mgmt_cli add host name "{o.name}" ip-address "{o.value}"')
        elif o.obj_type == "subnet":
            try:
                net = ipaddress.ip_network(o.value, strict=False)
                lines.append(f'mgmt_cli add network name "{o.name}" subnet "{net.network_address}" subnet-mask "{net.netmask}"')
            except ValueError:
                lines.append(f'mgmt_cli add network name "{o.name}" subnet "{o.value}"')
        elif o.obj_type == "range":
            if "-" in o.value:
                start, end = o.value.split("-", 1)
                lines.append(f'mgmt_cli add address-range name "{o.name}" ip-address-first "{start.strip()}" ip-address-last "{end.strip()}"')
        elif o.obj_type == "fqdn":
            lines.append(f'mgmt_cli add dns-domain name "{o.name}" name "{o.value}"')

    groups = [o for o in objects if o.obj_type == "group"]
    for g in groups:
        if g.members:
            member_list = " ".join(f'"{m.strip()}"' for m in g.members.split(",") if m.strip())
            lines.append(f'mgmt_cli add group name "{g.name}" members {member_list}')

    return "\n".join(lines)


def export_csv_objects(objects: list) -> str:
    """Export as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["name", "type", "value", "description", "source", "members"])
    for o in objects:
        writer.writerow([o.name, o.obj_type, o.value, o.description or "", o.source or "", o.members or ""])
    return output.getvalue()


def export_json_objects(objects: list) -> str:
    """Export as JSON."""
    data = {
        "exported_at": datetime.utcnow().isoformat(),
        "count": len(objects),
        "objects": [
            {
                "name": o.name,
                "obj_type": o.obj_type,
                "value": o.value,
                "description": o.description or "",
                "source": o.source or "",
                "members": o.members or "",
            }
            for o in objects
        ]
    }
    return json.dumps(data, indent=2)


def export_plain(objects: list) -> str:
    """Export as plain text — one value per line."""
    return "\n".join(o.value for o in objects if o.obj_type != "group")


EXPORTERS = {
    "fortigate": ("text/plain", ".conf", export_fortigate),
    "paloalto": ("text/plain", ".txt", export_paloalto),
    "cisco": ("text/plain", ".txt", export_cisco),
    "juniper": ("text/plain", ".txt", export_juniper),
    "checkpoint": ("text/plain", ".txt", export_checkpoint),
    "csv": ("text/csv", ".csv", export_csv_objects),
    "json": ("application/json", ".json", export_json_objects),
    "plain": ("text/plain", ".txt", export_plain),
}


# =====================================================================
#  HTML Page Routes
# =====================================================================

@router.get("/address-objects/", response_class=HTMLResponse, name="address_object_list")
async def address_object_list_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    search: Optional[str] = None,
    obj_type: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=10, le=500),
):
    """Display address objects with server-side pagination."""
    # Build base query with filters
    query = select(AddressObject)

    if search:
        query = query.where(
            AddressObject.name.ilike(f"%{search}%") |
            AddressObject.value.ilike(f"%{search}%")
        )
    if obj_type:
        query = query.where(AddressObject.obj_type == obj_type)

    # Get filtered count (single COUNT query, not loading all rows)
    count_query = select(func.count(AddressObject.id))
    if search:
        count_query = count_query.where(
            AddressObject.name.ilike(f"%{search}%") |
            AddressObject.value.ilike(f"%{search}%")
        )
    if obj_type:
        count_query = count_query.where(AddressObject.obj_type == obj_type)
    filtered_count = (await db.execute(count_query)).scalar() or 0

    # Paginated results
    offset = (page - 1) * per_page
    query = query.order_by(AddressObject.name.asc()).offset(offset).limit(per_page)
    result = await db.execute(query)
    objects = result.scalars().all()

    total_pages = (filtered_count + per_page - 1) // per_page if filtered_count > 0 else 1

    # Stats via efficient SQL COUNT with GROUP BY (single query, no row loading)
    stats_query = select(
        AddressObject.obj_type,
        func.count(AddressObject.id)
    ).group_by(AddressObject.obj_type)
    stats_result = await db.execute(stats_query)
    type_counts = dict(stats_result.all())

    total = sum(type_counts.values())
    hosts = type_counts.get("host", 0)
    subnets = type_counts.get("subnet", 0)
    ranges = type_counts.get("range", 0)
    fqdns = type_counts.get("fqdn", 0)
    groups = type_counts.get("group", 0)

    return templates.TemplateResponse("address_objects/address_object_list.html", {
        "request": request,
        "current_user": getattr(request.state, "current_user", None),
        "unread_alert_count": 0,
        "objects": objects,
        "search": search or "",
        "obj_type_filter": obj_type or "",
        "total": total,
        "hosts": hosts,
        "subnets": subnets,
        "ranges": ranges,
        "fqdns": fqdns,
        "groups": groups,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "filtered_count": filtered_count,
        "has_prev": page > 1,
        "has_next": page < total_pages,
    })


@router.post("/address-objects/add/", name="address_object_add")
async def address_object_add(
    request: Request,
    name: str = Form(...),
    obj_type: str = Form(...),
    value: str = Form(...),
    description: str = Form(None),
    db: AsyncSession = Depends(get_db),
):
    """Add a single address object manually."""
    name = name.strip()
    value = value.strip()
    obj_type = obj_type.strip().lower()

    existing = await db.execute(select(AddressObject).where(AddressObject.name == name))
    if existing.scalar_one_or_none():
        return RedirectResponse(url="/address-objects/?error=duplicate", status_code=303)

    obj = AddressObject(
        name=name,
        obj_type=obj_type,
        value=value,
        description=description.strip() if description else None,
        source="manual",
    )
    db.add(obj)
    await db.commit()

    return RedirectResponse(url="/address-objects/", status_code=303)


@router.post("/address-objects/{obj_id}/delete/", name="address_object_delete")
async def address_object_delete(
    obj_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Delete an address object."""
    result = await db.execute(select(AddressObject).where(AddressObject.id == obj_id))
    obj = result.scalar_one_or_none()
    if not obj:
        raise HTTPException(status_code=404, detail="Address object not found")

    await db.delete(obj)
    await db.commit()

    return RedirectResponse(url="/address-objects/", status_code=303)


def _name_is_value_like(name: str, value: str) -> bool:
    """Check if a name is essentially just the value (IP address) itself.
    e.g. '10.10.112.31' or 'H_10.10.112.31' for value '10.10.112.31'."""
    name_lower = name.lower().strip()
    value_lower = value.lower().strip()
    # Exact match
    if name_lower == value_lower:
        return True
    # Auto-generated names from plain IP import: H_x.x.x.x, N_10.0.0.0_8, FQDN_google.com, R_x-y
    stripped = re.sub(r'^(?:h|n|r|fqdn|obj)_', '', name_lower)
    # For subnets: last underscore becomes slash (N_10.0.0.0_8 -> 10.0.0.0/8)
    last_us = stripped.rfind('_')
    if last_us > 0:
        maybe = stripped[:last_us] + '/' + stripped[last_us + 1:]
        if maybe == value_lower:
            return True
    if stripped == value_lower:
        return True
    # Name is just the IP with dots/slashes/dashes (strip all non-IP chars)
    name_clean = re.sub(r'[^0-9a-f.:/-]', '', name_lower)
    if name_clean and name_clean == value_lower:
        return True
    return False


@router.post("/address-objects/deduplicate/", name="address_object_deduplicate")
async def address_object_deduplicate(
    db: AsyncSession = Depends(get_db),
):
    """Remove duplicate-value objects, keeping the one with the best (most descriptive) name."""
    result = await db.execute(select(AddressObject).order_by(AddressObject.name.asc()))
    all_objects = result.scalars().all()

    # Group by (obj_type, value)
    from collections import defaultdict
    groups = defaultdict(list)
    for obj in all_objects:
        key = (obj.obj_type, obj.value.strip().lower())
        groups[key].append(obj)

    deleted = 0
    for key, objs in groups.items():
        if len(objs) <= 1:
            continue

        # Score each object: prefer names that are NOT just the value
        def score(o):
            # Lower score = better (will be kept)
            s = 0
            if _name_is_value_like(o.name, o.value):
                s += 100  # Penalize value-like names heavily
            if not o.description:
                s += 10  # Slight penalty for no description
            # Prefer longer, more descriptive names
            s -= len(o.name)
            return s

        objs.sort(key=score)
        keep = objs[0]
        for remove in objs[1:]:
            await db.delete(remove)
            deleted += 1

    await db.commit()
    return JSONResponse({"success": True, "deleted": deleted})


@router.post("/address-objects/delete-all/", name="address_object_delete_all")
async def address_object_delete_all(
    db: AsyncSession = Depends(get_db),
):
    """Delete all address objects."""
    await db.execute(delete(AddressObject))
    await db.commit()
    return RedirectResponse(url="/address-objects/", status_code=303)


@router.post("/address-objects/import/", name="address_object_import")
async def address_object_import(
    request: Request,
    format: str = Form(...),
    config_text: str = Form(None),
    file: UploadFile = File(None),
    db: AsyncSession = Depends(get_db),
):
    """Import address objects from config paste, file upload, or plain IP list."""
    text = ""
    if file and file.filename:
        content = await file.read()
        text = content.decode("utf-8", errors="ignore")
    elif config_text:
        text = config_text
    else:
        return JSONResponse({"success": False, "error": "No input provided"}, status_code=400)

    parser = PARSERS.get(format)
    if not parser:
        return JSONResponse({"success": False, "error": f"Unknown format: {format}"}, status_code=400)

    parsed = parser(text)
    if not parsed:
        return JSONResponse({"success": False, "error": "No objects parsed from input. Check format selection and input data."}, status_code=400)

    # Get existing names
    existing_result = await db.execute(select(AddressObject.name))
    existing_names = {row[0] for row in existing_result.all()}

    imported = 0
    skipped = 0
    for obj_data in parsed:
        if obj_data["name"] in existing_names:
            skipped += 1
            continue

        obj = AddressObject(
            name=obj_data["name"],
            obj_type=obj_data.get("obj_type", "host"),
            value=obj_data.get("value", ""),
            description=obj_data.get("description") or None,
            source=format,
            members=obj_data.get("members") or None,
        )
        db.add(obj)
        existing_names.add(obj_data["name"])
        imported += 1

    await db.commit()

    return JSONResponse({
        "success": True,
        "imported": imported,
        "skipped": skipped,
        "total_parsed": len(parsed),
    })


@router.get("/address-objects/export/", name="address_object_export")
async def address_object_export(
    format: str = Query("csv"),
    obj_type: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Export address objects in various firewall formats."""
    query = select(AddressObject)
    if obj_type:
        query = query.where(AddressObject.obj_type == obj_type)
    if search:
        query = query.where(
            AddressObject.name.ilike(f"%{search}%") |
            AddressObject.value.ilike(f"%{search}%")
        )
    query = query.order_by(AddressObject.name.asc())
    result = await db.execute(query)
    objects = result.scalars().all()

    if not objects:
        raise HTTPException(status_code=404, detail="No objects to export")

    exporter = EXPORTERS.get(format)
    if not exporter:
        raise HTTPException(status_code=400, detail=f"Unknown export format: {format}")

    media_type, ext, export_fn = exporter
    content = export_fn(objects)
    filename = f"address_objects_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}{ext}"

    return PlainTextResponse(
        content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/address-objects/{obj_id}/export/", name="address_object_export_single")
async def address_object_export_single(
    obj_id: int,
    format: str = Query("fortigate"),
    db: AsyncSession = Depends(get_db),
):
    """Export a single address object in the chosen format."""
    result = await db.execute(select(AddressObject).where(AddressObject.id == obj_id))
    obj = result.scalar_one_or_none()
    if not obj:
        raise HTTPException(status_code=404, detail="Address object not found")

    exporter = EXPORTERS.get(format)
    if not exporter:
        raise HTTPException(status_code=400, detail=f"Unknown export format: {format}")

    media_type, ext, export_fn = exporter
    content = export_fn([obj])

    return PlainTextResponse(
        content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{obj.name}{ext}"'}
    )


# =====================================================================
#  API Endpoints (JSON)
# =====================================================================

@router.get("/api/address-objects/", name="api_address_objects")
async def api_address_objects(
    db: AsyncSession = Depends(get_db),
    search: Optional[str] = None,
    obj_type: Optional[str] = None,
    limit: int = Query(500, ge=1, le=10000),
    offset: int = Query(0, ge=0),
):
    """Get address objects as JSON with pagination."""
    query = select(AddressObject)
    if search:
        query = query.where(
            AddressObject.name.ilike(f"%{search}%") |
            AddressObject.value.ilike(f"%{search}%")
        )
    if obj_type:
        query = query.where(AddressObject.obj_type == obj_type)

    query = query.order_by(AddressObject.name.asc()).offset(offset).limit(limit)
    result = await db.execute(query)
    objects = result.scalars().all()

    return [
        {
            "id": o.id,
            "name": o.name,
            "obj_type": o.obj_type,
            "value": o.value,
            "description": o.description,
            "source": o.source,
            "members": o.members,
        }
        for o in objects
    ]


@router.get("/api/address-objects/lookup", name="api_address_object_lookup")
async def api_address_object_lookup(
    ip: str = Query(..., description="IP address to look up"),
    db: AsyncSession = Depends(get_db),
):
    """Lookup address objects matching an IP (exact, subnet contains, range contains)."""
    ip = ip.strip()
    matches = []

    result = await db.execute(select(AddressObject))
    objects = result.scalars().all()

    try:
        lookup_addr = ipaddress.ip_address(ip)
    except ValueError:
        for o in objects:
            if o.value == ip or o.name == ip:
                matches.append(o)
        return [
            {"id": o.id, "name": o.name, "obj_type": o.obj_type, "value": o.value}
            for o in matches
        ]

    for o in objects:
        try:
            if o.obj_type == "host":
                if ipaddress.ip_address(o.value) == lookup_addr:
                    matches.append(o)
            elif o.obj_type == "subnet":
                net = ipaddress.ip_network(o.value, strict=False)
                if lookup_addr in net:
                    matches.append(o)
            elif o.obj_type == "range":
                if "-" in o.value:
                    start_str, end_str = o.value.split("-", 1)
                    start = ipaddress.ip_address(start_str.strip())
                    end = ipaddress.ip_address(end_str.strip())
                    if start <= lookup_addr <= end:
                        matches.append(o)
        except (ValueError, TypeError):
            continue

    return [
        {"id": o.id, "name": o.name, "obj_type": o.obj_type, "value": o.value}
        for o in matches
    ]
