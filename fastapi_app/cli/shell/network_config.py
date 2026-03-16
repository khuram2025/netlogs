"""Netplan YAML read/write for interface, DNS, and NTP configuration."""

import os
import yaml
from .system_utils import sudo_tee, apply_netplan, CommandError

NETPLAN_FILE = "/etc/netplan/01-zentryc.yaml"


def read_netplan() -> dict:
    """Read the current netplan configuration."""
    if not os.path.exists(NETPLAN_FILE):
        return {"network": {"version": 2, "ethernets": {}}}
    with open(NETPLAN_FILE) as f:
        data = yaml.safe_load(f)
    if not data or "network" not in data:
        return {"network": {"version": 2, "ethernets": {}}}
    return data


def _write_netplan(config: dict) -> None:
    """Write netplan config and apply."""
    content = yaml.dump(config, default_flow_style=False, sort_keys=False)
    sudo_tee(NETPLAN_FILE, content)
    apply_netplan()


def _ensure_iface(config: dict, iface: str) -> dict:
    """Ensure interface entry exists in config."""
    ethernets = config["network"].setdefault("ethernets", {})
    if iface not in ethernets:
        ethernets[iface] = {}
    return config


def list_interfaces() -> list[str]:
    """List physical network interfaces from /sys/class/net."""
    interfaces = []
    try:
        for name in os.listdir("/sys/class/net"):
            if name == "lo":
                continue
            # Skip virtual interfaces
            path = f"/sys/class/net/{name}/device"
            if os.path.exists(path) or name.startswith(("eth", "ens", "enp", "eno")):
                interfaces.append(name)
    except OSError:
        pass
    return sorted(interfaces)


def set_static_address(iface: str, address: str, gateway: str = None) -> None:
    """Set a static IP address on an interface.

    Args:
        iface: Interface name (e.g., 'ens18')
        address: IP/CIDR (e.g., '192.168.1.10/24')
        gateway: Optional gateway IP
    """
    config = read_netplan()
    config = _ensure_iface(config, iface)

    iface_cfg = config["network"]["ethernets"][iface]
    iface_cfg["dhcp4"] = False
    iface_cfg["addresses"] = [address]
    if gateway:
        iface_cfg["routes"] = [{"to": "default", "via": gateway}]
    elif "routes" in iface_cfg:
        # Keep existing routes if no new gateway specified
        pass

    _write_netplan(config)


def set_gateway(iface: str, gateway: str) -> None:
    """Set the default gateway on an interface."""
    config = read_netplan()
    config = _ensure_iface(config, iface)

    iface_cfg = config["network"]["ethernets"][iface]
    iface_cfg["routes"] = [{"to": "default", "via": gateway}]

    _write_netplan(config)


def set_dhcp(iface: str) -> None:
    """Set an interface to DHCP mode."""
    config = read_netplan()
    config = _ensure_iface(config, iface)

    iface_cfg = config["network"]["ethernets"][iface]
    iface_cfg.clear()
    iface_cfg["dhcp4"] = True

    _write_netplan(config)


def set_dns(primary: str, secondary: str = None) -> None:
    """Set DNS nameservers globally on all configured interfaces."""
    config = read_netplan()
    servers = [primary]
    if secondary:
        servers.append(secondary)

    ethernets = config["network"].get("ethernets", {})
    if not ethernets:
        raise CommandError("No interfaces configured in netplan")

    for iface_cfg in ethernets.values():
        iface_cfg["nameservers"] = {"addresses": servers}

    _write_netplan(config)


def get_current_config() -> dict:
    """Return a summary of current network configuration."""
    config = read_netplan()
    result = {}
    ethernets = config["network"].get("ethernets", {})
    for name, cfg in ethernets.items():
        info = {"dhcp": cfg.get("dhcp4", False)}
        if "addresses" in cfg:
            info["addresses"] = cfg["addresses"]
        if "routes" in cfg:
            for route in cfg["routes"]:
                if route.get("to") == "default":
                    info["gateway"] = route.get("via", "")
        if "nameservers" in cfg:
            info["dns"] = cfg["nameservers"].get("addresses", [])
        result[name] = info
    return result
