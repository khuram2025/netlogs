"""set commands — interface, dns, hostname, timezone, ntp."""

from ..formatters import success, error, info, bold, print_section
from ..system_utils import set_hostname, set_timezone, write_timesyncd_conf, CommandError
from ..network_config import (
    set_static_address, set_gateway, set_dhcp, set_dns, list_interfaces,
)


def cmd_set(args: list[str]) -> None:
    """Dispatch set subcommands."""
    if not args:
        _usage()
        return

    sub = args[0].lower()

    if sub == "interface":
        _set_interface(args[1:])
    elif sub == "dns":
        _set_dns(args[1:])
    elif sub == "hostname":
        _set_hostname(args[1:])
    elif sub == "timezone":
        _set_timezone(args[1:])
    elif sub == "ntp":
        _set_ntp(args[1:])
    else:
        print(error(f"Unknown: set {sub}"))
        _usage()


def _usage() -> None:
    print(error("Usage:"))
    print("  set interface <name> address <ip/mask> [gateway <ip>]")
    print("  set interface <name> gateway <ip>")
    print("  set interface <name> dhcp")
    print("  set dns <primary> [secondary]")
    print("  set hostname <name>")
    print("  set timezone <tz>")
    print("  set ntp <server>")


def _set_interface(args: list[str]) -> None:
    """Handle: set interface <name> address|gateway|dhcp ..."""
    if len(args) < 2:
        available = list_interfaces()
        if available:
            print(info(f"Available interfaces: {', '.join(available)}"))
        print(error("Usage: set interface <name> <address <ip/mask>|gateway <ip>|dhcp>"))
        return

    iface = args[0]
    action = args[1].lower()

    try:
        if action == "address":
            if len(args) < 3:
                print(error("Usage: set interface <name> address <ip/mask> [gateway <ip>]"))
                return
            address = args[2]
            if "/" not in address:
                print(error("Address must include CIDR notation (e.g., 192.168.1.10/24)"))
                return
            gateway = None
            if len(args) >= 5 and args[3].lower() == "gateway":
                gateway = args[4]
            set_static_address(iface, address, gateway)
            print(success(f"Interface {iface} configured: {address}" + (f" gw {gateway}" if gateway else "")))

        elif action == "gateway":
            if len(args) < 3:
                print(error("Usage: set interface <name> gateway <ip>"))
                return
            set_gateway(iface, args[2])
            print(success(f"Gateway for {iface} set to {args[2]}"))

        elif action == "dhcp":
            set_dhcp(iface)
            print(success(f"Interface {iface} set to DHCP"))

        else:
            print(error(f"Unknown interface action: {action}"))
            print("  Valid: address, gateway, dhcp")

    except CommandError as e:
        print(error(f"Failed: {e.message}"))


def _set_dns(args: list[str]) -> None:
    """Handle: set dns <primary> [secondary]."""
    if not args:
        print(error("Usage: set dns <primary> [secondary]"))
        return

    primary = args[0]
    secondary = args[1] if len(args) > 1 else None

    try:
        set_dns(primary, secondary)
        servers = primary + (f", {secondary}" if secondary else "")
        print(success(f"DNS servers set to: {servers}"))
    except CommandError as e:
        print(error(f"Failed: {e.message}"))


def _set_hostname(args: list[str]) -> None:
    """Handle: set hostname <name>."""
    if not args:
        print(error("Usage: set hostname <name>"))
        return

    name = args[0]
    # Basic validation
    if len(name) > 63 or not all(c.isalnum() or c == "-" for c in name):
        print(error("Hostname must be alphanumeric with hyphens, max 63 chars"))
        return

    try:
        set_hostname(name)
        print(success(f"Hostname set to: {name}"))
    except CommandError as e:
        print(error(f"Failed: {e.message}"))


def _set_timezone(args: list[str]) -> None:
    """Handle: set timezone <tz>."""
    if not args:
        print(error("Usage: set timezone <tz> (e.g., America/New_York, UTC)"))
        return

    tz = args[0]
    try:
        set_timezone(tz)
        print(success(f"Timezone set to: {tz}"))
    except CommandError as e:
        print(error(f"Failed: {e.message}"))


def _set_ntp(args: list[str]) -> None:
    """Handle: set ntp <server>."""
    if not args:
        print(error("Usage: set ntp <server> (e.g., pool.ntp.org)"))
        return

    server = args[0]
    try:
        write_timesyncd_conf(server)
        print(success(f"NTP server set to: {server}"))
    except CommandError as e:
        print(error(f"Failed: {e.message}"))
