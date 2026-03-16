"""Appliance CLI main loop — banner, prompt, command dispatch, history."""

import os
import sys

from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

from .completer import ShellCompleter
from .formatters import bold, info, error, dim, Color
from .system_utils import get_version, get_hostname
from .commands.show import cmd_show
from .commands.set_cmd import cmd_set
from .commands.request import cmd_request


HISTORY_FILE = os.path.expanduser("~/.zentryc_cli_history")

BANNER = r"""
{cyan}╔══════════════════════════════════════════════════════════╗
║              Zentryc SOAR/SIEM Platform                  ║
║                   Appliance CLI                          ║
╠══════════════════════════════════════════════════════════╣
║  Type 'help' or '?' for available commands               ║
║  Tab completion is available                             ║
╚══════════════════════════════════════════════════════════╝{reset}
""".format(cyan=Color.CYAN, reset=Color.RESET)

HELP_TEXT = """
{bold}Available Commands:{reset}

  {cyan}show{reset}
    system status          System overview (CPU, memory, disk, services)
    system health          Application health check (from API)
    interfaces             Network interface status
    services               Service status details
    version                Application version
    disk usage             Disk and ClickHouse storage
    logs count [period]    Log counts (today|week|month|all)
    running-config         Current configuration (passwords masked)

  {cyan}set{reset}
    interface <name> address <ip/mask> [gateway <ip>]
    interface <name> gateway <ip>
    interface <name> dhcp
    dns <primary> [secondary]
    hostname <name>
    timezone <tz>
    ntp <server>

  {cyan}request{reset}
    system reboot          Reboot the appliance
    system shutdown        Shut down the appliance
    backup now             Create a backup
    upgrade local <path>   Upgrade from local tarball
    factory-reset          Wipe all data (requires confirmation)
    service restart <name> Restart web|syslog|nginx

  {cyan}exit / quit / logout{reset}   End session
""".format(bold=Color.BOLD, reset=Color.RESET, cyan=Color.CYAN)


def dispatch(line: str) -> bool:
    """Parse and dispatch a command line. Returns False to exit."""
    line = line.strip()
    if not line:
        return True

    parts = line.split()
    cmd = parts[0].lower()
    args = parts[1:]

    if cmd in ("exit", "quit", "logout"):
        return False
    elif cmd in ("help", "?"):
        print(HELP_TEXT)
    elif cmd == "show":
        cmd_show(args)
    elif cmd == "set":
        cmd_set(args)
    elif cmd == "request":
        cmd_request(args)
    else:
        print(error(f"Unknown command: {cmd}"))
        print(dim("  Type 'help' for available commands"))

    return True


def get_prompt() -> str:
    """Build the CLI prompt string."""
    try:
        hostname = get_hostname()
    except Exception:
        hostname = "zentryc"
    return f"{hostname}> "


def main() -> None:
    """Main CLI entry point."""
    print(BANNER)

    try:
        version = get_version()
        hostname = get_hostname()
        print(f"  {bold('Version:')} {info(version)}    {bold('Host:')} {info(hostname)}")
        print()
    except Exception:
        pass

    session = PromptSession(
        completer=ShellCompleter(),
        history=FileHistory(HISTORY_FILE),
        auto_suggest=AutoSuggestFromHistory(),
    )

    prompt_text = get_prompt()

    while True:
        try:
            line = session.prompt(prompt_text)
            if not dispatch(line):
                print(dim("  Goodbye."))
                break
        except KeyboardInterrupt:
            print()  # New line after ^C
            continue
        except EOFError:
            print(dim("\n  Goodbye."))
            break
        except Exception as e:
            print(error(f"Error: {e}"))


if __name__ == "__main__":
    main()
