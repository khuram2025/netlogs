"""Curses-based TUI screens for the first-boot wizard."""

import curses
import os
from .validators import (
    validate_cidr, validate_gateway, validate_dns, validate_hostname,
    validate_timezone, validate_password, validate_ntp, validate_email,
)


# ── Curses helpers ──────────────────────────────────────────────────

def draw_box(win, y: int, x: int, h: int, w: int) -> None:
    """Draw a box using unicode box chars."""
    try:
        win.addstr(y, x, "┌" + "─" * (w - 2) + "┐")
        for i in range(1, h - 1):
            win.addstr(y + i, x, "│" + " " * (w - 2) + "│")
        win.addstr(y + h - 1, x, "└" + "─" * (w - 2) + "┘")
    except curses.error:
        pass


def draw_title(win, y: int, title: str) -> None:
    """Draw a centered title."""
    h, w = win.getmaxyx()
    x = max(0, (w - len(title)) // 2)
    try:
        win.addstr(y, x, title, curses.A_BOLD)
    except curses.error:
        pass


def draw_status(win, y: int, text: str, color_pair: int = 0) -> None:
    """Draw status text at bottom of screen."""
    h, w = win.getmaxyx()
    try:
        win.addstr(y, 2, " " * (w - 4))  # Clear line
        win.addstr(y, 2, text[:w - 4], color_pair)
    except curses.error:
        pass


def input_field(win, y: int, x: int, width: int, prompt: str,
                default: str = "", password: bool = False,
                validator=None) -> str:
    """Draw an input field and get user input with validation."""
    h, w = win.getmaxyx()
    curses.echo()
    if password:
        curses.noecho()

    while True:
        # Draw prompt
        try:
            win.addstr(y, x, prompt, curses.A_BOLD)
            # Draw input area
            field_x = x + len(prompt) + 1
            field_w = min(width, w - field_x - 2)
            win.addstr(y, field_x, "[" + " " * field_w + "]")
            if default:
                display = "*" * len(default) if password else default
                win.addstr(y, field_x + 1, display[:field_w])
            win.move(y, field_x + 1)
        except curses.error:
            pass
        win.refresh()

        # Get input
        curses.echo()
        if password:
            curses.noecho()
        try:
            raw = win.getstr(y, field_x + 1, field_w).decode("utf-8", errors="replace").strip()
        except curses.error:
            raw = ""

        if not raw and default:
            raw = default

        if validator and raw:
            err = validator(raw)
            if err:
                draw_status(win, y + 1, f"  Error: {err}", curses.color_pair(1))
                win.refresh()
                continue

        curses.noecho()
        return raw


def menu_select(win, y: int, x: int, options: list[str], selected: int = 0) -> int:
    """Arrow-key menu selection. Returns index."""
    curses.noecho()
    curses.curs_set(0)

    while True:
        for i, opt in enumerate(options):
            marker = " > " if i == selected else "   "
            attr = curses.A_REVERSE if i == selected else curses.A_NORMAL
            try:
                win.addstr(y + i, x, f"{marker}{opt}  ", attr)
            except curses.error:
                pass
        win.refresh()

        key = win.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(options) - 1:
            selected += 1
        elif key in (curses.KEY_ENTER, 10, 13):
            curses.curs_set(1)
            return selected
        elif key == ord('q'):
            curses.curs_set(1)
            return -1  # Cancel


# ── Screen implementations ──────────────────────────────────────────

def screen_welcome(stdscr, state: dict) -> str:
    """Welcome screen. Returns 'next' or 'quit'."""
    stdscr.clear()
    h, w = stdscr.getmaxyx()

    # Read version
    version = "3.x.x"
    try:
        version_file = os.path.join(
            os.environ.get("ZENTRYC_DIR", "/opt/zentryc"),
            "fastapi_app", "__version__.py"
        )
        with open(version_file) as f:
            for line in f:
                if "__version__" in line:
                    version = line.split("=")[1].strip().strip('"').strip("'")
    except Exception:
        pass

    draw_title(stdscr, 2, "╔══════════════════════════════════════════════════════════╗")
    draw_title(stdscr, 3, "║              Zentryc SOAR/SIEM Platform                  ║")
    draw_title(stdscr, 4, f"║                   v{version:<37s}║")
    draw_title(stdscr, 5, "╠══════════════════════════════════════════════════════════╣")
    draw_title(stdscr, 6, "║                  First-Time Setup                        ║")
    draw_title(stdscr, 7, "╚══════════════════════════════════════════════════════════╝")

    draw_title(stdscr, 10, "This wizard will configure your Zentryc appliance.")
    draw_title(stdscr, 11, "You will set up:")
    stdscr.addstr(13, 10, "  1. Network configuration (IP address, DNS)")
    stdscr.addstr(14, 10, "  2. System settings (hostname, timezone, NTP)")
    stdscr.addstr(15, 10, "  3. Admin account (password)")

    draw_title(stdscr, h - 3, "Press ENTER to begin, or 'q' to cancel")
    stdscr.refresh()

    while True:
        key = stdscr.getch()
        if key in (curses.KEY_ENTER, 10, 13):
            return "next"
        elif key == ord('q'):
            return "quit"


def screen_network(stdscr, state: dict) -> str:
    """Network configuration screen."""
    stdscr.clear()
    h, w = stdscr.getmaxyx()

    draw_title(stdscr, 1, "── Step 1: Network Configuration ──")

    # List interfaces
    interfaces = []
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            if name == "lo":
                continue
            if os.path.exists(f"/sys/class/net/{name}/device") or \
               name.startswith(("eth", "ens", "enp", "eno")):
                interfaces.append(name)
    except OSError:
        interfaces = ["eth0"]

    if not interfaces:
        interfaces = ["eth0"]

    stdscr.addstr(3, 4, "Select interface:", curses.A_BOLD)
    idx = menu_select(stdscr, 4, 6, interfaces, 0)
    if idx < 0:
        return "back"
    state["interface"] = interfaces[idx]

    # DHCP or Static
    stdscr.addstr(4 + len(interfaces) + 1, 4, "IP Configuration:", curses.A_BOLD)
    mode_y = 4 + len(interfaces) + 2
    mode_idx = menu_select(stdscr, mode_y, 6, ["DHCP (automatic)", "Static IP"], 0)
    if mode_idx < 0:
        return "back"

    if mode_idx == 0:
        state["mode"] = "dhcp"
    else:
        state["mode"] = "static"
        base_y = mode_y + 3
        stdscr.addstr(base_y, 4, "Enter network details:", curses.A_BOLD)
        curses.curs_set(1)

        state["address"] = input_field(
            stdscr, base_y + 1, 6, 30, "IP/CIDR:",
            default=state.get("address", ""),
            validator=validate_cidr,
        )
        state["gateway"] = input_field(
            stdscr, base_y + 3, 6, 30, "Gateway:",
            default=state.get("gateway", ""),
            validator=validate_gateway,
        )
        state["dns1"] = input_field(
            stdscr, base_y + 5, 6, 30, "Primary DNS:",
            default=state.get("dns1", "8.8.8.8"),
            validator=validate_dns,
        )
        state["dns2"] = input_field(
            stdscr, base_y + 7, 6, 30, "Secondary DNS:",
            default=state.get("dns2", "8.8.4.4"),
            validator=validate_dns,
        )

    draw_title(stdscr, h - 2, "Press ENTER to continue")
    stdscr.refresh()
    stdscr.getch()
    return "next"


def screen_system(stdscr, state: dict) -> str:
    """System settings screen: hostname, timezone, NTP."""
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    curses.curs_set(1)

    draw_title(stdscr, 1, "── Step 2: System Settings ──")

    state["hostname"] = input_field(
        stdscr, 4, 4, 40, "Hostname:",
        default=state.get("hostname", "zentryc"),
        validator=validate_hostname,
    )

    state["timezone"] = input_field(
        stdscr, 7, 4, 40, "Timezone:",
        default=state.get("timezone", "UTC"),
        validator=validate_timezone,
    )

    state["ntp_server"] = input_field(
        stdscr, 10, 4, 40, "NTP Server:",
        default=state.get("ntp_server", "pool.ntp.org"),
        validator=validate_ntp,
    )

    draw_title(stdscr, h - 2, "Press ENTER to continue")
    stdscr.refresh()
    stdscr.getch()
    return "next"


def screen_admin(stdscr, state: dict) -> str:
    """Admin account screen."""
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    curses.curs_set(1)

    draw_title(stdscr, 1, "── Step 3: Admin Account ──")

    stdscr.addstr(3, 4, "Set the admin password for the web interface.", curses.A_NORMAL)
    stdscr.addstr(4, 4, "Requirements: 8+ chars, uppercase, lowercase, digit", curses.A_DIM)

    while True:
        password = input_field(
            stdscr, 6, 4, 40, "Password:",
            password=True, validator=validate_password,
        )
        confirm = input_field(
            stdscr, 8, 4, 40, "Confirm:",
            password=True,
        )
        if password == confirm:
            state["admin_password"] = password
            break
        draw_status(stdscr, 10, "Passwords do not match. Try again.", curses.color_pair(1))

    state["admin_email"] = input_field(
        stdscr, 11, 4, 40, "Email (optional):",
        default=state.get("admin_email", ""),
        validator=validate_email,
    )

    draw_title(stdscr, h - 2, "Press ENTER to continue")
    stdscr.refresh()
    stdscr.getch()
    return "next"


def screen_summary(stdscr, state: dict) -> str:
    """Summary screen — review before applying."""
    stdscr.clear()
    h, w = stdscr.getmaxyx()

    draw_title(stdscr, 1, "── Summary — Review Configuration ──")

    y = 3
    sections = [
        ("Network", [
            ("Interface", state.get("interface", "?")),
            ("Mode", state.get("mode", "?")),
        ]),
        ("System", [
            ("Hostname", state.get("hostname", "?")),
            ("Timezone", state.get("timezone", "?")),
            ("NTP", state.get("ntp_server", "?")),
        ]),
        ("Admin", [
            ("Password", "********"),
            ("Email", state.get("admin_email", "(none)")),
        ]),
    ]

    if state.get("mode") == "static":
        sections[0][1].extend([
            ("Address", state.get("address", "?")),
            ("Gateway", state.get("gateway", "?")),
            ("DNS", f"{state.get('dns1', '?')}, {state.get('dns2', '')}".rstrip(", ")),
        ])

    for section_name, items in sections:
        try:
            stdscr.addstr(y, 4, f"[{section_name}]", curses.A_BOLD)
            y += 1
            for label, value in items:
                stdscr.addstr(y, 6, f"{label + ':':<18} {value}")
                y += 1
            y += 1
        except curses.error:
            pass

    draw_title(stdscr, h - 4, "Apply this configuration?")
    idx = menu_select(stdscr, h - 3, 10, ["Yes, apply", "Go back and edit"], 0)
    if idx == 0:
        return "apply"
    return "back"


def screen_apply(stdscr, state: dict) -> str:
    """Apply configuration with progress display."""
    stdscr.clear()
    h, w = stdscr.getmaxyx()
    curses.curs_set(0)

    draw_title(stdscr, 1, "── Applying Configuration ──")
    log_y = [3]  # Mutable so nested fn can modify

    def log_fn(msg: str):
        try:
            stdscr.addstr(log_y[0], 2, msg[:w - 4])
            log_y[0] += 1
            stdscr.refresh()
        except curses.error:
            pass

    from .appliers import (
        apply_network, apply_system, apply_database,
        apply_env, start_services_and_create_admin,
        write_configured_marker,
    )

    try:
        log_fn("Applying network configuration...")
        apply_network(state, log_fn)

        log_fn("")
        log_fn("Applying system settings...")
        apply_system(state, log_fn)

        log_fn("")
        log_fn("Configuring databases...")
        pg_pass, ch_pass = apply_database(log_fn)

        log_fn("")
        log_fn("Generating configuration...")
        apply_env(pg_pass, ch_pass, state, log_fn)

        log_fn("")
        log_fn("Starting services and creating admin user...")
        start_services_and_create_admin(
            state.get("admin_password", "changeme"),
            state.get("admin_email", ""),
            log_fn,
        )

        log_fn("")
        write_configured_marker(log_fn)

        log_fn("")
        log_fn("Configuration complete!")
        state["_apply_success"] = True

    except Exception as e:
        log_fn("")
        log_fn(f"ERROR: {e}")
        state["_apply_success"] = False

    draw_title(stdscr, h - 2, "Press ENTER to continue")
    stdscr.refresh()
    stdscr.getch()
    return "next"


def screen_complete(stdscr, state: dict) -> str:
    """Completion screen."""
    stdscr.clear()
    h, w = stdscr.getmaxyx()

    if state.get("_apply_success"):
        draw_title(stdscr, 2, "╔══════════════════════════════════════════════════════════╗")
        draw_title(stdscr, 3, "║           Setup Complete!                                ║")
        draw_title(stdscr, 4, "╚══════════════════════════════════════════════════════════╝")

        # Show access info
        ip = "your-ip"
        if state.get("mode") == "static" and state.get("address"):
            ip = state["address"].split("/")[0]
        else:
            try:
                import subprocess
                result = subprocess.run(
                    ["hostname", "-I"], capture_output=True, text=True, timeout=5,
                )
                ip = result.stdout.strip().split()[0]
            except Exception:
                pass

        stdscr.addstr(7, 4, f"Web UI:      https://{ip}/")
        stdscr.addstr(8, 4, "Username:    admin")
        stdscr.addstr(9, 4, "Password:    (the password you just set)")
        stdscr.addstr(10, 4, f"Syslog:      UDP {ip}:514")
        stdscr.addstr(12, 4, "SSH to this appliance for the management CLI.")
    else:
        draw_title(stdscr, 3, "Setup completed with errors. Check logs.")
        stdscr.addstr(5, 4, "You may need to run the wizard again or configure manually.")

    draw_title(stdscr, h - 2, "Press ENTER for the appliance CLI")
    stdscr.refresh()
    stdscr.getch()
    return "done"
