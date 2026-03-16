"""First-boot wizard orchestrator — screen flow and state machine.

Run as: python -m fastapi_app.cli.firstboot.wizard

This is a curses-based TUI that runs once on first VM boot before services start.
It configures network, system settings, database, and admin user.
"""

import curses
import sys
import os

from .screens import (
    screen_welcome,
    screen_network,
    screen_system,
    screen_admin,
    screen_summary,
    screen_apply,
    screen_complete,
)

# Screen flow: name → (function, {result → next_screen})
SCREENS = {
    "welcome":  (screen_welcome,  {"next": "network", "quit": None}),
    "network":  (screen_network,  {"next": "system", "back": "welcome"}),
    "system":   (screen_system,   {"next": "admin", "back": "network"}),
    "admin":    (screen_admin,    {"next": "summary", "back": "system"}),
    "summary":  (screen_summary,  {"apply": "apply", "back": "network"}),
    "apply":    (screen_apply,    {"next": "complete"}),
    "complete": (screen_complete, {"done": None}),
}


def run_wizard(stdscr) -> None:
    """Main wizard loop — drives screen transitions."""
    # Initialize curses colors
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_CYAN, -1)

    curses.curs_set(1)

    # Shared state across all screens
    state = {}

    current_screen = "welcome"

    while current_screen is not None:
        screen_fn, transitions = SCREENS[current_screen]

        try:
            result = screen_fn(stdscr, state)
        except KeyboardInterrupt:
            result = "quit" if "quit" in transitions else "back"

        next_screen = transitions.get(result)

        if result == "quit":
            # Confirm quit
            stdscr.clear()
            stdscr.addstr(5, 10, "Are you sure you want to cancel setup?")
            stdscr.addstr(6, 10, "The system will not be configured.")
            stdscr.addstr(8, 10, "Press 'y' to quit, any other key to go back.")
            stdscr.refresh()
            key = stdscr.getch()
            if key == ord('y'):
                break
            else:
                continue

        current_screen = next_screen


def main():
    """Entry point for the first-boot wizard."""
    # Check if already configured
    configured_marker = os.path.join(
        os.environ.get("ZENTRYC_DIR", "/opt/zentryc"),
        ".configured"
    )
    if os.path.exists(configured_marker):
        print("System is already configured. Remove .configured to re-run wizard.")
        sys.exit(0)

    try:
        curses.wrapper(run_wizard)
    except Exception as e:
        print(f"\nWizard error: {e}")
        print("You may need to configure the system manually.")
        sys.exit(1)


if __name__ == "__main__":
    main()
