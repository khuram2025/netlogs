"""Colored output, table formatting, and size/time helpers for the appliance CLI."""

import shutil


# ANSI color codes
class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BRED = "\033[91m"
    BGREEN = "\033[92m"
    BYELLOW = "\033[93m"
    BCYAN = "\033[96m"


def colored(text: str, color: str) -> str:
    return f"{color}{text}{Color.RESET}"


def bold(text: str) -> str:
    return colored(text, Color.BOLD)


def success(text: str) -> str:
    return colored(text, Color.BGREEN)


def warning(text: str) -> str:
    return colored(text, Color.BYELLOW)


def error(text: str) -> str:
    return colored(text, Color.BRED)


def info(text: str) -> str:
    return colored(text, Color.BCYAN)


def dim(text: str) -> str:
    return colored(text, Color.DIM)


def status_color(status: str) -> str:
    """Color a status string based on its value."""
    s = status.lower()
    if s in ("healthy", "running", "active", "up", "ok", "online"):
        return success(status)
    elif s in ("degraded", "warning", "restarting"):
        return warning(status)
    else:
        return error(status)


def format_bytes(nbytes: int) -> str:
    """Human-readable byte sizes."""
    if nbytes < 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(nbytes) < 1024.0:
            if unit == "B":
                return f"{nbytes} {unit}"
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024.0
    return f"{nbytes:.1f} PB"


def format_uptime(seconds: int) -> str:
    """Human-readable uptime string."""
    if seconds < 0:
        seconds = 0
    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def format_percent(value: float, warn_threshold: float = 80.0, crit_threshold: float = 90.0) -> str:
    """Color-coded percentage."""
    text = f"{value:.1f}%"
    if value >= crit_threshold:
        return error(text)
    elif value >= warn_threshold:
        return warning(text)
    return success(text)


def print_table(headers: list[str], rows: list[list[str]], min_width: int = 10) -> None:
    """Print a formatted table with column alignment."""
    if not rows and not headers:
        return

    term_width = shutil.get_terminal_size((80, 24)).columns

    # Calculate column widths
    col_count = len(headers)
    widths = [max(min_width, len(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < col_count:
                # Strip ANSI codes for width calculation
                clean = _strip_ansi(str(cell))
                widths[i] = max(widths[i], len(clean))

    # Cap total width to terminal
    total = sum(widths) + (col_count - 1) * 3 + 4
    if total > term_width and col_count > 0:
        excess = total - term_width
        widths[-1] = max(min_width, widths[-1] - excess)

    # Print header
    header_line = " | ".join(
        _pad(bold(h), widths[i]) for i, h in enumerate(headers)
    )
    print(f"  {header_line}")
    sep = "-+-".join("-" * w for w in widths)
    print(f"  {sep}")

    # Print rows
    for row in rows:
        cells = []
        for i in range(col_count):
            val = str(row[i]) if i < len(row) else ""
            cells.append(_pad(val, widths[i]))
        print(f"  {' | '.join(cells)}")


def print_kv(pairs: list[tuple[str, str]], label_width: int = 22) -> None:
    """Print key-value pairs with aligned labels."""
    for label, value in pairs:
        print(f"  {bold(label + ':'):<{label_width + 7}} {value}")


def print_section(title: str) -> None:
    """Print a section header."""
    print()
    print(f"  {bold(colored(title, Color.CYAN))}")
    print(f"  {'─' * len(title)}")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences for width calculation."""
    import re
    return re.sub(r"\033\[[0-9;]*m", "", text)


def _pad(text: str, width: int) -> str:
    """Pad text to width, accounting for ANSI codes."""
    visible_len = len(_strip_ansi(text))
    padding = max(0, width - visible_len)
    return text + " " * padding
