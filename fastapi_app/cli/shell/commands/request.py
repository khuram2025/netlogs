"""request commands — reboot, shutdown, backup, upgrade, factory-reset, service restart."""

import os

from ..formatters import success, error, warning, bold, info, print_section
from ..system_utils import (
    system_reboot, system_poweroff, run_backup, run_upgrade,
    restart_service, SERVICE_MAP, CommandError, ZENTRYC_DIR,
)


def cmd_request(args: list[str]) -> None:
    """Dispatch request subcommands."""
    if not args:
        _usage()
        return

    sub = args[0].lower()

    if sub == "system" and len(args) > 1:
        sub2 = args[1].lower()
        if sub2 == "reboot":
            _request_reboot()
        elif sub2 == "shutdown":
            _request_shutdown()
        else:
            print(error(f"Unknown: request system {sub2}"))
    elif sub == "backup":
        if len(args) > 1 and args[1].lower() == "now":
            _request_backup()
        else:
            print(error("Usage: request backup now"))
    elif sub == "upgrade":
        if len(args) > 2 and args[1].lower() == "local":
            _request_upgrade(args[2])
        else:
            print(error("Usage: request upgrade local <path>"))
    elif sub == "factory-reset":
        _request_factory_reset()
    elif sub == "service" and len(args) > 2 and args[1].lower() == "restart":
        _request_service_restart(args[2])
    else:
        print(error(f"Unknown: request {' '.join(args)}"))
        _usage()


def _usage() -> None:
    print(error("Usage:"))
    print("  request system reboot")
    print("  request system shutdown")
    print("  request backup now")
    print("  request upgrade local <path>")
    print("  request factory-reset")
    print("  request service restart <web|syslog|nginx>")


def _confirm(prompt: str) -> bool:
    """Ask for yes/no confirmation."""
    try:
        answer = input(f"\n  {warning(prompt)} [y/N]: ").strip().lower()
        return answer in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _request_reboot() -> None:
    """Reboot the system."""
    if not _confirm("Are you sure you want to reboot the system?"):
        print("  Cancelled.")
        return

    print(info("  Rebooting..."))
    try:
        system_reboot()
    except CommandError as e:
        print(error(f"  Failed: {e.message}"))


def _request_shutdown() -> None:
    """Shut down the system."""
    if not _confirm("Are you sure you want to shut down the system?"):
        print("  Cancelled.")
        return

    print(info("  Shutting down..."))
    try:
        system_poweroff()
    except CommandError as e:
        print(error(f"  Failed: {e.message}"))


def _request_backup() -> None:
    """Run backup script."""
    print(info("  Starting backup... this may take a few minutes."))
    try:
        output = run_backup()
        print(success("  Backup completed successfully."))
        if output:
            # Show last few lines with backup path
            for line in output.splitlines()[-5:]:
                print(f"  {line}")
    except CommandError as e:
        print(error(f"  Backup failed: {e.message}"))


def _request_upgrade(path: str) -> None:
    """Run upgrade from a local tarball."""
    if not os.path.isfile(path):
        print(error(f"  File not found: {path}"))
        return

    if not path.endswith((".tar.gz", ".tgz")):
        print(error("  Expected a .tar.gz upgrade package"))
        return

    if not _confirm(f"Upgrade from {path}? This will restart services."):
        print("  Cancelled.")
        return

    print(info("  Starting upgrade..."))
    try:
        run_upgrade(path)
        print(success("  Upgrade completed."))
    except CommandError as e:
        print(error(f"  Upgrade failed: {e.message}"))


def _request_factory_reset() -> None:
    """Factory reset — wipe all data and configuration."""
    print()
    print(warning("  *** WARNING: FACTORY RESET ***"))
    print(warning("  This will:"))
    print(warning("    - Delete all logs and data"))
    print(warning("    - Remove all users and configuration"))
    print(warning("    - Reset to first-boot state"))
    print()

    try:
        confirm_text = input("  Type FACTORY-RESET to confirm: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n  Cancelled.")
        return

    if confirm_text != "FACTORY-RESET":
        print("  Cancelled. Text did not match.")
        return

    print(info("\n  Performing factory reset..."))
    try:
        # Stop services
        for svc in ["zentryc-web", "zentryc-syslog"]:
            try:
                restart_service(svc)  # Will use systemctl
            except CommandError:
                pass

        from ..system_utils import sudo_run

        # Stop services properly
        sudo_run(["/usr/bin/systemctl", "stop", "zentryc-web"], timeout=30)
        sudo_run(["/usr/bin/systemctl", "stop", "zentryc-syslog"], timeout=30)

        # Drop and recreate PostgreSQL database
        sudo_run([
            "sudo", "-u", "postgres", "psql", "-c",
            "DROP DATABASE IF EXISTS zentryc; CREATE DATABASE zentryc;"
        ], timeout=30)

        # Truncate ClickHouse tables
        from ..system_utils import read_env_file
        env = read_env_file()
        ch_pass = env.get("CLICKHOUSE_PASSWORD", "")
        for table in ["syslogs", "audit_logs", "ioc_matches", "correlation_matches"]:
            try:
                sudo_run([
                    "clickhouse-client",
                    "--user", env.get("CLICKHOUSE_USER", "default"),
                    "--password", ch_pass,
                    "--query", f"TRUNCATE TABLE IF EXISTS zentryc.{table}",
                ], timeout=30)
            except CommandError:
                pass

        # Remove configured marker to trigger first-boot wizard
        configured_marker = os.path.join(ZENTRYC_DIR, ".configured")
        if os.path.exists(configured_marker):
            sudo_run(["rm", "-f", configured_marker])

        # Remove .env to force reconfiguration
        env_file = os.path.join(ZENTRYC_DIR, ".env")
        if os.path.exists(env_file):
            sudo_run(["rm", "-f", env_file])

        # Clear logs
        logs_dir = os.path.join(ZENTRYC_DIR, "logs")
        if os.path.isdir(logs_dir):
            sudo_run(["find", logs_dir, "-type", "f", "-delete"])

        # Clear backups
        backups_dir = os.path.join(ZENTRYC_DIR, "backups")
        if os.path.isdir(backups_dir):
            sudo_run(["rm", "-rf", backups_dir])

        print(success("  Factory reset complete."))
        print(info("  The system will reboot now. First-boot wizard will run on next boot."))

        system_reboot()

    except CommandError as e:
        print(error(f"  Factory reset failed: {e.message}"))
        print(error("  System may be in an inconsistent state. Check manually."))


def _request_service_restart(service: str) -> None:
    """Restart a specific service."""
    service = service.lower()
    if service not in SERVICE_MAP:
        print(error(f"  Unknown service: {service}"))
        print(f"  Available: {', '.join(SERVICE_MAP.keys())}")
        return

    unit = SERVICE_MAP[service]
    if not _confirm(f"Restart {unit}?"):
        print("  Cancelled.")
        return

    print(info(f"  Restarting {unit}..."))
    try:
        restart_service(service)
        print(success(f"  {unit} restarted."))
    except CommandError as e:
        print(error(f"  Failed: {e.message}"))
