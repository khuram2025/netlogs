#!/bin/bash
#
# Setup script for NetLogs disk cleanup automation
# Run with sudo: sudo ./setup-disk-cleanup.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="$SCRIPT_DIR/netlogs-disk-cleanup.service"
TIMER_FILE="$SCRIPT_DIR/netlogs-disk-cleanup.timer"

echo "NetLogs Disk Cleanup Setup"
echo "=========================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo ./setup-disk-cleanup.sh)"
    exit 1
fi

# Create log directory if needed
mkdir -p /home/net/net-logs/logs
chown net:net /home/net/net-logs/logs

# Copy service and timer files
echo "Installing systemd service and timer..."
cp "$SERVICE_FILE" /etc/systemd/system/
cp "$TIMER_FILE" /etc/systemd/system/

# Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload

# Enable and start the timer
echo "Enabling and starting the cleanup timer..."
systemctl enable netlogs-disk-cleanup.timer
systemctl start netlogs-disk-cleanup.timer

# Show status
echo ""
echo "Setup complete! Timer status:"
systemctl status netlogs-disk-cleanup.timer --no-pager

echo ""
echo "The cleanup will run every 15 minutes."
echo ""
echo "Useful commands:"
echo "  systemctl status netlogs-disk-cleanup.timer  # Check timer status"
echo "  systemctl list-timers                        # List all timers"
echo "  journalctl -u netlogs-disk-cleanup.service   # View cleanup logs"
echo "  systemctl start netlogs-disk-cleanup.service # Run cleanup now"
echo ""
echo "Manual cleanup:"
echo "  cd /home/net/net-logs"
echo "  ./venv/bin/python -m fastapi_app.cli.disk_cleanup --status"
echo "  ./venv/bin/python -m fastapi_app.cli.disk_cleanup --threshold 90"
