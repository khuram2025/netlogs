#!/bin/bash
#
# NetLogs Production Deployment Script
# Installs and configures systemd services for syslog collector and web app
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "================================================"
echo "NetLogs Production Deployment"
echo "================================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Install dependencies
echo "[1/6] Checking Python dependencies..."
cd "$PROJECT_DIR"
source venv/bin/activate
pip install -q gunicorn

# Run migrations
echo "[2/6] Running database migrations..."
python manage.py migrate --no-input

# Collect static files
echo "[3/6] Collecting static files..."
python manage.py collectstatic --no-input 2>/dev/null || true

# Install systemd services
echo "[4/6] Installing systemd services..."
cp "$SCRIPT_DIR/netlogs-syslog.service" /etc/systemd/system/
cp "$SCRIPT_DIR/netlogs-web.service" /etc/systemd/system/

# Reload systemd
echo "[5/6] Reloading systemd daemon..."
systemctl daemon-reload

# Enable and start services
echo "[6/6] Starting services..."
systemctl enable netlogs-syslog netlogs-web
systemctl restart netlogs-syslog
systemctl restart netlogs-web

echo ""
echo "================================================"
echo "Deployment Complete!"
echo "================================================"
echo ""
echo "Services status:"
echo "  - Syslog Collector: $(systemctl is-active netlogs-syslog)"
echo "  - Web Application:  $(systemctl is-active netlogs-web)"
echo ""
echo "Useful commands:"
echo "  sudo systemctl status netlogs-syslog   # Check syslog status"
echo "  sudo systemctl status netlogs-web      # Check web status"
echo "  sudo journalctl -fu netlogs-syslog     # View syslog logs"
echo "  sudo journalctl -fu netlogs-web        # View web logs"
echo ""
echo "Web interface: http://$(hostname -I | awk '{print $1}'):8001/devices/"
echo ""
