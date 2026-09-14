#!/bin/bash
set -euo pipefail
test "$(id -u)" = 0
cd /opt/zensheild
apt-get install -y python3-cryptography python3-yaml rsync
install -d -m 0755 /usr/local/lib/zenshield/ota
install -m 0644 appliance/ota/*.py /usr/local/lib/zenshield/ota/
install -m 0644 appliance/ota_entry.py /usr/local/lib/zenshield/
install -d -m 0700 /etc/zenshield-updater /var/lib/zenshield-updater
if [[ ! -f .version ]]; then printf '0.2.0\n' > .version; fi
PYTHONPATH=/usr/local/lib/zenshield python3 - <<'PY'
from ota.common import CONFIG,DEFAULT,write,config
if not CONFIG.exists():write(CONFIG,DEFAULT)
else:
    c=config()
    if not c['product_id'] and c['origin']=='https://zentryc.com':
        c['product_id']=DEFAULT['product_id'];write(CONFIG,c)
PY
cat > /usr/local/sbin/zenshield-update <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /usr/local/lib/zenshield/ota_entry.py "$@"
EOF
chmod 0755 /usr/local/sbin/zenshield-update
for pair in 'zenshield-updater scheduled' 'zenshield-update-check check' 'zenshield-update-recover recover'; do
    read -r unit mode <<< "$pair"
    cat > "/etc/systemd/system/$unit.service" <<EOF
[Unit]
Description=ZenShield signed appliance updates ($mode)
After=network-online.target docker.service zenshield-agent.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/zenshield-update $mode
TimeoutStartSec=3600
UMask=0077
NoNewPrivileges=yes
EOF
done
cat >> /etc/systemd/system/zenshield-update-recover.service <<'EOF'
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/zenshield-updater.timer <<'EOF'
[Unit]
Description=Check ZenShield release eligibility every four hours
[Timer]
OnBootSec=5min
OnUnitActiveSec=4h
RandomizedDelaySec=5min
Persistent=true
[Install]
WantedBy=timers.target
EOF
cat > /etc/systemd/system/zensheild.service.d/ota.conf <<'EOF'
[Unit]
After=zenshield-update-recover.service
Requires=zenshield-update-recover.service
EOF
systemctl daemon-reload
systemctl enable --now zenshield-update-recover
systemctl enable --now zenshield-updater.timer
echo 'ZenShield update engine installed. Product contract, public key and registration must be provisioned separately.'
