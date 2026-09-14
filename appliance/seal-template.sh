#!/bin/bash
# Run ONLY in a disposable export clone, never the working/customer appliance.
set -euo pipefail
if [[ "${1:-}" != '--erase-clone-data-for-export' ]] || [[ ! -f /root/ZENSHEILD-DISPOSABLE-EXPORT-CLONE ]]; then
    echo 'Refused: requires --erase-clone-data-for-export and /root/ZENSHEILD-DISPOSABLE-EXPORT-CLONE' >&2
    exit 1
fi
test "$(id -u)" = 0
if [[ -d /root/ota-integration ]]; then
    echo 'Refused: OTA integration fixtures and test signing keys are present. Create a clean export clone from the master.' >&2
    exit 1
fi
cd /opt/zensheild
test -f /var/lib/zensheild/build-complete
if [[ -d /var/lib/zenshield-updater ]]; then
    exec 9>/var/lib/zenshield-updater/update.lock
    flock -n 9 || { echo 'An update is running; wait for it before sealing.' >&2; exit 1; }
    PYTHONPATH=/usr/local/lib/zenshield python3 - <<'PY'
from ota.common import read,STATE
tx=read(STATE/'transaction.json')
if tx and tx['phase'] not in ('committed','rolled_back','aborted'):
    raise SystemExit('Recover the unfinished update before sealing this clone')
PY
fi
systemctl stop zensheild
systemctl stop zenshield-updater.timer zenshield-updater.service zenshield-update-check.service || true
if [[ -f /etc/zenshield-updater/config.json ]]; then
    PYTHONPATH=/usr/local/lib/zenshield python3 - <<'PY'
from ota.common import config,CONFIG,write
c=config();c.update(appliance_id='',api_key='',auto_update=False)
write(CONFIG,c)
PY
fi
rm -rf /var/lib/zenshield-updater
systemctl stop zenshield-agent
if [[ -f compose.storage.yaml ]]; then
    docker compose -f compose.yaml -f compose.storage.yaml down --volumes --remove-orphans
    python3 /opt/zensheild/appliance/control/clear-clone-storage.py
else
    docker compose down --volumes --remove-orphans
fi
docker builder prune --all --force
rm -f .env certs/server.key certs/server.crt /root/zensheild-build-access.json /root/firstboot-test-access.json
rm -f /root/firstboot-test-result.json /root/ZENSHIELD-FIRSTBOOT-TEST-CLONE
rm -f /root/zenshield-updater-before-production.json /root/zenshield-enrollment.json
rm -f /root/zenshield-production-before.json /root/zenshield-production-verification.json
rm -f /tmp/zenshield-enrollment.json /tmp/provision-canary.py /tmp/production-appliance.py /tmp/probe-download.py
rm -f /var/lib/zensheild/initialized /var/lib/zensheild/build-complete
rm -rf /var/lib/zenshield
rm -f /root/ZENSHEILD-DISPOSABLE-EXPORT-CLONE
find /home /root -type f \( -name authorized_keys -o -name '.bash_history' -o -name '.python_history' \) -delete
rm -f /home/zenadmin/upstream.tar.gz /home/zenadmin/appliance-config.tar.gz
passwd -l zenadmin
id zenbuild >/dev/null 2>&1 && userdel --remove zenbuild || true
rm -f /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/zensheild-admin /etc/sudoers.d/zenshield-build
sed -i 's/^AllowUsers .*/AllowUsers zenadmin/' /etc/ssh/sshd_config.d/00-zensheild.conf
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 514/udp
ufw --force enable
# No shared SSH host identity. Generation happens before ssh.service/socket.
cat > /etc/systemd/system/zensheild-hostkeys.service <<'EOF'
[Unit]
Description=Generate unique ZenShield SSH host keys
Before=ssh.service
[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl enable zensheild-hostkeys
mkdir -p /etc/systemd/system/ssh.service.d
cat > /etc/systemd/system/ssh.service.d/zenshield-hostkeys.conf <<'EOF'
[Unit]
Requires=zensheild-hostkeys.service
After=zensheild-hostkeys.service
EOF
rm -f /etc/ssh/ssh_host_*
# Generic DHCP matching survives VMware/KVM interface-name and MAC changes.
rm -f /etc/netplan/*.yaml
cat > /etc/netplan/60-zensheild.yaml <<'EOF'
network:
  version: 2
  ethernets:
    appliance:
      match:
        name: "e*"
      dhcp4: true
      dhcp-identifier: mac
EOF
chmod 600 /etc/netplan/60-zensheild.yaml
cloud-init clean --logs --machine-id --seed
touch /etc/cloud/cloud-init.disabled
rm -f /var/lib/systemd/random-seed
rm -f /var/lib/dhcp/*.leases /var/lib/chrony/chrony.drift
find /var/log -type f -exec truncate -s 0 {} +
rm -f /var/lib/dbus/machine-id
ln -s /etc/machine-id /var/lib/dbus/machine-id
apt-get clean
sync
fstrim -av || true
systemctl poweroff
