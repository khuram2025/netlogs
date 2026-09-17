#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
test "$(id -u)" = 0
cd /opt/zensheild
apt-get install -y lvm2 rsync python3-yaml python3-pexpect
install -d -m 0755 /usr/local/lib/zenshield /run/zenshield /etc/systemd/system/zensheild.service.d
install -d -m 0700 /var/lib/zenshield
install -m 0644 appliance/control/agent.py appliance/control/rpc.py appliance/control/cli.py appliance/control/ntp.py /usr/local/lib/zenshield/
cat > /usr/local/bin/zenshield <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /usr/local/lib/zenshield/cli.py "$@"
EOF
chmod 0755 /usr/local/bin/zenshield
grep -qxF /usr/local/bin/zenshield /etc/shells || echo /usr/local/bin/zenshield >> /etc/shells
cat > /etc/systemd/system/zenshield-agent.service <<'EOF'
[Unit]
Description=ZenShield appliance management
After=network-online.target docker.service
Wants=network-online.target
[Service]
Type=notify
TimeoutStartSec=120
ExecStart=/usr/bin/python3 /usr/local/lib/zenshield/agent.py
Restart=on-failure
RestartSec=3
RuntimeDirectory=zenshield
RuntimeDirectoryMode=0755
UMask=0077
NoNewPrivileges=yes
# This service must mount data volumes in the host mount namespace for Docker.
# Do not enable options that implicitly create a private mount namespace.
RestrictRealtime=yes
LockPersonality=yes
MemoryMax=512M
TasksMax=128
TimeoutStopSec=35
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/zensheild.service.d/control.conf <<'EOF'
[Unit]
Description=ZenShield SIEM/SOAR appliance
Requires=zenshield-agent.service
After=zenshield-agent.service local-fs.target
[Service]
ExecStart=
ExecStart=/usr/bin/python3 /usr/local/lib/zenshield/agent.py start-services
ExecStop=
ExecStop=/usr/bin/python3 /usr/local/lib/zenshield/agent.py stop-services
EOF
cat > /etc/systemd/system/zensheild-firstboot.service <<'EOF'
[Unit]
Description=ZenShield first-run configuration wizard
After=network-online.target docker.service zenshield-agent.service
Requires=zenshield-agent.service
Wants=network-online.target
Before=getty@tty1.service
ConditionPathExists=!/var/lib/zenshield/setup-complete
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/zensheild/initialize.py
StandardInput=tty-force
StandardOutput=tty
StandardError=tty
TTYPath=/dev/tty1
TTYReset=yes
TTYVHangup=yes
TimeoutStartSec=infinity
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
# Development access is separate from the appliance console and removed by sealing.
if [[ "${1:-}" == '--development' ]]; then
    id zenbuild >/dev/null 2>&1 || useradd --create-home --shell /bin/bash zenbuild
    install -d -m 0700 -o zenbuild -g zenbuild /home/zenbuild/.ssh
    sed 's/^/restrict,from="192.168.18.1" /' /home/zenadmin/.ssh/authorized_keys > /home/zenbuild/.ssh/authorized_keys
    chown zenbuild:zenbuild /home/zenbuild/.ssh/authorized_keys
    chmod 0600 /home/zenbuild/.ssh/authorized_keys
    echo 'zenbuild ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/zenshield-build
    chmod 0440 /etc/sudoers.d/zenshield-build
    sed -i 's/^AllowUsers .*/AllowUsers zenadmin zenbuild/' /etc/ssh/sshd_config.d/00-zensheild.conf
    touch /var/lib/zenshield/setup-complete
fi
rm -f /etc/sudoers.d/90-cloud-init-users
echo 'zenadmin ALL=(ALL:ALL) ALL' > /etc/sudoers.d/zensheild-admin
chmod 0440 /etc/sudoers.d/zensheild-admin
visudo -c
usermod --shell /usr/local/bin/zenshield zenadmin
if [[ "$(hostname)" == 'zensheild' ]]; then
    hostnamectl set-hostname zenshield
    sed -i 's/^127\.0\.1\.1.*/127.0.1.1 zenshield/' /etc/hosts
fi
cat > /etc/issue <<'EOF'

  ZenShield
  Security appliance | Authorized administration only
  Management address: \4

EOF
printf 'ZenShield security appliance. Authorized administration only.\n' > /etc/issue.net
printf '\nZenShield 0.2.0\nUse help or setup from the appliance console.\n' > /etc/motd
chmod -x /etc/update-motd.d/*
install -d -m 0755 /etc/systemd/system/getty@tty1.service.d /etc/default/grub.d
cat > /etc/systemd/system/getty@tty1.service.d/zenshield.conf <<'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty -o '-p -- \\u' - $TERM
EOF
cat > /etc/default/grub.d/99-zenshield.cfg <<'EOF'
GRUB_DISTRIBUTOR="ZenShield"
GRUB_TIMEOUT=2
GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT quiet loglevel=3 systemd.show_status=false"
EOF
cat > /etc/ssh/sshd_config.d/01-zenshield-brand.conf <<'EOF'
DebianBanner no
Banner /etc/issue.net
PrintMotd yes
EOF
sed -i '/^GRUB_DISTRIBUTOR=/c\GRUB_DISTRIBUTOR="ZenShield"' /etc/default/grub
update-grub >/dev/null
sshd -t
systemctl daemon-reload
bash scripts/install-updater.sh
systemctl enable --now zenshield-agent
systemctl restart zenshield-agent
systemctl enable zensheild-firstboot
systemctl reload ssh
echo 'ZenShield appliance controls installed.'
