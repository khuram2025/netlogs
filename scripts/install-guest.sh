#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
test "$(id -u)" = 0
test -f /etc/lsb-release
cd /opt/zensheild
apt-get update
apt-get dist-upgrade -y
apt-get install -y docker.io docker-compose-v2 open-vm-tools qemu-guest-agent ufw auditd fail2ban unattended-upgrades chrony curl git openssl python3
install -d -m 0755 /etc/docker /etc/ssh/sshd_config.d /etc/systemd/journald.conf.d /etc/fail2ban/jail.d /var/lib/zensheild
cat > /etc/docker/daemon.json <<'EOF'
{"log-driver":"json-file","log-opts":{"max-size":"20m","max-file":"3"},"live-restore":true,"userland-proxy":false}
EOF
cat > /etc/ssh/sshd_config.d/00-zensheild.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowUsers zenadmin
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
EOF
sshd -t
systemctl reload ssh
passwd -l root
cat > /etc/sysctl.d/60-zensheild.conf <<'EOF'
kernel.randomize_va_space=2
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.suid_dumpable=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
EOF
sysctl --system >/dev/null
cat > /etc/systemd/journald.conf.d/zensheild.conf <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=500M
MaxRetentionSec=30day
Compress=yes
EOF
cat > /etc/fail2ban/jail.d/zensheild.conf <<'EOF'
[sshd]
enabled = true
backend = systemd
maxretry = 5
bantime = 3600
EOF
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
cat > /etc/apt/apt.conf.d/52zensheild <<'EOF'
Unattended-Upgrade::Automatic-Reboot "false";
EOF
cat > /etc/issue <<'EOF'
ZenSheild — Ubuntu SIEM/SOAR Appliance
Authorized administration only. Management: HTTPS / SSH public key.
IP: \4

EOF
cp /etc/issue /etc/issue.net
printf 'ZenSheild appliance 0.1.0\nUse sudo docker compose -f /opt/zensheild/compose.yaml ps to inspect services.\n' > /etc/motd
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 514/udp
chmod +x firewall.sh initialize.py
cat > /etc/systemd/system/zensheild-firewall.service <<'EOF'
[Unit]
Description=ZenSheild Docker ingress policy
Requires=docker.service
After=docker.service network-online.target
PartOf=docker.service
Before=zensheild.service
[Service]
Type=oneshot
ExecStart=/opt/zensheild/firewall.sh
RemainAfterExit=yes
[Install]
WantedBy=docker.service
EOF
cat > /etc/systemd/system/zensheild.service <<'EOF'
[Unit]
Description=ZenSheild SIEM/SOAR appliance
Requires=docker.service zensheild-firewall.service
After=docker.service zensheild-firewall.service network-online.target
ConditionPathExists=/var/lib/zensheild/initialized
[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/zensheild
ExecStart=/usr/bin/docker compose up -d --wait --wait-timeout 300
ExecStop=/usr/bin/docker compose stop
TimeoutStartSec=600
TimeoutStopSec=120
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/zensheild-firstboot.service <<'EOF'
[Unit]
Description=ZenSheild first-boot console configuration
After=network-online.target docker.service
Wants=network-online.target
Before=getty@tty1.service
ConditionPathExists=!/var/lib/zensheild/initialized
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
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now docker chrony auditd fail2ban
systemctl restart docker systemd-journald
systemctl enable zensheild zensheild-firstboot zensheild-firewall
python3 initialize.py --build
systemctl start zensheild-firewall
docker compose build --pull web
docker compose pull postgres clickhouse redis nginx
systemctl start zensheild
docker compose ps
touch /var/lib/zensheild/build-complete
