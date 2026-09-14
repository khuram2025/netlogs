#!/bin/bash
set -euo pipefail
# Docker published traffic bypasses UFW INPUT rules. Filter it independently.
iface=$(ip -4 route show default | awk 'NR==1 {print $5}')
test -n "$iface"
iptables -N ZENSHEILD-INGRESS 2>/dev/null || true
iptables -F ZENSHEILD-INGRESS
iptables -A ZENSHEILD-INGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -A ZENSHEILD-INGRESS -i "$iface" -p tcp -m multiport --dports 80,443 -j RETURN
iptables -A ZENSHEILD-INGRESS -i "$iface" -p udp --dport 5514 -j RETURN
iptables -A ZENSHEILD-INGRESS -i "$iface" -j DROP
iptables -A ZENSHEILD-INGRESS -j RETURN
iptables -C DOCKER-USER -j ZENSHEILD-INGRESS 2>/dev/null || iptables -I DOCKER-USER 1 -j ZENSHEILD-INGRESS
