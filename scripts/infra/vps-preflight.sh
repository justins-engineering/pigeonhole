#!/usr/bin/env bash
# Read-only inventory of the VPS before the broker is brought up. Run it
# over ONE connection, which is all it costs against the port-22 throttle:
#
#   ssh -o ControlMaster=auto -o ControlPath="$HOME/.ssh/cm-%r@%h:%p" \
#       -o ControlPersist=10m debian@15.204.254.3 'bash -s' \
#       < scripts/infra/vps-preflight.sh
#
# It changes nothing. The sudo calls read firewall chains and socket owners
# and are skipped (not prompted for) when passwordless sudo is unavailable.
# What it answers, in order: can the binary run here, is IPv6 usable, what
# the firewall looks like on both families, whether certbot is present,
# and what already occupies the ports and paths the runbook will touch.
set +e

section() { printf '\n== %s\n' "$1"; }

section "host"
hostname
grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release
uname -r
systemctl --version | head -1
printf 'cpus=%s mem_mb=%s\n' "$(nproc)" "$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)"
df -h / | tail -1

section "runtime libraries the broker links"
dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\n' libssl3t64 libc6 2>&1
openssl version

section "addresses"
ip -br addr
printf -- '-- global v6:\n'
ip -6 addr show scope global
printf -- '-- v6 routes:\n'
ip -6 route show
printf -- '-- v4 default:\n'
ip -4 route show default

section "sysctls that decide whether [::]:8883 binds dual-stack"
sysctl net.ipv6.conf.all.disable_ipv6 net.ipv6.bindv6only \
  net.ipv4.ip_unprivileged_port_start 2>&1
sysctl net.netfilter.nf_conntrack_max 2>&1

section "egress as dovecote sees it"
printf 'v4: '
curl -4 -sS -m 8 -o /dev/null -w '%{http_code} from %{remote_ip}\n' https://api.pidgeiot.com/ 2>&1 | head -1
printf 'v6: '
curl -6 -sS -m 8 -o /dev/null -w '%{http_code} from %{remote_ip}\n' https://api.pidgeiot.com/ 2>&1 | head -1

section "name resolution"
resolvectl status 2>/dev/null | grep -E 'Protocols|DNS Servers|Current DNS' | head -4
grep -E '^hosts:' /etc/nsswitch.conf

section "services"
for u in loft kratos cloudflared fail2ban docker netfilter-persistent certbot.timer pigeonhole; do
  printf '%-22s enabled=%-10s active=%s\n' "$u" \
    "$(systemctl is-enabled "$u" 2>&1 | head -1)" "$(systemctl is-active "$u" 2>&1 | head -1)"
done

section "listeners on the ports the runbook touches"
if sudo -n true 2>/dev/null; then
  sudo -n ss -tulnp | grep -E ':(22|5684|5685|8883|4433|4434)\s'
else
  ss -tuln | grep -E ':(22|5684|5685|8883|4433|4434)\s'
  echo "(no passwordless sudo: owning processes not shown)"
fi

section "firewall"
if sudo -n true 2>/dev/null; then
  printf -- '-- iptables INPUT:\n'; sudo -n iptables -S INPUT
  printf -- '-- ip6tables INPUT:\n'; sudo -n ip6tables -S INPUT
  printf -- '-- DOCKER-USER:\n'; sudo -n iptables -S DOCKER-USER 2>&1 | head -6
  printf -- '-- fail2ban chains present: '; sudo -n iptables -S | grep -c f2b
else
  echo "(no passwordless sudo: chains not readable)"
fi
printf -- '-- persisted rule files:\n'
ls -la /etc/iptables 2>&1
dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\n' \
  iptables-persistent netfilter-persistent fail2ban 2>&1

section "certbot"
dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\n' \
  certbot python3-certbot-dns-cloudflare 2>&1
find /etc/letsencrypt -maxdepth 1 -printf '%M %u %g %f\n' 2>&1 | head -8
ls /etc/letsencrypt/renewal-hooks/deploy 2>&1

section "paths the runbook creates"
ls -ld /etc/pigeonhole /etc/systemd/system/pigeonhole.service \
  /etc/systemd/system/pigeonhole.service.d /usr/local/bin/pigeonhole 2>&1
ls -la /usr/local/bin/{loft,kratos,pigeonhole}* 2>/dev/null || echo '(none of loft, kratos, pigeonhole under /usr/local/bin)'
ls -la /etc/loft 2>&1

section "loft unit, non-secret lines"
systemctl cat loft 2>/dev/null | grep -E '^(# /|Environment|LoadCredential|MemoryMax|TimeoutStopSec)'

section "how the network is managed (decides where a v6 address is configured)"
for u in systemd-networkd networking NetworkManager; do
  printf '%-16s %s\n' "$u" "$(systemctl is-active "$u" 2>&1)"
done
ls /etc/netplan /etc/network/interfaces.d /etc/systemd/network 2>&1
for f in /etc/netplan/*.yaml /etc/network/interfaces /etc/network/interfaces.d/*; do
  [ -f "$f" ] && { printf -- '-- %s\n' "$f"; sed -n 1,40p "$f"; }
done

section "docker (an on-box build needs it)"
docker version --format '{{.Server.Version}}' 2>&1 | head -1

printf '\n== done\n'
