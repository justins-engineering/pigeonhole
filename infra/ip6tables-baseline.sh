#!/usr/bin/env bash
# Installs the IPv6 INPUT baseline on the VPS, mirroring the documented
# IPv4 chain (loft's docs/infra/coap-terminator.md, "Host baseline"), plus
# the broker's 8883 accept. Idempotent: every rule is checked before it is
# added, and the policy is set last. Run as root:
#
#   infra/ip6tables-baseline.sh                       # fail2ban guards SSH
#   infra/ip6tables-baseline.sh --with-ssh-throttle   # v4 still uses xt_recent
#
# Why now: the box gains a global IPv6 address in the same step that lets
# the AAAA record exist, and sshd already listens on [::]:22. Whatever
# guards port 22 on v4 must guard it on v6 from the first moment the
# address is up, and a chain with no rules and an ACCEPT policy guards
# nothing.
#
# Why it is safe to run over SSH: the operator's session arrives over
# IPv4, which this chain never sees, so a mistake here cannot lock the
# session out the way an iptables (v4) policy change could.
#
# 5684 stays closed on v6 on purpose. loft binds 0.0.0.0 today, so a v6
# accept for it would advertise a black hole; open it when loft binds
# [::]:5684, not before.
#
# ipv6-icmp is accepted whole, not rate-limited like v4 echo: Neighbor
# Discovery and Router Advertisements ride on it, and filtering them
# produces a delayed, unexplained loss of connectivity as neighbor and
# route state expires.
#
# Nothing here persists across a reboot on its own; the runbook covers
# netfilter-persistent, and the house rule of stopping fail2ban first.
set -euo pipefail

with_throttle=no
case "${1:-}" in
  "") ;;
  --with-ssh-throttle) with_throttle=yes ;;
  *) echo "usage: $0 [--with-ssh-throttle]" >&2; exit 64 ;;
esac

ensure() {
  if ip6tables -C INPUT "$@" 2>/dev/null; then
    echo "present: $*"
  else
    ip6tables -A INPUT "$@"
    echo "added:   $*"
  fi
}

ensure -i lo -j ACCEPT
ensure -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ensure -p ipv6-icmp -j ACCEPT

if [ "$with_throttle" = yes ]; then
  # Its own xt_recent table (ssh6, not ssh): the module keys hit lists by
  # name across both families, so sharing the v4 name would let one
  # family's attempts count against, or clear, the other's.
  ensure -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --name ssh6 --set
  ensure -p tcp --dport 22 -m conntrack --ctstate NEW \
    -m recent --name ssh6 --update --seconds 60 --hitcount 6 -j DROP
fi
ensure -p tcp --dport 22 -j ACCEPT
ensure -p tcp --dport 8883 -j ACCEPT

ip6tables -P INPUT DROP
echo "policy:  INPUT DROP"

echo
echo "live chain:"
ip6tables -S INPUT
