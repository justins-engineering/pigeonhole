#!/usr/bin/env bash
# Opens or closes 8883/tcp for the broker in the host INPUT chain, on both
# address families, idempotently. Run as root on the VPS:
#
#   infra/firewall-8883.sh          # add the two accepts
#   infra/firewall-8883.sh remove   # delete them (rollback)
#
# INPUT rather than DOCKER-USER: the broker is a bare binary bound directly
# on the host, so its packets never transit Docker's FORWARD path and a
# DOCKER-USER rule would match nothing. Same reasoning as loft's 5684 rules,
# which these sit beside.
#
# Both families or neither: the listener is dual-stack ([::]:8883), so once
# an AAAA record exists a v6 client meeting a chain with no v6 accept sees a
# black hole rather than a refusal, and keeps retrying into it.
#
# Nothing here survives a reboot on its own; the runbook covers
# netfilter-persistent.
set -euo pipefail

mode=${1:-add}
rule=(INPUT -p tcp --dport 8883 -j ACCEPT)

apply() {
  local tool=$1
  case "$mode" in
    add)
      if "$tool" -C "${rule[@]}" 2>/dev/null; then
        echo "$tool: 8883/tcp accept already present"
      else
        "$tool" -A "${rule[@]}"
        echo "$tool: 8883/tcp accept added"
      fi
      ;;
    remove)
      if "$tool" -C "${rule[@]}" 2>/dev/null; then
        "$tool" -D "${rule[@]}"
        echo "$tool: 8883/tcp accept removed"
      else
        echo "$tool: no 8883/tcp accept to remove"
      fi
      ;;
    *)
      echo "usage: $0 [add|remove]" >&2
      exit 64
      ;;
  esac
}

apply iptables
apply ip6tables

echo "live 8883 rules:"
iptables -S INPUT | grep -- '--dport 8883' || true
ip6tables -S INPUT | grep -- '--dport 8883' || true
