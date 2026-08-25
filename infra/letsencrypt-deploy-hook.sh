#!/usr/bin/env bash
# certbot deploy hook: restart the broker when its certificate renews.
# Install to /etc/letsencrypt/renewal-hooks/deploy/pigeonhole, mode 0755.
#
# The unit reads the chain and key once, at start, through LoadCredential=,
# so a renewed lineage on disk changes nothing until the process restarts.
# certbot runs every deploy hook for every lineage it renews, hence the
# name check: another certificate on this host must not bounce the broker.
#
# The restart drains rather than drops: in-flight publishes finish and are
# acknowledged, every session is told the server is shutting down, and the
# fleet reconnects with backoff. That is what makes restart-on-renew cheap.
set -euo pipefail

case "${RENEWED_LINEAGE:-}" in
  */mqtt.pidgeiot.com) systemctl restart pigeonhole.service ;;
  *) ;;
esac
