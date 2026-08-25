# Phase 4: bringing pigeonhole up on the VPS

This is the ordered, run-ready procedure for putting the MQTT broker into
production on the VPS beside `loft` and Kratos. It is written so the owner
can execute it top to bottom in one sitting, with every step marked:

- **GATED**: changes production (DNS, the VPS, a Worker deploy, a production
  pigeon) and is run by the owner. Nothing marked GATED has been done.
- **SAFE**: read-only, or touches only the workstation. Everything marked
  SAFE was run while preparing this document, and the results are recorded
  under "What is already in place".

Each step carries the exact commands, the output to expect, and how to
undo it. `docs/infra/mqtt-broker.md` holds the reasoning behind the shape
(why DNS-only, why DNS-01, why the pinned chain, why the drain makes
restart-on-renew cheap); `docs/design.md` ADR D and ADR E are the decisions.
The sibling services' runbooks are the pattern this follows: `loft`'s
`docs/infra/coap-terminator.md` (the host firewall baseline, the PSK
allowlist, the build-through-Docker convention) and the PidgeIoT repo's
`docs/infra/kratos-systemd-migration.md` (install, verify, rollback shape).

Two rules that hold throughout:

1. **One SSH connection.** The VPS drops new port-22 connections past six a
   minute, silently, for the rest of that minute. Open one control master
   and let every command reuse it. The helper and the alias below do this;
   never loop `ssh` by hand.
2. **Secret values are never printed.** The service secret, the private key
   and the Cloudflare token are referred to by file name, compared with
   `cmp` or by HTTP status, and pass through command substitution only where
   `loft`'s runbook already does the same.

Shell setup used by every remote command below, run once on the workstation:

```sh
vps() {
  ssh -o ControlMaster=auto -o ControlPath="$HOME/.ssh/cm-%r@%h:%p" \
      -o ControlPersist=10m -o BatchMode=yes debian@15.204.254.3 "$@"
}
```

`vps 'command'` runs one command; `vps` alone opens a shell on the same
connection. The transfer helper uses the same control path, so the first
`vps-put.sh` call opens the master and everything after it rides along.

## What is already in place

Checked from the workstation while preparing this, all SAFE:

| Fact | State | How it was checked |
|---|---|---|
| `mqtt.pidgeiot.com` | no A, no AAAA | `dig +short A/AAAA` against the Cloudflare nameservers (`fish`/`reese.ns.cloudflare.com`) |
| `coap.pidgeiot.com` | A `15.204.254.3` only, no AAAA | same |
| Production dovecote | carries the MQTT contract: `MQTT_DEVICE_HOST = "mqtt.pidgeiot.com"` in `dovecote/wrangler.toml` `[vars]`, and `GET /internal/device-psk/:id` answers **403** (allowlist gate), not 404, from a non-allowlisted address | `curl` with a distinctive User-Agent, no credentials |
| Production dovecote allowlist | `COAP_SERVICE_ALLOWED_IPS = "15.204.254.3"`, IPv4 only | `dovecote/wrangler.toml` |
| Production fancier | the served wasm contains the `Mqtt` connector text (`mqtts://`, the reveal copy) | downloaded the hashed asset from `pidgeiot.com` and grepped it |
| Release binary | builds in the Dockerfile's `rust:1-trixie` stage; extracted artifact 9.5 MB, needs `libssl.so.3`, `libcrypto.so.3`, `libgcc_s.so.1`, glibc (`GLIBC_2.34` max, `OPENSSL_3.0.0` symbols); runs `--check` cleanly inside `debian:trixie-slim` + `libssl3t64` 3.5.7, which is the VPS's runtime set | step 1's commands |
| `pigeonhole --check` | validates the config and credentials without binding; refuses a missing variable, a key that does not match the chain, and a malformed listen address | run against the dev certificate, positive and negative cases |
| Unit file | `systemd-analyze verify` clean once the binary exists (the only local finding is the not-yet-installed `/usr/local/bin/pigeonhole`, exactly as the Kratos runbook records); `systemd-analyze security --offline` scores **1.7 OK**, its one ✗ being `UMask=`, moot for a process that writes nothing | step 8's commands, locally |
| Hardening set against a real handshake | under `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `LockPersonality`, `RestrictRealtime`, `NoNewPrivileges`, `RestrictNamespaces`: TLS 1.2 certificate handshake (`ECDHE-ECDSA-AES128-GCM-SHA256`, verify 0), TLS 1.3 (verify 0), and a PSK ClientHello that selected `PSK-AES128-CCM8` and was refused with alert 115 after the resolver hit an unreachable upstream. Zero seccomp or SIGSYS entries. `DynamicUser`, `ProtectSystem` and the other privileged directives can only be exercised on the VPS | `systemd-run --user` on the workstation |
| Scripts | `shellcheck` clean: `scripts/infra/vps-put.sh`, `scripts/infra/vps-preflight.sh`, `infra/firewall-8883.sh`, `infra/ip6tables-baseline.sh`, `infra/letsencrypt-deploy-hook.sh` | |
| Test suite | 182 passed, 0 failed, workspace-wide | `cargo test` |

**Not read: the VPS itself.** The read-only session this preparation would
have used was refused by the workstation's tooling policy, so step 2 is
where those facts get collected, and two of them decide branches later:
whether IPv6 is usable on the host, and whether SSH is guarded by fail2ban
or still by the `xt_recent` throttle.

## Every value the broker reads, and where it comes from

The systemd unit **is** the configuration; there is no separate config
file on the production path. `infra/pigeonhole.env.example` is the same
set for the container path, and both validate with `pigeonhole --check`.

| Value | Source on the VPS | Secret? |
|---|---|---|
| `PIGEONHOLE_LISTEN` | `Environment=` in the unit: `[::]:8883` (dual-stack); the `listen-v4-only.conf` drop-in overrides it to `0.0.0.0:8883` on a host with IPv6 disabled | no |
| `PIGEONHOLE_DOVECOTE_URL` | `Environment=`: `https://api.pidgeiot.com` | no |
| `PIGEONHOLE_LOG` | `Environment=`: `info` | no |
| `PIGEONHOLE_TLS_CERT`, `PIGEONHOLE_TLS_KEY` | `Environment=`: `%d/tls-chain`, `%d/tls-key`, paths into the unit's credential store | no (paths) |
| `tls-chain`, `tls-key` credentials | `LoadCredential=` from `/etc/letsencrypt/live/mqtt.pidgeiot.com/{fullchain,privkey}.pem`, issued by certbot in step 6 | key: yes, root-only on disk, read by PID 1 |
| `PIGEONHOLE_SERVICE_SECRET` credential | `LoadCredential=` from `/etc/pigeonhole/service-secret`, the same value as `/etc/loft/coap-service-secret` and dovecote's `COAP_SERVICE_SECRET` Worker secret (step 7) | yes |
| `PIGEONHOLE_PSK_TTL_SECS`, `PIGEONHOLE_FEED_PING_SECS` | built-in defaults (60 s each); not set in the unit | no |
| Cloudflare API token for DNS-01 | `/etc/letsencrypt/cloudflare.ini`, root 0600, read only by certbot | yes |

## Step 0. Workstation prerequisites (SAFE)

```sh
which docker shellcheck openssl dig mosquitto_sub mosquitto_pub
docker version --format '{{.Server.Version}}'
cd ~/pigeonhole && git status --short && git log --oneline -1
```

Expect: all present (`mosquitto` clients come from the `mosquitto` package
if missing; the repo's own example client is the fallback in step 11), a
clean tree, and the commit this runbook shipped in or later.

## Step 1. Build the release binary (SAFE)

The VPS has no Rust toolchain by design, so the binary is built in the
Dockerfile's first stage (`rust:1-trixie`, the same base `loft` uses) on the
workstation and carried over. That stage links Debian's OpenSSL, so the
artifact is what the VPS's `libssl3t64` expects and Debian's apt patches
its crypto. A native Arch build happens to be ABI-compatible too (max
`GLIBC_2.34`, `OPENSSL_3.0.0` symbols), but the Docker stage is the one
whose environment matches production, so it is the one used.

```sh
cd ~/pigeonhole
docker build --target build -t pigeonhole-build -f pigeonhole/Dockerfile .
out=$(mktemp -d)
docker create --name pigeonhole-extract pigeonhole-build >/dev/null
docker cp pigeonhole-extract:/src/target/release/pigeonhole "$out/pigeonhole"
docker rm pigeonhole-extract >/dev/null
sha256sum "$out/pigeonhole"                     # record this
readelf -d "$out/pigeonhole" | grep NEEDED       # libssl.so.3 libcrypto.so.3 libgcc_s libm libc ld-linux
git rev-parse --short HEAD                       # record beside the sha256
git archive --format=tar.gz -o "$out/pigeonhole-infra.tgz" HEAD infra scripts/infra
echo "$out"
```

Expect: `Finished release profile`, a ~9.5 MB binary, six NEEDED lines and
nothing else (no `libmbedtls`, no brotli: unlike `loft`, this binary has no
mbedTLS listener and reqwest is built without compression). `.dockerignore`
keeps `target/`, `.git/`, the dev certificate and any `pigeonhole.env` out
of the build context, so nothing secret enters the BuildKit cache.

Rollback: none needed; delete `$out`.

## Step 2. Pre-flight: read the VPS (SAFE, read-only, one connection)

```sh
ssh -o ControlMaster=auto -o ControlPath="$HOME/.ssh/cm-%r@%h:%p" \
    -o ControlPersist=10m debian@15.204.254.3 'bash -s' \
    < scripts/infra/vps-preflight.sh | tee "$out/preflight.txt"
```

Read the output against this checklist; each line decides something later.

| Section | What to look for | Decides |
|---|---|---|
| `runtime libraries` | `libssl3t64 3.5.x ii` | step 4: nothing to install for the binary |
| `addresses`, `global v6`, `v6 routes` | a `scope global` v6 address and a `default` v6 route, or neither | step 12: whether the host already has IPv6 or it must be configured |
| `sysctls` | `disable_ipv6 = 0`, `bindv6only = 0` | step 8: `disable_ipv6 = 1` means install the `listen-v4-only.conf` drop-in, or `[::]:8883` will not bind |
| `egress` | `v4: 4xx from 104.21.x.x` or similar; `v6:` an error unless the host already has IPv6 | step 12 ordering: if v6 egress already works, the allowlist entry (12a) is **urgent**, because loft's PSK lookups may already be at risk of arriving over v6 |
| `services` | `loft` and `kratos` active; `fail2ban` active or not; `certbot.timer` absent | step 9: which SSH guard the v6 baseline mirrors; step 6: certbot must be installed |
| `listeners` | `5684` udp+tcp (loft), `127.0.0.1:4433/4434` (kratos), nothing on `8883` | sanity |
| `firewall` | the `INPUT` chain with `-P INPUT DROP`, the two `5684` accepts, and either `f2b-sshd` jumps or the `recent --name ssh` pair; the `ip6tables INPUT` chain, which may be empty with policy ACCEPT | step 9 and 12c: `firewall-8883.sh` appends beside loft's rules; `ip6tables-baseline.sh --with-ssh-throttle` only if v4 still carries `xt_recent` |
| `persisted rule files` | `iptables-persistent ii` and `/etc/iptables/rules.v4` present | step 9: install the package first if absent |
| `certbot` | probably absent; no `/etc/letsencrypt` | step 4 installs it |
| `paths the runbook creates` | none of `/etc/pigeonhole`, the unit, `/usr/local/bin/pigeonhole` exist; `/etc/loft/coap-service-secret` does | step 7 copies loft's secret file |
| `how the network is managed` | which of `systemd-networkd`, `networking` (ifupdown) or `NetworkManager` is active, and the config files present | step 12b: where the v6 address goes |

Rollback: none; nothing was changed.

## Step 3. Transfer the artifacts (GATED: writes to the VPS home directory only)

```sh
scripts/infra/vps-put.sh "$out/pigeonhole"           debian@15.204.254.3 /home/debian/pigeonhole.new
scripts/infra/vps-put.sh "$out/pigeonhole-infra.tgz" debian@15.204.254.3 /home/debian/pigeonhole-infra.tgz
vps 'mkdir -p ~/pigeonhole-p4 && tar xzf ~/pigeonhole-infra.tgz -C ~/pigeonhole-p4 && ls ~/pigeonhole-p4/infra ~/pigeonhole-p4/scripts/infra'
```

Expect: each `vps-put.sh` line ends `sha256 <hash>`, the first one equal to
step 1's recorded hash (the helper exits non-zero on a mismatch), then the
file listing: `pigeonhole.service`, `pigeonhole.service.d/`,
`firewall-8883.sh`, `ip6tables-baseline.sh`, `letsencrypt-deploy-hook.sh`,
`pigeonhole.env.example`, `docker-compose.yml`, and the two scripts.

Rollback: `vps 'rm -rf ~/pigeonhole.new ~/pigeonhole-infra.tgz ~/pigeonhole-p4'`.

## Step 4. Install the binary and certbot (GATED)

```sh
vps 'sudo install -m 0755 -o root -g root ~/pigeonhole.new /usr/local/bin/pigeonhole \
  && sha256sum /usr/local/bin/pigeonhole \
  && ldd /usr/local/bin/pigeonhole | grep -c "not found"; \
  sudo apt-get install -y --no-install-recommends certbot python3-certbot-dns-cloudflare \
  && certbot --version && systemctl is-enabled certbot.timer'
```

Expect: the recorded sha256; `0` unresolved libraries; certbot 4.x;
`certbot.timer` `enabled` (Debian's package installs the twice-daily
`certbot -q renew` timer, which is what renews the certificate in step 6
unattended).

Rollback: `vps 'sudo rm /usr/local/bin/pigeonhole && sudo apt-get purge -y certbot python3-certbot-dns-cloudflare'`.

On a later redeploy keep the outgoing binary as the rollback lever, the
convention `loft.prev` and `kratos.prev` already use on this host:

```sh
vps 'sudo systemctl stop pigeonhole && sudo cp -p /usr/local/bin/pigeonhole /usr/local/bin/pigeonhole.prev \
  && sudo install -m 0755 -o root -g root ~/pigeonhole.new /usr/local/bin/pigeonhole && sudo systemctl start pigeonhole'
```

## Step 5. DNS: the A record (GATED)

`mqtt.pidgeiot.com` A `15.204.254.3`, **DNS-only (grey cloud)**, TTL Auto.
The AAAA record is step 12e, published only after the host has the address,
the v6 firewall baseline and the dovecote allowlist entry, in that order.

Why grey cloud: Cloudflare's proxy carries HTTP on a fixed port list and
nothing else. An orange-clouded record would terminate at the edge, which
does not listen on 8883, so every MQTT connect would fail with nothing in
any log of ours. It also means no edge shielding for 8883, exactly as for
`loft`'s 5684; the broker's own admission control (4096 permits, 256 per
source, CONNECT rate and refusal brakes) is the mitigation.

Dashboard: DNS, Records, Add record: Type A, Name `mqtt`, IPv4 address
`15.204.254.3`, Proxy status **off**, TTL Auto, Comment "pigeonhole MQTT
broker on the VPS; DNS-only because Cloudflare cannot proxy 8883".

Or the API, with a token that has DNS edit on the zone (never echo it):

```sh
zone=$(curl -sS -H "Authorization: Bearer $CF_API_TOKEN" \
  'https://api.cloudflare.com/client/v4/zones?name=pidgeiot.com' | jq -r '.result[0].id')
curl -sS -X POST "https://api.cloudflare.com/client/v4/zones/$zone/dns_records" \
  -H "Authorization: Bearer $CF_API_TOKEN" -H 'Content-Type: application/json' \
  --data '{"type":"A","name":"mqtt","content":"15.204.254.3","ttl":1,"proxied":false,
           "comment":"pigeonhole MQTT broker on the VPS; DNS-only because Cloudflare cannot proxy 8883"}' \
  | jq '.success, .result.name, .result.proxied'
```

Verify from the workstation:

```sh
dig +short A mqtt.pidgeiot.com          # 15.204.254.3
dig +short AAAA mqtt.pidgeiot.com       # nothing, yet
```

Rollback: delete the record. Nothing else references it until step 11.

## Step 6. The certificate (GATED)

DNS-01, not HTTP-01: HTTP-01 needs inbound port 80 on the VPS, which the
host baseline drops and which this box deliberately has no listener for.
DNS-01 needs only a Cloudflare API token that can write one TXT record in
the zone, and it works the same for renewals, with no port opened.

6a. Create the token in the Cloudflare dashboard: My Profile, API Tokens,
Create Token, "Edit zone DNS" template, scoped to Zone: `pidgeiot.com`
only (permissions Zone.DNS:Edit and Zone.Zone:Read), no client IP filter
(the VPS's address changes with step 12), no expiry (renewal is unattended).
Name it `certbot dns-01 mqtt.pidgeiot.com (VPS)`.

6b. Store it on the VPS, root-only. Paste the token at the prompt and end
with Ctrl-D; it never appears in a command line or the journal:

```sh
vps 'sudo install -d -m 0700 /etc/letsencrypt && printf "dns_cloudflare_api_token = " | sudo tee /etc/letsencrypt/cloudflare.ini >/dev/null \
  && sudo tee -a /etc/letsencrypt/cloudflare.ini >/dev/null && sudo chmod 0600 /etc/letsencrypt/cloudflare.ini \
  && sudo wc -c /etc/letsencrypt/cloudflare.ini'
```

Expect: a byte count of 27 plus the token length (Cloudflare tokens are 40
characters, so 67 or 68 with a trailing newline).

6c. Issue. Both key flags matter together, the reasoning is in
`mqtt-broker.md`: `--key-type ecdsa` alone still yields the chain ending in
ISRG Root X2 cross-signed by X1 (an RSA-4096 signature that forces RSA into
every constrained build); pinning the chain gives leaf (P-256) to E5/E6
(P-384) anchored at X2, all ECDSA, which is what the device sample provisions
as its trust anchor. certbot records both flags in the renewal config, so
renewals keep them.

```sh
vps 'sudo certbot certonly --non-interactive --agree-tos --no-eff-email \
  -m <expiry-notice mailbox> \
  --dns-cloudflare --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
  --dns-cloudflare-propagation-seconds 30 \
  --key-type ecdsa --preferred-chain "ISRG Root X2" \
  --cert-name mqtt.pidgeiot.com -d mqtt.pidgeiot.com'
```

Expect: `Successfully received certificate`, with the two paths
`/etc/letsencrypt/live/mqtt.pidgeiot.com/fullchain.pem` and `privkey.pem`.
A `DNS problem: NXDOMAIN` or timeout means propagation; rerun with
`--dns-cloudflare-propagation-seconds 60`.

6d. Confirm what was actually issued, before trusting it:

```sh
vps 'sudo openssl crl2pkcs7 -nocrl -certfile /etc/letsencrypt/live/mqtt.pidgeiot.com/fullchain.pem | openssl pkcs7 -print_certs -noout; \
  sudo openssl x509 -in /etc/letsencrypt/live/mqtt.pidgeiot.com/fullchain.pem -noout -text | grep -E "Public Key Algorithm|NIST CURVE|Not After"; \
  grep -E "key_type|preferred_chain" /etc/letsencrypt/renewal/mqtt.pidgeiot.com.conf'
```

Expect exactly **two** certificates: `subject=CN=mqtt.pidgeiot.com` issued
by `CN=E5` or `CN=E6`, then that intermediate issued by `CN=ISRG Root X2`,
and **no third certificate** (a third one, X2 with issuer ISRG Root X1, is
the cross-signed chain and means the pin did not take). `id-ecPublicKey`,
`NIST CURVE: P-256`, a Not After about 90 days out, and the renewal config
carrying `key_type = ecdsa` and `preferred_chain = ISRG Root X2`.

6e. Install the renewal hook. The unit reads the chain once at start, so a
renewed lineage changes nothing until the process restarts; the hook
restarts it, and only for this lineage.

```sh
vps 'sudo install -m 0755 -o root -g root ~/pigeonhole-p4/infra/letsencrypt-deploy-hook.sh /etc/letsencrypt/renewal-hooks/deploy/pigeonhole \
  && sudo certbot renew --dry-run 2>&1 | tail -4'
```

Expect: `Congratulations, all simulated renewals succeeded`. The dry run
exercises the DNS-01 plugin and Let's Encrypt's staging CA and does not run
deploy hooks, so the hook is exercised in step 10 instead, once there is a
unit to restart.

Rollback: `vps 'sudo certbot delete --cert-name mqtt.pidgeiot.com && sudo rm -f /etc/letsencrypt/renewal-hooks/deploy/pigeonhole /etc/letsencrypt/cloudflare.ini'`,
then revoke the API token in the Cloudflare dashboard. (`certbot revoke`
is unnecessary: an unused, unexposed key needs no revocation.)

## Step 7. The service secret (GATED)

The broker's `PIGEONHOLE_SERVICE_SECRET` is the same value as dovecote's
`COAP_SERVICE_SECRET`, which `loft` already holds on this host. Copy loft's
file rather than minting a new value: one gate, one secret, and no
`wrangler secret put` is needed.

```sh
vps 'sudo install -d -m 0700 -o root -g root /etc/pigeonhole \
  && sudo install -m 0400 -o root -g root /etc/loft/coap-service-secret /etc/pigeonhole/service-secret \
  && sudo cmp /etc/loft/coap-service-secret /etc/pigeonhole/service-secret && echo identical \
  && sudo ls -l /etc/pigeonhole/service-secret'
```

Expect: `identical`, then `-r-------- 1 root root`.

Prove the pair (secret plus this host's egress address) is accepted by
production dovecote, using loft's own check: a garbage identity with the
real secret from the allowlisted address answers **400** (malformed id),
never 403 (which would mean the secret or the address gate):

```sh
vps 'curl -sS -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $(sudo cat /etc/pigeonhole/service-secret)" \
  https://api.pidgeiot.com/internal/device-psk/not-a-real-id'
```

Expect: `400`.

Rollback: `vps 'sudo rm -rf /etc/pigeonhole'`.

## Step 8. The unit, checked before it is started (GATED)

```sh
vps 'sudo install -m 0644 -o root -g root ~/pigeonhole-p4/infra/pigeonhole.service /etc/systemd/system/pigeonhole.service \
  && sudo systemctl daemon-reload && systemd-analyze verify pigeonhole.service && echo verify-clean'
```

Expect: `verify-clean` with nothing before it.

**Only if step 2 showed `net.ipv6.conf.all.disable_ipv6 = 1`**, add the
drop-in, because `[::]:8883` cannot bind on such a host and the broker
refuses to start rather than narrow its listener on its own:

```sh
vps 'sudo install -d -m 0755 /etc/systemd/system/pigeonhole.service.d \
  && sudo install -m 0644 ~/pigeonhole-p4/infra/pigeonhole.service.d/listen-v4-only.conf /etc/systemd/system/pigeonhole.service.d/ \
  && sudo systemctl daemon-reload && systemctl cat pigeonhole | grep PIGEONHOLE_LISTEN'
```

Expect both lines, the drop-in's `0.0.0.0:8883` last (drop-ins parse after
the main file, so the last assignment wins). Remove it in step 12b.

Now validate the configuration through the exact credential set the unit
uses, without binding the port. This is `pigeonhole --check` run as a
transient unit with the same three `LoadCredential=` lines (transient units
do not expand `%d`, hence the explicit credential paths):

```sh
vps 'sudo systemd-run --unit=pigeonhole-check --wait --pipe --collect -p DynamicUser=yes \
  -p LoadCredential=PIGEONHOLE_SERVICE_SECRET:/etc/pigeonhole/service-secret \
  -p LoadCredential=tls-chain:/etc/letsencrypt/live/mqtt.pidgeiot.com/fullchain.pem \
  -p LoadCredential=tls-key:/etc/letsencrypt/live/mqtt.pidgeiot.com/privkey.pem \
  -E PIGEONHOLE_TLS_CERT=/run/credentials/pigeonhole-check.service/tls-chain \
  -E PIGEONHOLE_TLS_KEY=/run/credentials/pigeonhole-check.service/tls-key \
  -E "PIGEONHOLE_LISTEN=[::]:8883" \
  /usr/local/bin/pigeonhole --check'
```

Expect one line beginning `ok listen=[::]:8883 dovecote=https://api.pidgeiot.com`
with `subject="mqtt.pidgeiot.com"` and the certificate's validity window,
then `Finished with result: success`. Any `Error:` here is a configuration
fault that `systemctl start` would hit identically; fix it before step 10.

Do **not** `enable` or `start` yet: the firewall step comes first, so the
first start is immediately testable from outside.

Rollback: `vps 'sudo rm -rf /etc/systemd/system/pigeonhole.service /etc/systemd/system/pigeonhole.service.d && sudo systemctl daemon-reload'`.

## Step 9. Firewall: 8883 on both families, persisted (GATED)

The chain that governs a bare binary is `INPUT`, beside loft's 5684 rules;
a `DOCKER-USER` rule would match nothing. The script adds one accept per
family, idempotently, and prints what is live. The host policy is `DROP`,
so until this runs the port is unreachable even with the broker up, which
is why step 8 could install the unit without exposing anything.

```sh
vps 'sudo ~/pigeonhole-p4/infra/firewall-8883.sh'
```

Expect:

```
iptables: 8883/tcp accept added
ip6tables: 8883/tcp accept added
live 8883 rules:
-A INPUT -p tcp -m tcp --dport 8883 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 8883 -j ACCEPT
```

If step 2 showed the `ip6tables` chain empty with policy `ACCEPT`, the v6
accept is harmless now and becomes meaningful with the baseline in 12c.

Persist, following the house rule from the PidgeIoT repo's
`docs/infra/ssh-hardening.md`: stop fail2ban first (if it is active), or its
runtime chains and every currently banned address get written into the
static rule files. Install `iptables-persistent` first if step 2 showed it
absent (`DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent`,
then do the save below properly rather than trusting the package's own
install-time snapshot).

```sh
vps 'sudo systemctl stop fail2ban; sudo netfilter-persistent save; sudo systemctl start fail2ban; \
  grep -c 8883 /etc/iptables/rules.v4 /etc/iptables/rules.v6; grep -ciE "f2b|recent" /etc/iptables/rules.v4 /etc/iptables/rules.v6'
```

Expect `1` for 8883 in each file, and for the second grep: `0` in both if
fail2ban is the SSH guard, or the two `recent` rules per family if
`xt_recent` still is (compare with step 2; `f2b` must be `0` either way).

Rollback: `vps 'sudo ~/pigeonhole-p4/infra/firewall-8883.sh remove'`, then
the same persist sequence.

## Step 10. Start, and verify on the host (GATED)

```sh
vps 'sudo systemctl enable --now pigeonhole.service && systemctl status pigeonhole --no-pager | head -12'
```

Expect `active (running)`, `Main PID: ... (pigeonhole)`, and in the log tail
the startup line. Then:

```sh
vps 'journalctl -u pigeonhole -n 20 --no-pager -o cat; sudo ss -tlnp | grep 8883; \
  systemd-analyze security pigeonhole.service --no-pager | tail -1; \
  openssl s_client -connect 127.0.0.1:8883 -servername mqtt.pidgeiot.com -tls1_2 -verify_return_error </dev/null 2>&1 | grep -E "Cipher is|Verify return"'
```

Expect:

- `INFO pigeonhole listening (TLS only, certificate and PSK on one port) listen=[::]:8883 dovecote=https://api.pidgeiot.com`
  (or `0.0.0.0:8883` with the drop-in), and no `WARN`/`ERROR`.
- `LISTEN 0 ... [::]:8883 [::]:* users:(("pigeonhole",pid=...))`. Under
  `DynamicUser=` the owning uid is ephemeral; `systemctl status` is the
  reliable way to match the PID, as loft's runbook notes.
- `Overall exposure level for pigeonhole.service: 1.7 OK` (the same figure
  as the offline score; a different number means a directive did not apply
  on this systemd version and the reason wants reading).
- `New, TLSv1.2, Cipher is ECDHE-ECDSA-AES128-GCM-SHA256` and
  `Verify return code: 0 (ok)`: the served chain verifies against Debian's
  own trust store, which carries ISRG Root X2.

Now the renewal hook, since there is finally a unit for it to restart. It
is also the first exercise of the drain (`shutting down: draining sessions`,
then `pigeonhole stopped summary=...`):

```sh
vps 'sudo env RENEWED_LINEAGE=/etc/letsencrypt/live/mqtt.pidgeiot.com /etc/letsencrypt/renewal-hooks/deploy/pigeonhole \
  && sleep 2 && journalctl -u pigeonhole -n 6 --no-pager -o cat && systemctl is-active pigeonhole'
```

Expect the stop lines, a fresh `listening` line, and `active`.

After sixty seconds a stats line appears every minute:
`INFO stats summary="sessions=0 accepted=0 refused=0 publishes=0 publish_errors=0 edge_403s=0 feeds=0 pushes=0" connections=0`.

Rollback: `vps 'sudo systemctl disable --now pigeonhole.service'`; the
port is then closed by the DROP policy regardless of the accept rules.

## Step 11. Verification matrix

From the workstation unless stated. The certificate checks need no
credentials. Everything from CONNACK onward needs one production pigeon
with the `Mqtt` connector (**GATED**: creating a production pigeon), whose
id, token and `tls_psk_secret` are shown once at creation; keep them in a
file outside the repo and export them into the shell that runs these
commands, never on a command line:

```sh
export PIGEON_ID=<id> PIGEON_TOKEN=<token> PIGEON_PSK=<tls_psk_secret>
PSK_HEX=$(printf '%s' "$PIGEON_PSK" | xxd -p -c 200)
```

A Coap-connector pigeon's token also works in certificate mode (the
connector is a provisioning hint, not a transport boundary), but a fresh
`Mqtt` pigeon is the one whose PSK pair is meant for this listener, and it
keeps the bench C6's CoAP pigeon untouched.

| # | Check | Command | Expected |
|---|---|---|---|
| 1 | TLS 1.2 certificate, verified against the OS store | `openssl s_client -connect mqtt.pidgeiot.com:8883 -servername mqtt.pidgeiot.com -tls1_2 -verify_return_error </dev/null 2>&1 \| grep -E 'Cipher is\|Verify return'` | `ECDHE-ECDSA-AES128-GCM-SHA256`, `Verify return code: 0 (ok)` |
| 2 | TLS 1.3 certificate | same with `-tls1_3` | `TLS_AES_...`, verify 0. Run both: the 1.2 certificate path is the only one every first-party device has, and it has been broken once while 1.3 stayed healthy |
| 3 | Chain shape as served | `openssl s_client -connect mqtt.pidgeiot.com:8883 -servername mqtt.pidgeiot.com -showcerts </dev/null 2>/dev/null \| grep -c 'BEGIN CERT'` | `2` (leaf plus E5/E6; the X1 cross-sign would make it 3) |
| 4 | PSK, CCM8 alone | `openssl s_client -connect mqtt.pidgeiot.com:8883 -tls1_2 -psk_identity "$PIGEON_ID" -psk "$PSK_HEX" -cipher 'PSK-AES128-CCM8:@SECLEVEL=0' -ciphersuites '' </dev/null 2>&1 \| grep 'Cipher is'` | `Cipher is PSK-AES128-CCM8` |
| 5 | PSK, CCM8 beside GCM (server preference) | same with `-cipher 'PSK-AES128-CCM8:PSK-AES128-GCM-SHA256:@SECLEVEL=0'` | still `PSK-AES128-CCM8` |
| 6 | Unknown identity | check 4 with `-psk_identity $(printf 'ab%.0s' {1..32})` | `alert unknown psk identity` (115) |
| 7 | Wrong key | check 4 with `-psk 6162` | `bad record mac` (alert 20) |
| 8 | CONNACK + retained seed, MQTT 5 | `mosquitto_sub -h mqtt.pidgeiot.com -p 8883 --tls-use-os-certs -V mqttv5 -i "$PIGEON_ID" -u "$PIGEON_ID" -P "$PIGEON_TOKEN" -t 'pigeon/shadow/target' -v -d` | `Received CONNACK (0)`, `SUBACK` granted QoS 1, then one retained message carrying the pigeon's shadow JSON. Leave it running for 10, 11 and 12 |
| 9 | Telemetry QoS 1 (v5), visible on the dashboard | `mosquitto_pub -h mqtt.pidgeiot.com -p 8883 --tls-use-os-certs -V mqttv5 -i "$PIGEON_ID" -u "$PIGEON_ID" -P "$PIGEON_TOKEN" -q 1 -t pigeon/telemetry -m '{"probe":"1","uptime_s":"1"}' -d` | `Received PUBACK`; within seconds the pigeon's telemetry page shows `probe = 1`. (`-i` must equal `-u`: a differing client id is refused 0x85, the identity-agreement rule) |
| 10 | Telemetry QoS 0 (rides the held device socket) | check 9 with `-q 0` and `"probe":"2"` | no ack; `probe = 2` on the dashboard, often before a QoS 1 report sent just earlier lands (cross-class ordering is deliberately unspecified) |
| 11 | Shadow push latency | `PUT /pigeons/:id/shadow` from the dashboard (edit the shadow, change `telemetry_interval`) | the subscriber from check 8 prints the new target within about a second (178 to 388 ms measured on staging) |
| 12 | Reconnect after a restart | `vps 'sudo systemctl restart pigeonhole'` | the subscriber sees DISCONNECT 0x8B (`Server shutting down`) and, rerun, gets its retained seed again; broker journal shows the drain lines and `session accepted` |
| 13 | Rotation ends the session | `POST /pigeons/:id/token/refresh` from the dashboard while check 8 runs | subscriber sees DISCONNECT 0x87 (not authorized); reconnecting with the old token is refused CONNACK 0x86. Export the new token before continuing |
| 14 | MQTT 3.1.1 | checks 8 and 9 with `-V mqttv311` | `CONNACK (0)`, retained target on `pigeon/#`, PUBACK |
| 15 | PSK session end to end | `PIGEONHOLE_ENDPOINT=mqtts://mqtt.pidgeiot.com:8883 PIGEONHOLE_PIGEON_ID=$PIGEON_ID PIGEONHOLE_PSK=$PIGEON_PSK cargo run -p pigeonhole-client --example subscribe-and-publish` | connects on the PSK handshake with no token, prints the retained target, publishes telemetry; broker journal: `session accepted ... transport="psk"`. (mosquitto's `--psk`/`--psk-identity` does the same where the client build has PSK) |
| 16 | Bench device, certificate mode | flash the C6 with `samples/mqtt_init` (board default, cert mode) built with `CONFIG_PIGEON_ENDPOINT="mqtts://mqtt.pidgeiot.com:8883"`, the pigeon id and token; bench flashing is pre-approved, the build is `west build -p -b esp32c6_devkitc/esp32c6/hpcore` in `~/pigeon-examples` | device console: `MQTT TLS ciphersuite: 0xc02b`, `MQTT session up`, `Target shadow received`, `Applied shadow`; broker journal: `session accepted version="3.1.1" ... transport="certificate"`; telemetry (`uptime_s`, `reset_cause`) visible on the dashboard; a shadow edit applied on the device within seconds |
| 17 | Bench device, PSK mode | same sample with `overlay-psk-native-tls.conf` and the pigeon's PSK pair | `0xc0a8` on the device, `transport="psk"` in the journal |
| 18 | Stats line | `vps 'journalctl -u pigeonhole --since -3m -o cat --no-pager \| grep stats \| tail -1'` | `sessions=` and `accepted=` counting the above, `refused=` only the deliberate refusals, `edge_403s=0` |

If mosquitto is not installed on the workstation, the repo's example client
covers 8 to 12 in certificate mode too (`PIGEONHOLE_TOKEN` instead of
`PIGEONHOLE_PSK`, no `PIGEONHOLE_CA` needed: it uses the OS trust store).

## Step 12. IPv6 and the AAAA record (GATED throughout)

The order here is load-bearing. The moment the host has a global IPv6
address and a default v6 route, outbound connections to Cloudflare may
prefer v6, and dovecote then sees the terminators arrive from an address
that is not in `COAP_SERVICE_ALLOWED_IPS`. `loft`'s PSK lookups (and this
broker's) would answer 403 until the allowlist catches up, which is why the
allowlist deploy comes **first**, and why the AAAA record comes **last**.
Skip nothing, reorder nothing.

12a. **dovecote allowlist** (PidgeIoT repo, production deploy). The address
must be static: a SLAAC or privacy-extension address would rotate the egress
out from under the allowlist. Use the address the OVH control panel assigns
(IPv6 tab of the VPS), and set `use_tempaddr = 0` on the interface in 12b.

```sh
cd ~/pidgeiot
# dovecote/wrangler.toml, production [vars]:
#   COAP_SERVICE_ALLOWED_IPS = "15.204.254.3,<vps v6 address>"
# and extend the comment above it: the host now has v6 egress.
git commit -am 'Allow the VPS'"'"'s IPv6 egress on the internal PSK route'
cd dovecote && bunx wrangler deploy          # production; the alias route needs no change
```

Verify the entry parsed (it is matched as an `IpAddr`, so a bracketed or
zone-suffixed form would be dropped silently and only shrink the list):
step 12d's `400` is the proof.

Rollback: revert the commit and deploy again.

12b. **Configure the address on the VPS.** The address, prefix length and
gateway come from the OVH panel; where the config goes depends on what step
2 showed managing the interface (`ens3` on this host). Two shapes:

ifupdown (`networking` active), `/etc/network/interfaces.d/60-ipv6`:

```
iface ens3 inet6 static
    address <v6 address>/<prefix>
    gateway <v6 gateway>
    # OVH's gateway is often outside the prefix; the on-link route lets it be reached.
    pre-up ip -6 route add <v6 gateway>/128 dev ens3 || true
```

systemd-networkd active, `/etc/systemd/network/60-ipv6.network`:

```
[Match]
Name=ens3
[Network]
Address=<v6 address>/<prefix>
IPv6PrivacyExtensions=no
[Route]
Gateway=<v6 gateway>
GatewayOnLink=yes
```

Apply (`sudo ifup --allow=auto ens3` is not safe on a live interface; use
`sudo ip -6 addr add` and `sudo ip -6 route add` by hand first, then the
file for reboot persistence), then confirm. If the `listen-v4-only.conf`
drop-in was installed in step 8, remove it now and restart the broker so
it binds dual-stack:

```sh
vps 'sudo sysctl -w net.ipv6.conf.ens3.use_tempaddr=0; ip -6 addr show scope global; ip -6 route show default; \
  ping -6 -c 2 -W 3 2606:4700:4700::1111 | tail -2; \
  curl -6 -sS -m 8 -o /dev/null -w "%{http_code} from %{remote_ip}\n" https://api.pidgeiot.com/; \
  sudo rm -f /etc/systemd/system/pigeonhole.service.d/listen-v4-only.conf && sudo systemctl daemon-reload && sudo systemctl restart pigeonhole; \
  sudo ss -tlnp | grep 8883'
```

Expect: the address with `scope global`, a `default via` v6 route, two
replies, an HTTP status from a `2606:4700:...` address, and `[::]:8883`
listening.

Rollback: delete the address and route (`ip -6 addr del`, `ip -6 route del default`)
and the file.

12c. **The v6 firewall baseline.** sshd already listens on `[::]:22`, so
from the moment the address is up whatever guards port 22 on v4 must guard
it on v6, and a chain with no rules and an ACCEPT policy guards nothing.
The script mirrors the documented v4 chain plus 8883, leaves 5684 closed on
v6 (loft binds v4 only today), and is safe to run over an SSH session that
arrived over v4, which this chain never sees.

```sh
vps 'sudo ~/pigeonhole-p4/infra/ip6tables-baseline.sh'                        # fail2ban guards SSH
vps 'sudo ~/pigeonhole-p4/infra/ip6tables-baseline.sh --with-ssh-throttle'    # only if step 2 showed xt_recent on v4
```

Expect `added:` lines, `policy: INPUT DROP`, and the live chain. Then
persist exactly as in step 9 (stop fail2ban, save, start, grep). If
fail2ban is the guard, confirm its v6 handling is on:
`vps 'sudo fail2ban-client get sshd actions; grep -i allowipv6 /etc/fail2ban/jail.local /etc/fail2ban/fail2ban.local 2>/dev/null'`
(`allowipv6 = auto` is the default and bans v6 addresses through
`ip6tables`).

Rollback: `sudo ip6tables -P INPUT ACCEPT && sudo ip6tables -F INPUT`, then
persist; but do this only together with 12b's rollback, never while the
address is up.

12d. **Prove the terminators still resolve PSKs over v6**, and that loft
did not break:

```sh
vps 'curl -6 -sS -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: Bearer $(sudo cat /etc/pigeonhole/service-secret)" \
  https://api.pidgeiot.com/internal/device-psk/not-a-real-id; \
  journalctl -u loft --since -10m --no-pager | grep -c "PSK source unreachable"'
```

Expect `400` and `0`. A `403` here means 12a did not land or the address
differs from the one allowlisted; fix that before 12e.

12e. **The AAAA record.** `mqtt.pidgeiot.com` AAAA `<vps v6 address>`,
DNS-only (grey cloud), same comment as the A record. Dashboard or the API
call from step 5 with `"type":"AAAA"`. `coap.pidgeiot.com` stays A-only
until loft binds `[::]:5684`.

Rollback: delete the record; v4 clients are unaffected.

12f. **Verify over v6** from a v6-capable vantage point (the workstation if
its network has v6; otherwise the bench's cellular path when the feather is
free, since LTE-M carriers are v6-first):

```sh
dig +short AAAA mqtt.pidgeiot.com
openssl s_client -6 -connect mqtt.pidgeiot.com:8883 -servername mqtt.pidgeiot.com -tls1_2 -verify_return_error </dev/null 2>&1 | grep -E 'Cipher is|Verify return'
```

Then check 8 from the matrix; the broker journal's `session accepted` line
names the peer, which must be a `[2...]` address.

## Step 13. Close-out (SAFE)

- Record in this file's history: the binary sha256 and commit, the
  certificate's Not After, the pre-flight's v6 answer, and the matrix
  results with timestamps, the way `docs/verification.md` records the
  staging runs.
- Update the PidgeIoT task list and memory: P4 executed; task #26's
  mqtt half done (A + AAAA), the loft half (5684 on v6) still queued.
- Schedule the soak (T12 in `docs/design.md`): 1000+ idle sessions with
  feeds, steady-state memory per session, `MemoryMax` replaced by a measured
  figure. Until then `MemoryMax=1G` is a backstop with a reasoned, not
  measured, budget.

## Complete rollback

In reverse order; each line is independent of the ones after it.

```sh
# DNS: delete the AAAA, then the A record (dashboard or API).
# dovecote: revert the 12a commit and `wrangler deploy` (only if 12a happened).
vps 'sudo systemctl disable --now pigeonhole.service; \
  sudo rm -rf /etc/systemd/system/pigeonhole.service /etc/systemd/system/pigeonhole.service.d; sudo systemctl daemon-reload; \
  sudo ~/pigeonhole-p4/infra/firewall-8883.sh remove; \
  sudo systemctl stop fail2ban; sudo netfilter-persistent save; sudo systemctl start fail2ban; \
  sudo rm -rf /etc/pigeonhole; \
  sudo certbot delete --cert-name mqtt.pidgeiot.com; sudo rm -f /etc/letsencrypt/renewal-hooks/deploy/pigeonhole /etc/letsencrypt/cloudflare.ini; \
  sudo apt-get purge -y certbot python3-certbot-dns-cloudflare; \
  sudo rm -f /usr/local/bin/pigeonhole /usr/local/bin/pigeonhole.prev; \
  rm -rf ~/pigeonhole.new ~/pigeonhole-infra.tgz ~/pigeonhole-p4'
# Cloudflare: revoke the certbot API token.
# IPv6 (12b, 12c): remove the address config and, only then, the ip6tables baseline; or keep both, they are host hygiene independent of the broker.
```

`MQTT_DEVICE_HOST` in dovecote can stay: it only shapes the endpoint minted
into `Mqtt` pigeons, and a pigeon created meanwhile keeps working over the
HTTPS routes with the same token.

## Open items for the owner

Each is a question with the default this runbook assumes.

1. **One window or two?** Steps 3 to 11 (the A-record bring-up) and step
   12 (IPv6 + AAAA) can run in one sitting or as two. Default: two, with
   12 started the same day only if step 2 shows the host already routable
   over v6 (in which case 12a is urgent regardless, for loft's sake).
2. **Which mailbox for Let's Encrypt expiry notices** (`-m` in 6c)?
   Default: the ops mailbox that already receives dovecote's
   `OPS_ALERT_EMAIL` notifications.
3. **Cloudflare API token shape for certbot.** Default: a dedicated token,
   Zone.DNS:Edit + Zone.Zone:Read on `pidgeiot.com` only, no client-IP
   filter, no expiry, living only in `/etc/letsencrypt/cloudflare.ini`.
4. **Build host.** Default: the workstation (Docker cache warm, VPS stays
   free of a 2 GB build image and a checkout); the VPS can build the same
   way from a clone, as loft's runbook describes.
5. **The verification pigeon.** Default: a new production `Mqtt` pigeon in
   its own flock ("MQTT Test Flock"), so the PSK pair exists and the C6's
   CoAP pigeon stays untouched; delete it after the matrix if unwanted.
6. **Accept restart-on-renew at certbot's timing?** Renewals happen about
   every 60 days at a random time inside the timer's window, and each one
   drains and restarts the broker (a small redelivery window, no loss).
   Default: accept; pinning a maintenance hour costs a timer override for
   no real gain at this fleet size.
7. **Keep `MemoryMax=1G` until the soak?** Default: yes; the soak (T12)
   runs after bring-up, against staging, from the workstation.
8. **A CAA record for the zone?** None exists today. Default: not in this
   phase; a CAA constrains every name in the zone, including Cloudflare's
   own certificates for the proxied hosts, so it is its own change.
9. **Open 5684 on v6 now?** Default: no; loft binds `0.0.0.0` today, and
   an accept ahead of a listener advertises a black hole. The ip6tables
   baseline leaves it closed on purpose; loft's dual-stack change opens it.
