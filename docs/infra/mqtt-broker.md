# MQTT broker (pigeonhole) runbook

`pigeonhole` terminates MQTT for PidgeIoT devices and translates every
publish onto dovecote's existing `/device/pigeons/:id/*` routes with the
device's own bearer token. It runs on the same VPS as `loft`, in the same
shape: a bare binary under a hardened systemd unit. `docs/design.md` is the
decision record; this file is how it gets run.

Two rules govern everything below and are not negotiable per deployment:

- **No unencrypted traffic, ever.** There is no port 1883, no plaintext
  listener in any deployment shape, and no byte is read before the TLS
  handshake completes. The CONNECT password is a device token, and that rule
  is what keeps it off the wire. The local dev loop runs TLS too, which is
  what `scripts/dev-cert.sh` exists for.
- **The broker holds no per-pigeon state.** It is a communication layer. If
  something here starts wanting a durable store, that is ADR G being
  reopened, not a configuration change.

## Configuration

Everything is environment variables. The systemd unit and the container
example read the same set, so the two shapes are configured identically.

| Variable | Default | What it is |
|---|---|---|
| `PIGEONHOLE_LISTEN` | `[::]:8883` | TLS listen address. Dual-stack by default, which is what lets one listener serve the A and the AAAA record. A v4-only host sets `0.0.0.0:8883`. |
| `PIGEONHOLE_DOVECOTE_URL` | `https://api.pidgeiot.com` | Where the device routes and the device WebSocket are. |
| `PIGEONHOLE_TLS_CERT` | required | PEM chain, leaf first. |
| `PIGEONHOLE_TLS_KEY` | required | PEM private key for that leaf. |
| `PIGEONHOLE_SERVICE_SECRET` | required | Same value as dovecote's `COAP_SERVICE_SECRET`. Read from `$CREDENTIALS_DIRECTORY` in preference to the environment. |
| `PIGEONHOLE_PSK_TTL_SECS` | `60` | Positive PSK cache TTL. |
| `PIGEONHOLE_FEED_PING_SECS` | `60` | Inbound silence on a device WebSocket before the bridge pings it. Two missed pongs replace the socket. Lower it on a link that goes half-open often. |
| `PIGEONHOLE_LOG` | `info` | `tracing` env filter. |

A missing secret or an unreadable key refuses to start. There is no degraded
mode to fall back to: without a servable chain there is no listener.

`pigeonhole --check` reads the same configuration, builds the TLS context
(so the chain and key must parse and match), resolves the listen address,
prints the leaf's validity window, and exits without binding. Run it from
the unit's own credential set with `systemd-run` (the exact invocation is
in `p4-bringup.md`, step 8) to validate an install or a renewed certificate
before a restart finds the fault.

## Production bring-up (systemd, the production path)

Every step here is owner-gated. This section is the reasoning; the ordered
procedure with exact commands, expected output and a rollback per step is
`p4-bringup.md`, and that is the one to execute from.

1. **DNS.** `mqtt.pidgeiot.com` A record to the VPS, DNS-only. Cloudflare
   cannot proxy MQTT without Spectrum, so the VPS address is exposed exactly
   as `loft`'s 5684 already is.

   Publish the AAAA record **only together with** adding the VPS's IPv6
   egress address to dovecote's `COAP_SERVICE_ALLOWED_IPS`. Otherwise PSK
   resolution starts failing the moment outbound traffic picks v6, and
   `loft`'s does too.

2. **Certificate.** certbot DNS-01 with a scoped Cloudflare API token, so no
   inbound port 80 is needed:

   ```sh
   certbot certonly --dns-cloudflare \
     --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
     --key-type ecdsa --preferred-chain "ISRG Root X2" \
     -d mqtt.pidgeiot.com
   ```

   Both flags matter together. `--key-type ecdsa` alone still yields a chain
   ending in X2 cross-signed **by** ISRG Root X1, an RSA-4096 signature,
   which forces RSA verification into every constrained device build.
   Pinning X2 gives leaf (P-256) to E5/E6 (P-384) anchored at X2: all ECDSA,
   so a device can enable P-256 and P-384 and nothing else.

   Confirm what was actually issued before trusting it:

   ```sh
   openssl crl2pkcs7 -nocrl -certfile /etc/letsencrypt/live/mqtt.pidgeiot.com/fullchain.pem \
     | openssl pkcs7 -print_certs -noout
   ```

3. **Secret.** Same value as dovecote's `COAP_SERVICE_SECRET`:

   ```sh
   install -d -m 0700 /etc/pigeonhole
   install -m 0400 -o root -g root /dev/stdin /etc/pigeonhole/service-secret
   ```

   Root-only is correct and does not need loosening: systemd reads the file
   as PID 1 and re-exposes it into the per-unit credential store, which is
   where the broker's own unprivileged dynamic uid reads from.

4. **Firewall.** An `INPUT` accept on 8883/tcp on both address families,
   next to `loft`'s rules (`infra/firewall-8883.sh`). The IPv6 side of the
   host chain, which the AAAA record makes load-bearing, is
   `infra/ip6tables-baseline.sh`.

5. **Unit.** `install -m 0644 infra/pigeonhole.service
   /etc/systemd/system/`, `systemctl daemon-reload`, `systemctl enable --now
   pigeonhole`. Check the hardening actually applied:

   ```sh
   systemd-analyze security pigeonhole.service
   ```

6. **Check that the constrained suites are actually SELECTED**, not merely
   listed. A cipher list can contain a suite OpenSSL never chooses:
   `openssl ciphers 'PSK-AES128-CCM8'` prints the suite identically at
   security levels 0, 1 and 2, and only level 0 selects it. The broker
   serves CCM8 by lowering the level per connection, and only for a
   ClientHello that offered CCM8, so the certificate path keeps the default
   floor. This check confirms both halves of that.

   ```sh
   # 1. CCM8 alone must come back as CCM8. If it does not, this host's
   #    OpenSSL cannot serve a device that offers only CCM8.
   HEX=$(printf '<tls_psk_secret>' | xxd -p -c 200)
   openssl s_client -connect <host>:8883 -tls1_2 \
     -psk_identity <pigeon id> -psk "$HEX" \
     -cipher 'PSK-AES128-CCM8:@SECLEVEL=0' -ciphersuites '' </dev/null \
     | grep -E 'Cipher *:'

   # 2. CCM8 alongside GCM must also come back as CCM8: server preference
   #    ranks CCM8 first, and GCM here would mean the relaxation is not
   #    reaching the connection.
   openssl s_client -connect <host>:8883 -tls1_2 \
     -psk_identity <pigeon id> -psk "$HEX" \
     -cipher 'PSK-AES128-CCM8:PSK-AES128-GCM-SHA256:@SECLEVEL=0' \
     -ciphersuites '' </dev/null | grep -E 'Cipher *:'

   # 3. A certificate client must still verify and negotiate normally. Its
   #    floor is untouched, so this is unchanged from check 1 above.
   openssl s_client -connect <host>:8883 -CAfile <ca.pem> -servername <host> \
     -tls1_2 -verify_return_error </dev/null | grep -E 'Cipher *:|Verify return'
   ```

   To ask the same question of a bare OpenSSL before the broker is even
   installed, use a loopback pair. **`s_server` exits the moment its stdin
   reaches EOF**, which it does immediately when backgrounded, and the
   resulting `unexpected eof while reading` reads exactly like a negotiation
   failure, so hold stdin open:

   ```sh
   (sleep 10 | openssl s_server -accept 9032 -naccept 1 -psk 1a2b3c4d \
      -nocert -tls1_2 -cipher 'PSK-AES128-CCM8:@SECLEVEL=0') &
   openssl s_client -connect 127.0.0.1:9032 -psk 1a2b3c4d -tls1_2 \
      -cipher 'PSK-AES128-CCM8:@SECLEVEL=0' </dev/null | grep '^New,'
   ```

7. **Renewal.** certbot's deploy hook (`infra/letsencrypt-deploy-hook.sh`,
   installed under `/etc/letsencrypt/renewal-hooks/deploy/`) restarts the
   unit when this lineage renews. That is cheap
   because the shutdown drains: in-flight publishes finish and are
   acknowledged, every session is told the server is shutting down, and the
   fleet reconnects with backoff. `TimeoutStopSec=45s` sits above the drain
   budget so systemd never kills the process mid-drain.

8. **Backend.** Set `MQTT_DEVICE_HOST` in dovecote's `wrangler.toml` so
   minted `Mqtt` endpoints point here. Where it is empty an environment
   falls back to its own API host, which is harmless because test clients
   dial the broker explicitly.

## Container path (self-hosting, documentation-grade)

For a developer running their own bridge. Not the production path.

```sh
cd infra
cp pigeonhole.env.example pigeonhole.env   # fill in the secret
mkdir -p tls && cp /path/to/chain.pem tls/ && cp /path/to/key.pem tls/
docker compose up --build
```

The container runs as an unprivileged user, so the chain and key have to be
readable by it: `chmod 644` on the two files and `755` on the directory that
holds them. `scripts/dev-cert.sh`'s output is deliberately 700, so pointing
the container straight at it fails with "not a readable file" rather than
starting on a chain it cannot serve.

**If you are pointing your own devices at this, have them offer
`PSK-AES128-GCM-SHA256` as well as `PSK-AES128-CCM8`.** This broker serves
CCM8 by relaxing OpenSSL's security level for exactly the connections that
offered it, but a stock OpenSSL listener does not, and a device offering CCM8
alone fails against one with nothing in the log to explain it. Wanting GCM
too costs nothing and makes the device portable across brokers.

The image checks at build time that its OpenSSL lists the PSK suites the
broker is configured for. Worth knowing what that proves: the suites are in
the library's cipher table, not that a handshake will negotiate one. See the
CCM8 note below.

## Local dev loop

```sh
./scripts/dev-cert.sh                      # issues an all-ECDSA local CA
PIGEONHOLE_LISTEN=127.0.0.1:8883 \
PIGEONHOLE_DOVECOTE_URL=http://127.0.0.1:8787 \
PIGEONHOLE_SERVICE_SECRET=<dev value> \
PIGEONHOLE_TLS_CERT=scripts/dev-cert/server.pem \
PIGEONHOLE_TLS_KEY=scripts/dev-cert/server.key \
PIGEONHOLE_LOG=debug \
  cargo run -p pigeonhole
```

`wrangler dev`'s allowlist already admits loopback, so PSK mode resolves
locally. Then drive it with the example client:

```sh
PIGEONHOLE_ENDPOINT=mqtts://127.0.0.1:8883 \
PIGEONHOLE_CA=scripts/dev-cert/ca.pem \
PIGEONHOLE_SERVER_NAME=localhost \
PIGEONHOLE_PIGEON_ID=<id> PIGEONHOLE_TOKEN=<token> \
  cargo run -p pigeonhole-client --example subscribe-and-publish
```

## Handshake checks

Run these against any broker before trusting it. The first two are the ones
that must pass.

```sh
# 1. Certificate mode, with verification on. Run it TWICE, once pinned to
#    each version: an unpinned client picks TLS 1.3, and the TLS 1.2
#    certificate path is a separate cipher list that has been broken before
#    while 1.3 stayed healthy.
openssl s_client -connect <host>:8883 -CAfile <ca.pem> -servername <host> \
  -tls1_2 -verify_return_error </dev/null
openssl s_client -connect <host>:8883 -CAfile <ca.pem> -servername <host> \
  -tls1_3 -verify_return_error </dev/null

# 2. TLS 1.2 PSK. The -psk argument is HEX, and the convention is the hex of
#    the secret string's UTF-8 bytes:
#      printf '<tls_psk_secret>' | xxd -p -c 200
openssl s_client -connect <host>:8883 -tls1_2 \
  -psk_identity <pigeon id> -psk <hex> -cipher PSK-AES128-GCM-SHA256 </dev/null

# 3. TLS 1.3 with a PSK offered. Recorded because the answer was assumed the
#    other way round.
openssl s_client -connect <host>:8883 -tls1_3 \
  -psk_identity <pigeon id> -psk <hex> </dev/null
```

**Which version each kind of client uses, because it decides what a check is
worth.** Zephyr's MQTT transport opens an `IPPROTO_TLS_1_2` socket
unconditionally, so **every first-party device is a TLS 1.2 client**, on the
certificate path and the PSK path alike. TLS 1.3 is reached only by
off-the-shelf clients such as mosquitto. TLS 1.2 is therefore not a legacy
path to keep working; it is the only path the fleet has. That is why check 1
is pinned twice: an unpinned certificate check exercises 1.3, which no
pigeon will ever speak, and this broker did once ship a listener that served
1.3 perfectly and refused every 1.2 certificate client.

What check 3 actually does, measured rather than assumed: OpenSSL does
**not** route a TLS 1.3 external PSK through the TLS 1.2 PSK callback. The
connection completes at TLS 1.3 against the server certificate, and no
session reaches the PSK path at all. That is the safer of the two
possibilities: a TLS 1.3 client offering a PSK gets an ordinary certificate
handshake, presents no CONNECT password, and is refused there rather than
being authenticated by a path nobody vetted.

The same measurement settles a second thing. A TLS 1.3 capable client always
lands on TLS 1.3 and the certificate whatever its 1.2 cipher list says,
because version negotiation happens before ciphersuite selection. The PSK
suites listed first with server preference decide between PSK and ECDHE only
among TLS 1.2 clients, which is what the constrained devices are.

Refusals, both confirmed: a wrong PSK key fails with a bad-record-mac alert,
and an unknown identity with alert 115 (`unknown_psk_identity`). Those are
distinguishable, which OpenSSL decides rather than this broker. It costs
nothing: a pigeon id is a 256-bit Durable Object id, so there is nothing to
enumerate.

**PSK-AES128-CCM8 is served, and it needed work to be.** OpenSSL's default
security level refuses to *select* the suite while still parsing the name
and listing it, so the broker relaxes the level per connection, and only for
a ClientHello that offered CCM8 (`relax_for_ccm8` in `tls.rs`; ADR D carries
the note). Confirmed on-device: a Zephyr/mbedTLS client negotiates `0xC0A8`
against this broker, where the same client on the same build got `0x00A8`
(GCM) before the change.

Check 6 in the bring-up list above is what verifies this on a given host,
and it verifies the scoping rather than bare selectability: CCM8 alone comes
back as CCM8, CCM8 alongside GCM also comes back as CCM8 because server
preference ranks it first, and a certificate client is unaffected.

## A note for `loft`, which shares this box

The trap under the CCM8 check above is not specific to this broker, and
`loft` is on the same VPS with the same OpenSSL.

`openssl ciphers 'PSK-AES128-CCM8'` prints the suite **identically at
security levels 0, 1 and 2**, while only level 0 will select it. So a
build-time check of the shape

```sh
openssl ciphers 'PSK-AES128-CCM8:...' | grep -q PSK-AES128-CCM8
```

passes on a library that will refuse every device offering that suite. Both
this repo's `Dockerfile` and `loft`'s carry a check of exactly that shape,
and neither can answer the question it looks like it is answering. Only a
negotiation can.

Two things follow for `loft` specifically, neither verified here:

- Its OpenSSL DTLS listener presumably runs at the default security level,
  in which case it does not serve `PSK-AES128-CCM8` whatever its cipher list
  says. This broker had exactly that problem and now scopes a relaxation to
  the connections that need it; `loft` has no such scoping. The loopback
  `s_server` pair above answers it for DTLS with `-dtls1_2` in place of
  `-tls1_2`.
- Its mbedTLS CID listener is a different stack and none of this applies to
  it. The CoAP CID work was on that listener, so a device negotiating CCM8
  over CID says nothing about the OpenSSL path.

The question for `loft` is narrower than "does it offer CCM8", though. Its
CoAP devices offer CCM8 **and** GCM (measured on the bench C6), so they are
landing on GCM today and nobody would have noticed. The gap only bites a
CoAP device that offers CCM8 alone, and no such device is known to exist.

One thing there does want re-reading rather than re-running: **if `loft`'s
own verification ever recorded "CCM8 negotiated", check how it was
measured.** The `s_server` stdin artifact above corrupts exactly that
measurement, and it corrupts it in the direction of a false failure, so a
recorded success is more likely to be sound than a recorded failure. A
recorded failure is the one worth repeating with stdin held open.

Worth an hour on that repo before a constrained device is pointed at either
service, and cheap to answer.

## What the logs say

One summary line a minute at info:

```
stats summary="sessions=12 accepted=340 refused=2 publishes=8912 publish_errors=1 edge_403s=0 feeds=12 pushes=41" connections=12
```

`edge_403s` is counted apart from `refused` on purpose: a 403 carrying an
HTML body is an edge-mitigation event, not a fleet credential failure, and
the two want very different responses.

## Rotation and revocation

Nothing here needs an operator. A `token/refresh` or a `delete` on a pigeon
closes its device WebSocket with 4004 or 4005, and the broker ends the MQTT
session on that signal without redialling the dead credential. A PSK
session's cached pair can be up to `PIGEONHOLE_PSK_TTL_SECS` stale, so an
old PSK can still complete a handshake inside that window; the session's
device socket upgrade then answers 401, the cache entry is evicted, and the
CONNECT is refused. No window exists where a revoked credential reads or
writes anything.

To rotate the service secret: update dovecote's `COAP_SERVICE_SECRET`,
rewrite `/etc/pigeonhole/service-secret`, `systemctl restart pigeonhole`.
The restart drains. Do dovecote first only if you can tolerate PSK sessions
failing in between; certificate sessions are unaffected either way, since
they never touch the internal route.

## Things that will look like a broker fault and are not

- **Every PSK CONNECT refused, certificate ones fine.** The service secret
  or the source-address allowlist. `/internal/device-psk` answers 403 for
  both, and the broker treats that as indeterminate rather than caching it
  against the device.
- **Sessions refused with "server unavailable" in bursts.** Read the stats
  line: `edge_403s` climbing means an edge-mitigation event upstream, not
  credentials.
- **A device connects, then is closed the moment it publishes.** The
  account's message allowance. On MQTT 5 the client is acknowledged 0x97 and
  the session survives; on 3.1.1 the close is the only signal the version
  has, which is why the device connector treats repeated
  close-after-publish as a long-backoff condition.
- **A fleet behind one NAT address reconnecting slowly.** The per-source
  CONNECT rate is 30 per 10 s, so 256 devices behind one address take about
  85 s to all get back. That is the intended trade against a credential
  flood from a single source.
