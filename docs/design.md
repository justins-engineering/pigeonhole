# pigeonhole design

`pigeonhole` is PidgeIoT's MQTT broker: a protocol terminator that lets a device speak MQTT
to the platform. It runs natively on the VPS next to `loft` (the CoAP terminator) and follows
the same shape: a transport the edge Worker cannot terminate, authenticated per device,
translated onto `dovecote`'s existing `/device/pigeons/:id/*` routes with the device's own
bearer token, so the broker is never a trusted proxy in the authorization sense. The
companion Rust client library exists for the broker's own test harness and as a reusable
typed client. A topic is a pigeonhole: the slot a message is filed into and collected from.

This document is the ratified structure. Alternatives live only in the ADR "alternatives"
lines; `open-questions.md` holds what still needs the owner.

Terms: "checked" means verified against the actual tree or crate on disk; "assumed" means
not yet verified and listed as an implementation-time check.

## 1. What the broker is, and is not

- A thin bridge, not a broker in the usual sense. It terminates MQTT (TLS, framing, sessions,
  keepalive, the things a Worker physically cannot do) and nothing else: every decision with
  meaning (does this token authorize this pigeon, what is the shadow, is a report accepted,
  what does the free-tier fuse say) is dovecote's, reached over the existing device routes.
  See ADR G.
- One session class: a pigeon. The connection is bound to exactly one pigeon by its handshake,
  so topics are session-scoped and carry no id (ADR C).
- No cross-client fan-out. A publish never reaches another MQTT client; it becomes an HTTP
  request. The one "subscription" in the system (the pigeon's target shadow) is fed by the
  pigeon's own Durable Object, not by another publisher.
- No persistence and no per-pigeon state. The only state the bridge holds is live socket
  state (the downstream MQTT connection and the upstream shadow WebSocket), both reconstructed
  on reconnect. A restart drops connections and loses nothing beyond in-flight QoS 1, which
  the device redelivers, exactly loft's property.
- Upstream data path = the HTTP device routes, identical to `loft`. Upstream push path = the
  pigeon's own device WebSocket (`GET /device/pigeons/:id/ws`), opened by the bridge on the
  device's behalf only while the session subscribes to its shadow.

## 2. ADRs

Read ADR G first: the thin-bridge / fat-Worker rule governs every other ADR, and each of A to
D records where it complies with that rule and where the line had to sit on the VPS. ADR H
decides the Worker topology; section 9 carries the performance and cost numbers the owner
asked to see per ADR.

### ADR A: build the core; codec from a crate; tokio, not a framework

Decision: pigeonhole's broker core (connection state machine, session, auth, bridge,
retained shadow feed) is first-party, on tokio. MQTT packet encoding/decoding comes from
`mqtt-proto` 0.4.0 (MIT; v3.1.1 and v5 codecs; `tokio` feature gives `decode_async` over
`tokio::io::AsyncRead`; proptest and fuzz targets in-tree; a 2025 release judging by its
thiserror 2 / embedded-io 0.7 dependencies; checked). TLS is OpenSSL via `tokio-openssl`.
Upstream HTTP is `reqwest` (rustls, HTTP/2), the PSK resolver is a blocking `ureq` client
behind an in-process cache, exactly loft's split (checked in `~/loft/loft/Cargo.toml`).

Alternatives:
- Embed `rumqttd` (Apache-2.0, 0.20): a general fan-out broker with its own router and a
  persistent commitlog. Disqualified by ADR G first: it PUBACKs when a publish is committed to
  its own log, which is exactly the bridge-held durable store the thin-bridge rule forbids, and
  it has a router/session store the bridge must not own. On top of that it has no per-session
  topic authorization hook, and its TLS is rustls/native-tls with no PSK (all checked). It does
  offer a dynamic CONNECT auth hook (`set_auth_handler`), but that one hook does not offset a
  whole persistent broker underneath the thin layer we want.
- `ntex-mqtt` 8.2 (MIT/Apache; v3 + v5 server framework with handshake/publish/control hooks):
  right shape, wrong ecosystem. It drags the ntex runtime and service stack (ntex-io,
  ntex-service, ntex-util, ntex-net, ntex-rt; checked), a second async world next to loft's
  tokio + reqwest, with frequent major-version churn to track; its TLS goes through ntex-tls,
  so the PSK-plus-certificate listener (ADR D) would be a port rather than a copy of loft's
  proven `tls_common.rs`.
- Own codec: ~1k lines for v3.1.1 plus v5 properties, all of it re-deriving what `mqtt-proto`
  already fuzzes. Not worth owning.
- Thread-per-connection with blocking OpenSSL (loft's model): simpler for request/response
  CoAP, but an MQTT session is full-duplex with server-initiated publishes and keepalive
  timers; one task with a `select!` over socket, outbound channel, and timer is the natural
  shape. The one sync point, the PSK callback's cache-miss lookup, runs under
  `tokio::task::block_in_place`, which requires the multi-thread runtime (the broker and every
  test using the PSK path must use `flavor = "multi_thread"`).

Performance: one task per connection with a `select!` loop is the lowest-overhead shape for
mostly-idle long-lived sessions (no thread stack per connection, no framework indirection per
packet); the codec decodes in place from the read buffer. `mqtt-proto`'s no-heap-until-needed
decoding keeps per-packet allocation to the payload itself.

Consequences: correctness of the session/bridge state machine is ours, covered by the raw
client harness (section 7). Every dependency is MIT/Apache, AGPL-3.0 compatible. The binary
links the system libssl like loft; rustls still appears once (reqwest upstream leg).

### ADR B: protocol versions and features

Decision:
- MQTT 3.1.1 first (phase 2); MQTT 5 in phase 4, through a version-neutral internal event
  model (`session.rs` sees `Connect`/`Publish`/`Subscribe`/... events; `proto/v3.rs` and
  `proto/v5.rs` adapt). v5 is wanted because reason codes make the bridge honest (section 5)
  and because off-the-shelf v5 clients exist. Zephyr 4.4.1's client defaults to 3.1.1 and
  marks 5.0 EXPERIMENTAL (checked), so the device connector targets 3.1.1.
- QoS 0 and 1 native, chosen per publish by the device. Telemetry may go QoS 0 (fire-and-
  forget, matching what the device already does over the WS transport: no PUBACK round trip,
  cheapest on the link) or QoS 1 (matching the HTTPS transport's 202: PUBACK after dovecote
  durably accepts). Shadow reports and log chunks should go QoS 1 (they need the confirmation).
  The bridge honors whatever QoS the packet carries; the ack table (section 5) is the QoS 1
  contract.
- QoS 2: a v3.1.1 PUBLISH is accepted with the full PUBREC/PUBREL/PUBCOMP exchange but at-
  least-once upstream semantics (forwarded at PUBLISH, no dedup store, since the dedup store
  would be exactly the bridge-held state ADR G forbids); a v5 CONNACK advertises Maximum
  QoS = 1 and a QoS 2 PUBLISH is then a protocol error (DISCONNECT 0x9B). SUBSCRIBE at QoS 2
  is granted at QoS 1.
- Retained: `pigeon/shadow/target` is retained server-side (the retained value is the
  pigeon's current shadow). The retain flag on inbound publishes is accepted and ignored.
- Last Will: accepted only if its topic is one of the session's own publish topics; delivered
  on ungraceful disconnect by bridging it exactly like an ordinary publish from that session,
  using the bearer token the session already holds. No new dovecote route. A will is lost if
  the broker itself dies (no persistence), as with any non-persistent broker.
- Sessions are stateless: `clean_session=0` is accepted and answered `session_present=0`
  (v5: Session Expiry Interval 0 in CONNACK). The retained shadow already gives a reconnecting
  device the catch-up that queued messages would have.
- Keepalive: client value honored up to 30 min (clamped above; v5 reports Server Keep Alive);
  0 means a broker-imposed 30 min idle deadline. Silence past 1.5x keepalive closes.
- Limits: inbound packet remaining-length cap 20 KiB (payload cap 16 KiB, mirroring
  `capsules::MAX_LOG_CHUNK_BYTES` and the WS frame cap; topic/properties headroom); topic
  name <= 256 bytes; client id / username <= 128; password <= 256 (token is 92 chars);
  inbound PUBLISH rate 60 per rolling 10 s per session; Receive Maximum 16 (bridge queue
  depth, backpressure by not reading further).

Performance: 3.1.1 is the smaller wire format at baseline (v5 adds at least a 1-byte property
length to every packet), and with the short session-scoped topics of ADR C the v5 topic-alias
saving is only a few bytes, so 3.1.1 is not just the compatibility default but the leaner one
for this fleet; v5's value here is reason codes and negotiated Maximum QoS, not fewer bytes.
QoS 0 telemetry removes one packet and one round trip per report versus QoS 1 (section 9). A
persistent session amortizes the TLS handshake to roughly one per device-connection
rather than one per report, so at a 30 s cadence the handshake cost is negligible per day.

Alternatives: reject QoS 2 outright on both versions (cleaner, but a client hardcoded to QoS 2
is a support ticket and v3.1.1 has no way to say why); v5-only (breaks Zephyr); force QoS 1 on
telemetry (loses the fire-and-forget path the device already has over WS, for no gain); drop
LWT (users expect it; the bridging form costs nothing); real persistent sessions (nothing to
persist that the shadow does not already carry).

### ADR C: topic map and payloads

Decision: topics are session-scoped and carry no pigeon id, rooted at `pigeon/`. The handshake
already bound the connection to one pigeon, so the id in the topic would be redundant weight on
every publish; ThingsBoard (the competitor frame) uses the same session-scoped shape with
`v1/devices/me/...`. Payloads are byte-identical to the HTTP bodies so the bridge copies bytes.
Authorization is therefore "is this a known leaf": the pigeon is fixed, so there is no id to
compare (the loft "path id equals identity" check has no analogue here, and needs none). An
unknown topic closes the connection (v5 DISCONNECT 0x90).

| Topic | Dir | Payload | Bridge |
|---|---|---|---|
| `pigeon/telemetry` | dev -> | flat JSON object of string values, as `POST .../telemetry` takes | `POST /device/pigeons/<id>/telemetry`, `application/json` |
| `pigeon/shadow/report` | dev -> | `{"current_config":{...},"current_version":N}` | `POST /device/pigeons/<id>/shadow` |
| `pigeon/logs` | dev -> | raw dictionary-log chunk, <= 16 KiB | `POST /device/pigeons/<id>/logs`, `application/octet-stream` |
| `pigeon/shadow/target` | -> dev, retained | the `PigeonShadow` JSON exactly as `GET /device/pigeons/<id>/shadow` returns it (same `JsonString` asymmetry) | seeded by one GET at CONNECT, refreshed by `shadow_update` frames over the device WS |

The `<id>` in the Bridge column is the session's own pigeon id, taken from the handshake, not
from the topic. Accepted subscription filters: `pigeon/shadow/target`, `pigeon/shadow/#`,
`pigeon/#`; all three mean "the shadow target". Any other filter gets SUBACK failure (v3:
0x80, v5: 0x87) for that entry.

How the device learns of shadow changes, and why this stays inside ADR G: the bridge opens the
pigeon's device WS (`GET /device/pigeons/:id/ws`, `Authorization: Bearer <token>`) lazily on
the first accepted shadow subscription and closes it with the session. This is a live upstream
socket, not stored state: the retained value is always the DO's own bytes (the `shadow` member
of the snapshot-on-accept frame and of each `shadow_update`, lifted as a raw JSON slice,
`serde_json::value::RawValue`, never re-serialized), and a restart re-opens the WS and re-reads
it. A retained PUBLISH goes to the device only when `(target_version, updated_at)` changed
since the last delivery; the "last delivered" marker is the one disposable cache the bridge
keeps, and losing it on restart only risks one duplicate push, which is harmless. WS reconnect
is exponential backoff 1 s to 60 s with jitter while the subscription exists; close code 4009
("replaced by new connection", checked in `objects/pigeons.rs`) means something else holds this
pigeon's socket, so the bridge backs off to the ceiling and logs at warn rather than fighting.

Alternatives: polling `GET shadow` per session (no push, adds N edge requests per interval,
raises device link traffic and latency, the exact thing the WS exists to avoid); the DO pushing
to the bridge over HTTP (puts the bridge's address and "this pigeon is on MQTT" routing state
into the DO, and has a DO reach a DNS-only host, more coupling for no latency win over the WS);
a dedicated fan-out Worker (evaluated in ADR H, not needed because one pigeon has one MQTT
session on one bridge instance, so the DO's one-device-WS rule already routes correctly, even
multi-region); opening the WS at CONNECT for every session (publish-only sessions would each
cost an idle WS and make `POST /pigeons/:id/shell` time out instead of 409 for them).

Firmware has no MQTT surface. Images are up to megabytes, the HTTPS/CoAP routes already do
Range/Block2 chunking with device-side resume, and every MQTT-capable device has TCP+TLS. The
`firmware` key arrives inside the retained shadow target; the device fetches via
`GET /device/pigeons/:id/firmware` with its bearer token. Consequence for `pigeon`: a build
with the MQTT connector plus `CONFIG_PIGEON_FOTA` needs the HTTPS download transport factored
out of `pigeon_https.c` (today FOTA depends on the HTTPS connector); phase 3 item.

Consequence of the WS choice: while a subscribed MQTT session exists, dovecote's
`POST /pigeons/:id/shell` sees an open device socket, relays `shell_cmd` to the bridge (which
ignores unknown frames), and answers 504 instead of 409. Mapping shell onto
`pigeon/shell/{cmd,output}` later is cheap because the WS is already there; not now.

### ADR D: auth and transport security

Decision: one TLS listener on 8883, OpenSSL, TLS 1.2 minimum, with both a server certificate
chain (Let's Encrypt for `mqtt.pidgeiot.com`) and the PSK ciphersuites loft uses
(`PSK-AES128-CCM8:PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256`); the ClientHello decides.
No plaintext 1883, ever (the CONNECT password is the device token).

- Certificate session: CONNECT `username` = pigeon id, `password` = device bearer token,
  `client_id` = pigeon id or empty. This is the shape every off-the-shelf client supports
  (username is the id because the token carries no subject claim; the broker must know which
  Durable Object to ask). The broker cannot verify the Ed25519 token itself; it is
  verified by issuing `GET /device/pigeons/<id>/shadow` with it. 200 authenticates the
  session and seeds the retained shadow in the same round trip; 401 is CONNACK 0x04 (v3) /
  0x86 (v5); anything else is 0x03 / 0x88.
- PSK session: identity = pigeon id, key = UTF-8 bytes of `tls_psk_secret`, resolved mid-
  handshake through dovecote's service-internal PSK route (loft's resolver and 60 s / 10 s
  caches, copied). The lookup also yields the bearer token the session uses upstream. After
  CONNECT the same shadow GET runs: a 401 there means the cache served a rotated PSK, so the
  entry is evicted and the CONNECT refused. `username`, if present, must equal the identity;
  `password` is ignored.
- One identity, three places it may appear (PSK identity, username, client id); all present
  ones must agree or CONNACK 0x02 / 0x85.
- Token rotation mid-session: the next bridged request 401s, the session is closed (v5
  DISCONNECT 0x87) and its WS dropped. Same semantics as loft's "every request 401s".
- Takeover: a new session for a pigeon replaces the live one (v5 DISCONNECT 0x8E), mirroring
  the device WS's 4009 rule.
- Admission: loft's `quota.rs` (4096 global, 256 per source bucket, IPv6 per /64), loft's
  30 s wall-clock handshake deadline, 10 s CONNECT deadline after it, 30 CONNECTs per source
  per 10 s, and a 10 s negative cache keyed by (identity, sha256(password)) so a
  bad-credential flood does not become a dovecote request flood.
- DNS: `mqtt.pidgeiot.com` is DNS-only (Cloudflare cannot proxy MQTT without Spectrum), so the
  VPS address is exposed exactly as loft's 5684 already is; firewall is an `INPUT` accept on
  8883/tcp next to loft's rules. Certificate: certbot DNS-01 with a scoped Cloudflare API
  token (no inbound port 80); renewal restarts the unit (fleet reconnects with backoff).

Performance: for a persistent MQTT session the handshake is paid once per connection, not per
report, so the cert-versus-PSK difference (a Let's Encrypt chain is ~3-4 KB and a few round
trips; a PSK handshake is ~1 KB and 1 round trip after TCP, the figures in loft's own notes)
is amortized to near-zero at a 30 s cadence, where a device stays connected all day. That is
why cert mode is acceptable for the mains/WiFi devices MQTT targets even though it is heavier
on the wire than PSK: it happens roughly once. PSK stays for the constrained and native_sim
paths, where it is also the lighter handshake. The one auth round trip the bridge adds, the
CONNECT-time shadow GET, doubles as the retained-shadow seed, so it is not a wasted trip.
Session resumption (TLS 1.2 tickets/IDs, on by default in OpenSSL) is a lever only for devices
that cycle connections; MQTT's target devices do not, so it is not load-bearing.

Dovecote-side contract changes (one atomic change across capsules/dovecote/fancier, since
adding an enum variant breaks every `match`; the topology question, whether any of this instead
belongs in a separate Worker, is ADR H, which concludes it does not):
1. `capsules::Connector::Mqtt(MqttConfig)` with
   `MqttConfig { endpoint: String, token: String, tls_psk_identity: Option<String>, tls_psk_secret: Option<String> }`
   (same shape as `CoapConfig`; the `connector` column is JSONB, so no schema change; checked
   `infra/init-db.sql`). Endpoint form: `mqtts://<MQTT_DEVICE_HOST>:8883`, no path.
2. `build_mqtt_endpoint` in `objects/pigeons.rs`; `MQTT_DEVICE_HOST` in all three `wrangler.toml`
   env blocks (prod `mqtt.pidgeiot.com`, staging and dev empty -> falls back to
   `DEVICE_API_HOST`, loft's exact precedent, harmless because test clients dial the broker
   explicitly). `create`/`refresh_token` mint token + PSK for `Mqtt` as for `Coap`;
   `strip_secrets` covers it.
3. `get_coap_psk_internal` matches any PSK-bearing connector (`Coap` or `Mqtt`); the gateway
   gains `GET /internal/device-psk/:pigeon_id` as a neutral alias of `/internal/coap-psk/:pigeon_id`
   (same handler, same `COAP_SERVICE_SECRET` + `COAP_SERVICE_ALLOWED_IPS` gate). pigeonhole
   calls the neutral name; loft moves over at its own cleanup. The VPS egress address is
   already in the production allowlist; no change there.
4. `docs/api.md`: "MQTT device surface (via the pigeonhole broker)" after the CoAP section,
   plus the connector note under `POST /flock/pigeons` and the type reference.
5. `fancier`: connector picker entry, badge, detail card (endpoint, username = id, password
   and PSK pair only at reveal time, one copy-pasteable `mosquitto_pub` line), `TokenReveal`.

Alternatives: PSK-only (no off-the-shelf client support; kills the adoption case); cert-only
(loses the constrained path and the local native_sim loop, and would be the first device
transport without PSK parity); rustls (no PSK ciphersuites, so it cannot host the dual
listener); authenticating the token by publishing a new dovecote "verify token" route (the
shadow GET already is that, and it seeds the retained value).

### ADR E: repo and workspace shape, deploy, examples

Decision: Cargo workspace, three crates, loft's conventions (`rustfmt.toml` tab_spaces = 2,
`docs/`, `infra/`, `scripts/`, env-var config, one `LoadCredential=` secret path). Two deploy
shapes read the same env config: the production shape is the bare binary under a hardened
systemd unit (loft/kratos pattern), and a first-class Docker path (a small multi-stage image
plus a docker-compose example pointed at a configurable `PIGEONHOLE_DOVECOTE_URL`) exists for
developers self-hosting the bridge. The Docker path is documentation-grade, not the production
path, exactly loft's split. A runnable Rust client example ships alongside.

```
pigeonhole/
  Cargo.toml                 workspace; shared dependency versions
  pigeonhole-wire/           what both ends must agree on: topic scheme, payload types mirrored
                             from capsules (loft wire.rs precedent: defined locally, paired
                             type named), limits, size-capped packet framing over tokio IO
  pigeonhole-client/         raw framed connection (arbitrary packets; the harness's tool for
                             misbehaving-client tests) + typed PigeonClient (cert or PSK,
                             keepalive, QoS 1 tracking, typed publish/subscribe)
    examples/                subscribe-and-publish.rs: connect as a pigeon (cert or PSK, env/CLI
                             configured), subscribe to pigeon/shadow/target, publish telemetry,
                             print what arrives; the documentation-grade client demo
  pigeonhole/                the bridge binary: config, tls, psk, quota, auth, session,
                             proto/{v3,v5}, bridge, shadow, upstream
    Dockerfile               multi-stage; runtime stage carries libssl (OpenSSL is dynamically
                             linked, as in loft), verifies the PSK ciphersuites at image build
  docs/                      design.md, open-questions.md, infra/mqtt-broker.md (runbook)
  infra/                     pigeonhole.service (hardened like loft.service), env example,
                             docker-compose.yml (the self-host example, same env vars)
  scripts/                   dev-cert.sh, test/ (native_sim e2e driver)
```

Config: environment variables (`PIGEONHOLE_LISTEN`, `PIGEONHOLE_DOVECOTE_URL`,
`PIGEONHOLE_TLS_CERT`, `PIGEONHOLE_TLS_KEY`, `PIGEONHOLE_PSK_TTL_SECS`, `PIGEONHOLE_LOG`) plus
`PIGEONHOLE_SERVICE_SECRET`, whose value is dovecote's `COAP_SERVICE_SECRET` (the terminator
service gate; the name on dovecote's side is historical), read from `$CREDENTIALS_DIRECTORY`
first (loft's `resolve_service_secret`, copied with its tests). The TLS key and chain arrive
via `LoadCredential=` under systemd, or bind-mounted files named by the same env vars under
Docker, so both deploy shapes are configured identically. The client example reads its own
`PIGEONHOLE_*` / CLI settings and shares nothing with the bridge's config.

Logging: `tracing` with an env filter, a one-line stats summary every 60 s at info (sessions,
publishes bridged, upstream errors, WS feeds open). No metrics endpoint in v1.

Deliberate duplication from loft, listed so a later shared crate has its inventory: `quota.rs`,
`psk.rs` (resolver + cache), `config.rs` credential resolution, `tls_common.rs` PSK context
builder. `roost` (LwM2M) would be the third copy; extraction is worth doing at the second
copy's first divergence, not before.

Alternatives: single crate (the harness needs the raw client as a library, and the wire crate
is the contract other Rust consumers want); a fourth "shared with loft" crate now (premature:
loft has not stabilised its Phase 6 cleanup); config file (loft precedent is env; nothing here
needs structure); a from-scratch client example crate rather than a `cargo` example on
`pigeonhole-client` (the example is one file that uses the library, so the `[[example]]`
convention is the lighter home and stays build-checked with the crate).

### ADR F: phasing

See section 8. Owner-gated throughout: DNS record, Let's Encrypt issuance on the VPS, VPS
deploy, production dovecote/fancier deploys, production pigeon creates, bench flashing of the
C6, `git push`, `cargo publish`.

### ADR G: thin bridge, fat Worker (the governing rule)

Decision: the VPS bridge is the communication layer only. It terminates MQTT (TLS including the
PSK ciphersuites, packet framing, the session state machine, keepalive timers) and holds the
two live sockets per session (the device's MQTT connection, and while subscribed, the upstream
device WebSocket). Everything else lives on the Cloudflare side, in dovecote and the per-pigeon
Durable Objects:

- Credential resolution: PSK identity -> secret + token is dovecote's internal route; the
  bearer token is verified by the owning DO on every bridged request.
- Topic authorization: the bridge's "known leaf?" check (ADR C) is a pre-filter, not an
  authority; a publish it let through to the wrong pigeon would carry this pigeon's token to
  that pigeon's DO and be refused there. The decision is the DO's either way.
- Retained state: the retained value of `pigeon/shadow/target` IS the DO's shadow, read from it
  and refreshed by its pushes; the bridge never holds shadow contents as state.
- Will/offline: a will is forwarded as an ordinary device-route publish; no bridge-held
  offline state, no bridge-side offline detection beyond the socket closing.
- Per-pigeon state of any kind: none. The bridge is stateless beyond in-flight QoS 1 (which
  the device redelivers after a reconnect), loft's exact property: restartable with no data loss.

Line-by-line audit of ADRs A to D against this rule:

| ADR | Already compliant | Where the line had to sit on the VPS, and why |
|---|---|---|
| A | First-party core holds no router/log/session store; `mqtt-proto` is a codec, not a broker. `rumqttd` fails this rule outright (it PUBACKs at its own commitlog). | The session state machine and keepalive timers: a Worker cannot hold the TCP/TLS socket. |
| B | Stateless sessions (`session_present` always 0, v5 Session Expiry 0); retained = the DO's shadow; QoS 2 uses no dedup store; will is a deferred device-route publish. | QoS 1 ack timing: the PUBACK is issued only when the upstream POST completes (2xx), so the ack's meaning is dovecote's durable accept, and nothing is buffered on the bridge. An earlier ack would require a bridge store or risk silent loss. |
| C | Session-scoped topics mean no id to authorize; the retained bytes are the DO's; the "last delivered version" marker is a per-connection duplicate suppressor, dies with the socket. | The lazily opened device WS for shadow push: a Worker cannot hold a socket to a VPS process, so the push must ride a bridge-held live socket to the DO. It is connection state, not stored state. |
| D | Auth is "GET shadow with the presented token": the DO decides, the bridge relays the verdict; PSK lookup is dovecote's route. | Admission counters (global/per-source permits, per-source CONNECT rate, 30 s handshake deadline): these protect the VPS itself from floods and exist only there by nature. Two caches, both bounded and expiring (below). |

Bridge-side caches, stated so they are not mistaken for state: the PSK cache (loft's: positive
entries 60 s, negative 10 s, stale-positive grace only while dovecote is unreachable; bounded
by the number of distinct identities seen in the window) and the negative auth cache (10 s, keyed
by identity + sha256(password), bounded the same way). Both are pure accelerators against a
dovecote request flood; losing them costs extra upstream lookups and nothing else, and neither
can make the bridge answer differently from what dovecote would answer.

Consequences: the Worker side needs exactly one new/generalized surface, the neutral internal
credential route (ADR D); will and offline need no new route; and no component on the VPS may
grow a durable store without reopening this ADR.

### ADR H: Worker topology (one fat Worker or many thin ones)

Options evaluated, with the edge request path a telemetry publish takes in each:

| | (a) routes on dovecote (decided) | (b) dedicated `pigeonhole-worker` | (c) hybrid: bridge -> dovecote data path, separate Worker for session authz + push fan-out |
|---|---|---|---|
| Bridge addresses | dovecote device routes, device WS, `/internal/device-psk` | one Worker: `/mqtt/session`, `/mqtt/publish`, `/mqtt/events` (WS) | dovecote for publishes; the new Worker for CONNECT authz and a push feed |
| Worker -> DO pattern, hops per publish | edge -> dovecote -> pigeon DO (1 Worker hop + 1 DO hop), identical to an HTTPS device | edge -> pigeonhole-worker -> pigeon DO via a cross-script DO binding (same hop count, second wrangler config, second secret set) | same as (a) for data; CONNECT pays one extra Worker hop |
| Telemetry queue | dovecote's existing `TELEMETRY_QUEUE`, unchanged | either re-enqueue into the same queue (duplicate producer binding) or a parallel ingestion path that bypasses the route's token verification | same as (a) |
| Shadow push | DO -> device WS -> bridge (exists, hardware-verified) | DO -> new fan-out path -> Worker -> bridge (new, and a Worker still cannot hold a socket to the VPS, so it ends up as a WS from the bridge anyway) | a new WS endpoint on the new Worker proxying the DO's push: one more hop, no latency win |
| Deploy coupling | one Worker to deploy; capsules shapes shared as today | two Workers with cross-script DO bindings and shared secrets to keep in step | two Workers, split responsibilities to keep in sync |
| Cold start / per-request cost | same per-request price as HTTPS/CoAP devices; no new Worker means no new cold-start surface | one more Worker request per publish (~$0.30/M), one more cold-start surface, more code paths between device and DO | extra cost only on CONNECT (rare) |

Decision: (a). Performance is the tie-breaker and (a) has the fewest hops on the hot path (a
publish is the same two-hop edge path an HTTPS device already uses, entering the same queue),
the lowest per-request cost (no second Worker invocation), and the push path that already exists.
(b) adds a hop, a cold-start surface, and a second deploy unit without reducing any edge work,
because MQTT introduces no new per-pigeon logic: every publish is an existing device route.

What would flip it: a need for shadow-push fan-out to many bridge instances for one pigeon
(anycast bridges where the device's session and the DO's WS could land on different instances),
or session-authorization logic that grows state of its own (rate plans per session, per-pigeon
MQTT ACLs). Either would justify (c) first, a small authz/fan-out Worker beside dovecote, not (b).
Neither exists now, and the DO's one-device-WS rule already routes the push to the one bridge
instance that holds the session, even across regions.

Alternatives beyond the table: the bridge producing to the telemetry Queue directly (bypasses the
token verification the device route performs, breaking "the bridge is not a trusted proxy").

## 3. Sequence

```
device                    pigeonhole                         dovecote
  |-- TLS ClientHello ------>|                                   |
  |   (cert suites, or PSK)  |-- PSK? GET /internal/device-psk/:id (cache miss only) -->|
  |<-- handshake done -------|                                   |
  |-- CONNECT (user=id,pw=token | client_id=id) -->|             |
  |                          |-- GET /device/pigeons/:id/shadow  Bearer token -------->|
  |                          |<-- 200 PigeonShadow (401 -> CONNACK refused) -----------|
  |<-- CONNACK 0 ------------|   body seeds this connection's first retained delivery |
  |-- SUBSCRIBE pigeon/shadow/target -->|                              |
  |<-- SUBACK 1, PUBLISH retained shadow --|                    |
  |                          |-- WSS /device/pigeons/:id/ws  Bearer token ----------->|
  |                          |<-- shadow_update snapshot (no change: not re-sent) -----|
  |-- PUBLISH QoS1 telemetry -->|                               |
  |                          |-- POST .../telemetry  bytes as-is --------------------->|
  |                          |<-- 202 --------------------------------------------------|
  |<-- PUBACK ---------------|                                   |
  |                          |        dashboard PUT /pigeons/:id/shadow -> DO        |
  |                          |<-- shadow_update {shadow:{...}} --------------------------|
  |<-- PUBLISH retained pigeon/shadow/target (version changed) --|       |
  |-- PUBLISH QoS1 pigeon/shadow/report -->|                     |
  |                          |-- POST .../shadow ----------------------------------->|
  |<-- PUBACK (on 200) ------|                                   |
  |-- DISCONNECT / drop ---->|   close WS; bridge will if ungraceful and set        |
```

## 4. Broker internals (module contracts)

Each module's stub carries its own contract; the load-bearing points are: `tls` builds one
`SslContext` (cert chain + key, min TLS 1.2, loft's PSK callback storing identity + token in
ex_data; assumed: OpenSSL serves certificate and PSK suites from one context, verified at
implementation with `openssl s_client -psk` and a plain `s_client`); `psk` is loft's resolver
against `GET /internal/device-psk/:id`; `quota` is loft's RAII permits plus the CONNECT-rate and
negative-auth caches; `auth` turns (transport identity, CONNECT) into an authenticated pigeon or
a CONNACK refusal; `session` is one task per connection with a reader half (size-capped decode),
a bounded (16) in-order bridge queue, a writer half serialising one outbound channel (acks,
retained pushes, PINGRESP), the keepalive timer, the will, and a registry entry for takeover,
over version-neutral events that `proto/v3` and `proto/v5` adapt; `bridge` owns the ack table
(section 5) and never parses payloads; `shadow` is the per-session lazy WS feed with change
detection, backoff, and the 4009 policy; `upstream` is the reqwest client (`pigeonhole/<version>`
UA, 30 s / 10 s timeouts) and the WSS dial with the `Authorization` header.

## 5. Bridge ack policy

PUBACK means dovecote gave this message a final answer (stored, or permanently refused); a
close means "retry later or re-authenticate". QoS 0 follows the same table minus the ack.

| dovecote result | v3.1.1 | v5 |
|---|---|---|
| 2xx (incl. telemetry 202) | PUBACK | PUBACK 0x00 |
| 400 / 404 / 413 (permanent, not retryable) | PUBACK, logged | PUBACK 0x99 (400) / 0x80 |
| 401 / 403 | close | DISCONNECT 0x87 |
| 429 (free-tier fuse: delayed, not lost) | no PUBACK, close | no PUBACK, DISCONNECT 0x97 |
| 5xx / timeout / unreachable | no PUBACK, close | no PUBACK, DISCONNECT 0x89 |

A closed client reconnects with backoff and retransmits unacked QoS 1 publishes (3.1.1
section 4.4), which is the retry.

## 6. Device-side plan

`pigeon` (Zephyr module): a third connector, `CONFIG_PIGEON_CONNECTOR_MQTT`, in the existing
`PIGEON_CONNECTOR_TYPE` choice (`select MQTT_LIB MQTT_LIB_TLS JSON_LIBRARY`), source
`src/pigeon_mqtt.c`, implementing the same hooks the other connectors do (checked in
`src/pigeon_internal.h`): `pigeon_shadow_get()` (serves the latest retained target; the first
call after connect waits on a semaphore up to a Kconfig timeout), `pigeon_shadow_report()`
(QoS 1, returns after PUBACK), `pigeon_transport_report_telemetry()` (QoS 1),
`pigeon_transport_upload_logs()` (QoS 1, binary payload). A worker thread on the
`pigeon_ws.c` pattern owns connect/reconnect with backoff, `mqtt_live()` keepalive and
`mqtt_input()` polling, and delivers a shadow-update callback (the existing
`PIGEON_WS_EVENT_SHADOW_UPDATE` shape, surfaced connector-neutrally). `CONFIG_PIGEON_ENDPOINT`
is the `mqtts://host:8883` string; `CONFIG_PIGEON_TOKEN` is the CONNECT password on
certificate builds and may be empty on PSK builds (CoAP's exact rule); client id and username
are `pigeon_config.device_id`. TLS goes through a sec tag like the other connectors: a CA
cert the app provisions, or the PSK pair registered by the library (the CoAP registration
helper generalised into core, including its `modem_key_mgmt` branch); checked:
`mqtt_transport_socket_tls.c` opens an `IPPROTO_TLS_1_2` socket with `TLS_SEC_TAG_LIST`, the
same socket setup the CoAP TCP connector's PSK session already uses. Keep the transport lock
discipline (`pigeon_transport_lock`) for the handshake.

`pigeon-examples`: one sample, `mqtt_init`, two board targets on the `coap_dtls_init`
board-conditional pattern (that sample already carries `native_sim_native_64.conf` and
`esp32c6_devkitc_hpcore.conf` side by side; checked): `native_sim/native/64` in PSK mode
against a local pigeonhole (dev loop and the e2e driver), `esp32c6_devkitc/esp32c6/hpcore` in
certificate mode over Wi-Fi (connection manager and PSA/TLS Kconfig copied from `wifi_init`;
the CA is ISRG Root X1 for the Let's Encrypt chain, not the GTS root the HTTPS samples
carry). The bench C6 currently serves CoAP testing; flashing it for MQTT is a scheduling item
for the owner, not an assumption.

## 7. Test strategy

- Unit: topic parse/format (proptest), framing caps, ack-policy table, auth identity rule,
  config/credential resolution, quota (loft's tests carried over).
- Integration (`pigeonhole/tests/`): broker in-process on an ephemeral port with a self-signed
  certificate (`rcgen`) and a mock dovecote (axum: device routes, internal PSK route, a WS
  endpoint that emits `shadow_update`); the raw client drives: auth matrix (cert good/bad,
  PSK good/stale/unknown, identity disagreement), topic rule (unknown publish topic, bad
  subscribe filter), QoS 0/1/2 semantics and ack table per upstream status, oversize packet, rate cap,
  takeover, will delivery, retained delivery on subscribe, push on `shadow_update`, WS
  reconnect and 4009 policy, token rotation mid-session, keepalive expiry. Multi-thread
  runtime throughout (ADR A).
- Live: the typed client against a local broker pointed at `dovecote-staging` in certificate
  mode (needs no staging allowlist change, since cert auth uses only public device routes);
  PSK mode against `wrangler dev` locally (the dev allowlist already admits loopback;
  checked in `wrangler.toml`); then the native_sim sample as the device-side e2e
  (`scripts/test/native-sim-e2e.sh`), then the C6.
- Soak before production: 1000+ idle sessions, each with a WSS feed to the edge, to confirm
  there is no per-source limit on WebSocket connections through Cloudflare (assumed, must be
  measured) and that memory stays inside the unit's `MemoryMax`.

## 8. Phasing (implementation tasks)

Each task: repo, files, acceptance. "Gated" marks owner approval points.

Phase 1, backend contract (`~/pidgeiot`), one atomic change that compiles at every commit:
- T1 capsules: `Connector::Mqtt(MqttConfig)`; `docs/api.md` MQTT section + connector note +
  type reference. Accept: `cargo check -p capsules`, api.md renders in fancier's reference.
- T2 dovecote: `build_mqtt_endpoint`, `MQTT_DEVICE_HOST` x3, mint/refresh/strip for `Mqtt`,
  PSK handler generalised, `/internal/device-psk/:id` alias. Accept: curl against
  `wrangler dev`: create Mqtt pigeon (token + PSK returned once), GET stripped, refresh
  rotates, internal route 200 for Mqtt / 404 for Https; staging deploy (pre-approved).
- T3 fancier: picker, badge, detail card, reveal, docs page. Accept: release build + Playwright
  pass on the pigeon detail and create flows; staging deploy.

Phase 2, broker (this repo):
- T4 `pigeonhole-wire`: topics, payload types, limits, framing. Accept: unit + proptest green.
- T5 `pigeonhole-client` raw layer + cert/PSK client TLS builders. Accept: round-trips a
  CONNECT/CONNACK against a scripted server in tests.
- T6 broker v3.1.1: config, tls, psk, quota, auth, session, proto/v3, bridge, shadow,
  upstream; integration harness with mock dovecote. Accept: the section 7 integration list
  green; `openssl s_client` both modes.
- T7 `pigeonhole-client` typed layer + `examples/subscribe-and-publish.rs` (env/CLI configured,
  cert or PSK, subscribe to `pigeon/shadow/target`, publish telemetry, print what arrives).
  Accept: the example runs against the T6 harness broker; used by the harness happy paths.
- T8 infra + runbook + Docker: `infra/pigeonhole.service`, env example, `pigeonhole/Dockerfile`
  (small multi-stage image), `infra/docker-compose.yml` (self-host example, same env vars,
  configurable `PIGEONHOLE_DOVECOTE_URL`), `docs/infra/mqtt-broker.md` (bring-up in both
  shapes, DNS, certbot DNS-01, firewall, secret, rotation, local dev loop), `scripts/dev-cert.sh`.
  Accept: `systemd-analyze verify`; `docker compose up` runs the bridge against a local
  `wrangler dev`. Gated: DNS, cert, VPS deploy.
- T9 live: local broker vs `dovecote-staging` in cert mode with the typed client: connect,
  subscribe, dashboard PUT -> push observed, telemetry visible in the dashboard. Accept: a
  written transcript of the run with the observed latencies.

Phase 3, device side:
- T10 `~/pigeon`: `CONFIG_PIGEON_CONNECTOR_MQTT` + `src/pigeon_mqtt.c` + Kconfig + PSK helper
  generalisation; FOTA download transport factored so an MQTT+FOTA build compiles. Accept:
  builds for native_sim and C6; unit tests where the CoAP connector has them.
- T11 `~/pigeon-examples`: `samples/mqtt_init` (native_sim PSK, C6 cert); `scripts/test/
  native-sim-e2e.sh` here drives native_sim against a local broker + mock dovecote. Accept:
  e2e script green; C6 hardware run is gated on bench scheduling.

Phase 4, MQTT 5 and production:
- T12 `proto/v5` + ack reason codes + CONNACK properties; harness v5 matrix. Accept: green.
- T13 soak (section 7) and `MemoryMax` sizing. Accept: numbers in the runbook.
- T14 production bring-up: DNS, cert, unit, firewall, prod dovecote `MQTT_DEVICE_HOST`, prod
  fancier. Gated entirely. Accept: one prod pigeon round-trips with `mosquitto_pub`/`_sub`.

## 9. Performance and cost model

Unit of analysis: one device, telemetry every 30 s (2880 reports/day), a handful of shadow
changes per day, one connection held all day. Prices are Cloudflare list prices as understood at
design time and are to be confirmed at billing; they are order-of-magnitude inputs, not the
design's foundation.

Device link, per telemetry report (the bytes a cellular plan or a battery pays for):

| Item | MQTT 3.1.1 | MQTT 5 | Notes |
|---|---|---|---|
| PUBLISH overhead over payload, QoS 0 | 2 + 2 + 16 = 20 B | 21 B | fixed header, 2-byte length-prefixed topic `pigeon/telemetry` (16 B), v5 adds a 1-byte property length |
| PUBLISH overhead, QoS 1 | 22 B (+2 B packet id) | 23 B | plus a 4 B PUBACK back, one extra round trip |
| Id-in-topic scheme (rejected, ADR C) | +65 B per publish | +65 B | the 64-char pigeon id; ~187 KB/device/day at this cadence for no information the session lacks |
| v5 topic alias after first publish | n/a | topic 2 B instead of 16 B | ~14 B saving per report against a 16 B topic: marginal, so v5 is chosen for reason codes, not bytes |
| Payload | the flat JSON string map the HTTP route takes, byte-identical | same | no re-encoding on the bridge; a CBOR or line-protocol variant would be a dovecote contract change, not an MQTT one |

Round trips: QoS 0 = 1 packet, no wait; QoS 1 = PUBLISH + PUBACK, where the PUBACK waits on the
bridge's upstream POST (one edge round trip, ~20-60 ms VPS to edge), because the ack means
dovecote's durable accept (ADR G). Keepalive at this cadence is near zero: every report resets
the keepalive timer, so PINGREQ/PINGRESP (2 B each) are sent only on a quiet link.

Connection setup, once per device-connection (amortized over a day at this cadence):

| Mode | Round trips after TCP | Handshake bytes | Notes |
|---|---|---|---|
| Certificate, TLS 1.3 | 1 | ~3-4 KB down (Let's Encrypt chain), ~0.3 KB up | the device verifies a chain, needs a CA store and a clock |
| Certificate, TLS 1.2 | 2 | ~3-4 KB down | Zephyr mbedTLS default for a CA-verified socket |
| PSK, TLS 1.2 | 2 | ~1 KB total | loft's figures for the same suites; no CA store, no clock |
| Resumption (1.2 tickets / 1.3 PSK) | 1 | ~0.5 KB | on by default in OpenSSL, stateless tickets; only matters for devices that cycle connections |
| CONNECT + CONNACK | 1 | cert mode ~250 B (id + id + 92-char token), PSK mode ~90 B | one extra edge round trip on the bridge side for the auth/seed shadow GET |

Shadow push latency, dashboard PUT to device PUBLISH: DO broadcast over the open device WS (the
same path the WS transport measured at ~1 s on hardware) plus one bridge-to-device PUBLISH;
no polling interval in the path. A poll design would add up to one interval of latency and
2880 extra edge requests per device per day at a 30 s poll.

Cloudflare cost, per device per day at this cadence, option (a) of ADR H versus option (b):

| Driver | (a) dovecote routes (decided) | (b) dedicated Worker | Unit price assumed |
|---|---|---|---|
| Worker requests | 2880 (one per POST) -> $0.00086 | 5760 if the new Worker fronts dovecote (two invocations per publish), or 2880 if it replaces it but then re-implements the device route -> $0.0017 / $0.00086 | $0.30/M |
| Durable Object requests | 2880 (verify + upsert) -> $0.00043 | same 2880 | $0.15/M |
| DO wall-clock | ~2880 x ~10 ms x 128 MB = ~3.7 GB-s -> $0.00005 | same | $12.50/M GB-s |
| WS held open for the push | hibernated between pushes: no duration billed; the upgrade is 1 request/day | same, plus a second WS hop if the new Worker proxies it | |
| Queue operations (existing `TELEMETRY_QUEUE`) | 2880 writes + 2880 reads/acks -> ~$0.0023 | same queue, same ops (or a parallel ingestion path, rejected in ADR H) | $0.40/M ops |
| Per device per day | ~$0.004 | ~$0.005 (fronting) / ~$0.004 (replacing, with duplicated code) | |
| Per device per month | ~$0.11 | ~$0.14 / ~$0.11 | |

The load-bearing reading: under (a) an MQTT device costs the edge exactly what an HTTPS or CoAP
device costs, because the bridged publish is the identical device-route call into the identical
queue/DO path; the queue is the largest line and is the platform's existing telemetry-history
design, not something MQTT adds. (b) is never cheaper and is slower by a hop on the hot path, so
there is no speed-versus-cost trade to put to the owner here; ADR H's flip conditions are about
future fan-out or authz state, not cost.

VPS cost: an idle session is a socket plus small buffers and, while subscribed, one upstream WSS
whose memory is rustls session state plus buffers; at the expected fleet (hundreds to low
thousands of mostly idle sessions on the shared small box loft already sizes for) the marginal
per-device cost is effectively zero. The per-session figure must be measured (below) to set
`MemoryMax`.

What "unreasonable cost" would look like, so the owner can judge the line: an MQTT device costing
materially more on the edge than an HTTPS/CoAP device for the same telemetry (the design holds
them equal), or the bridge needing a larger VPS tier than loft's box at the 4096-session ceiling.
The three ways a design crosses that line, each a real fork taken above: a billed DO wall-clock
socket pinned per idle device around the clock (avoided by the hibernatable device WS), a second
Worker request or a new durable store per report (avoided by reusing the device route and its
queue; the reason (b) loses), and a per-report handshake (avoided by the persistent session).
Polling `GET shadow` per session would reintroduce 2880 requests/day and is rejected on exactly
this basis.

Assumed and to be measured before production (T13): that Cloudflare imposes no per-source ceiling
on the number of concurrent WebSocket connections the bridge opens to the edge for the shadow
feeds, and the bridge's steady-state memory per idle session, which sets `MemoryMax`.
