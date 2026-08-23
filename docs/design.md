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

- One session class: a pigeon. Every topic a session may touch is under its own id.
- No cross-client fan-out. A publish never reaches another MQTT client; it becomes an HTTP
  request. The one "subscription" in the system (the pigeon's target shadow) is fed by
  dovecote, not by another publisher.
- No persistence. Session state is the live connection; the durable state is the pigeon's
  Durable Object, reached through dovecote. A broker restart drops sessions and nothing else.
- Upstream data path = the HTTP device routes, identical to `loft`. Upstream push path = the
  pigeon's own device WebSocket (`GET /device/pigeons/:id/ws`), opened by the broker on the
  device's behalf only while the session subscribes to its shadow.

## 2. ADRs

### ADR A: build the core; codec from a crate; tokio, not a framework

Decision: pigeonhole's broker core (connection state machine, session, auth, bridge,
retained shadow feed) is first-party, on tokio. MQTT packet encoding/decoding comes from
`mqtt-proto` 0.4.0 (MIT; v3.1.1 and v5 codecs; `tokio` feature gives `decode_async` over
`tokio::io::AsyncRead`; proptest and fuzz targets in-tree; a 2025 release judging by its
thiserror 2 / embedded-io 0.7 dependencies; checked). TLS is OpenSSL via `tokio-openssl`.
Upstream HTTP is `reqwest` (rustls, HTTP/2), the PSK resolver is a blocking `ureq` client
behind an in-process cache, exactly loft's split (checked in `~/loft/loft/Cargo.toml`).

Alternatives:
- Embed `rumqttd` (Apache-2.0, 0.20): a general fan-out broker with its own router and log.
  It does offer a dynamic CONNECT auth hook (`set_auth_handler`; checked), but its router
  PUBACKs when a publish is committed to its own log, not when an upstream call succeeds,
  it has no per-session topic authorization hook, and its TLS is rustls/native-tls with no
  PSK (checked). "PUBACK only after dovecote answered" and "a session may only touch its own
  pigeon's topics" would both have to be fought into its router, and its persistence and
  config surface is dead weight here.
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
- QoS 0 and 1 native. QoS 2: a v3.1.1 PUBLISH is accepted with the full
  PUBREC/PUBREL/PUBCOMP exchange but at-least-once upstream semantics (forwarded at PUBLISH,
  no dedup store); a v5 CONNACK advertises Maximum QoS = 1 and a QoS 2 PUBLISH is then a
  protocol error (DISCONNECT 0x9B). SUBSCRIBE at QoS 2 is granted at QoS 1.
- Retained: `pigeons/<id>/shadow/target` is retained server-side (the retained value is the
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

Alternatives: reject QoS 2 outright on both versions (cleaner, but a client hardcoded to QoS 2
is a support ticket and v3.1.1 has no way to say why); v5-only (breaks Zephyr); drop LWT
(users expect it; the bridging form costs nothing); real persistent sessions (nothing to
persist that the shadow does not already carry).

### ADR C: topic map and payloads

Decision: topics are rooted at `pigeons/<pigeon_id>/`; payloads are byte-identical to the
HTTP bodies so the bridge copies bytes. Authorization rule (loft's "path id equals handshake
identity"): every topic a session publishes or subscribes must carry the session's own pigeon
id; anything else closes the connection (v5 DISCONNECT 0x87).

| Topic | Dir | Payload | Bridge |
|---|---|---|---|
| `pigeons/<id>/telemetry` | dev -> | flat JSON object of string values, as `POST .../telemetry` takes | `POST /device/pigeons/<id>/telemetry`, `application/json` |
| `pigeons/<id>/shadow/report` | dev -> | `{"current_config":{...},"current_version":N}` | `POST /device/pigeons/<id>/shadow` |
| `pigeons/<id>/logs` | dev -> | raw dictionary-log chunk, <= 16 KiB | `POST /device/pigeons/<id>/logs`, `application/octet-stream` |
| `pigeons/<id>/shadow/target` | -> dev, retained | the `PigeonShadow` JSON exactly as `GET /device/pigeons/<id>/shadow` returns it (same `JsonString` asymmetry) | seeded by one GET at CONNECT, refreshed by `shadow_update` frames over the device WS |

Accepted subscription filters: `pigeons/<id>/shadow/target`, `pigeons/<id>/shadow/#`,
`pigeons/<id>/#`; all three mean "the shadow target". Any other filter gets SUBACK failure
(v3: 0x80, v5: 0x87) for that entry. Unknown leaves under the session's own id close the
connection (v5 0x90).

How the device learns of shadow changes: the broker opens the pigeon's device WS
(`GET /device/pigeons/:id/ws`, `Authorization: Bearer <token>`) lazily on the first accepted
shadow subscription and closes it with the session. The WS snapshot on accept and every
`shadow_update` frame refresh the retained value; a retained PUBLISH is sent to the device
only when `(target_version, updated_at)` changed since the last delivery. The frame's `shadow`
member is lifted as a raw JSON slice (`serde_json::value::RawValue`), not re-serialized. WS
reconnect is exponential backoff 1 s to 60 s with jitter while the subscription exists; close
code 4009 ("replaced by new connection", checked in `objects/pigeons.rs`) means something
else holds this pigeon's socket, so the broker backs off to the 60 s ceiling and logs at warn
rather than fighting for it.

Alternatives: polling `GET shadow` per session (no push, N polls per interval against the
edge); a new dovecote -> broker webhook or queue consumer (new inbound surface, new secret, new
route; the WS exists and is hardware-verified); opening the WS at CONNECT for every session
(simpler, but publish-only sessions would each cost a WSS and make `POST /pigeons/:id/shell`
time out instead of 409 for them).

Firmware has no MQTT surface. Images are up to megabytes, the HTTPS/CoAP routes already do
Range/Block2 chunking with device-side resume, and every MQTT-capable device has TCP+TLS. The
`firmware` key arrives inside the retained shadow target; the device fetches via
`GET /device/pigeons/:id/firmware` with its bearer token. Consequence for `pigeon`: a build
with the MQTT connector plus `CONFIG_PIGEON_FOTA` needs the HTTPS download transport factored
out of `pigeon_https.c` (today FOTA depends on the HTTPS connector); phase 3 item.

Consequence of the WS choice: while a subscribed MQTT session exists, dovecote's
`POST /pigeons/:id/shell` sees an open device socket, relays `shell_cmd` to the broker (which
ignores unknown frames), and answers 504 instead of 409. Mapping shell onto
`pigeons/<id>/shell/{cmd,output}` later is cheap because the WS is already there; not now.

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

Dovecote-side contract changes (one atomic change across capsules/dovecote/fancier, since
adding an enum variant breaks every `match`):
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

### ADR E: repo and workspace shape

Decision: Cargo workspace, three crates, loft's conventions (`rustfmt.toml` tab_spaces = 2,
`docs/`, `infra/`, `scripts/`, env-var config, one `LoadCredential=` secret path).

```
pigeonhole/
  Cargo.toml                 workspace; shared dependency versions
  pigeonhole-wire/           what both ends must agree on: topic scheme, payload types mirrored
                             from capsules (loft wire.rs precedent: defined locally, paired
                             type named), limits, size-capped packet framing over tokio IO
  pigeonhole-client/         raw framed connection (arbitrary packets; the harness's tool for
                             misbehaving-client tests) + typed PigeonClient (cert or PSK,
                             keepalive, QoS 1 tracking, typed publish/subscribe)
  pigeonhole/                the broker binary: config, tls, psk, quota, auth, session,
                             proto/{v3,v5}, bridge, shadow, upstream
  docs/                      design.md, open-questions.md, infra/mqtt-broker.md (runbook)
  infra/                     pigeonhole.service (hardened like loft.service), env example
  scripts/                   dev-cert.sh, test/ (native_sim e2e driver)
```

Config: environment variables (`PIGEONHOLE_LISTEN`, `PIGEONHOLE_DOVECOTE_URL`,
`PIGEONHOLE_TLS_CERT`, `PIGEONHOLE_TLS_KEY`, `PIGEONHOLE_PSK_TTL_SECS`, `PIGEONHOLE_LOG`) plus
`PIGEONHOLE_SERVICE_SECRET`, whose value is dovecote's `COAP_SERVICE_SECRET` (the terminator
service gate; the name on dovecote's side is historical), read from `$CREDENTIALS_DIRECTORY`
first (loft's `resolve_service_secret`, copied with its tests). The TLS key and chain also
arrive via `LoadCredential=`.

Logging: `tracing` with an env filter, a one-line stats summary every 60 s at info (sessions,
publishes bridged, upstream errors, WS feeds open). No metrics endpoint in v1.

Deliberate duplication from loft, listed so a later shared crate has its inventory: `quota.rs`,
`psk.rs` (resolver + cache), `config.rs` credential resolution, `tls_common.rs` PSK context
builder. `roost` (LwM2M) would be the third copy; extraction is worth doing at the second
copy's first divergence, not before.

Alternatives: single crate (the harness needs the raw client as a library, and the wire crate
is the contract other Rust consumers want); a fourth "shared with loft" crate now (premature:
loft has not stabilised its Phase 6 cleanup); config file (loft precedent is env; nothing here
needs structure).

### ADR F: phasing

See section 8. Owner-gated throughout: DNS record, Let's Encrypt issuance on the VPS, VPS
deploy, production dovecote/fancier deploys, production pigeon creates, bench flashing of the
C6, `git push`, `cargo publish`.

## 3. Sequence

```
device                    pigeonhole                         dovecote
  |-- TLS ClientHello ------>|                                   |
  |   (cert suites, or PSK)  |-- PSK? GET /internal/device-psk/:id (cache miss only) -->|
  |<-- handshake done -------|                                   |
  |-- CONNECT (user=id,pw=token | client_id=id) -->|             |
  |                          |-- GET /device/pigeons/:id/shadow  Bearer token -------->|
  |                          |<-- 200 PigeonShadow (401 -> CONNACK refused) -----------|
  |<-- CONNACK 0 ------------|   retained[id] = body            |
  |-- SUBSCRIBE shadow/target -->|                              |
  |<-- SUBACK 1, PUBLISH retained shadow --|                    |
  |                          |-- WSS /device/pigeons/:id/ws  Bearer token ----------->|
  |                          |<-- shadow_update snapshot (no change: not re-sent) -----|
  |-- PUBLISH QoS1 telemetry -->|                               |
  |                          |-- POST .../telemetry  bytes as-is --------------------->|
  |                          |<-- 202 --------------------------------------------------|
  |<-- PUBACK ---------------|                                   |
  |                          |        dashboard PUT /pigeons/:id/shadow -> DO        |
  |                          |<-- shadow_update {shadow:{...}} --------------------------|
  |<-- PUBLISH retained shadow/target (version changed) --|       |
  |-- PUBLISH QoS1 shadow/report -->|                            |
  |                          |-- POST .../shadow ----------------------------------->|
  |<-- PUBACK (on 200) ------|                                   |
  |-- DISCONNECT / drop ---->|   close WS; bridge will if ungraceful and set        |
```

## 4. Broker internals (module contracts)

- `config`: env + credentials, fail closed on a missing secret or unreadable key/chain.
- `tls`: one `SslContext`: cert chain + key, min TLS 1.2, PSK callback from loft's
  `tls_common.rs` storing (identity, token) in ex_data. TLS 1.3 clients negotiate certificate
  auth; PSK suites are TLS 1.2 (assumed: OpenSSL serves both from one context; verify at
  implementation with `openssl s_client -psk` and a plain `s_client`).
- `psk`: resolver + positive/negative cache; source = `GET /internal/device-psk/:id` via ureq.
- `quota`: admission permits (RAII).
- `auth`: turns (transport identity, CONNECT packet) into `Authenticated { pigeon_id, token,
  shadow_seed }` or a CONNACK refusal, with the negative cache and the identity-agreement rule.
- `session`: one task per connection. Reader half decodes packets with the size cap from
  `pigeonhole-wire::framing`; a bounded (16) bridge queue executes publishes sequentially in
  arrival order and emits acks on the outbound channel; the writer half serialises the outbound
  channel (acks, retained pushes, PINGRESP); keepalive timer; will; takeover via a
  `registry` map (pigeon id -> session handle). Version-neutral events; `proto/v3` and
  `proto/v5` adapt.
- `bridge`: the ack policy table (section 5); sets `Content-Type`; never parses payloads.
- `shadow`: per-session retained feed: seed, lazy WS, change detection, backoff, 4009 policy.
- `upstream`: reqwest client (`pigeonhole/<version>` UA, 30 s timeout, 10 s connect) and the
  WSS dial (tokio-tungstenite) with the `Authorization` header.

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
  PSK good/stale/unknown, identity disagreement), topic ACL (other id, unknown leaf, bad
  filter), QoS 0/1/2 semantics and ack table per upstream status, oversize packet, rate cap,
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
- T7 `pigeonhole-client` typed layer + `examples/`. Accept: used by the harness happy paths.
- T8 infra + runbook: `infra/pigeonhole.service`, env example, `docs/infra/mqtt-broker.md`
  (bring-up, DNS, certbot DNS-01, firewall, secret, rotation, local dev loop),
  `scripts/dev-cert.sh`. Accept: `systemd-analyze verify`. Gated: DNS, cert, VPS deploy.
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
