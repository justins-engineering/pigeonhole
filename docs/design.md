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
  meaning is dovecote's, reached over the existing device routes. See ADR G.
- One session class: a pigeon. The connection is bound to exactly one pigeon by its handshake,
  so topics are session-scoped and carry no id (ADR C).
- No cross-client fan-out. A publish never reaches another MQTT client; it becomes an HTTP
  request. The one "subscription" in the system (the pigeon's target shadow) is fed by the
  pigeon's own Durable Object, not by another publisher.
- No persistence and no per-pigeon state. The only state the bridge holds is live socket
  state (the downstream MQTT connection and the upstream device WebSocket), both reconstructed
  on reconnect. A restart drops connections; redelivery of in-flight QoS 1 is the client's
  (guaranteed by the spec only for CleanSession=0 clients whose library persists unacked
  publishes; the pigeon connector re-publishes from its own pending store, and a drain on
  shutdown makes the window small; ADR B, ADR E).
- Upstream data path = the HTTP device routes, identical to `loft`, plus the pigeon's own
  device WebSocket (`GET /device/pigeons/:id/ws`), opened by the bridge at CONNECT as the
  session's authentication, its shadow feed, and the QoS 0 telemetry fast path.

## 2. ADRs

Read ADR G first: the thin-bridge / fat-Worker rule governs every other ADR. ADR H decides
the Worker topology; section 9 carries the performance and cost numbers.

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
- Own codec: ~1k lines re-deriving what `mqtt-proto` already covers. Not worth owning.
- Thread-per-connection with blocking OpenSSL (loft's model): simpler for request/response
  CoAP, but an MQTT session is full-duplex with server-initiated publishes and timers; one
  task with a `select!` is the natural shape and the cheaper one for mostly-idle long-lived
  sessions. The one sync point, the PSK callback's cache-miss lookup, runs under
  `tokio::task::block_in_place`, which requires the multi-thread runtime everywhere,
  including every test that touches the PSK path.

Consequences: correctness of the session/bridge state machine is ours, covered by the raw
client harness (section 7). Every dependency is MIT/Apache, AGPL-3.0 compatible. The binary
links the system libssl like loft; rustls still appears once (reqwest upstream leg). On
provenance: the published `mqtt-proto` crate carries proptest as a dev-dependency and an
`arbitrary` feature for fuzzing; the fuzz targets themselves live in its upstream repository,
it has a single author, and at ~6k lines it is vendorable if it ever goes quiet.
`decode_raw_header_async` is the hook the size cap needs.

### ADR B: protocol versions and features

Decision:
- MQTT 3.1.1 first; MQTT 5 in the final phase, through a version-neutral internal event
  model (`session.rs` sees `Connect`/`Publish`/`Subscribe`/... events; `proto/v3.rs` and
  `proto/v5.rs` adapt). v5 is wanted because reason codes make the bridge honest (section 5)
  and because off-the-shelf v5 clients exist. Zephyr 4.4.1's client defaults to 3.1.1 and
  marks 5.0 EXPERIMENTAL (checked), so the device connector targets 3.1.1.
- QoS 0 and 1 native, chosen per publish by the device. QoS 0 telemetry rides the session's
  already-open device WS as a `telemetry` frame when the socket is up, falling back to the
  POST when it is not (the evaluation and numbers are in ADR C and section 9); QoS 1
  telemetry, shadow reports and log chunks always go over the POST, because a PUBACK needs an
  HTTP status behind it. The bridge honors whatever QoS the packet carries; the ack table
  (section 5) is the QoS 1 contract.
- QoS 2: a v3.1.1 PUBLISH is accepted with the full PUBREC/PUBREL/PUBCOMP exchange but at-
  least-once upstream semantics (forwarded at PUBLISH, no dedup store, since the dedup store
  would be exactly the bridge-held state ADR G forbids); a v5 CONNACK advertises Maximum
  QoS = 1 and a QoS 2 PUBLISH is then a protocol error (DISCONNECT 0x9B). SUBSCRIBE at QoS 2
  is granted at QoS 1.
- Retained: `pigeon/shadow/target` is retained server-side (the retained value is the
  pigeon's current shadow). The retain flag on inbound publishes is accepted and ignored.
- Last Will: accepted only if its topic is one of the session's own publish topics (a will at
  QoS 2 follows the QoS 2 rule); delivered on ungraceful disconnect by bridging it exactly
  like an ordinary publish from that session, using the bearer token the session already
  holds. No new dovecote route. Suppression rule: the will is NOT bridged if a newer live
  session for the same pigeon exists in the registry when the old one dies, because the
  common reconnect-before-timeout case would otherwise report a connected device as offline
  (the takeover close and the keepalive-expiry close of a superseded session both hit this
  rule; it is one registry lookup, no new state). A will is lost if the bridge itself dies
  (no persistence), as with any non-persistent broker.
- Sessions are stateless: `clean_session=0` is accepted and answered `session_present=0`
  (v5: Session Expiry Interval 0 in CONNACK). The retained shadow already gives a reconnecting
  device the catch-up that queued messages would have.
- Keepalive: client value honored up to 30 min (clamped above; v5 reports Server Keep Alive);
  0 means a broker-imposed 30 min idle deadline. Silence past 1.5x keepalive closes; the
  reader never pauses (below) and the 10 s upstream publish timeout sits far below any 1.5x
  deadline, so a slow upstream can never masquerade as client silence.
- Flow control: the reader never stops reading. In-flight QoS 1 publishes are counted and
  capped as protocol: 16 (Receive Maximum on v5; over it, DISCONNECT 0x93) with a v3.1.1
  grace ceiling of 64 before close. PINGREQ, PUBACK and DISCONNECT keep flowing while the
  bridge waits on upstream; publishes are bridged one at a time in arrival order, so ordering
  holds and a slow upstream bounds memory at the cap, not by stalling the socket.
- Limits: inbound packet remaining-length cap 20 KiB (payload cap 16 KiB, mirroring
  `capsules::MAX_LOG_CHUNK_BYTES` and the WS frame cap; topic/properties headroom); topic
  name <= 256 bytes; client id / username <= 128; password <= 256 (token is 92 chars);
  inbound PUBLISH rate 40 per rolling 10 s per session, deliberately under the DO WS frame
  limit of 50 per 10 s so the QoS 0 fast path can never trip the DO's own 4008 close.
- v5 lines the codec work must honor: `$share/...` filters answer 0x9E; a Topic Alias
  property against an advertised Topic Alias Maximum of 0 is DISCONNECT 0x94; a zero-length
  client id with CleanSession=0 is CONNACK 0x02 on 3.1.1; a message matching two accepted
  filters is delivered once.

Performance: 3.1.1 is the smaller wire format at baseline (v5 adds at least a 1-byte property
length to every packet), and with the short session-scoped topics of ADR C the v5 topic-alias
saving is only a few bytes, so 3.1.1 is not just the compatibility default but the leaner one
for this fleet; v5's value here is reason codes and negotiated Maximum QoS, not fewer bytes.
QoS 0 telemetry removes one packet and one round trip per report versus QoS 1, and on the air
the difference is dominated by TLS record and TCP framing, not the 4-byte PUBACK: about
110-160 bytes per report (section 9). A persistent session amortizes the TLS handshake to
roughly one per device-connection rather than one per report, so at a 30 s cadence the
handshake cost is negligible per day.

Alternatives: reject QoS 2 outright (a client hardcoded to it is a support ticket and v3.1.1
cannot say why); v5-only (breaks Zephyr); force QoS 1 on telemetry (loses the fire-and-forget
path for no gain); drop LWT (users expect it); real persistent sessions (nothing to persist
that the shadow does not already carry).

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
| `pigeon/telemetry` | dev -> | flat JSON object of string values, as `POST .../telemetry` takes | QoS 0: a `telemetry` frame on the held device WS when it is up, else the POST; QoS 1: always `POST /device/pigeons/<id>/telemetry`, `application/json` |
| `pigeon/shadow/report` | dev -> | `{"current_config":{...},"current_version":N}` | `POST /device/pigeons/<id>/shadow` |
| `pigeon/logs` | dev -> | raw dictionary-log chunk, <= 16 KiB | `POST /device/pigeons/<id>/logs`, `application/octet-stream` |
| `pigeon/shadow/target` | -> dev, retained | the `PigeonShadow` JSON exactly as the device shadow GET returns it (same `JsonString` asymmetry) | the device WS's snapshot-on-accept frame and every `shadow_update` frame; the live feed IS the retained value |

The `<id>` in the Bridge column is the session's own pigeon id, taken from the handshake, not
from the topic. Accepted subscription filters: `pigeon/shadow/target`, `pigeon/shadow/#`,
`pigeon/#`; all three mean "the shadow target". Any other filter gets SUBACK failure (v3:
0x80, v5: 0x87) for that entry.

The device WS is the session's spine, opened at CONNECT, not lazily: the upgrade
(`GET /device/pigeons/:id/ws`, `Authorization: Bearer <token>`) IS the session's
authentication (101 accepts, 401 refuses; ADR D), its snapshot-on-accept frame seeds the
retained value, its `shadow_update` frames refresh it, and QoS 0 telemetry rides it as
`telemetry` frames. It is a live socket, not stored state: the retained value is always the
DO's own bytes (the `shadow` member lifted as a raw JSON slice, `serde_json::value::RawValue`,
never re-serialized), and a restart re-opens the WS and re-reads it. A retained PUBLISH goes
to the device only when `target_version` changed since the last delivery (`target_version`
alone: `updated_at` bumps on every shadow write including device report-backs, checked, so it
would re-push on the device's own reports).

Feed rules, each a review finding closed:
- Liveness: the DO never pings (checked: `WsOutboundFrame::Ping` is dead code), so the bridge
  owns it, exactly as the device WS client does: a protocol-level WebSocket ping each 60 s of
  feed silence, two missed pongs marks the socket half-open and reconnects. Whether the edge
  answers protocol pings without waking the DO is checked at implementation; if not, the JSON
  `{"type":"ping"}` frame is the fallback and its cost is in section 9. A session with QoS 0
  telemetry flowing needs no pings (its frames prove the socket).
- Reconnect: exponential backoff 1 s to 60 s with jitter while the session lives; while the
  socket is down, QoS 0 telemetry falls back to the POST and pushes are caught up by the
  snapshot on reconnect.
- Close code 4009 ("replaced by new connection", checked) is terminal for this session's feed:
  something else holds the pigeon's socket, and redialing would close it back, a fight with no
  winner. The feed re-arms only on a new MQTT session; QoS 0 telemetry stays on the POST; a
  warn line names the pigeon.
- Close codes 4004 ("token revoked") and 4005 ("pigeon deleted"), which dovecote now sends
  from `token/refresh` and `delete` (shipped, in `docs/api.md`), end the MQTT session itself:
  the bridge sends v5 DISCONNECT 0x87 (4004) or 0x87 with a "deleted" reason string (4005),
  closes, and never redials with the dead token.

Alternatives: opening the WS lazily on first subscribe (the earlier revision; dropped because
auth then needs a separate shadow GET, QoS 0 telemetry loses its cheap path, and a stale
CONNECT-time shadow copy has to be held for late subscribers); polling `GET shadow` per
session (no push, 2880 extra edge requests per device-day); the DO pushing to the bridge over
HTTP (routing state in the DO, a DO reaching a DNS-only host, no latency win); a dedicated
fan-out Worker (ADR H).

Firmware has no MQTT surface. Images are up to megabytes, the HTTPS/CoAP routes already do
Range/Block2 chunking with device-side resume, and every MQTT-capable device has TCP+TLS. The
`firmware` key arrives inside the retained shadow target; the device fetches via
`GET /device/pigeons/:id/firmware` with its bearer token. Consequence for `pigeon`: a build
with the MQTT connector plus `CONFIG_PIGEON_FOTA` needs the HTTPS download transport factored
out of `pigeon_https.c` (today FOTA depends on the HTTPS connector); phase 3 item.

Shell: with the WS open for every session, dovecote's `POST /pigeons/:id/shell` sees a
connected device and relays `shell_cmd`. The bridge answers it immediately with a
`shell_output` frame (`exit_code` -1, output "shell not available over MQTT"), so the
dashboard gets an honest error instead of a 10 s 504. Mapping shell onto
`pigeon/shell/{cmd,output}` later is cheap because the WS is already there; not now.

QoS 0 telemetry over the held WS, the trade evaluated (numbers in section 9): the frame path
costs one DO message billed 20:1 and no Worker request, no verify round trip, no per-report
fuse query, about $0.05 per device-month less than the POST path and one edge hop lower
latency, with in-order synchronous upserts (the queued POST path is only best-effort ordered).
It is thin-bridge clean: the frame is exactly what a WS device sends. The costs: the DO's WS
telemetry path has no free-tier fuse check today (a pre-existing enforcement gap for WS
devices; the backend phase closes it with a DO-cached fuse verdict, and until that lands the
bridge routes QoS 0 telemetry over the POST for fuse parity, one config flag), and the
bridge's publish rate cap must sit under the DO's WS frame limit (40 versus 50 per 10 s).
Decision: adopted, gated on the fuse-parity change; the fallback is the POST either way, so
the flag is a routing choice, not a capability.

### ADR D: auth and transport security

Decision: one TLS listener on 8883, OpenSSL, TLS 1.2 minimum, with both a server certificate
chain (Let's Encrypt for `mqtt.pidgeiot.com`) and the PSK ciphersuites loft uses
(`PSK-AES128-CCM8:PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256`); the ClientHello decides.
No plaintext 1883, ever (the CONNECT password is the device token).

- Certificate session: CONNECT `username` = pigeon id, `password` = device bearer token,
  `client_id` = pigeon id or empty. This is the shape every off-the-shelf client supports
  (username is the id because the token carries no subject claim; the bridge must know which
  Durable Object to address). The bridge cannot verify the Ed25519 token itself; the device
  WS upgrade IS the verification: a 101 authenticates the session, opens its feed, and the
  snapshot frame seeds the retained value, all in one round trip. The bridge first checks the
  identity's shape locally (64 lowercase hex; anything else is refused without an upstream
  call, and raw usernames never reach a log line unescaped).
- PSK session: identity = pigeon id, key = UTF-8 bytes of `tls_psk_secret`, resolved mid-
  handshake through dovecote's service-internal PSK route (loft's resolver and 60 s / 10 s
  caches, copied). The lookup also yields the bearer token the session uses upstream; the
  same WS upgrade then runs, and a 401 there means the cache served a rotated PSK, so the
  entry is evicted and the CONNECT refused. `username`, if present, must equal the identity;
  `password` is ignored.
- CONNACK mapping, retryable kept apart from permanent: 401 is 0x04 (v5 0x86); 403 with the
  API's plain-text body is 0x05 (0x87); a 403 with an HTML body or edge-mitigation headers is
  edge security, not auth, and maps with 5xx to 0x03 (0x88), named in the stats line so a WAF
  event does not read as a fleet credential failure; 400 (malformed id, pre-filtered) is 0x02
  (0x85). A deleted pigeon's DO currently answers 500 on device routes (checked: `one_row` on
  an empty table); the backend phase makes that a 401 so deletion reads as permanent.
- One identity, three places it may appear (PSK identity, username, client id); all present
  ones must agree or CONNACK 0x02 / 0x85.
- Credential rotation and deletion mid-session, both directions now closed: a bridged publish
  answers 401 and the session is closed (v5 DISCONNECT 0x87), and dovecote's `token/refresh`
  and `delete` themselves close the pigeon's open device WS with 4004 / 4005 (shipped, in
  `docs/api.md`), which ends the session even if it never publishes again (ADR C's feed
  rules). Better than loft's parity: loft has no push path to revoke.
- Takeover: a new session for a pigeon replaces the live one (v5 DISCONNECT 0x8E), mirroring
  the device WS's 4009 rule; the superseded session's will is suppressed (ADR B).
- Admission: loft's `quota.rs` (4096 global, 256 per source bucket, IPv6 per /64), loft's
  30 s wall-clock handshake deadline, 10 s CONNECT deadline after it, 30 CONNECTs per source
  per 10 s plus a global CONNECT ceiling (120 per 10 s), a 10 s negative cache keyed by
  (identity, sha256(password)), and a per-identity failure budget (10 refusals in 60 s parks
  that pigeon id locally for the rest of the window, any password), so neither a
  distinct-password flood nor a distributed one becomes a dovecote request flood or a DO wake
  storm on one pigeon.
- DNS: `mqtt.pidgeiot.com` is DNS-only (Cloudflare cannot proxy MQTT without Spectrum), so the
  VPS address is exposed exactly as loft's 5684 already is; firewall is an `INPUT` accept on
  8883/tcp next to loft's rules. The listener binds dual-stack (`[::]:8883`); AAAA is
  published only together with adding the VPS's v6 egress address to
  `COAP_SERVICE_ALLOWED_IPS`, or PSK resolution (loft's too) starts failing over v6.
  Certificate: certbot DNS-01 with a scoped Cloudflare API token (no inbound port 80),
  `--key-type ecdsa` pinned (E5/E6 chain to ISRG Root X2 cross-signed by X1, the smaller
  chain; the device verifies with P-256 + P-384 enabled and the X1 anchor); renewal restarts
  the unit (fleet reconnects with backoff, drained per ADR E).
- Listener TLS details a real device will hit (each checked against the trees):
  `SSL_CTX_set_max_send_fragment(4096)` so small-buffer mbedTLS builds (native_sim caps
  content at 7168) can read the chain and any large retained shadow; PSK suites listed first
  with server preference, so a device offering PSK and ECDHE suites lands on PSK rather than
  a chain it cannot verify; `SSL_MODE_RELEASE_BUFFERS` on. OpenSSL also consults the TLS 1.2
  PSK callback for a TLS 1.3 external PSK when no `psk_find_session` callback is set; still
  PSK-authenticated, harmless, and the implementation check includes `-tls1_3 -psk` so it is
  known, not assumed.
- Trust, stated plainly: in certificate mode the bridge holds only what the device presented;
  in PSK mode it holds the service secret, which resolves any PSK-bearing pigeon's
  credentials, so a compromised bridge is trusted to exactly loft's degree. That is why the
  unit is hardened; it is not a property the DO's per-request verification can remove.
- The connector variant is a provisioning hint, not a transport boundary: any pigeon's bearer
  token works in certificate mode, and any PSK-bearing pigeon's PSK completes the handshake,
  consistent with how a CoAP pigeon's token already works on every device route. `docs/api.md`
  and the dashboard say so rather than implying the picker restricts the device.

Performance: the handshake is paid once per connection, not per report, so the
cert-versus-PSK difference is amortized to near-zero over a day-long session (numbers in
section 9); cert mode is therefore acceptable for the mains/WiFi devices MQTT targets, and
PSK stays for the constrained and native_sim paths, where it is also the lighter handshake.
The bridge's one auth round trip, the device WS upgrade, is also the feed and the
retained-value seed, so nothing is spent on auth alone.

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
   (same handler, same `COAP_SERVICE_SECRET` + `COAP_SERVICE_ALLOWED_IPS` gate). Until this
   lands the bridge calls the existing name; loft moves over at its own cleanup. The VPS v4
   egress address is already in the production allowlist; the v6 one joins it with the AAAA
   record.
4. Free-tier fuse parity on the DO's WS `telemetry` path (a cached per-pigeon verdict inside
   the DO): a pre-existing enforcement gap for WS devices, and the gate on routing QoS 0
   telemetry over the WS (ADR C).
5. `is_authorized_device` answers 401 instead of 500 when the pigeons table is empty, so a
   deleted pigeon reads as permanent on every device route instead of as an outage.
6. `docs/api.md`: "MQTT device surface (via the pigeonhole broker)" after the CoAP section,
   the connector note under `POST /flock/pigeons`, the type reference, and the
   connector-is-a-hint sentence.
7. `fancier`: connector picker entry, badge, detail card (endpoint, username = id, password
   and PSK pair only at reveal time, one copy-pasteable `mosquitto_pub` line), `TokenReveal`.

Already shipped ahead of this design (consumed, not proposed): `token/refresh` and `delete`
close the pigeon's open device WS with 4004 "token revoked" / 4005 "pigeon deleted"
(documented in `docs/api.md`); ADR C's feed rules act on both.

Alternatives: PSK-only (no off-the-shelf client support; kills the adoption case); cert-only
(loses the constrained path and the local native_sim loop, and would be the first device
transport without PSK parity); rustls (no PSK ciphersuites, so it cannot host the dual
listener); a separate CONNECT-time shadow GET for auth (the earlier revision; the WS upgrade
verifies the same token against the same DO and opens the feed in the same trip).

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
  pigeonhole-wire/           the shared contract: topic scheme, payload types mirrored from
                             capsules (loft wire.rs precedent), limits, size-capped framing
  pigeonhole-client/         raw framed connection (the harness's misbehaving-client tool) +
                             typed PigeonClient (cert or PSK, keepalive, QoS 1 tracking)
    examples/                subscribe-and-publish.rs: the documentation-grade client demo
  pigeonhole/                the bridge binary: config, tls, psk, quota, auth, session,
                             proto/{v3,v5}, bridge, shadow, upstream
    Dockerfile               multi-stage, small runtime image with libssl; verifies the PSK
                             ciphersuites at image build, loft's convention
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
publishes bridged, upstream errors, WS feeds open, edge-shaped 403s). No metrics endpoint in v1.

Shutdown: on SIGTERM the listener stops accepting, in-flight upstream requests finish (bounded
by the 10 s publish timeout), their acks are sent, then every session gets v5 DISCONNECT 0x8B
(server shutting down) and a clean close; the unit sets `TimeoutStopSec` above that bound.
This makes a deploy or certbot's restart-on-renew a small redelivery window instead of a loss
event, and it is what makes the restart-on-renew answer in `open-questions.md` genuinely cheap.

Deliberate duplication from loft, listed so a later shared crate has its inventory: `quota.rs`,
`psk.rs` (resolver + cache), `config.rs` credential resolution, `tls_common.rs` PSK context
builder. `roost` (LwM2M) would be the third copy; extraction is worth doing at the second
copy's first divergence, not before.

Alternatives: single crate (the harness needs the raw client as a library); a fourth "shared
with loft" crate now (premature until loft's own cleanup settles); config file (loft precedent
is env); a standalone example crate (the `[[example]]` convention is lighter and stays
build-checked).

### ADR F: phasing

See section 8. Owner-gated throughout: DNS record, Let's Encrypt issuance on the VPS, VPS
deploy, production dovecote/fancier deploys, production pigeon creates, bench flashing of the
C6, `git push`, `cargo publish`.

### ADR G: thin bridge, fat Worker (the governing rule)

Decision: the VPS bridge is the communication layer only. It terminates MQTT (TLS including
the PSK ciphersuites, packet framing, the session state machine, keepalive timers) and holds
the two live sockets per session (the device's MQTT connection and the upstream device
WebSocket). Everything else is dovecote's and the per-pigeon Durable Objects': credential
resolution, authorization (the bridge's "known leaf?" check is a pre-filter, not an authority:
a wrongly forwarded publish still carries only this pigeon's token and dies at the DO),
retained state (the retained value IS the DO's shadow), will/offline (a will is an ordinary
device-route publish), and every kind of per-pigeon state. The bridge is stateless beyond
in-flight QoS 1 and the drain window (ADR E); redelivery is the client's, per ADR B.

Line-by-line audit of ADRs A to D against this rule:

| ADR | Already compliant | Where the line had to sit on the VPS, and why |
|---|---|---|
| A | First-party core holds no router/log/session store; `mqtt-proto` is a codec, not a broker. `rumqttd` fails this rule outright (it PUBACKs at its own commitlog). | The session state machine and keepalive timers: a Worker cannot hold the TCP/TLS socket. |
| B | Stateless sessions (`session_present` always 0, v5 Session Expiry 0); retained = the DO's shadow; QoS 2 uses no dedup store; will is a deferred device-route publish. | QoS 1 ack timing: the PUBACK is issued only when the upstream POST completes, so its meaning is dovecote's answer, and nothing is buffered on the bridge. Two VPS-side semantic decisions live here and are named as policy: the ack table itself (HTTP status to MQTT outcome), and the will-suppression rule on takeover (only the VPS knows two sessions overlapped). |
| C | Session-scoped topics mean no id to authorize; the retained bytes are the DO's; the "last delivered target_version" marker is a per-connection duplicate suppressor, dies with the socket. | The device WS: a Worker cannot hold a socket to a VPS process, so the push (and the QoS 0 frame path) must ride a bridge-held live socket to the DO. It is connection state, not stored state. |
| D | Auth is the device WS upgrade with the presented token: the DO decides, the bridge relays the verdict; PSK lookup is dovecote's route; rotation/deletion reach the bridge as the DO's own 4004/4005 closes. | Admission counters (global and per-source permits, CONNECT rates, per-identity failure budget, 30 s handshake deadline): these protect the VPS itself from floods and exist only there by nature. Two caches, both bounded and expiring (below). |

Bridge-side caches, stated so they are not mistaken for state: the PSK cache (positive 60 s,
negative 10 s, loft's) and the negative auth cache (10 s, keyed identity + sha256(password)),
both bounded by identities seen in the window. Pure accelerators: losing them costs extra
upstream lookups and nothing else, and neither can make the bridge answer differently from
what dovecote would.

Consequences: the Worker-side surface this design adds or consumes, listed so it stays small:
the neutral internal credential route, the WS-path fuse check, the 401-on-empty fix (all
ADR D's contract list), and the already-shipped 4004/4005 rotation and deletion closes. Will
and offline need no new route, and no component on the VPS may grow a durable store without
reopening this ADR.

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

What would flip it: shadow-push fan-out to many bridge instances for one pigeon (anycast
bridges), or session-authorization logic that grows state of its own; either justifies (c)
first, never (b). Neither exists now, and the DO's one-device-WS rule already routes the push
to the one bridge instance holding the session, even across regions. One more rejected shape:
the bridge producing to the telemetry Queue directly, which bypasses the token verification
the device route performs.

## 3. Sequence

```
device                    pigeonhole                         dovecote
  |-- TLS ClientHello ------>|                                   |
  |   (cert suites, or PSK)  |-- PSK? GET /internal/coap-psk/:id (cache miss only) ---->|
  |<-- handshake done -------|                                   |
  |-- CONNECT (user=id,pw=token | client_id=id) -->|             |
  |                          |-- WSS /device/pigeons/:id/ws  Bearer token ------------>|
  |                          |<-- 101 (auth) then shadow_update snapshot (seed) --------|
  |<-- CONNACK 0 ------------|      (401 -> CONNACK bad credentials, no session)       |
  |-- SUBSCRIBE pigeon/shadow/target -->|                        |
  |<-- SUBACK 1, PUBLISH retained (the feed's current value) --| |
  |-- PUBLISH QoS0 telemetry -->|                               |
  |                          |-- WS frame {"type":"telemetry",...} -------------------->|
  |-- PUBLISH QoS1 pigeon/shadow/report -->|                    |
  |                          |-- POST .../shadow  bytes as-is -------------------------->|
  |<-- PUBACK (on 200) ------|                                   |
  |                          |        dashboard PUT /pigeons/:id/shadow -> DO          |
  |                          |<-- shadow_update {shadow:{...}} --------------------------|
  |<-- PUBLISH retained pigeon/shadow/target (target_version changed) --|              |
  |-- DISCONNECT / drop ---->|   close WS; bridge will if ungraceful, will set,        |
  |                          |   and no newer session holds this pigeon                |
```

## 4. Broker internals (module contracts)

Each module's stub carries its own contract; the load-bearing points are: `tls` builds one
`SslContext` (cert chain + key, min TLS 1.2, loft's PSK callback storing identity + token in
ex_data, PSK suites first with server preference, `SSL_CTX_set_max_send_fragment(4096)`,
`SSL_MODE_RELEASE_BUFFERS`; assumed: one context serves certificate and PSK suites, verified
at implementation with `openssl s_client -psk`, plain `s_client`, and `-tls1_3 -psk`); `psk`
is loft's resolver against the internal credential route; `quota` is loft's RAII permits plus
the CONNECT rates, negative-auth cache, and per-identity failure budget; `auth` checks the
identity's shape and agreement, then hands the session to `shadow`'s WS dial, whose result is
the CONNACK; `session` is one task per connection with a reader that never stops (in-flight
QoS 1 counted and capped as protocol, publishes bridged one at a time in arrival order, PINGREQ
answered from the reader), a writer serialising one outbound channel, the keepalive timer, the
will with its suppression rule, and a registry entry for takeover, over version-neutral events
that `proto/v3` and `proto/v5` adapt; `bridge` owns the ack table (section 5), routes QoS 0
telemetry to the WS frame path when the feed is up, and never parses payloads; `shadow` owns
the device WS: dial at CONNECT, snapshot seed, `target_version` change detection, liveness
pings on silence, backoff, and the 4009/4004/4005 rules; `upstream` is the reqwest client
(`pigeonhole/<version>` UA, 10 s publish timeout, 10 s connect) and the WSS dial with tuned
buffers (read and write 4 KiB, max message 64 KiB) and the `Authorization` header.

## 5. Bridge ack policy

What a PUBACK means, per leaf: telemetry, "authenticated and durably queued" (the 202: the DO
write is retried by the queue consumer until it lands, history is best-effort, the same words
`docs/api.md` uses); shadow report and logs, "the DO write completed" (the 200). A close means
"retry later or re-authenticate". QoS 0 follows the same table minus the ack; QoS 0 telemetry
normally rides the WS frame path (ADR C), where a synchronous upsert also makes rapid reports
land in order, which the queued POST path only best-effort guarantees.

| dovecote result | v3.1.1 | v5 |
|---|---|---|
| 2xx (incl. telemetry 202) | PUBACK | PUBACK 0x00 |
| 400 / 404 / 413 (permanent, not retryable) | PUBACK, logged | PUBACK 0x99 (400) / 0x80 |
| 401 / 403 (API-shaped body) | close | DISCONNECT 0x87 |
| 403 with an HTML body / edge-mitigation headers | treated as 5xx (edge security, not auth); named in the stats line | same |
| 429 (free-tier fuse: delayed, not lost) | no PUBACK, close | PUBACK 0x97 Quota exceeded, session kept: the v5 client learns the reason, requeues, and keeps its push feed |
| 5xx / timeout / unreachable | no PUBACK, close | no PUBACK, DISCONNECT 0x89 |

Redelivery after a close is the client's responsibility, and the spec guarantees it only for a
CleanSession=0 client whose library persists unacked publishes; clean-session third-party
clients drop what was in flight, which is inherent to a stateless bridge and is why the drain
(ADR E) and the v5 429 row exist. The pigeon connector owns its own redelivery (section 6). A
v3.1.1 device under the fuse sees only close-after-publish and cannot tell it from an outage;
its connector treats repeated close-after-publish as a long-backoff condition.

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
same socket setup the CoAP TCP connector's PSK session already uses (the nRF91 modem also
advertises two of the bridge's three PSK suites, so a future cellular PSK build has a suite to
land on; its modem-store PSK write path exists but is not yet hardware-verified). Keep the
transport lock discipline (`pigeon_transport_lock`) for the handshake.

Review findings the connector work must carry, so they are not re-derived on the bench:
redelivery is the connector's own (Zephyr's client never retransmits; on any close before
PUBACK, re-publish from the core's pending store with `dup_flag` set, and treat repeated
close-after-publish as a long-backoff condition, the fuse's only v3.1.1 signal); set
`CONFIG_MQTT_KEEPALIVE` deliberately per target (the 60 s default suits mains/WiFi and is
wrong for a PSM device); extend `CONFIG_PIGEON_LOG_UPLOAD`'s `depends on` to the MQTT
connector or log upload silently vanishes from MQTT builds (checked, it lists only HTTPS and
CoAP today); plan the send-timeout socket option from the start (the WS client needed
`NET_CONTEXT_SNDTIMEO` to survive a half-dead link, checked); and mind
`CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN` against the server's 4096-byte max send fragment
(ADR D) plus the certificate chain and the largest expected retained shadow.

`pigeon-examples`: one sample, `mqtt_init`, two board targets on the `coap_dtls_init`
board-conditional pattern (that sample already carries both board confs side by side;
checked): `native_sim/native/64` in PSK mode against a local pigeonhole (dev loop and the e2e
driver), `esp32c6_devkitc/esp32c6/hpcore` in certificate mode over Wi-Fi (connection manager
and PSA/TLS Kconfig copied from `wifi_init`; trust anchor ISRG Root X1, mbedTLS configured
for the pinned ECDSA chain: P-256 + P-384, peer verification required, hostname set). The
bench C6 currently serves CoAP testing; flashing it for MQTT is a scheduling item for the
owner, not an assumption.

## 7. Test strategy

- Unit: topic parse/format (proptest), framing caps, ack-policy table, auth identity rule,
  config/credential resolution, quota (loft's tests carried over).
- Integration (`pigeonhole/tests/`): broker in-process on an ephemeral port with a self-signed
  certificate (`rcgen`) and a mock dovecote (axum: device routes, internal PSK route, a WS
  endpoint that emits `shadow_update` and can send 4004/4005/4009 and drop pongs); the raw
  client drives: auth matrix (cert good/bad, PSK good/stale/unknown, identity disagreement,
  malformed identity refused locally), topic rule (unknown publish topic, bad subscribe
  filter), QoS 0/1/2 semantics and the ack table per upstream status (including the
  edge-shaped 403 classified as 5xx), the QoS 0 WS frame path and its POST fallback, PINGREQ
  answered while a publish is stalled upstream, the in-flight cap as protocol, oversize
  packet, rate caps, per-identity failure budget, takeover with will suppression, will
  delivery when genuinely alone, retained delivery on subscribe, push on `shadow_update`
  keyed by `target_version`, feed liveness (missed pongs force reconnect), 4009 terminal,
  4004/4005 ending the session, `shell_cmd` answered, keepalive expiry, SIGTERM drain
  (in-flight acked, 0x8B sent). Multi-thread runtime throughout (ADR A).
- Live: the typed client against a local broker pointed at `dovecote-staging` in certificate
  mode (needs no staging allowlist change, since cert auth uses only public device routes);
  PSK mode against `wrangler dev` locally (the dev allowlist already admits loopback;
  checked in `wrangler.toml`); then the native_sim sample as the device-side e2e
  (`scripts/test/native-sim-e2e.sh`), then the C6.
- Soak before production: 1000+ idle sessions, each with a WSS feed to the edge, to confirm
  there is no per-source limit on WebSocket connections through Cloudflare (assumed, must be
  measured) and that memory stays inside the unit's `MemoryMax`.

## 8. Phasing (implementation tasks)

Each task: repo, files, acceptance. "Gated" marks owner approval points. Bridge first, backend
second: certificate mode needs no backend change (any existing pigeon's token already works
against the device routes and the WS upgrade), and PSK mode reaches the existing internal
route name, so a real client talks to `dovecote-staging` before any monorepo change lands.

Phase 1, the bridge (this repo):
- T1 `pigeonhole-wire`: topics, payload types, limits, framing. Accept: unit + proptest green.
- T2 `pigeonhole-client` raw layer + cert/PSK client TLS builders. Accept: round-trips a
  CONNECT/CONNACK against a scripted server in tests.
- T3 edge WS probe, before the broker is built on the answer: a script opens N concurrent
  device WS connections from one address against `dovecote-staging` (existing pigeons) and
  holds them; find any per-source ceiling. Accept: the measured number in `docs/`, and the
  push design revisited if it is under the session ceiling.
- T4 broker v3.1.1: config, tls, psk, quota, auth, session, proto/v3, bridge, shadow,
  upstream; integration harness with mock dovecote. Accept: the section 7 integration list
  green; `openssl s_client` all three handshake checks.
- T5 `pigeonhole-client` typed layer + `examples/subscribe-and-publish.rs` (env/CLI
  configured, cert or PSK, subscribe to `pigeon/shadow/target`, publish telemetry, print what
  arrives). Accept: the example runs against the T4 harness broker; used by the harness happy
  paths.
- T6 infra + runbook + Docker: `infra/pigeonhole.service` (with the drain's `TimeoutStopSec`),
  env example, `pigeonhole/Dockerfile`, `infra/docker-compose.yml` (self-host example, same
  env vars, configurable `PIGEONHOLE_DOVECOTE_URL`), `docs/infra/mqtt-broker.md` (bring-up in
  both shapes, DNS + AAAA/v6 note, certbot DNS-01 with the pinned key type, firewall, secret,
  rotation, local dev loop), `scripts/dev-cert.sh`. Accept: `systemd-analyze verify`;
  `docker compose up` runs the bridge against a local `wrangler dev`.
- T7 live against `dovecote-staging`: cert mode with an existing pigeon's token end to end
  (connect, subscribe, dashboard PUT -> push observed, telemetry visible); PSK mode against
  `wrangler dev` locally, and against staging too once the staging
  `COAP_SERVICE_ALLOWED_IPS` gains the VPS egress address (one var, staging deploys
  pre-approved). Accept: a written transcript with observed latencies.

Phase 2, backend contract (`~/pidgeiot`), one atomic change that compiles at every commit:
- T8 capsules + dovecote: `Connector::Mqtt(MqttConfig)`; `build_mqtt_endpoint` +
  `MQTT_DEVICE_HOST` x3; mint/refresh/strip for `Mqtt`; PSK handler generalised +
  `/internal/device-psk/:id` alias; WS-path fuse check; `is_authorized_device` 401 on empty;
  `docs/api.md` MQTT section. Accept: curl matrix against `wrangler dev` (create Mqtt pigeon,
  token + PSK returned once, GET stripped, refresh rotates and closes with 4004, delete
  closes with 4005, internal route 200 for Mqtt / 404 for Https, fuse verdict honored on a WS
  telemetry frame); staging deploy (pre-approved). The bridge flips QoS 0 telemetry to the WS
  frame path after this lands.
- T9 fancier: picker, badge, detail card, reveal, docs page, connector-is-a-hint wording.
  Accept: release build + Playwright pass on the pigeon detail and create flows; staging
  deploy.

Phase 3, device side:
- T10 `~/pigeon`: `CONFIG_PIGEON_CONNECTOR_MQTT` + `src/pigeon_mqtt.c` + Kconfig (incl. the
  log-upload dependency and deliberate keepalive) + PSK helper generalisation + connector-owned
  redelivery; FOTA download transport factored so an MQTT+FOTA build compiles. Accept: builds
  for native_sim and C6; unit tests where the CoAP connector has them.
- T11 `~/pigeon-examples`: `samples/mqtt_init` (native_sim PSK, C6 cert with the pinned chain's
  mbedTLS config); `scripts/test/native-sim-e2e.sh` here drives native_sim against a local
  broker + mock dovecote. Accept: e2e script green; C6 hardware run is gated on bench
  scheduling.

Phase 4, MQTT 5 and production:
- T12 `proto/v5` + ack reason codes + CONNACK properties; harness v5 matrix. Accept: green.
- T13 soak: 1000+ sessions with feeds against staging, steady-state memory per session
  measured, `MemoryMax` set from it. Accept: numbers in the runbook.
- T14 production bring-up: DNS (+AAAA with the v6 allowlist entry), cert, unit, firewall,
  prod dovecote `MQTT_DEVICE_HOST`, prod fancier. Gated entirely. Accept: one prod pigeon
  round-trips with `mosquitto_pub`/`_sub`.

## 9. Performance and cost model

Unit of analysis: one device, telemetry every 30 s (2880 reports/day), a handful of shadow
changes per day, one connection held all day. Prices are Cloudflare list prices as understood
at design time, order-of-magnitude inputs to be confirmed at billing. Two platform facts this
model rests on, both current: telemetry verification is one DO round trip at the gateway and
the queue consumer's write is a second, and the DO's telemetry store writes one merged-blob
row per report regardless of key count (one row read, one written; the earlier per-key row
model is gone).

Device link, per telemetry report:

| Item | MQTT 3.1.1 | MQTT 5 | Notes |
|---|---|---|---|
| PUBLISH overhead over payload, QoS 0 | 2 + 2 + 16 = 20 B | 21 B | fixed header, length-prefixed `pigeon/telemetry`, v5 adds a property-length byte |
| PUBLISH overhead, QoS 1 | 22 B + 4 B PUBACK | 23 B | plus one extra round trip |
| On the air, the part that dominates | each MQTT packet rides its own TLS record (~29 B for TLS 1.2 AES-GCM: header, explicit nonce, tag) in its own TCP segment (~40 B IPv4+TCP, plus the peer's ~40 B ACK) | same | so QoS 1 versus QoS 0 is ~110-160 B per report on the air, ~340-460 KB/device-day at this cadence, the number a cellular plan sees |
| Id-in-topic scheme (rejected, ADR C) | +65 B per publish | +65 B | ~187 KB/device-day, rides inside the existing record |
| v5 topic alias | n/a | topic 2 B after the first publish | ~14 B against a 16 B topic: marginal, v5 is for reason codes |

Connection setup, once per device-connection: certificate TLS 1.3 is 1 round trip and ~3-4 KB
of chain (the pinned ECDSA chain is at the low end), TLS 1.2 is 2 round trips; PSK TLS 1.2 is
2 round trips and ~1 KB (loft's figures); resumption tickets make a reconnect 1 round trip and
~0.5 KB; CONNECT+CONNACK adds one round trip (~250 B cert mode, ~90 B PSK); the device WS
upgrade behind CONNACK is the bridge's one auth round trip and doubles as feed and seed.
Amortized over a day-long session, all of it is noise at this cadence.

Shadow push latency, dashboard PUT to device PUBLISH: DO broadcast over the open WS (the WS
transport measured ~1 s on hardware) plus one bridge-to-device PUBLISH; no polling interval
anywhere in the path.

Cloudflare cost, per device per month at this cadence, both telemetry routings under ADR H's
decided topology (the dedicated-Worker option pays every line below plus one more Worker
invocation per POST; it is never cheaper, so it is priced once here and not again):

| Driver | QoS 1 over POST | QoS 0 over the WS frame (decided fast path) | Unit price assumed |
|---|---|---|---|
| Worker requests | 86,400 -> $0.026 | none on the frame path | $0.30/M |
| DO requests | 172,800 (verify + consumer write) -> $0.026 | 86,400 messages at 20:1 -> 4,320 -> $0.0006, plus the consumer write 86,400 -> $0.013 | $0.15/M; WS messages billed 20:1 |
| DO wall-clock | ~220 GB-s -> $0.003 | ~$0.002 | $12.50/M GB-s |
| Queue operations | 259,200 (write, read, ack) -> $0.104 | same -> $0.104 | $0.40/M ops |
| DO storage rows written | 86,400 (one merged row per report) -> $0.086 past allowance | same -> $0.086 | $1.00/M rows; reads negligible |
| Feed liveness pings | none needed while frames flow | ~2,160 request-equivalents if JSON pings on a quiet feed -> under $0.001 | |
| Total | ~$0.25 | ~$0.19 | |

The fast path saves ~$0.05 per device-month (~21 %) and one edge hop, and its synchronous
upsert keeps rapid reports in order; that is the trade ADR C records, adopted behind the
fuse-parity gate. Queue operations and storage rows dominate either path and are platform-wide
(HTTPS, CoAP, WS, MQTT identical), so the load-bearing reading stands: an MQTT device costs
the edge what any other device costs, and MQTT adds only the VPS. The included 50 M rows
written per month are exhausted by roughly 575 devices at this profile fleet-wide; that number
moves first as the fleet grows, and it is the platform's, not this design's.

VPS budget, per session (the reviewer's finding: library defaults, not rustls, dominate):
tungstenite 0.30 defaults to 128 KiB read + 128 KiB write buffers per connection, ~1 GiB of WS
buffers alone at the 4096-session ceiling, on a 4 GB box already carrying `MemoryMax` caps of
2G (kratos) and 1536M (loft). The upstream dial therefore sets read and write buffers to
4 KiB and max message to 64 KiB (shadow frames are hundreds of bytes to a few KiB), the
listener sets `SSL_MODE_RELEASE_BUFFERS`, and the budget target is tens of KiB idle per
session with the worst case bounded by the in-flight cap (16 x 20 KiB) under authenticated
flood only. 4096 x 64 KiB is ~256 MiB, so the unit ships with `MemoryMax=1G` and T13's
measurement replaces the target with the real figure.

"Unreasonable cost", so the owner can judge the line: an MQTT device costing materially more
on the edge than an HTTPS/CoAP device for the same telemetry (the design holds them equal or
cheaper), or the bridge needing a larger VPS tier at the session ceiling. The three ways a
design crosses it, each a fork taken above: a billed DO wall-clock socket pinned per idle
device (avoided: the WS hibernates), a second Worker request or new durable store per report
(avoided: the device routes and their queue; why the dedicated Worker lost in ADR H), and a
per-report handshake (avoided: the persistent session).

Measured before the broker is built or shipped: the per-source ceiling on concurrent WS
connections to the edge (T3, before T4, because the push design depends on the answer) and
steady-state per-session memory (T13, sets `MemoryMax`).
