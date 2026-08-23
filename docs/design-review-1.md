# pigeonhole design review 1

Reviewed: `docs/design.md` at commit ce819e9 (the tree moved from a41f0ed to ce819e9 while
this review was in progress; line numbers below are against ce819e9, 630 lines, md5
46b05609e75d1d1737e4bfe08f1a8faa), `docs/open-questions.md`, `README.md`, and the crate
stubs. Claims about other systems were checked read-only in `~/pidgeiot`, `~/loft`,
`~/pigeon`, `~/pigeon-examples` (Zephyr v4.4.1 under its west workspace), and the vendored
crates in the cargo registry. "Checked" means the evidence is a file and line in one of
those trees; "reasoned" means it rests on arithmetic, spec text, or Cloudflare pricing as
understood without network access.

Severity counts: 0 BLOCKER, 8 MAJOR, 13 MINOR, 8 NIT. Nothing here says the design cannot
work as written; the MAJORs are places where a stated property is not true for a realistic
client or operating condition, or where a number the owner asked for is wrong by enough to
matter. Each finding ends with the smallest fix that would close it.

## Protocol mapping and the ack contract

### R1. MAJOR. The QoS 1 retry relies on a client behaviour most clients do not have

Lines 31-32, 110-112, 451-455. The design closes the connection on 429, 5xx, timeout and
unreachable, and states that "a closed client reconnects with backoff and retransmits unacked
QoS 1 publishes (3.1.1 section 4.4), which is the retry", and in section 1 that a restart
"loses nothing beyond in-flight QoS 1, which the device redelivers".

That citation only holds for a client that connected with CleanSession=0. 3.1.1 section 4.4
makes redelivery mandatory exactly when "a Client reconnects with CleanSession set to 0" and
says that is the only circumstance where redelivery is required; section 3.1.2.4 says a
CleanSession=1 client "MUST discard any previous Session", whose state includes unacknowledged
QoS 1 messages. MQTT 5 is stricter still: a client that receives Session Present 0 discards its
session state. The bridge always answers session_present=0 / Session Expiry 0, so a
spec-following client with a clean session drops whatever was in flight when the bridge
closed. mosquitto_pub, paho (default clean session true), and MQTT.js (default clean: true)
are all in that class. Zephyr's client defaults to clean_session=0 (CONFIG_MQTT_CLEAN_SESSION
is a bool with no default, so n; `subsys/net/lib/mqtt/Kconfig:72-83`, `mqtt.c:238`), but the
Zephyr library has no retransmission at all: it never stores a sent publish, the application
sets `dup_flag` and re-publishes itself (`include/zephyr/net/mqtt.h:510-513`; no resend path in
`mqtt.c`). So for the first-party connector the redelivery is whatever `pigeon_mqtt.c` builds
on top of the core's existing unsent queue, not a protocol property. Checked.

Consequence: the design's headline "restartable with no data loss" (lines 31-32, and ADR G's
last bullet) is true for the pigeon connector only if the connector owns redelivery, and false
for clean-session third-party clients. The 429 row has a second effect worth stating: a paused
free-tier device on v3.1.1 sees only "closed after publish", cannot distinguish the fuse from an
outage, and cycles a full TLS handshake plus the CONNECT-time shadow GET at its reconnect
interval for the rest of the billing period, losing the shadow push feed each time.

Smallest fix: rewrite lines 454-455 to say that redelivery after a close is the client's
responsibility, that it is guaranteed only for CleanSession=0 clients with a persisting
library, and that `pigeon_mqtt.c` must re-publish from the core queue on any close before
PUBACK (with dup set). For v5, answer 429 with PUBACK 0x97 and keep the session (the client
learns the reason and can requeue) rather than disconnecting. For v3.1.1 keep the close, but
say so in the device plan: the connector should treat repeated close-after-publish as a
long-backoff condition. Related: R11 (drain on restart).

### R2. MAJOR. "Backpressure by not reading" starves keepalive in both directions

Lines 113-120 ("Receive Maximum 16 (bridge queue depth, backpressure by not reading
further)") and 434-436 (a bounded in-order queue drained sequentially; upstream timeout 30 s).

The queue is drained one POST at a time. A single slow upstream request (the reqwest timeout is
30 s) stalls every later publish behind it; sixteen of them is eight minutes. While the reader is
paused the bridge also stops seeing PINGREQ, so its own "silence past 1.5x keepalive closes"
fires on a client that is in fact sending; and the client, whose PINGREQ the bridge has not
read, times out waiting for PINGRESP and disconnects on its side. A device with the Zephyr
default keepalive of 60 s (`subsys/net/lib/mqtt/Kconfig:43-45`, checked) is closed after one
upstream timeout plus a few seconds. Each such close is a TLS handshake and a CONNECT-time
shadow GET, and under R1 it is also a loss event for clean-session clients. The failure is
worst exactly when dovecote is degraded, which is when retries are most expensive.

Smallest fix: never stop reading. Decode every packet; count in-flight QoS 1 publishes per
session and enforce the cap as a protocol matter (v5: Receive Maximum exceeded is DISCONNECT
0x93; v3.1.1: a generous ceiling, close only above it), so PINGREQ, DISCONNECT and PUBACK keep
flowing while the bridge is waiting on upstream. Keep the per-session ordering guarantee for
publishes but let the reader run ahead of the bridge. Also note in section 5 that the upstream
timeout must be shorter than the smallest keepalive the bridge will accept, or the keepalive
timer must be suspended while a publish is in flight.

### R3. MAJOR. The will fires after a reconnect and reports a connected device as offline

Lines 106-109, 215-216, open-questions item 5 (the recommended will is `{"status":"offline"}`
to `pigeon/telemetry`).

The common reconnect case is a device that loses its link and reconnects before the bridge
has noticed the old session is dead. Under the takeover rule the new CONNECT closes the old
session; that close is ungraceful from the old session's point of view, so its will is bridged
as a telemetry POST carrying `status=offline`, concurrently with or just after the new session's
first publishes. Both land in the DO's latest-value table (`upsert_telemetry`,
`objects/pigeons.rs:1664-1679`, checked), and there is no ordering between the two bridge tasks,
so the dashboard can show the device offline while it is connected, until its next report.
Without takeover the same thing happens later, when the half-open old session hits its 1.5x
keepalive deadline. Either way the one documented use of the will produces a wrong reading in
the most common scenario. MQTT 5's Will Delay Interval exists for exactly this; 3.1.1 has
nothing.

Smallest fix: suppress the will when a newer live session for the same pigeon exists in the
registry at the moment the old one dies (the registry already exists for takeover, so this is
one lookup, not new state). State the rule in ADR B. For v5, honour Will Delay Interval later
if wanted; it is not needed once the registry check exists.

### R4. MINOR. The 4009 policy still fights, just slowly

Lines 166-169: on 4009 the bridge "backs off to the ceiling and logs at warn rather than
fighting". The ceiling is 60 s, and a retry at the ceiling still dials
`GET /device/pigeons/:id/ws`, which closes whoever holds the socket with 4009
(`accept_websocket_device`, `objects/pigeons.rs:1288-1291`, checked). The other party (a
developer's websocat, a misprovisioned second device) reconnects and closes the bridge's, and
so on once a minute for as long as the MQTT session lives. Rare, but the design text promises
the opposite of what the policy does.

Smallest fix: treat 4009 as terminal for the feed for the rest of that MQTT session (re-arm only
on a new SUBSCRIBE or a new session), or back off to a keepalive-scale interval (tens of
minutes), and say which. Do not treat the rotation close code proposed in R6 as a 4009.

### R5. MAJOR. The upstream WS has no liveness rule, and the DO never pings

Lines 158-169 and 600. The design says what the feed does on close and on 4009, and prices the
hibernated socket at zero, but says nothing about how the bridge learns that an upstream socket
is half-open. The DO never initiates a ping (`WsOutboundFrame::Ping` is dead code with a comment
saying so, `objects/ws.rs:70-79`, checked). The pigeon WS client learned this the hard way: it
owns keepalive with one `{"type":"ping"}` per 60 s and treats two missed pongs as half-open
(`~/pigeon/zephyr/Kconfig:470-478`, `src/pigeon_ws.c:13-18`, checked). A bridge that does the
same as the design describes (dial, read, reconnect on close) will sit on a dead socket after an
edge reassignment or a path failure and silently stop delivering shadow pushes, with no error
anywhere, for as long as the MQTT session lives. That is the worst failure mode the headline
feature can have.

Smallest fix: state a liveness rule for the feed. Cheapest is a protocol-level WebSocket ping
(tungstenite `Message::Ping`) with a pong deadline; verify at implementation whether the edge
answers those without waking the DO. If not, copy the device client: a JSON ping every 60 s,
two missed pongs means reconnect, and put the cost in section 9 (1440 inbound frames per day
per subscribed session, billed 20:1 as DO requests, about 72 request-equivalents plus a few
milliseconds of duration each; negligible but not zero).

### R6. MAJOR. Token rotation does not reach the push path

Lines 213-214: "Token rotation mid-session: the next bridged request 401s, the session is
closed ... Same semantics as loft's 'every request 401s'." That is the publish half only. The
DO verifies the bearer token once, at socket accept, and never again (`websocket_message`
comment, `objects/pigeons.rs:297-299`, checked), and `refresh_token`
(`objects/pigeons.rs:775` onward, checked) mints the new keypair without closing any open
`WS_DEVICE_TAG` socket. So after a rotation the bridge's upstream WS, opened with the revoked
token, keeps receiving `shadow_update` frames, and a subscribe-only MQTT session (or one that
publishes rarely, or only QoS 0 telemetry that happens not to be sent for a while) keeps
delivering config pushes to a device whose credential the owner just revoked, until something
else drops the socket. The same gap already exists for WS devices; the design inherits it
while claiming parity with loft, which has no push path and therefore no such gap.

Smallest fix: T2 already edits `refresh_token`. Add a loop over
`get_websockets_with_tag(WS_DEVICE_TAG)` closing each with a distinct code (say 4010,
"credentials rotated"); the bridge closes the MQTT session on that code (v5 DISCONNECT 0x87)
and does not reconnect. This closes the gap for WS devices too and costs one line of docs in
`docs/api.md`'s close-code table.

### R7. MINOR. "Durable accept" overstates what a telemetry 202 is

Lines 95-97, 353, 448. For telemetry in staging and production, the gateway returns 202 after
the DO has verified the token and the message has been enqueued (`lib.rs:536-634`, checked);
the DO's latest-value upsert and the history write happen in the consumer afterwards. The queue
is durable and the consumer retries a failed DO write (`queue.rs:216-223`, checked), so the
latest-value write is guaranteed eventually, but the history write and the per-pigeon forward
are fire-and-log (`store_and_alert`, `queue.rs:339-403`), and two rapid reports can be written
out of order (Queues are best-effort ordered; the WS path upserts synchronously and does not
have this property). None of this is MQTT's doing, but section 5 defines PUBACK as "stored, or
permanently refused", which a 202 is not.

Smallest fix: define PUBACK on telemetry as "authenticated and durably queued; the DO write is
retried until it lands; history is best-effort", and say that shadow report and logs PUBACK on
a completed DO write. Same words `docs/api.md` already uses for the 202.

### R8. MINOR. A deleted pigeon looks like a transient outage forever

Line 204 ("anything else is 0x03 / 0x88") and the 5xx row at 452. `is_authorized_device` reads
`device_public_key` through `one_row`, which returns an error on zero rows, and maps that to
500 (`objects/pigeons.rs:1144-1182` and `115-121`, checked). A deleted pigeon's DO has empty
tables, so every device route, including the CONNECT-time shadow GET, answers 500, which the
bridge maps to "server unavailable, retry later". A device whose pigeon was deleted will
reconnect at its backoff ceiling indefinitely, each attempt a TLS handshake plus an edge
request. `docs/api.md` documents the dashboard GET on a deleted pigeon as 403 but says nothing
about the device routes.

Smallest fix: in T2, have `is_authorized_device` return 401 (or 404) when the pigeons table is
empty, and add the deleted-pigeon case to the CONNACK and ack tables as permanent.

### R9. MINOR. CONNACK mapping sends retryable codes for non-retryable failures

Line 204. A CONNECT whose username is not a valid pigeon id never reaches a DO: the gateway
answers 400 "Malformed Pigeon ID string" (`get_pigeon_do!`, `lib.rs:311-315`, checked); a
staging Access rejection or a WAF challenge answers 403. Both map to 0x03 "server unavailable",
which tells the client to try again. The v3 code for "your credentials are wrong" is 0x04, for
"not authorized" 0x05 (v5 0x86 / 0x87). Also, since a pigeon id is 64 hex characters (and the
DO id parser rejects anything else), the bridge can refuse a non-conforming username locally,
saving an edge request per garbage CONNECT and removing untrusted bytes from the warn log line
(tracing's fmt layer prints a string field as given, so a newline in a username splits a log
line; loft has the same property in `resolve_psk_identity`).

Smallest fix: 400 and 403 map to 0x04/0x05 (v5 0x86/0x87); only 5xx, timeouts and unreachable
map to 0x03/0x88; check the identity's shape before any upstream call.

## Security and admission

### R10. MINOR. The negative cache does not bound a distinct-password flood

Lines 217-220, 357-361. The negative cache is keyed by (identity, sha256(password)), so a
flood that varies the password misses it every time and each attempt costs dovecote a Worker
request and a DO request (the shadow GET). The only brake is 30 CONNECTs per source per 10 s.
Sixteen sources is 48 verify requests per second, about 4 million a day, which is real money
on the edge and a DO wake storm on one pigeon. loft has the same shape for unknown PSK
identities; MQTT cert mode makes it cheaper for the attacker because a bad password is a full
CONNECT, not a handshake.

Smallest fix: add a per-identity failure budget (after N refusals for one pigeon id in 60 s,
refuse without asking dovecote for the rest of the window, any password) and a global CONNECT
rate ceiling next to the per-source one. Both are bounded, expiring counters of the kind ADR G
already allows.

### R11. MINOR. No graceful drain, so every restart is R1's loss case

Lines 31 ("a restart drops connections"), 224 ("renewal restarts the unit"), and the absence
of any shutdown sequence in section 4 or ADR E. A deploy or a certificate renewal (every ~60
days, at whatever hour certbot picks) drops every session with whatever publishes are mid-POST.
Under R1 that is data loss for clean-session clients, and for the pigeon connector it is a
timeout and a retry it could have been spared.

Smallest fix: on SIGTERM stop accepting, let in-flight upstream requests finish (bounded by the
30 s upstream timeout), send their acks, then close every session (v5 DISCONNECT 0x8B "server
shutting down"); set `TimeoutStopSec` above that bound in the unit. This also makes the
"restart-on-renew" answer in open-questions item 8 genuinely harmless.

### R12. MINOR. "Never a trusted proxy" is true for cert mode only

Line 7 and README lines 49-52. In PSK mode the bridge holds `PIGEONHOLE_SERVICE_SECRET`, which
resolves any PSK-bearing pigeon's PSK and bearer token through `/internal/device-psk/:id`
(handler `get_coap_psk_internal`, `objects/pigeons.rs:887-918`, checked). A compromised bridge
process can therefore impersonate every PSK pigeon; the token verification at the DO does not
help, because the bridge is handed the token. This is exactly loft's trust level, which the
platform accepted and documented, and it is the reason both units are hardened. It is not a
flaw in the design; it is an overclaim in the text.

Smallest fix: say "in certificate mode the bridge holds only what the device presented; in PSK
mode it holds the service secret and is trusted to the same degree as loft", and point at the
hardened unit as the mitigation.

### R13. MINOR. Retained seed can deliver a stale target, including `reboot` and `firmware`

Lines 151, 164-165, 407-411. The CONNECT-time GET body is held for the session and delivered as
the retained message at SUBSCRIBE; the WS is dialled after that and its snapshot corrects the
value if it changed. A client that subscribes some time after CONNECT (or a dashboard PUT that
lands in the gap) gets the stale target first, and `target_config` carries `reboot` and
`firmware` keys that a device acts on. The window is small and self-healing but it is the only
place the design hands a device something the DO no longer says. Separately, the change key
`(target_version, updated_at)` will re-push on every device report-back, because
`set_shadow_updated_at` bumps `updated_at` on any UPDATE of `pigeon_shadow`
(`objects/pigeons.rs:204-210`, checked) while `target_version` bumps only when `target_config`
actually changes (`increment_pigeon_target_version`, lines 194-201); harmless, but
`target_version` alone is the real change key.

Smallest fix: on SUBSCRIBE, dial the WS first and use its snapshot frame as the retained
delivery; fall back to the CONNECT-time body only if the dial fails within a short deadline.
That also removes the one copy of shadow bytes the bridge holds for longer than a request,
which tightens the ADR G audit row for C. Key change detection on `target_version`.

## Performance, cost, and sizing

### R14. MAJOR. The Cloudflare cost table undercounts, and omits its largest line

Lines 595-610. Three corrections, none of which changes (a) versus (b) in ADR H (both options
pay them equally), but which do change the "load-bearing reading" paragraph and the per-device
economics the owner will see on the bill.

1. Durable Object requests are two per telemetry publish, not one: the gateway verifies the
   token with a DO round trip (`verify_device_via_do`, `lib.rs:577`) and the queue consumer
   writes with a second (`dispatch_http_sourced`, `queue.rs:131-235`). Checked. 5760/day, not
   2880: $0.00086/day, not $0.00043.
2. Queue operations are three per message (write, read, delete/ack), not two: 8640/day, about
   $0.0035/day at $0.40/M, not $0.0023. Reasoned (Cloudflare's published operation model).
3. The Pigeons DO is SQLite-backed (`new_sqlite_classes = ["Pigeons"]`, `wrangler.toml:156`,
   checked) and `upsert_telemetry` writes one row per metric key per report (lines 1664-1679).
   SQLite-backed DO storage bills rows written at $1.00 per million beyond the included 50
   million per month (reasoned, price from memory). A five-key report every 30 s is 14,400 rows
   a day, about $0.43 per device per month past the allowance. That line is absent from the
   table and is roughly four times the rest of it combined. It is platform-wide (HTTPS, CoAP,
   WS and MQTT all take it), so "MQTT == HTTPS == CoAP on the edge" still holds.

Revised per device per month under (a): about $0.16 for Worker, DO requests, duration and queue
(design says $0.11), plus about $0.43 of DO rows written for a five-key report once past the
included allowance, so about $0.59. Add the CONNECT-time GET and WS upgrade per connection (one
Worker plus one DO request each, negligible at one connection a day) and, if R5 is answered
with JSON pings, about 72 DO request-equivalents a day. What it changes: the "what unreasonable
cost would look like" paragraph (lines 618-626) should name the storage line as the platform's
dominant per-report cost, because the next time someone weighs a per-report design choice that
is the number that moves; and the fleet-size point at which the included allowances run out
should be stated (roughly 115 such devices for the 50 million rows).

### R15. MAJOR. A cheaper and lower-latency path for QoS 0 telemetry exists inside the design and is not evaluated

Lines 93-96 ("Telemetry may go QoS 0 ... matching what the device already does over the WS
transport"), 177-178 (the lazy-WS decision), 605-610 ("there is no speed-versus-cost trade to
put to the owner here").

The bridge already holds the pigeon's device WebSocket for any subscribed session. That socket
accepts `telemetry` frames (`handle_ws_telemetry`, `objects/pigeons.rs:1529-1600`, checked),
and on that path a report costs no Worker request, no verify hop, no Hyperdrive fuse query
(`check_perch_ingest_fuse` is a Postgres lookup per HTTP report, `helpers/usage.rs:411-423`),
one inbound WS message billed 20:1 as a DO request, a synchronous latest-value upsert (so two
rapid reports land in order, which the queued HTTP path does not guarantee), and the same queue
leg for history. Per million publishes that is roughly $0.0075 + $1.20 (queue) against the HTTP
path's $0.30 + $0.30 + $1.20, about a third less, and one edge hop shorter. It is also exactly
the semantics the design says QoS 0 is meant to match, and it is "thin bridge" by the design's
own standard (the frame is what the device itself would send).

The trade the owner should see: the WS path skips the free-tier fuse (no fuse check exists in
`handle_ws_telemetry`; a pre-existing gap for WS devices), its frame cap is 50 per 10 s
(`objects/ws.rs:18-19`) against the bridge's 60 per 10 s, and it needs the WS open at CONNECT
rather than lazily, which reopens the shell 504-versus-409 point (see N7 for a one-frame
answer). QoS 1 stays on the POST because the ack needs a status.

Smallest fix: evaluate it in ADR C or H with these numbers and record the decision either way.
If taken: open the WS at CONNECT, route QoS 0 telemetry as a `telemetry` frame when the socket
is up and fall back to the POST when it is not, add a fuse check to the WS path in T2 (a cached
per-pigeon verdict in the DO is enough), and align the two rate caps. If not taken: say why
(the fuse parity cost is a fair reason) and drop the "no trade to put to the owner" sentence.

### R16. MAJOR. Per-session memory is dominated by a default the design does not mention

Lines 612-616, 628-630. tungstenite 0.30's `WebSocketConfig::default()` allocates a 128 KiB
read buffer per connection and sizes the write buffer at 128 KiB, with a 64 MiB maximum message
(`tungstenite-0.30.0/src/protocol/mod.rs:96-104`, checked). The design's "rustls session state
plus buffers" is therefore about 256 KiB per subscribed session before rustls and OpenSSL are
counted: 4096 sessions is about 1 GiB of WS buffers alone. The box is an OVH VPS-1 with 4 GB
(`~/pidgeiot/docs/infra/immediate-production-hosting.md:191`), on which `kratos.service` has
`MemoryMax=2G` (`~/pidgeiot/infra/systemd/kratos.service:119`) and `loft.service` has
`MemoryMax=1536M` (`~/loft/infra/coap-terminator/loft.service:172`); those are caps, not
reservations, but they say where the design's "shared small box loft already sizes for" stands.
The inbound side has its own worst case: 16 queued publishes of up to 20 KiB is 320 KiB per
session under flood, bounded only by how many valid sessions an attacker holds.

Smallest fix: set `read_buffer_size` to a few KiB (shadow_update frames are a few hundred bytes
to a few KiB), `write_buffer_size` small, and `max_message_size` to 64 KiB or so on the
upstream dial; set `SSL_MODE_RELEASE_BUFFERS` on the listener context; put a per-session budget
(socket, OpenSSL, tokio task, upstream rustls + WS, queue worst case) into section 9 as a target
(tens of KiB idle, under half a MiB worst case) and derive `MemoryMax` and the 4096 ceiling from
it before T13 measures it. Also move the soak's WS-per-source probe earlier (R19).

### R17. NIT. The byte table omits the TLS record and TCP cost, which is where QoS 1 actually pays

Lines 567-573. The table counts MQTT bytes only. Each MQTT packet rides in its own TLS record
(5 byte header plus a 16 byte tag and, for AES-GCM in TLS 1.2, an 8 byte explicit nonce) in
its own TCP segment (40 bytes of IPv4+TCP headers, plus the peer's ACK). A QoS 1 PUBACK is
therefore about 4 + 29 + 40 bytes down and a 40 byte ACK up, roughly 110-120 bytes per report
on the air rather than the table's 4 + 2. At 2880 reports a day that is about 340 KB, which
is the number a cellular plan sees. The conclusion (QoS 0 is cheaper) stands; the magnitude is
understated by about twenty times and the same correction applies to the id-in-topic row (the
65 extra bytes ride inside an existing record, so that row is right as is).

Smallest fix: add a TLS+TCP row and restate the QoS 0 versus QoS 1 difference in on-air bytes.

## Thin-bridge compliance (ADR G)

The bridge's state inventory, as read from the design and stubs: session registry (pigeon id to
handle), per-session will, subscription set, last-delivered target version, in-flight publish
queue, outbound QoS 1 packet ids, the upstream WS, the CONNECT-time shadow body (see R13), PSK
cache, negative auth cache, admission counters. Every one is reconstructible or disposable, and
nothing is durable. The ADR holds. Two semantic decisions do live on the VPS and should be
named as such in the audit table rather than left implicit: the will-suppression rule this
review asks for in R3 (a decision about what "offline" means, taken on the VPS because only the
VPS knows two sessions overlapped), and the ack table itself (a mapping of HTTP status to MQTT
outcome, which is policy even if it is the obvious policy). ADR G's "no dedicated Worker"
reasoning holds; the named flip trigger (fan-out across bridge instances) is the right one, and
R6's rotation close code is a second small DO-side hook worth listing as "Worker-side surface
this design adds", since it is one.

## Device side

### R18. MINOR. What the first real device will catch that the harness cannot

Section 6 and 7. Three concrete items, each verified against the trees:

1. TLS record size against the device's mbedTLS content length. The native_sim PSK build sets
   `CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN=7168` (`samples/coap_dtls_init/boards/
   native_sim_native_64.conf:36`, checked); the C6 HTTPS samples use 16384
   (`samples/wifi_init/prj.conf:303`). OpenSSL writes records up to 16 KiB. A Let's Encrypt
   chain (3-4 KB, one Certificate message) and any retained shadow larger than the device's
   limit fail the handshake or the read on a smaller build. Either set
   `SSL_CTX_set_max_send_fragment` conservatively on the listener or require the sample to
   enable the max_fragment_length extension, and say which.
2. Cipher preference when a device offers both PSK and ECDHE suites. The native_sim conf
   deliberately does not pin a ciphersuite list (same file, lines 43-50), so mbedTLS offers
   every enabled suite; against loft's PSK-only context that is fine, against the dual
   listener the server's order decides. If certificate suites come first, a PSK-provisioned
   device that also has ECDHE enabled negotiates a certificate handshake it cannot verify.
   The listener must list PSK suites first and set server cipher preference; the sample should
   still pin PSK on the client side.
3. Send timeouts. The pigeon WS client needed `NET_CONTEXT_SNDTIMEO` because a stalled TCP
   path otherwise hangs a blocking send for good (`~/pigeon/zephyr/Kconfig:437-439`,
   `src/pigeon_ws.c:370-376`, checked). The MQTT connector will hit the same thing on
   `mqtt_publish` over a half-dead link; plan for it in T10, not after the first bench hang.

Two confirmations so they do not get re-derived: `mqtt_transport_socket_tls.c` opens an
`IPPROTO_TLS_1_2` socket with `TLS_SEC_TAG_LIST`, `TLS_PEER_VERIFY` and (when set)
`TLS_HOSTNAME` (lines 29, 78, 96, 118), matching the CoAP TCP connector (`pigeon_coap_tcp.c:
68-89`); and the nRF91 modem's TLS advertises `TLS_PSK_WITH_AES_128_CCM_8` and
`TLS_PSK_WITH_AES_128_CBC_SHA256` (`nrfxlib/nrf_modem/include/nrf_socket.h:908-911`, checked),
both in the bridge's PSK list, so a future nRF91 PSK MQTT build has a suite to land on; the
modem-store PSK write path in `pigeon_coap.c` exists but is marked not yet hardware-verified in
`~/pigeon/CLAUDE.md`, which the design should repeat rather than cite as proven.

### R19. MINOR. Phasing: a thinner route to a real device, and one probe that belongs first

Lines 512-552. Certificate mode needs no backend change at all: any Https pigeon's token works
against the bridge today, and PSK mode can be exercised against a Coap pigeon through the
existing `/internal/coap-psk/:id` name. So T4-T7 and T9 can run before T1-T3, with a real
client talking to `dovecote-staging` before any capsules/dovecote/fancier change lands; T1-T3
then follows once the broker has proved out, and the `/internal/device-psk` alias can wait for
loft's own rename. Two more points. The WS-per-source-IP ceiling (line 628) is the one unknown
that would change the push design if it exists; it costs a script and an afternoon against
`dovecote-staging` and should run before T6, not at T13. And PSK mode never touches the real
edge before production: the staging allowlist is empty (`COAP_SERVICE_ALLOWED_IPS = ""`,
`wrangler.toml:216`, checked), so T9 is cert mode only; adding the VPS egress address to the
staging allowlist is a one-line var and lets T9 cover both modes.

### R20. MINOR. Pin the Let's Encrypt key type and chain, and state what the device must verify

Line 483 (ISRG Root X1). Which chain the bridge serves depends on the key type certbot
requests: an RSA leaf chains R10/R11 to ISRG Root X1; the default ECDSA chain goes E5/E6 to
ISRG Root X2 cross-signed by X1. Both anchor at X1, but the device's mbedTLS algorithm set
differs (RSA-4096 verify for the X1 signature on the intermediate, or P-384 for X2 plus P-256
for the leaf), and `wifi_init` already had to tune exactly this for the GTS chain
(`samples/wifi_init/prj.conf:202-228`). The chain size also enters the handshake table.

Smallest fix: the runbook names the `--key-type` and the served chain; the C6 sample's
mbedTLS config is written against it; the sample sets peer verification required and the
hostname, since a cert-mode client that skips verification has no server authentication at
all.

## Omissions and smaller items

### R21. MINOR. A WAF 403 is indistinguishable from an auth 403 in the ack table

Line 450 maps 403 to close. `docs/api.md:93-107` documents that a request from a datacenter
address or a suspicious User-Agent can be stopped by edge security with a 403 and an HTML body
before the API sees it. If that ever happens to the VPS (a publish flood from one address is
exactly the kind of thing that trips it), the bridge will close every session as "not
authorized", every device will reconnect, the CONNECT-time GET will also 403, and the fleet sits
in CONNACK-refused loops while the logs blame credentials. loft shares the exposure.

Smallest fix: classify a 403 whose body is not the API's plain-text form (or that carries the
edge's mitigation headers) as 5xx-class, and alarm on it in the 60 s stats line.

### R22. MINOR. IPv6 on both sides of the bridge

Line 221 (DNS-only A/AAAA) and the config stub's default `PIGEONHOLE_LISTEN=0.0.0.0:8883`
(`pigeonhole/src/config.rs`). A v4-only bind cannot serve the AAAA record; bind `[::]:8883`
(dual-stack) or do not publish AAAA. On the egress side, if the VPS gains v6 connectivity for
that AAAA record, its PSK lookups may leave over v6, and `is_allowed_coap_service_ip` compares
`CF-Connecting-IP` against a list that holds the v4 address
(`~/pidgeiot/dovecote/src/helpers/coap_service.rs:25-33`, checked): both loft and pigeonhole
would start getting 403 on PSK resolution. Add the v6 egress address to the allowlist in the
same change that adds the AAAA record.

### N1. NIT. "ADR 0" survives in two places

`docs/open-questions.md:4` and `pigeonhole/src/main.rs` (module doc) still name "ADR 0"; the
design now calls the governing rule ADR G and the topology ADR H.

### N2. NIT. mqtt-proto 0.4.0 provenance

Line 48-49 says "proptest and fuzz targets in-tree". The published crate carries proptest as a
dev-dependency and an `arbitrary` feature "only for fuzz testing"; the fuzz targets live in the
upstream repository (the Makefile references `cargo fuzz coverage mqtt_v5_arbitrary`), not in
the crate (`mqtt-proto-0.4.0/Cargo.toml.orig`, `Makefile`, checked). The README's TODO list is
unfinished and there is one author. A codec this size is vendorable, so this is fine; say so,
and note `decode_raw_header_async` (`src/common/utils.rs:14`) is the hook the size cap needs.

### N3. NIT. v5 and 3.1.1 edge cases worth one line each

`$share/...` filters answer 0x9E (shared subscriptions not supported), not 0x87; a PUBLISH with a
Topic Alias property when Topic Alias Maximum is 0 is DISCONNECT 0x94; a will at QoS 2 follows
the QoS 2 rule; a zero-length client id with CleanSession=0 is CONNACK 0x02 in 3.1.1; a message
matching two accepted filters (`pigeon/#` and `pigeon/shadow/target`) should be delivered once;
and `pigeon/#` will receive any future downstream topic (shell), which old firmware must ignore.

### N4. NIT. PSK suites are not strictly "TLS 1.2 only" on OpenSSL

Line 428-430 and `tls.rs` ("TLS 1.3 clients negotiate certificate auth"). OpenSSL consults the
TLS 1.2 `psk_server_callback` for a TLS 1.3 external PSK as well when no `psk_find_session`
callback is set, so a TLS 1.3 client offering a PSK identity can complete a PSK handshake. Still
PSK-authenticated, so harmless; the s_client check in section 4 should include `-tls1_3 -psk`
so the behaviour is known rather than assumed. loft avoids the question by capping its PSK
context at 1.2 (`~/loft/loft/src/tls_common.rs:44-48`, checked), which the dual context cannot.

### N5. NIT. The connector is a provisioning hint, not a transport boundary

ADR D items 1-3. An Https pigeon's token already works over MQTT in cert mode (the bridge cannot
tell connectors apart), and once `get_coap_psk_internal` matches any PSK-bearing connector an
Mqtt pigeon's PSK also completes a loft handshake and vice versa. Consistent with the platform
(a CoAP PSK yields a token that works on every device route), but fancier's badge and detail
card will read as if the choice restricts the device. One sentence in ADR D and in `docs/api.md`.

### N6. NIT. Device-side Kconfig wiring the plan does not list

`CONFIG_PIGEON_LOG_UPLOAD` depends on `PIGEON_CONNECTOR_HTTPS || PIGEON_CONNECTOR_COAP`
(`~/pigeon/zephyr/Kconfig:219-223`, checked) and needs the MQTT connector added or log upload
is unavailable on MQTT builds; `CONFIG_MQTT_KEEPALIVE` defaults to 60 s, which is right for the
mains/WiFi targets and wrong for a PSM cellular device (a wake every minute); the sample should
set it deliberately. Firmware download is an HTTPS-only hook (`src/pigeon_internal.h:117-135`),
as the design says.

### N7. NIT. Answer `shell_cmd` instead of letting it time out

Lines 186-190. Replying to a `shell_cmd` frame with a `shell_output` of
`{"exit_code":-1,"output":"shell not available over MQTT","truncated":false}` turns the
dashboard's 10 s 504 into an immediate, honest answer, costs one frame, and removes the one
argument against opening the WS at CONNECT (see R15). It is a small semantic the bridge would
own; if that is unwelcome, keep the 504 and say so in `docs/api.md`.

## On the owner's constraints

(a) Thin, stateless bridge: met; the PSK trust point (R12) should be stated, not denied.
(b) Worker topology weighed on merit: met (ADR H).
(c) Best performance with the trade in numbers: partly met; the numbers need R14, R16 and
R17, and the QoS 0 over WS option (R15) is a trade the owner has not been shown.
(d) Bare binary plus hardened unit and a documentation-grade Docker path: met in the plan (T8).
(e) Rust client example in the workspace: met in the plan (T7).
(f) Zephyr connector plus native_sim and esp32-c6 samples: met in the plan (T10, T11), with
the C6 bench gated as the design says.
