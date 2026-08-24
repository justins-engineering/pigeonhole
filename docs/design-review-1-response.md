# Response to design review 1

Disposition of every finding in `design-review-1.md`, against `design.md` as revised. Three
facts changed after the review was written and are folded in as current: dovecote now closes a
pigeon's open device WS with 4004 (token revoked) / 4005 (pigeon deleted) from `token/refresh`
and `delete`; the DO telemetry store writes one merged-blob row per report regardless of key
count; and the free-tier fuse now covers WS frames (upgrade 429 when paused, close 4029 on a
billable frame while paused). Where a finding's evidence was superseded by those facts the
disposition says so.

| Finding | Disposition | What changed, where |
|---|---|---|
| R1 | Accepted | Redelivery restated as the client's, guaranteed only for CleanSession=0 with a persisting library; pigeon connector owns re-publish with dup from its pending store (section 1, section 5, section 6). v5 429 is now PUBACK 0x97 with the session kept; v3.1.1 keeps the close and the connector treats repeated close-after-publish as long backoff (section 5, ADR B). |
| R2 | Accepted | The reader never stops; in-flight QoS 1 counted and capped as protocol (16, v5 0x93; v3 grace 64); PINGREQ answered from the reader; upstream publish timeout cut to 10 s, below any 1.5x keepalive deadline (ADR B flow control, section 4). |
| R3 | Accepted | Will-suppression rule: no will is bridged while a newer live session for the pigeon exists in the registry; covers takeover and late keepalive expiry of a superseded session (ADR B, sequence, tests). |
| R4 | Accepted | 4009 is terminal for the session's feed (re-armed only by a new session); QoS 0 telemetry falls back to the POST; warn names the pigeon (ADR C feed rules). |
| R5 | Accepted | Feed liveness owned by the bridge: protocol-level WS ping per 60 s of silence, two missed pongs reconnects; edge-answers-without-DO-wake checked at implementation, JSON ping fallback priced in section 9; flowing QoS 0 frames substitute (ADR C feed rules). |
| R6 | Accepted, and the dovecote half shipped meanwhile | The design consumes 4004/4005: 4004 ends the MQTT session with no redial on the dead token, 4005 ends it as deleted (ADR C feed rules, ADR D rotation bullet, ADR G surface list). |
| R7 | Accepted | PUBACK defined per leaf: telemetry = authenticated and durably queued (202, consumer retries the DO write, history best-effort); shadow report and logs = completed DO write (section 5). |
| R8 | Accepted | Backend phase makes `is_authorized_device` answer 401 on an empty pigeons table; deleted-pigeon added to the CONNACK mapping as permanent (ADR D, contract item 5, T8). |
| R9 | Accepted | Identity shape checked locally (64 hex) before any upstream call; 400/403 map to 0x02/0x05-class, only 5xx/timeout to 0x03/0x88; raw usernames never logged unescaped (ADR D). |
| R10 | Accepted | Per-identity failure budget (10 refusals per 60 s parks the id locally) plus a global CONNECT ceiling (120 per 10 s) beside the per-source one (ADR D admission, quota stub). |
| R11 | Accepted | SIGTERM drain: stop accepting, finish in-flight (bounded 10 s), ack, DISCONNECT 0x8B, `TimeoutStopSec` above the bound (ADR E shutdown, T6, tests). |
| R12 | Accepted | Trust stated plainly: cert mode holds only what devices present; PSK mode holds the service secret and is trusted to loft's degree, hardened unit as mitigation (ADR D). |
| R13 | Accepted, resolved structurally | With the WS opened at CONNECT there is no CONNECT-time GET copy at all: the live feed is the retained value, so a late SUBSCRIBE delivers the current target; change key is `target_version` alone (ADR C, ADR D). |
| R14 | Accepted with a correction the review could not have known | DO requests 2x and queue ops 3x folded in; the per-key row model in item 3 was replaced platform-side by one merged row per report, so the recomputed totals are ~$0.25/device-month (POST path) and ~575 devices to the 50 M row allowance; storage and queue named as the dominant platform-wide lines (section 9). |
| R15 | Accepted, adopted | QoS 0 telemetry rides the held WS as `telemetry` frames with POST fallback, ~$0.19 vs ~$0.25 per device-month and one hop shorter, in-order; rate caps aligned 40 vs 50 per 10 s; WS moved to CONNECT, which also let the WS upgrade replace the shadow GET as session auth. The one condition, fuse parity on the WS path, shipped platform-side during review (`WsInboundFrame::is_billable`, upgrade 429 when paused, close 4029 on a billable frame), so the adoption is unconditional and the bridge consumes 429/4029 (ADR C, ADR B, ADR D, section 9). |
| R16 | Accepted | Upstream WS buffers tuned (4 KiB read/write, 64 KiB max message), `SSL_MODE_RELEASE_BUFFERS`, per-session budget target (tens of KiB idle, in-flight-cap bound under flood), `MemoryMax=1G` beside kratos 2G and loft 1536M, T13 measures (section 9, upstream stub). |
| R17 | Accepted | On-air row added: TLS record + TCP framing makes QoS 1 vs QoS 0 ~110-160 B per report, ~340-460 KB/device-day at cadence (section 9, ADR B performance). |
| R18 | Accepted | `SSL_CTX_set_max_send_fragment(4096)`, PSK suites first with server preference, send-timeout socket option planned in T10, mbedTLS content-length note in the device plan; nRF91 suite overlap kept, modem-store PSK path repeated as not yet hardware-verified (ADR D, section 6). |
| R19 | Accepted | Phasing reordered bridge-first (T1-T7 before the backend phase), the edge WS-per-source probe is T3 before the broker task, staging allowlist gains the VPS egress for PSK-mode T7. The `/internal/device-psk` alias still lands with the backend phase (one line while in that code) rather than waiting for loft's rename (section 8). |
| R20 | Accepted | `--key-type ecdsa` pinned, E5/E6-to-X2-cross chain named, device verifies with P-256 + P-384 and the X1 anchor, peer verification and hostname required in the sample (ADR D, section 6, T6). |
| R21 | Accepted | A 403 with an HTML body or edge-mitigation headers classifies as 5xx and is named in the stats line, in both the CONNACK mapping and the ack table (ADR D, section 5). |
| R22 | Accepted | Dual-stack `[::]:8883` bind; AAAA published only together with the v6 egress address joining the allowlist (ADR D, contract item 3, T14). |
| N1 | Already fixed | Both stale "ADR 0" references were corrected in the commit the review examined. |
| N2 | Accepted | Provenance restated: proptest as dev-dependency, fuzz targets upstream, single author, vendorable at ~6k lines; `decode_raw_header_async` named as the cap hook (ADR A). |
| N3 | Accepted | The v5/3.1.1 edge cases added as a codec-work bullet: `$share` 0x9E, topic alias vs maximum 0 is 0x94, zero-length client id with CleanSession=0 is 0x02, double-matching filters deliver once, will at QoS 2 follows the QoS 2 rule (ADR B). |
| N4 | Accepted | TLS 1.3 external PSK via the 1.2 callback noted; the s_client check includes `-tls1_3 -psk` (ADR D, section 4). |
| N5 | Accepted | Connector-is-a-provisioning-hint sentence in ADR D and the `docs/api.md` task (contract item 6). |
| N6 | Accepted | `CONFIG_PIGEON_LOG_UPLOAD` dependency extension and a deliberate `CONFIG_MQTT_KEEPALIVE` per target in the device plan and T10 (section 6). |
| N7 | Accepted | The bridge answers `shell_cmd` with an immediate `shell_output` (`exit_code` -1, "shell not available over MQTT") instead of letting the dashboard 504 (ADR C). |

Counts: 8 MAJOR accepted (0 rebutted), 13 MINOR accepted (0 rebutted), 8 NIT: 7 accepted, 1
already fixed. The review's thin-bridge section asked for two VPS-side semantic decisions to be
named in the audit table (the ack table as policy, the will-suppression rule) and for the
Worker-side surface list to include the rotation close codes; all three are in ADR G.

## Verify round (design-review-1-verify.md)

| Finding | Disposition | What changed, where |
|---|---|---|
| V1 | Accepted | The feed-liveness timer keys on INBOUND silence only (no pong, no `shadow_update`, no `shell_cmd` received); the "frames prove the socket" sentence is gone, with the half-open send-buffer reason stated (ADR C feed rules, section 4, shadow stub). |
| V2 | Accepted | The global brake now counts refused CONNECTs only (120 refusals per 10 s), with the arithmetic stated: an all-CONNECT ceiling at that size would stretch a post-drain fleet reconnect to nearly six minutes of spurious refusals, while successful reconnects are already bounded by the permit table and per-source caps (ADR D admission). |
| V3 | Accepted | `--preferred-chain "ISRG Root X2"` pinned with `--key-type ecdsa`: all-ECDSA chain, device anchors X2 with P-256 + P-384 only; the cross-signed-by-X1 RSA trap is named (ADR D, section 6 sample config, open-questions item 7). |
| V4 | Accepted | Stated consequence: a paused free-tier MQTT device cannot connect at all and loses config delivery, parity with WS devices, strictly less than HTTPS/CoAP whose non-ingest routes stay served (ADR C). |
| V5 | Accepted | Ordering guaranteed within a QoS class only: QoS 0 frames bypass the sequential bridge queue (a stalled POST must not delay the fast path); cross-class overtaking stated as fitting the semantics (ADR B flow control, section 9, session stub). |
| V6 | Accepted | On 429/4029 the bridge sets a bounded, expiring per-session pause flag and drops QoS 0 telemetry for a fuse-scale window instead of POSTing each report into a guaranteed 429 (ADR C 4029 rule). |
| V7 | Accepted | The missing `SSL_CTX_set_max_send_fragment` binding is named: one raw `SSL_CTX_ctrl` call, loft FFI-shim precedent (ADR D, tls stub unchanged in intent). |
| V8 | Accepted | The takeover 4009 warn is suppressed when the closer is the bridge's own newer session; the will is skipped after a 4004/4005 close instead of being bridged into a guaranteed 401 (ADR C feed rules). |
| V9 | Accepted | In-flight is capped by bytes as well as count (`MAX_INFLIGHT_BYTES` 64 KiB per session): flood worst case ~512 MiB fleet-wide, inside `MemoryMax=1G`; the 1.28 GiB count-only figure is named as what the byte cap prevents (ADR B, section 9, limits). |
| V10 | Accepted as a wording correction to this file | The R13 row's "no CONNECT-time GET copy at all" means no separately fetched auth-time copy exists; the bridge does buffer the latest feed bytes per session to serve a later SUBSCRIBE, bounded, per-connection, dying with the socket, as the design text says. |
| V11 | Accepted | A malformed identity refuses as 0x04/0x86 when it arrived as the username, 0x02/0x85 when only the client id carried it (ADR D). |

Also folded from the verify pass's section 2: the frame-path column's total corrected to
~$0.21 per device-month, the saving to ~$0.04 (~16 %), in section 9 and ADR C; the POST
column's ~$0.25 was confirmed and stands.
