# pigeonhole design review 1: verification of the revision

Scope: `docs/design.md` at commit 5ff4927 (753 lines, md5 43e42b7941ba7dc60bb2c5dedcb0061b),
`docs/design-review-1-response.md`, `docs/open-questions.md`. This pass verifies that the
fixes claimed for the round-one findings actually landed and hold together, spot-checks the
recomputed section 9, hunts for contradictions the revision itself introduced, and reads the
final open questions. It is not a fresh review. The three platform facts the revision consumes
were re-verified in the `~/pidgeiot` tree, not taken on faith: `token/refresh` and `delete`
close open device sockets with 4004/4005 (`dovecote/src/objects/pigeons.rs:917` and `:1027`,
codes in `objects/ws.rs:44,52`, documented at `docs/api.md:1841`); the telemetry store is one
merged-blob row, one read plus one write per report (`pigeon_telemetry_latest`, id=1 CHECK,
`read_telemetry_blob`/`write_telemetry_blob`, `objects/pigeons.rs:263-270,1824-1860`); and the
fuse covers every ingest surface including the WS (upgrade 429 at `objects/pigeons.rs:1407-1410`,
close 4029 at `:380`, `WsInboundFrame::is_billable` in `objects/ws.rs:103` with tests,
`docs/api.md:180,1707-1715`). All checked.

## 1. The eight majors

- R1 (redelivery contract): VERIFIED. Restated in section 1, ADR B, section 5 (lines 539-544)
  and carried into the connector work list (section 6). The v5 429 row is now PUBACK 0x97 with
  the session kept, which is a legal PUBACK reason code; v3.1.1 keeps the close and the
  long-backoff instruction is on the device side where it belongs.
- R2 (reader never stops): VERIFIED. Flow control at ADR B lines 119-123, echoed in section 4;
  in-flight counted as protocol (16 v5 / 64 v3 grace), PINGREQ answered from the reader,
  upstream publish timeout 10 s. The math holds because the reader never pauses; the sentence
  "the 10 s upstream publish timeout sits far below any 1.5x deadline" is overbroad for a
  client keepalive under about 7 s, but nothing depends on it. One wording gap noted as V5.
- R3 (will suppression): VERIFIED. The rule is in ADR B, the sequence diagram's last line, and
  the test list ("takeover with will suppression, will delivery when genuinely alone"). It
  interacts correctly with the new close codes: a will bridged after a 4004/4005 close dies at
  the DO with 401 (harmless noise, see V8), and a v3.1.1 close on 4029 fires a will into the
  same fuse that drops it, which is also semantically the truth (the device is going offline).
- R5 (feed liveness): BROKEN in one sentence, otherwise landed. ADR C's rule pings on "60 s of
  feed silence" and that is right, but the follow-on claim "a session with QoS 0 telemetry
  flowing needs no pings (its frames prove the socket)" is false: telemetry frames are
  outbound, a half-open TCP path absorbs outbound writes into the send buffer until the
  retransmission timeout (many minutes), and the DO sends no response to a telemetry frame. If
  outbound activity resets the ping timer, exactly the sessions on the fast path get silent
  QoS 0 loss plus missed shadow pushes for that whole window, which is the failure R5 was
  raised to prevent. Smallest fix: one word. The ping timer keys on INBOUND silence (no pong,
  no shadow_update, no shell_cmd received for 60 s), regardless of what the bridge is sending.
- R6 (rotation reaches the push path): VERIFIED. The dovecote half is genuinely shipped (cites
  above); the bridge half is in ADR C's feed rules, ADR D's rotation bullet, and ADR G's
  consumed-surface list. 4004 ends the session with no redial; 4005 reads as deleted.
- R14 (cost model): VERIFIED with one arithmetic slip in the totals row, see section 2.
- R15 (QoS 0 over the WS): VERIFIED as adopted and coherent. The fuse condition is genuinely
  closed platform-side (is_billable checked in code, ping/pong and shell_output exempt); the
  v3.1.1 no-signal concern from R1 is answered by the 4029 close being the signal, and the
  POST fallback's 429 row closes a v3.1.1 session the same way. The bridge's 40 per 10 s cap
  under the DO's 50 leaves headroom for pings and shell_output replies. Two consequences the
  design does not yet name are V4 and V6.
- R16 (per-session memory): VERIFIED. The knobs are real: tungstenite 0.30's
  `WebSocketConfig.read_buffer_size`/`write_buffer_size`/`max_message_size` (checked in the
  vendored crate, defaults 128 KiB/128 KiB/64 MiB), `SslMode::RELEASE_BUFFERS` exists in
  openssl 0.10.81 (checked). 4096 x 64 KiB = 256 MiB under MemoryMax=1G is consistent. Two
  caveats: `SSL_CTX_set_max_send_fragment` has no binding in openssl 0.10 or openssl-sys
  0.9.117 (checked: no MAX_SEND_FRAGMENT symbol; it needs a raw `SSL_CTX_ctrl` call, control
  52, the loft FFI-shim precedent, or the client-driven max_fragment_length extension), noted
  as V7; and the named worst case (16 x 20 KiB per session under authenticated flood) is
  1.28 GiB fleet-wide, above MemoryMax=1G, so either cap in-flight bytes per session as well
  as count, or state that the cap accepts an OOM restart as the flood backstop (V9).

The four minors folded into majors' territory also landed where claimed: R4's 4009 is
terminal per session (ADR C), R8's 401-on-empty is contract item 4 plus a CONNACK note, R11's
drain is ADR E's shutdown paragraph plus T6 and the test list, R13 is resolved structurally by
the WS-at-CONNECT shape. The response table's other dispositions were spot-checked against the
design text and are present where it says they are; none silently dropped.

## 2. Section 9 spot-check

Line items all reproduce: 86,400 Worker requests -> $0.026; 172,800 DO requests -> $0.026;
frame path 86,400 at 20:1 -> 4,320 -> $0.0006 plus one consumer DO round trip per report ->
$0.013 (the WS-sourced consumer does hit the DO once, for the endpoint lookup:
`queue.rs::dispatch_ws_sourced`, checked); queue 259,200 ops -> $0.104; rows written 86,400 ->
$0.086 (one merged row per report, verified in code); 50 M / 86,400 = 578 devices, "~575"
holds; the on-air row's 340-460 KB/device-day reproduces from 2880 x 120-160 B.

One slip: the frame-path column's own line items sum to about $0.21 per device-month
(0.0006 + 0.013 + 0.002 + 0.104 + 0.086 + 0.001), not the stated ~$0.19, so the saving over
the POST path is about $0.04 (~16 %), not ~$0.05 (~21 %). The POST column's ~$0.25 is right.
Nothing decision-bearing moves; fix the two numbers.

## 3. New findings introduced by the revision

- V1 (from R5, the one real break): the "frames prove the socket" sentence, above. One-word
  fix: inbound silence.
- V2: the new global CONNECT ceiling (120 per 10 s, ADR D admission) collides with the
  design's own restart story. After a deploy or certbot renewal the whole fleet reconnects;
  at 120 per 10 s, 4096 sessions take about 5.7 minutes to re-admit, and every refused
  CONNECT stretches that through client backoff. Even the 1000-session soak takes 80+
  seconds. Smallest fix: apply the global ceiling to failed or pre-auth CONNECTs only, or
  size it against the fleet reconnect (several hundred per 10 s) and say the restart storm is
  the sizing case.
- V3: the certificate chain math in ADR D and section 6 is internally inconsistent. With
  `--key-type ecdsa`, the DEFAULT Let's Encrypt chain is leaf <- E5/E6 <- ISRG Root X2
  cross-signed by ISRG Root X1, and that cross-signature is X1's, an RSA-4096 signature; a
  device anchored at X1 must therefore verify RSA-4096 as well, so "P-256 + P-384 enabled and
  the X1 anchor" will not validate the chain as written. Two consistent shapes: anchor ISRG
  Root X2 on the device and have certbot serve the alternate chain (`--preferred-chain "ISRG
  Root X2"`), keeping the sample ECDSA-only (smallest fix, recommended); or keep the X1
  anchor and enable RSA-4096 verification in the sample's mbedTLS config. Open-questions item
  7 should carry whichever is chosen; the recommendation itself (ecdsa, restart-on-renew)
  stands.
- V4: fuse asymmetry worth one honest sentence: because the WS upgrade is both the session's
  auth and is refused 429 while paused, a paused MQTT device cannot connect at all, so it
  loses the shadow READ path too; a paused HTTPS or CoAP device can still GET its shadow
  (the fuse covers ingest surfaces only, checked in `docs/api.md`). Parity with WS devices,
  strictly less than HTTPS devices. Platform-shipped behavior, consumed correctly; the design
  should state the consequence (no config delivery to paused MQTT devices) rather than leave
  it implicit in the CONNACK bullet.
- V5: with QoS 0 on the WS frame path and QoS 1 on the POST path, "publishes are bridged one
  at a time in arrival order" (ADR B) now holds per path, not across paths: a QoS 0 frame can
  overtake an earlier QoS 1 publish or vice versa, and the design does not say whether frames
  share the sequential bridge queue (order kept, but then a stalled POST delays the fast
  path) or bypass it (fast, but cross-class order is unspecified). One sentence either way;
  recommend bypass plus stating that ordering is guaranteed within a QoS class only.
- V6: a v5 session that survives a fuse pause keeps sending its QoS 0 fallback POSTs, each a
  Worker request plus a DO verify answered 429 and dropped, for the rest of the billing
  period; the feed's own "fuse-scale backoff" does not throttle this. Smallest fix: on
  seeing 429/4029, remember the pause locally (a bounded, expiring flag, ADR G-compatible)
  and drop QoS 0 telemetry on the bridge for a fuse-scale window instead of POSTing each one.
- V7: `SSL_CTX_set_max_send_fragment` binding gap (under R16 above). Note it in ADR D or T4
  so it is not discovered mid-implementation.
- V8: cosmetics with real log noise: the bridge's own takeover 4009s its previous session's
  feed, so the "something else holds this pigeon's socket" warn fires on every legitimate
  device reconnect (suppress when the closer is the bridge's own newer session); and a will
  should be skipped, not bridged into a guaranteed 401, when the session ended on 4004/4005.
- V9: the flood worst case versus MemoryMax=1G (under R16 above).
- V10: response-doc wording only: R13's "there is no CONNECT-time GET copy at all" overstates;
  the bridge still buffers the latest feed bytes per session to serve a later SUBSCRIBE's
  retained delivery. The design text itself ("the live feed IS the retained value") is
  acceptable; the buffered-bytes reality is bounded, per-connection, and dies with the
  socket, so ADR G is unaffected.
- V11, nit: ADR D maps a malformed identity to CONNACK 0x02 (identifier rejected); in cert
  mode the identity arrives as the username, where 0x04 / 0x85-class fits the spec's wording
  better. Cosmetic.

Checked and clean: the 4029/429 handling is consistent across ADR C, ADR D and section 5; the
sequence diagram matches the WS-at-CONNECT shape and uses the existing internal PSK route
name, matching the reordered phasing; the test list covers the new close codes, the fuse
rows, the stalled-upstream PINGREQ case, and the drain; T3 (the edge WS probe) sits before
the broker task as asked; ADR G's audit table names the ack table and the will rule as VPS
policy and lists the consumed Worker-side surface.

## 4. Open questions

All seven are genuinely owner-level, sharply posed, and none hides a decision the design
already made; the preamble is honest about the two dissolved candidates and about the
rate-cap alignment being an implementation choice already taken. Recommendations are sound as
they stand, with one amendment: item 7 must absorb V3 (name the anchor and the
`--preferred-chain` flag, or the RSA alternative), since as written its "the device samples
are configured against it" points at a configuration that would not validate the default
chain. Item 1's AAAA/allowlist coupling and item 5's alias deferral correctly reflect the
revised design. One candidate the list could carry but defensibly leaves out: MemoryMax caps
on the shared 4 GB box now sum past physical memory (2G kratos + 1536M loft + 1G pigeonhole);
they are ceilings, not reservations, and T13 re-measures, so treating it as an
implementation-time check is acceptable.

## 5. Verdict

The revision is faithful: every accepted finding is present where the response says it is,
the shipped platform facts are real, and the recomputation is sound apart from one totals
cell. What remains is small and text-shaped: V1 (one word, but a real correctness defect in
the liveness rule), V2 (one number and its rationale), V3 (one chain/anchor sentence in ADR
D, section 6, and open-questions item 7), V4-V6 (a sentence each), and the V-nits at leisure.
None of it changes any recommendation the owner is being asked to rule on.

Gate: READY FOR OWNER RULINGS, with V1, V2 and V3 folded in as author edits before
implementation starts (none of them alters an open-question recommendation; V3 slightly
rewords item 7's parenthetical).
