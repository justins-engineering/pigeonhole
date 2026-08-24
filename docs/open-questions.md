# Open questions for the owner

Only what genuinely needs a ruling, updated after review round one (`design-review-1.md`,
dispositions in `design-review-1-response.md`). Each item carries the recommended answer; the
design is written as if the recommendation stands. Two candidates dissolved without needing a
ruling: ADR H found no speed-versus-cost trade in the Worker topology (the decided option is
both the fewest hops and the cheapest), and the QoS 0 over-the-WS fast path's one condition,
free-tier fuse parity on the WS path, shipped platform-side during review (upgrade 429 when
paused, close 4029 on a billable frame), so its adoption is unconditional and the remaining
rate-cap alignment (bridge 40 versus DO 50 per 10 s) is a bridge-side implementation choice
already made.

1. **Hostname, port, address families.** `mqtt.pidgeiot.com`, DNS-only to the same VPS as
   loft, TLS on 8883, no plaintext listener; dual-stack bind, with the AAAA record published
   only together with the VPS's v6 egress address joining `COAP_SERVICE_ALLOWED_IPS` (or PSK
   resolution, loft's included, fails over v6). No separate staging hostname. Recommend: yes
   to all, A record first, AAAA with the allowlist change.

2. **Two auth modes on one listener from the start** (Let's Encrypt certificate + username/
   password, and TLS-PSK) versus certificate-only first and PSK later. PSK is a copy of loft's
   context builder and resolver, and it is what the native_sim dev loop and constrained Zephyr
   builds want. Recommend: both from the first broker phase.

3. **QoS 2 policy.** v3.1.1: accept with the full four-packet exchange but at-least-once
   upstream semantics; v5: advertise Maximum QoS 1 and treat QoS 2 as the protocol error the
   spec makes it. The alternative is refusing QoS 2 on both versions. Recommend: as designed.

4. **Will and offline: bridge the will, add no offline route.** A Last Will is accepted only
   on the session's own publish topics and, on ungraceful disconnect, forwarded as an ordinary
   device-route publish (a will to `pigeon/telemetry` with `{"status":"offline"}` is the
   useful form), suppressed when a newer live session for the same pigeon exists so a
   reconnect never reports a connected device offline. The alternative remains a DO-side
   offline hook; the connection-state indicator already derives "went quiet" from
   `updated_at`, so I do not recommend it now. Rule here if you want an explicit
   device-offline event in the platform.

5. **Internal PSK route and secret naming.** The bridge uses the existing
   `/internal/coap-psk/:pigeon_id` name until the backend phase, which adds the neutral
   `/internal/device-psk/:pigeon_id` alias while in that code; dovecote's
   `COAP_SERVICE_SECRET` / `COAP_SERVICE_ALLOWED_IPS` names stay for this round (pigeonhole
   reads the same value as `PIGEONHOLE_SERVICE_SECRET`), renamed when loft's own cleanup
   touches its unit. Recommend: yes.

6. **Bench scheduling.** The ESP32-C6 currently serves CoAP testing; the `mqtt_init` C6
   target needs it flashed for MQTT. native_sim covers the e2e until then. Recommend: a
   scheduled window or a second C6; the design does not assume the board.

7. **Certificate issuance and renewal.** certbot DNS-01 with a scoped Cloudflare API token on
   the VPS (no inbound port 80), `--key-type ecdsa` pinned (the smaller chain; the device
   samples are configured against it), key and chain via `LoadCredential=`, renewal restarts
   the service through the SIGTERM drain (in-flight publishes acked, sessions closed with
   "server shutting down", one fleet reconnect every ~60 days absorbed by client backoff).
   The alternative is a SIGHUP hot reload with a stable service user. Recommend:
   restart-on-renew for v1.
