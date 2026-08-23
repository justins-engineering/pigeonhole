# Open questions for the owner

Only what genuinely needs a ruling after the thin-bridge / deploy-shape / performance guidance,
which is now folded into `design.md` (ADR 0, ADR E, ADR G, section 9) and no longer in
question. Each item carries the recommended answer; the design is written as if the
recommendation stands, so a different ruling means a revision there.

1. **Hostname and port.** `mqtt.pidgeiot.com`, DNS-only A/AAAA to the same VPS as loft,
   TLS on 8883, no plaintext listener. No separate staging hostname: staging verification runs
   a local bridge against `dovecote-staging` (certificate mode needs no dovecote config change)
   and PSK mode against `wrangler dev`. Recommend: yes to all.

2. **Two auth modes on one listener from the start** (Let's Encrypt certificate + username/
   password, and TLS-PSK) versus certificate-only first and PSK later. PSK is a copy of loft's
   context builder and resolver, and it is what the native_sim dev loop and constrained Zephyr
   builds want. Recommend: both from phase 2.

3. **Internal PSK route and secret naming.** Add `GET /internal/device-psk/:pigeon_id` as a
   neutral alias of `/internal/coap-psk/:pigeon_id` now (same handler, generalized to any
   PSK-bearing connector); keep dovecote's `COAP_SERVICE_SECRET` / `COAP_SERVICE_ALLOWED_IPS`
   names for this round, with pigeonhole reading the same value as `PIGEONHOLE_SERVICE_SECRET`;
   rename the dovecote vars when loft's Phase 6 cleanup touches its unit anyway. Recommend: yes.

4. **QoS 2 policy.** v3.1.1: accept with the full four-packet exchange but at-least-once
   upstream semantics; v5: advertise Maximum QoS 1 and treat QoS 2 as the protocol error the
   spec makes it. The alternative is refusing QoS 2 on both versions. Recommend: as designed.

5. **Will and offline: bridge the will, add no offline route.** A Last Will is accepted only on
   the session's own publish topics and, on ungraceful disconnect, forwarded as an ordinary
   device-route publish (a will to `pigeon/telemetry` with `{"status":"offline"}` is the useful
   form), so the semantics stay in dovecote and the bridge only forwards. The alternative you
   raised, a DO-side offline hook, would be new backend surface; the existing connection-state
   indicator already derives "went quiet" from the shadow's `updated_at`, and a will publish
   gives an explicit signal through the existing route, so I do not recommend adding the hook
   now. Rule here if you want an explicit device-offline event in the platform.

6. **MQTT 5 and the shell relay timing.** MQTT 5 lands in phase 4 (after the device samples),
   not before; mapping `POST /pigeons/:id/shell` onto `pigeon/shell/{cmd,output}` is also a
   phase 4 candidate (until then a shell request to a subscribed MQTT pigeon answers 504 instead
   of 409). Recommend: phase 4 for both.

7. **Bench scheduling.** The ESP32-C6 currently serves CoAP testing; the `mqtt_init` C6 target
   needs it flashed for MQTT. native_sim covers the e2e until then. Recommend: a scheduled
   window or a second C6; the design does not assume the board.

8. **Certificate issuance and renewal.** certbot DNS-01 with a scoped Cloudflare API token on
   the VPS (no inbound port 80), key and chain handed to the unit via `LoadCredential=`,
   renewal restarts the service (one fleet reconnect every ~60 days, absorbed by client
   backoff). The alternative is a SIGHUP hot reload with a stable service user. Recommend:
   restart-on-renew for v1.
