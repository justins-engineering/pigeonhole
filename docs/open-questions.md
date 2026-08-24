# Owner rulings

These were the open questions; the owner has ruled on all seven, and the design is updated
to match. The two candidates that dissolved before ruling stay recorded: ADR H found no
speed-versus-cost trade in the Worker topology, and the QoS 0 fast path's fuse-parity
condition shipped platform-side during review, leaving the rate-cap alignment a bridge-side
choice already made.

1. **Hostname, port, address families.** RULED yes as recommended: `mqtt.pidgeiot.com`,
   DNS-only to the same VPS as loft, TLS on 8883, dual-stack bind; A record first, AAAA only
   together with the VPS's v6 egress address joining `COAP_SERVICE_ALLOWED_IPS`.

2. **Auth modes and cleartext.** RULED yes to both modes (Let's Encrypt certificate +
   username/password, and TLS-PSK) from the first broker phase, with an explicit addition now
   load-bearing in ADR D: NO unencrypted traffic, ever. No plaintext 1883 listener, no byte
   accepted before TLS on any listener, in any deploy shape, the Docker example and the local
   dev loop included (`scripts/dev-cert.sh` exists so dev is TLS too).

3. **Protocol versions and QoS 2.** RULED: follow the specifications; the primary version
   target is MQTT 5. Folded in as: v5 is the design center and ships in the first broker
   phase (T4 carries both adapters; the former phase-4 v5 task is gone), 3.1.1 beside it for
   Zephyr-class clients; and QoS 2 is not offered spec-faithfully on either version, v5 by
   the spec's own mechanism (Maximum QoS 1, DISCONNECT 0x9B), 3.1.1 by refusing the
   connection on a QoS 2 PUBLISH, since true exactly-once would need the durable per-client
   dedup store ADR G forbids and an at-least-once shim would silently break the contract
   (ADR B carries the one-paragraph trade).

4. **Will and offline.** RULED as recommended: bridge-only will on the session's own publish
   topics with the newer-session suppression rule; no new offline event or DO hook.

5. **Internal PSK route and secret naming.** RULED yes as recommended: the bridge uses
   `/internal/coap-psk/:pigeon_id` until the backend phase adds the neutral
   `/internal/device-psk/:pigeon_id` alias; `COAP_SERVICE_SECRET` /
   `COAP_SERVICE_ALLOWED_IPS` names stay until loft's own cleanup renames them.

6. **Bench scheduling for the C6 `mqtt_init` target.** RULED after verification: the bench
   ESP32-C6 is not in use (its CoAP pigeon has been silent since the CID work wound down), so
   the plan uses the existing board, no second unit, no reserved window, with one
   coordination note carried in the device plan: loft's Phase 6 CID cleanup may want a final
   CoAP regression pass on it first, so the MQTT flash coordinates with that; reflashing back
   to the CoAP sample is routine, and bench flashing is pre-approved either way.

7. **Certificate issuance and renewal.** RULED yes as amended: certbot DNS-01 with a scoped
   Cloudflare API token, `--key-type ecdsa` together with `--preferred-chain "ISRG Root X2"`
   (all-ECDSA chain, device anchors X2 with only P-256 + P-384 enabled; the unpinned default
   chain's X1 cross-signature would force RSA-4096 into every constrained build), key and
   chain via `LoadCredential=`, restart-on-renew through the SIGTERM drain.
