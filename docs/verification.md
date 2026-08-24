# What has been measured

Design decisions that rested on an assumption, and what happened when the
assumption was checked. Kept apart from the runbook because these are
findings rather than procedure, and two of them came out the other way from
what `docs/design.md` predicted.

Environment: one workstation, OpenSSL 3.6.3, mosquitto clients 2.1.2, the
broker built from this tree. The platform side is `dovecote-staging`, which
runs the same backend code as production.

## Edge WebSocket ceiling, per source

The bridge holds one device WebSocket per live MQTT session, so a per-source
ceiling below the broker's own connection ceiling would cap the fleet one
instance can serve, and the push design would have to change. Measured with
`scripts/ws-ceiling-probe.py` against `dovecote-staging`, from one address,
one pigeon per socket (the Durable Object closes an older socket when a new
one arrives for the same pigeon, so concurrency needs distinct pigeons).

| Measure | Result |
|---|---|
| Concurrent upgrades opened | 256 of 256 attempted, no refusals |
| Time to open them | 15 s at 16 in parallel |
| Still open after a 120 s idle hold | 253 of 256 |

**No per-source ceiling was found at 256.** The push design stands: 256 is
far above any plausible per-instance session count in the near term, and the
broker's own ceiling is 4096.

Two things this does not settle, both belonging to the production soak: the
ceiling above 256, and the three sockets that dropped during the idle hold.
Three of 256 over two minutes is not obviously noise and is not obviously a
problem either; the soak holds a larger set for longer and is where a drop
rate becomes a number rather than an anecdote.

## Handshake checks

Details and the commands are in `docs/infra/mqtt-broker.md`. In brief:

| Check | Result |
|---|---|
| Certificate mode, verification on | TLS 1.3, verify return code 0 |
| TLS 1.2 PSK, `PSK-AES128-GCM-SHA256` | negotiated, session authenticated |
| TLS 1.2 client offering PSK and ECDHE | lands on PSK, as intended |
| TLS 1.3 with a PSK offered | certificate handshake, PSK callback not reached |
| Wrong PSK key | bad-record-mac alert |
| Unknown PSK identity | alert 115, `unknown_psk_identity` |
| `PSK-AES128-CCM8` | **not verified**, see below |

Two design assumptions were wrong, both in the safe direction, and the code
comments now say what was measured:

- **A TLS 1.3 capable client always lands on TLS 1.3 and the certificate**,
  whatever its TLS 1.2 cipher list says, because version negotiation happens
  before ciphersuite selection. The design's "PSK suites first with server
  preference, so a device offering both PSK and ECDHE lands on PSK" holds
  only among TLS 1.2 clients, which is what the constrained devices are.
- **OpenSSL does not route a TLS 1.3 external PSK through the TLS 1.2 PSK
  callback.** The design expected it would, and treated that as harmless. It
  does not happen at all: a TLS 1.3 client offering a PSK gets an ordinary
  certificate handshake, presents no CONNECT password, and is refused there.
  No session reaches the PSK code by that path.

**`PSK-AES128-CCM8` is open.** The broker offers it, but it could not be
exercised here: on this OpenSSL build no CCM8 suite is negotiable between an
OpenSSL client and server at all, PSK or ECDHE, even at security level 0
with the suite named explicitly on both sides. It still appears in `openssl
ciphers` output, which is why a build-time `openssl ciphers | grep CCM8`
check passes and proves less than it looks like it does. That check is worth
re-reading wherever it is used. The real CCM8 client is mbedTLS on the
device, so this is verified on the bench and against the VPS's own OpenSSL,
not here.

## Live, through the broker to dovecote-staging

Certificate mode, real `mosquitto_pub` and `mosquitto_sub` clients, one
staging `Mqtt` pigeon, on 2026-08-24. Every flow below is the platform's own
answer, read back through the dashboard routes.

| Flow | Observed |
|---|---|
| CONNECT, MQTT 5 | accepted 19:48:32Z; the device WebSocket upgrade is what authenticated it |
| Retained `pigeon/shadow/target` on SUBACK | the pigeon's real shadow, immediately |
| Telemetry, QoS 1 | PUBACK reason 0 within 1 s; visible on `GET /pigeons/:id/telemetry` at 19:48:55Z |
| Telemetry, QoS 0 | no ack, rode the held socket as a frame; visible at 19:48:50Z |
| Dashboard `PUT /pigeons/:id/shadow` to MQTT push | **388 ms**, 19:49:20.129Z to 19:49:20.517Z |
| Log chunk, QoS 1 | PUBACK; 29 bytes read back byte-identical through `GET /pigeons/:id/logs` |
| Shadow report back, MQTT 3.1.1, QoS 1 | PUBACK; `current_version` and `current_config` updated |
| Telemetry and subscribe, MQTT 3.1.1 | both work, `pigeon/#` delivers the target |
| `POST /pigeons/:id/token/refresh` mid-session | 19:51:00Z rotated; 19:51:01.007Z the broker logged "session ended by the platform, token revoked" and sent DISCONNECT 0x87; the client's reconnect with the stale token was refused CONNACK 0x86 at 19:51:03.182Z |

One live result is worth pointing at rather than leaving in the table. The
QoS 0 report was published **after** the QoS 1 one and landed **five seconds
before** it: 19:48:50Z against 19:48:55Z. That is the design's cross-class
ordering caveat happening for real, and the reason it is stated as a caveat
rather than a bug. The frame path is a synchronous upsert at the Durable
Object; the QoS 1 path is a queued write. Ordering holds within a QoS class,
not across them.

**PSK mode against staging is not reachable** and was not attempted: the
internal credential route is gated on a source-address allowlist that is
empty for staging, so it fails closed for any address. PSK mode is proven
against the mock in `pigeonhole/tests/admission.rs` (handshake, resolution,
identity disagreement, unknown identity, and the stale-entry eviction after
a rotation) and stays on the production bring-up checklist.
