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

These were re-run after the TLS 1.2 certificate defect below was fixed. Two
rows changed meaning entirely, which is the reason this section now says
which protocol version each check actually exercised.

| Check | Result |
|---|---|
| Certificate mode, TLS 1.2 pinned | `ECDHE-ECDSA-AES128-GCM-SHA256`, verify return code 0 |
| Certificate mode, TLS 1.3 pinned | verify return code 0 |
| Certificate mode, version unpinned | TLS 1.3, verify return code 0 |
| TLS 1.2 PSK, `PSK-AES128-GCM-SHA256` | negotiated, session authenticated |
| TLS 1.2 client offering both PSK and ECDHE | lands on PSK, server preference honored |
| TLS 1.3 with a PSK offered | certificate handshake, PSK callback not reached |
| Wrong PSK key | bad-record-mac alert |
| Unknown PSK identity | alert 115, `unknown_psk_identity` |
| `PSK-AES128-CCM8` | **not verified**, see below |
| mbedTLS client, PSK and certificate | interoperates on both, see below |

## The TLS 1.2 certificate defect, and what hid it

Found by the device connector work running a Zephyr client against a local
broker, not by anything here. The listener's cipher list was
`"{PSK suites}:DEFAULT"`, and OpenSSL treats `DEFAULT` as an initialiser
rather than as a set to append: everything before it survives and it
contributes nothing. The broker therefore offered the three PSK suites and
no TLS 1.2 certificate suite at all, so **every TLS 1.2 certificate client
got a handshake failure** while TLS 1.3 clients were fine, because their
suites come from a separate setter.

That is the class of client certificate mode exists for: off-the-shelf
clients, and the Zephyr connector, which opens an `IPPROTO_TLS_1_2` socket
and has no 1.3 to fall back to. The suites are now named one by one
(`tls::CERT_CIPHER_LIST`).

Two things in the first version of this document were wrong because of it,
and both are worth naming rather than quietly editing:

- The certificate row read "TLS 1.3, verify return code 0". True, and it
  proved only TLS 1.3. Every certificate check here had let OpenSSL pick the
  version, and OpenSSL picks 1.3.
- The row "TLS 1.2 client offering PSK and ECDHE lands on PSK, as intended"
  was **vacuous**. The server was offering no ECDHE at all, so PSK winning
  demonstrated nothing about server preference. It is now a real result.

The regression test (`a_certificate_client_with_no_tls13_can_still_connect`)
drives a client capped at TLS 1.2 through a full CONNECT and publish, and
was confirmed to fail against the old cipher list before being kept. The
general lesson is cheap to state and was expensive to miss: a check that
lets the peer choose the version only tests the version the peer chose.

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

**`PSK-AES128-CCM8` is still open**, and one attempt to close it is worth
recording because it nearly went in as a pass.

The broker offers CCM8 first, but it could not be exercised here: on this
OpenSSL build no CCM8 suite is negotiable between an OpenSSL client and
server at all, PSK or ECDHE, even at security level 0 with the suite named
explicitly on both sides. It still appears in `openssl ciphers` output,
which is why a build-time `openssl ciphers | grep CCM8` check passes and
proves less than it looks like it does. That check is worth re-reading
wherever it is used.

The device connector work then reported a Zephyr/mbedTLS client negotiating
`0x00a8` and read it as CCM8. It is not: `0x00A8` is
`TLS_PSK_WITH_AES_128_GCM_SHA256` (RFC 5487), and CCM8 is `0xC0A8`
(RFC 6655). One byte apart in the prefix.

The broker's own configuration is the independent check that settles it.
CCM8 is **first** in the cipher list and `SSL_OP_CIPHER_SERVER_PREFERENCE`
is set, so had the client offered CCM8 the server would have chosen it.
Landing on GCM proves the client did not offer it, which fits a build whose
mbedTLS or PSA configuration has no CCM enabled. A code point and a
preference order agreeing is what makes this a correction rather than two
opinions.

CCM8 therefore stays open, and the way to close it is specific: enable CCM
in the device build and re-run, expecting `0xC0A8`.

## mbedTLS interoperability, from the device connector work

What that run did establish is worth more than the row it was aimed at. A
real Zephyr/mbedTLS client interoperates with this broker on both
handshakes, which no OpenSSL client here can stand in for.

| Mode | Negotiated | Reading |
|---|---|---|
| PSK, TLS 1.2 | `0x00A8`, `TLS_PSK_WITH_AES_128_GCM_SHA256` | PSK works end to end with a constrained client; two sessions in one run, initial connect and reconnect |
| Certificate, TLS 1.2 | `0xC02B`, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | all-ECDSA, which is what anchoring the chain at ISRG Root X2 is for, and the device build wants no RSA at all |

The certificate row is also independent confirmation that the TLS 1.2
cipher-list fix above is right: a real device completing the handshake that
failed before it.

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

## Re-run after the staging redeploy

`dovecote-staging` was redeployed on 2026-08-25 (P1 backend plus batched
telemetry and unrelated work), so the matrix was run again against it. Every
flow above still holds; the numbers below are from the second run.

| Flow | Observed |
|---|---|
| CONNECT, MQTT 5, and the retained seed | accepted and seeded 12:39:29.605Z |
| Dashboard `PUT` to MQTT push | **178 ms**, 12:39:34.463Z to 12:39:34.641Z |
| Telemetry QoS 1 (v5) | PUBACK; visible 12:40:42Z |
| Telemetry QoS 0 (v5), flat frame on the held socket | no ack, as QoS 0 means; visible 12:40:43Z |
| Telemetry QoS 0, MQTT 3.1.1 | visible 12:40:44Z |
| Log chunk QoS 1 | PUBACK; 26 bytes read back byte-identical |
| Shadow report QoS 1, MQTT 3.1.1 | PUBACK; `current_config` updated |
| Retained target on `pigeon/#`, MQTT 3.1.1 | delivered |
| `token/refresh` mid-session | DISCONNECT 0x87 at 12:39:43.397Z, stale-token reconnect refused 0x86 at 12:39:45.532Z |

The backend gained a batched form of the telemetry WebSocket frame in that
deploy (`{"reports":[...]}`). The bridge does not send it and does not need
to: the QoS 0 rows above are the flat frame still being accepted, which is
what makes that a later optimisation rather than a compatibility break.

One row is an accident worth keeping. The first attempt gave its publishers
a client id that disagreed with the username, and every one was refused
`ClientIdNotValid` (v5 0x85, 3.1.1 0x02) while the subscriber, whose id
agreed, stayed up. The identity-agreement rule is therefore confirmed
against a live platform as well as against the mock, by a mistake rather
than by a test written to find it.

**PSK mode against staging is not reachable** and was not attempted: the
internal credential route is gated on a source-address allowlist that is
empty for staging, so it fails closed for any address. PSK mode is proven
against the mock in `pigeonhole/tests/admission.rs` (handshake, resolution,
identity disagreement, unknown identity, and the stale-entry eviction after
a rotation) and stays on the production bring-up checklist.
