# pigeonhole

`pigeonhole` is PidgeIoT's MQTT broker. It accepts MQTT over TLS from devices, authenticates
each one as a specific pigeon, and translates its publishes onto ordinary HTTP calls to the
backend; it feeds the pigeon's target configuration back as a retained message. A topic is a
pigeonhole: the slot a message is filed into and collected from.

It exists for the same reason `loft` (the CoAP terminator) does: a Cloudflare Workers runtime
is HTTP-only and cannot terminate a persistent MQTT session. `pigeonhole` runs on an ordinary
VPS in front of that backend and does the part the edge cannot, and only that part: it is a
thin bridge, not a broker in the usual sense. It terminates MQTT and translates; every decision
with meaning (whether a token authorizes a pigeon, what the shadow is, whether a report is
accepted) stays in the backend, reached over the same device routes an HTTPS device uses. It
holds no persistent state, so it restarts with no data loss beyond the in-flight QoS 1 messages
a device redelivers on its own.

What it handles:

- **MQTT 3.1.1 over TLS on 8883**, MQTT 5 behind the same sessions once the device samples
  exist. No plaintext listener. QoS 0 and 1; QoS 2 accepted on 3.1.1 with at-least-once
  upstream delivery, refused with a reason code on 5.
- **Two handshakes on one listener.** Certificate TLS (Let's Encrypt) with CONNECT
  username = pigeon id and password = the pigeon's device bearer token, the shape every
  off-the-shelf client expects; and TLS-PSK with the pigeon's minted PSK, for constrained
  clients with no CA store and no clock. The ClientHello decides.
- **One session class: a pigeon.** The handshake binds the connection to exactly one pigeon, so
  topics are session-scoped and carry no id: a device publishes to `pigeon/telemetry`,
  `pigeon/shadow/report`, `pigeon/logs` and subscribes to `pigeon/shadow/target` (the shape
  ThingsBoard uses with `v1/devices/me/...`, and the reason is the same: keep the id off the
  wire). No fan-out between clients; the durable state is the pigeon's Durable Object.
- **Retained target shadow and push.** `pigeon/shadow/target` is delivered on subscribe and
  re-published whenever the dashboard changes the pigeon's configuration, fed by the pigeon's
  own device WebSocket on the backend, which the bridge opens at CONNECT on the device's
  behalf: that upgrade is also the session's authentication, and QoS 0 telemetry rides the
  same socket. The retained value is always the Durable Object's own bytes, never bridge-held
  state.
- **Admission control** in loft's style: global and per-source connection ceilings, handshake
  and CONNECT deadlines, per-session publish rate and packet size caps, a negative cache for
  bad credentials.

`docs/design.md` is the decision record (ADRs, topic and payload table, acknowledgement
policy, phasing); `docs/open-questions.md` lists what awaits the owner's ruling.

## Wire contract with the backend

The backend today is `dovecote`, the PidgeIoT edge Worker, in a separate repository whose
`docs/api.md` is the authority. Three surfaces connect the two:

1. **The device data path.** Each publish maps 1:1 onto a `/device/pigeons/:id/*` HTTP route,
   carrying the device's bearer token in an `Authorization` header, with the payload bytes
   copied as the request body. `pigeonhole` is not a trusted proxy in the authorization sense:
   the backend verifies the token cryptographically on every request, exactly as for a device
   speaking HTTPS directly. A PUBACK is sent only once the backend has answered.
2. **The device push path.** `GET /device/pigeons/:id/ws`, the backend's device WebSocket,
   opened with the same bearer token; its `shadow_update` frames become the retained
   `shadow/target` publishes.
3. **PSK resolution.** `GET /internal/device-psk/:identity`, authenticated by a service secret
   shared with the backend and additionally gated there by source address. The response
   carries the short PSK that keys the handshake plus the pigeon's bearer token; its shape is
   mirrored in `pigeonhole-wire`, which names the paired backend definition.

Certificate sessions are authenticated by the device WebSocket upgrade itself, made with the
presented token: a 101 authenticates the session, opens its push feed, and delivers the
current shadow in one round trip, so no new backend route is needed for authentication.

## Workspace

- `pigeonhole-wire`: the contract both ends share (topic scheme, payload shapes, limits,
  size-capped packet framing).
- `pigeonhole-client`: a Rust client in two layers, a raw framed connection for test harnesses
  and a typed `PigeonClient` over it, plus a runnable example
  (`examples/subscribe-and-publish.rs`) that connects as a pigeon, subscribes to its shadow
  topic, publishes telemetry, and prints what it receives, all configured by env/CLI.
- `pigeonhole`: the bridge binary.

## Build

```sh
cargo check
cargo test
```

The bridge and the client link the system OpenSSL (the listener serves PSK ciphersuites, which
rustls does not have), so `libssl-dev` or the distribution's equivalent is needed on a build
host.

## Deploy

Two deploy shapes read the same environment-variable config (`PIGEONHOLE_LISTEN`,
`PIGEONHOLE_DOVECOTE_URL`, `PIGEONHOLE_TLS_CERT`, `PIGEONHOLE_TLS_KEY`, `PIGEONHOLE_PSK_TTL_SECS`,
`PIGEONHOLE_LOG`, and the `PIGEONHOLE_SERVICE_SECRET` shared with the backend):

- **Production**: the bare binary under a systemd unit hardened to this process shape
  (`infra/pigeonhole.service`, arriving with the infra task), the service secret and the TLS
  key delivered through `LoadCredential=`.
- **Self-hosting / development**: a small container image (`pigeonhole/Dockerfile`) and a
  `docker compose` example (`infra/docker-compose.yml`) that runs the bridge against a
  configurable `PIGEONHOLE_DOVECOTE_URL`, with the secret and TLS files bind-mounted. This is a
  documentation-grade path for developers who want to run the bridge themselves, not the
  production path.

`docs/infra/mqtt-broker.md` will be the runbook for both.

## License

AGPL-3.0. See `LICENSE`.
