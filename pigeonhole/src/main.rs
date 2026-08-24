//! pigeonhole, PidgeIoT's MQTT bridge. One TLS listener on 8883 serving both
//! certificate and PSK handshakes, per-pigeon sessions whose topics are
//! session-scoped (the handshake fixes the pigeon, so the id is not in the
//! topic), and a bridge that turns each publish into the matching HTTP call
//! on dovecote's device routes with the device's own bearer token, so every
//! decision with meaning stays at the edge (ADR G, the thin-bridge rule).
//! The other upstream leg is the pigeon's device WebSocket, opened at
//! CONNECT on the device's behalf: it is the session's authentication, the
//! retained-shadow feed, and the QoS 0 telemetry fast path. Concurrency model: one tokio task
//! per session on the multi-thread runtime (the PSK callback's cache-miss
//! lookup uses `block_in_place`, which needs it). Configured entirely by
//! environment variables, the same set whether run as the hardened systemd
//! unit (`infra/pigeonhole.service`) or the container example (`Dockerfile`
//! plus `infra/docker-compose.yml`). `docs/design.md` is the decision
//! record; `docs/infra/mqtt-broker.md` will be the runbook.

mod auth;
mod bridge;
mod config;
mod proto;
mod psk;
mod quota;
mod session;
mod shadow;
mod tls;
mod upstream;

fn main() {
  // Wiring lands with the broker's implementation task: config from the
  // environment, the OpenSSL context, the listener and admission loop, and
  // the periodic stats line.
}
