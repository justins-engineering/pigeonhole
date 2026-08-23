//! pigeonhole, PidgeIoT's MQTT broker. One TLS listener on 8883 serving both
//! certificate and PSK handshakes, per-pigeon sessions whose every topic is
//! under their own id, and a bridge that turns each publish into the
//! matching HTTP call on dovecote's device routes with the device's own
//! bearer token, so authorization stays where it already is. The only other
//! upstream leg is the pigeon's device WebSocket, opened on the device's
//! behalf while it subscribes to its shadow, to turn dashboard config
//! pushes into retained publishes. Concurrency model: one tokio task per
//! session on the multi-thread runtime (the PSK callback's cache-miss lookup
//! uses `block_in_place`, which needs it). `docs/design.md` is the decision
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
