//! pigeonhole, PidgeIoT's MQTT bridge. One TLS listener serving both
//! certificate and PSK handshakes, per-pigeon sessions whose topics are
//! session-scoped (the handshake fixes the pigeon, so the id is not in the
//! topic), and a bridge that turns each publish into the matching HTTP call
//! on dovecote's device routes with the device's own bearer token, so every
//! decision with meaning stays at the edge (ADR G, the thin-bridge rule).
//!
//! The other upstream leg is the pigeon's device WebSocket, opened at
//! CONNECT on the device's behalf: it is the session's authentication, the
//! retained-shadow feed, and the QoS 0 telemetry fast path.
//!
//! The broker is a library with a thin binary over it so the integration
//! harness can stand a real one up in-process, on an ephemeral port, against
//! a mock dovecote. A protocol this size is not provable from unit tests
//! alone: most of what can go wrong is a sequence, not a function.

pub mod auth;
pub mod bridge;
pub mod config;
pub mod proto;
pub mod psk;
pub mod quota;
pub mod server;
pub mod session;
pub mod shadow;
pub mod tls;
pub mod upstream;
