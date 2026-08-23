//! Rust MQTT client for PidgeIoT pigeons, in two layers. `raw` is a framed
//! connection that sends and receives arbitrary `mqtt_proto` packets over a
//! TLS stream: it exists so the broker's test harness can drive exact
//! packet sequences, including the malformed and unauthorized ones a polite
//! client would never produce. `client` is the typed `PigeonClient` built
//! on it: connect with a pigeon's credentials in either transport mode,
//! keepalive, QoS 1 acknowledgement tracking, typed publishes for telemetry,
//! shadow reports and log chunks, and a typed subscription to the retained
//! shadow target. `tls` builds the two OpenSSL client contexts (CA-verified
//! certificate, or PSK). It is its own client rather than a wrapper over an
//! existing crate because the raw layer is the part the harness needs and
//! no general client exposes it, and because PSK rules out the rustls-based
//! clients; `docs/design.md` ADR A and ADR E hold the reasoning.

pub mod client;
pub mod raw;
pub mod tls;
