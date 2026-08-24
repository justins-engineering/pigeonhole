//! Rust MQTT client for PidgeIoT pigeons, in two layers. `raw` is a framed
//! connection that sends and receives arbitrary `mqtt_proto` packets over a
//! TLS stream: it exists so the broker's test harness can drive exact packet
//! sequences, including the malformed and unauthorized ones a polite client
//! would never produce. `client` is the typed `PigeonClient` built on it:
//! connect with a pigeon's credentials in either transport mode, keepalive,
//! QoS 1 acknowledgement tracking, typed publishes for telemetry, shadow
//! reports and log chunks, and a typed subscription to the retained shadow
//! target. `tls` builds the two OpenSSL client contexts (CA-verified
//! certificate, or PSK). It is its own client rather than a wrapper over an
//! existing crate because the raw layer is the part the harness needs and no
//! general client exposes it, and because PSK rules out the rustls-based
//! clients; `docs/design.md` ADR A and ADR E hold the reasoning. A runnable
//! `examples/subscribe-and-publish.rs` doubles as the documentation-grade
//! client demo.

pub mod client;
pub mod raw;
pub mod tls;

/// Everything either layer can fail with. The variants stay separate where a
/// caller would act differently: a refusal carries the broker's own reason,
/// while a transport failure says nothing about the credentials.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
  #[error("endpoint: {0}")]
  Endpoint(String),
  #[error("tls: {0}")]
  Tls(String),
  #[error("io: {0}")]
  Io(#[from] std::io::Error),
  #[error("framing: {0}")]
  Framing(#[from] pigeonhole_wire::framing::FramingError),
  #[error("codec: {0}")]
  Codec(String),
  /// The broker answered, but not with what the protocol calls for here.
  #[error("protocol: {0}")]
  Protocol(String),
  /// The broker refused the session or the publish, and said why.
  #[error("refused: {0}")]
  Refused(String),
  #[error("timed out waiting for {0}")]
  Timeout(&'static str),
  /// The session ended underneath an operation.
  #[error("session closed")]
  Closed,
}
