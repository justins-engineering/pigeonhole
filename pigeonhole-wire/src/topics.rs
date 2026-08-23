//! The per-pigeon topic scheme. Every topic is rooted at
//! `pigeons/<pigeon_id>/`, and a session may only publish to or subscribe
//! under its own id: the broker applies the same rule loft applies to a
//! CoAP Uri-Path (the id in the path must equal the handshake identity),
//! and closes the connection on anything else. Three publish leaves map
//! one-to-one onto dovecote's device routes (`telemetry`, `shadow/report`,
//! `logs`) and one retained leaf carries the platform's target shadow to
//! the device (`shadow/target`); the accepted subscription filters all mean
//! that one leaf. Parsing and formatting, with property tests, land with
//! the wire crate's implementation task; this module currently pins the
//! names.

/// Root segment of every topic.
pub const ROOT: &str = "pigeons";

/// Device to platform. Payload: the flat JSON string map `POST
/// /device/pigeons/:id/telemetry` takes.
pub const LEAF_TELEMETRY: &str = "telemetry";

/// Device to platform. Payload: `capsules::PigeonShadowReportRequest` JSON.
pub const LEAF_SHADOW_REPORT: &str = "shadow/report";

/// Device to platform. Payload: one raw dictionary-log chunk.
pub const LEAF_LOGS: &str = "logs";

/// Platform to device, retained. Payload: `capsules::PigeonShadow` JSON
/// exactly as the device shadow GET returns it.
pub const LEAF_SHADOW_TARGET: &str = "shadow/target";

/// Topics a session may publish to, relative to its own `pigeons/<id>/`.
pub const PUBLISH_LEAVES: &[&str] = &[LEAF_TELEMETRY, LEAF_SHADOW_REPORT, LEAF_LOGS];

/// Subscription filters accepted, relative to the session's own
/// `pigeons/<id>/`; every one of them resolves to `LEAF_SHADOW_TARGET`.
pub const SUBSCRIBE_FILTERS: &[&str] = &[LEAF_SHADOW_TARGET, "shadow/#", "#"];
