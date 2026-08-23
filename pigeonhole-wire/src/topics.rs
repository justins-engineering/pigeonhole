//! The topic scheme. Every topic is session-scoped: the pigeon is fixed by
//! the authenticated connection, so the id does not appear in the topic (the
//! shape ThingsBoard uses with `v1/devices/me/...`, and the reason is the
//! same here, a device link should not carry a 64-character id on every
//! publish when the session already names the pigeon). Topics are rooted at
//! `pigeon/`; three publish leaves map one-to-one onto dovecote's device
//! routes and one retained leaf carries the platform's target shadow down.
//! Authorization is therefore just "is this one of the known leaves": there
//! is no id in the topic to compare, because the TLS/PSK handshake already
//! bound the connection to exactly one pigeon (`docs/design.md` ADR C).
//! Parsing and formatting, with property tests, land with the wire crate's
//! implementation task; this module pins the names.

/// Root segment of every topic.
pub const ROOT: &str = "pigeon";

/// Device to platform. Payload: the flat JSON string map `POST
/// /device/pigeons/:id/telemetry` takes.
pub const TELEMETRY: &str = "pigeon/telemetry";

/// Device to platform. Payload: `capsules::PigeonShadowReportRequest` JSON.
pub const SHADOW_REPORT: &str = "pigeon/shadow/report";

/// Device to platform. Payload: one raw dictionary-log chunk.
pub const LOGS: &str = "pigeon/logs";

/// Platform to device, retained. Payload: `capsules::PigeonShadow` JSON
/// exactly as the device shadow GET returns it.
pub const SHADOW_TARGET: &str = "pigeon/shadow/target";

/// Topics a session may publish to.
pub const PUBLISH_TOPICS: &[&str] = &[TELEMETRY, SHADOW_REPORT, LOGS];

/// Subscription filters accepted; every one resolves to `SHADOW_TARGET`.
pub const SUBSCRIBE_FILTERS: &[&str] = &[SHADOW_TARGET, "pigeon/shadow/#", "pigeon/#"];
