//! Size and rate limits both ends enforce. The payload cap mirrors the
//! platform's two existing device-facing caps (`capsules::MAX_LOG_CHUNK_BYTES`
//! and the device WebSocket frame cap, both 16 KiB) so a log chunk that fits
//! the HTTP route fits an MQTT publish and nothing larger ever does; the
//! packet cap on top of it is headroom for the topic name, packet id, and
//! (v5) properties. The broker refuses a packet from its fixed header alone
//! once the remaining length exceeds the packet cap, before reading a byte
//! of body, so the cap bounds per-connection memory as well as payloads.

/// Largest application payload in one PUBLISH, in bytes.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024;

/// Largest MQTT packet (remaining length) accepted from a client, in bytes.
pub const MAX_PACKET_BYTES: usize = 20 * 1024;

/// Longest topic name or filter accepted, in bytes.
pub const MAX_TOPIC_BYTES: usize = 256;

/// Longest client id and username accepted, in bytes. A pigeon id is 64 hex
/// characters.
pub const MAX_CLIENT_ID_BYTES: usize = 128;

/// Longest password accepted, in bytes. A device bearer token is 92
/// characters of base64url.
pub const MAX_PASSWORD_BYTES: usize = 256;

/// Inbound PUBLISH rate ceiling per session: this many packets in any
/// rolling window of `PUBLISH_RATE_WINDOW_SECS`. Deliberately below the
/// backend Durable Object's own WebSocket frame limit (50 per 10 s), so
/// the QoS 0 telemetry fast path over that socket can never trip the DO's
/// rate close.
pub const PUBLISH_RATE_MAX: u32 = 40;
pub const PUBLISH_RATE_WINDOW_SECS: u64 = 10;

/// Unacknowledged inbound QoS 1 publishes the bridge holds per session,
/// advertised as Receive Maximum on MQTT 5 and enforced as a protocol
/// matter (never by pausing the socket, which would starve keepalive):
/// over it a v5 session gets DISCONNECT 0x93, and a v3.1.1 session is
/// closed only past `RECEIVE_MAXIMUM_V3_GRACE`.
pub const RECEIVE_MAXIMUM: u16 = 16;
pub const RECEIVE_MAXIMUM_V3_GRACE: u16 = 64;

/// Longest keepalive honored, in seconds; larger client values are clamped
/// here, and a client keepalive of 0 gets this as its idle deadline.
pub const MAX_KEEPALIVE_SECS: u16 = 30 * 60;

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn packet_cap_leaves_header_room_above_the_payload_cap() {
    assert!(MAX_PACKET_BYTES > MAX_PAYLOAD_BYTES + MAX_TOPIC_BYTES);
  }
}
