//! Publish translation and the acknowledgement policy that makes a PUBACK
//! mean something: telemetry acks mean "authenticated and durably queued"
//! (the 202), shadow reports and logs mean "the DO write completed". QoS 0
//! telemetry is routed as a `telemetry` frame on the session's device WS
//! when the feed is up, falling back to the POST when it is down or
//! fuse-paused (close 4029); QoS 1 publishes go over the POST with the session's
//! bearer token and the right `Content-Type`, payload bytes copied, never
//! parsed. The outcome table (design section 5) maps each upstream status
//! to ack, ack-and-log, keep-session-with-reason (v5 429), or
//! close-so-the-client-retries, and classifies an HTML-bodied 403 as edge
//! security rather than auth. Also bridges a session's will on ungraceful
//! exit, a deferred publish from that session, unless a newer session for
//! the pigeon exists. Lands with the broker's implementation task.
