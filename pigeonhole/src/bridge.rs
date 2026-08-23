//! Publish to HTTP translation, and the acknowledgement policy that makes a
//! PUBACK mean something: one is sent only when dovecote answered. The
//! three publish leaves map onto `POST /device/pigeons/:id/{telemetry,
//! shadow,logs}` with the session's bearer token and the right
//! `Content-Type`; payload bytes are copied, never parsed (dovecote
//! validates and answers 400, the same as for a direct HTTPS device). The
//! outcome table (`docs/design.md` section 5) turns each upstream status
//! into ack, ack-and-log, or close-so-the-client-retries, with the v5
//! reason codes alongside. Also bridges a session's will on ungraceful
//! exit, since a will is just a deferred publish from that session. Lands
//! with the broker's implementation task.
