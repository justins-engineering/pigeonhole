//! The retained shadow feed for one session. Seeded by the CONNECT-time
//! shadow GET; once the session subscribes, the broker opens the pigeon's
//! device WebSocket with the session's bearer token and treats the snapshot
//! frame and every `shadow_update` frame as a new retained value, lifting
//! the `shadow` member out as a raw JSON slice so the bytes the device sees
//! are the bytes dovecote sent. A retained PUBLISH goes out only when
//! `(target_version, updated_at)` changed since the last delivery.
//! Reconnects with 1 s to 60 s jittered backoff while the subscription
//! lives; a 4009 close ("replaced by new connection") means another client
//! holds this pigeon's socket, so the feed parks at the backoff ceiling and
//! logs a warning instead of fighting. Closed with the session. Lands with
//! the broker's implementation task.
