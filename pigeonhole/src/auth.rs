//! Turns what the transport established and what the CONNECT packet claims
//! into one authenticated pigeon, or a CONNACK refusal. The identity's
//! shape is checked locally first (64 lowercase hex, so garbage never
//! costs an upstream call or lands raw in a log line), and every place the
//! identity appears (PSK identity, username, client id) must agree. The
//! verification itself is the device WS upgrade with the presented bearer
//! token (PSK sessions arrive with identity and token already resolved by
//! the handshake): a 101 authenticates and opens the session's feed in the
//! same round trip, a 401 refuses (and evicts a stale PSK cache entry), a
//! plain-text 403 refuses as not-authorized, an HTML-bodied 403 counts as
//! edge security and maps to server-unavailable, and 5xx/timeouts are
//! retryable. Refusals feed the negative cache and the per-identity
//! failure budget in `quota`. Lands with the broker's implementation task.
