//! PSK identity to (secret, bearer token) resolution against dovecote's
//! service-internal route (`GET /internal/coap-psk/:pigeon_id` today; a
//! neutral `/internal/device-psk` alias lands with the backend phase),
//! gated by
//! `PIGEONHOLE_SERVICE_SECRET` and, on dovecote's side, by the VPS egress
//! address. A copy of loft's resolver: blocking `ureq` client, 60 s positive
//! and 10 s negative caches, stale-positive grace while dovecote is
//! unreachable, and the same staleness consequences after a token refresh
//! (an old PSK can still complete a handshake inside the TTL, but the
//! session's device WS upgrade then 401s, the entry is evicted, and the
//! CONNECT is refused). Lands with the broker's implementation task.
