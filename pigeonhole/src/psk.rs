//! PSK identity to (secret, bearer token) resolution against dovecote's
//! service-internal route (`GET /internal/device-psk/:pigeon_id`, the
//! neutral alias of the CoAP terminator's route), gated by
//! `PIGEONHOLE_SERVICE_SECRET` and, on dovecote's side, by the VPS egress
//! address. A copy of loft's resolver: blocking `ureq` client, 60 s positive
//! and 10 s negative caches, stale-positive grace while dovecote is
//! unreachable, and the same staleness consequences after a token refresh
//! (an old PSK can still complete a handshake inside the TTL, but every
//! upstream call it makes 401s; the broker additionally evicts the entry
//! when the CONNECT-time shadow GET 401s). Lands with the broker's
//! implementation task.
