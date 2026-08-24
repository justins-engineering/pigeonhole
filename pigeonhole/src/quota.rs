//! Connection admission: a global ceiling, a per-source fair share (IPv4
//! per address, IPv6 per /64), and an RAII permit released on every
//! teardown path; a copy of loft's `quota.rs` with its tests. On top of
//! it, the MQTT-specific brakes the session layer consults: CONNECT
//! attempts per source and globally per rolling 10 s, the 10 s negative
//! authentication cache keyed by (identity, sha256(password)), and a
//! per-identity failure budget (repeated refusals for one pigeon id park
//! that id locally for the rest of the window, whatever the password), so
//! neither a distinct-password flood nor a distributed one becomes a
//! dovecote request flood or a wake storm on one Durable Object. All of it
//! is bounded and expiring, accelerators rather than state. Lands with the
//! broker's implementation task.
