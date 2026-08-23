//! Connection admission: a global ceiling, a per-source fair share (IPv4
//! per address, IPv6 per /64), and an RAII permit released on every
//! teardown path. A copy of loft's `quota.rs` with its tests, plus the two
//! MQTT-specific ceilings the session layer consults: CONNECT attempts per
//! source per rolling 10 s, and the 10 s negative authentication cache
//! keyed by (identity, sha256(password)) that keeps a bad-credential flood
//! from becoming a dovecote request flood. Lands with the broker's
//! implementation task.
