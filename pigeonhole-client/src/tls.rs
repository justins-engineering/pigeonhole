//! Client-side OpenSSL contexts for the two transport modes the broker
//! serves on one port: certificate mode (server chain verified against a
//! CA the caller supplies, or the system store; hostname verification on)
//! and PSK mode (identity = pigeon id, key = the UTF-8 bytes of
//! `tls_psk_secret`, TLS 1.2, the same PSK ciphersuites the broker offers).
//! Mirrors what the Zephyr device library configures through its sec tag so
//! a behaviour proven here with the Rust client holds for the firmware.
//! Lands with the client crate's implementation task.
