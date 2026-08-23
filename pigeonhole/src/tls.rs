//! The listener's OpenSSL context: a server certificate chain and key
//! (Let's Encrypt in production, `scripts/dev-cert.sh` locally) plus the
//! PSK server callback from loft's `tls_common.rs`, on one context, TLS 1.2
//! minimum. A certificate client negotiates ordinary cipher suites (TLS 1.3
//! allowed); a constrained client offering only the PSK suites gets a TLS
//! 1.2 PSK handshake whose identity and resolved bearer token are stashed
//! in the connection's ex_data for `auth` to read. Also owns the 30 s
//! handshake deadline. The PSK callback is synchronous and may miss the
//! resolver cache, which is the one `block_in_place` in the process.
//! Lands with the broker's implementation task.
