//! The listener's OpenSSL context: a server certificate chain and key
//! (Let's Encrypt ECDSA in production, `scripts/dev-cert.sh` locally) plus
//! the PSK server callback from loft's `tls_common.rs`, on one context,
//! TLS 1.2 minimum. PSK suites are listed first with server preference
//! set, so a device offering both PSK and ECDHE lands on PSK rather than a
//! chain it cannot verify; `SSL_CTX_set_max_send_fragment(4096)` keeps
//! records readable for small-buffer mbedTLS builds; and
//! `SSL_MODE_RELEASE_BUFFERS` returns idle buffers. A PSK handshake
//! stashes (identity, token) in the connection's ex_data for `auth`. Owns
//! the 30 s handshake deadline. The PSK callback is synchronous and may
//! miss the resolver cache, the one `block_in_place` in the process. To
//! verify at implementation with `openssl s_client`: cert mode, `-psk`
//! mode, and `-tls1_3 -psk` (OpenSSL consults the 1.2 PSK callback for a
//! TLS 1.3 external PSK too). Lands with the broker's implementation task.
