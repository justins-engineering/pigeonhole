//! Turns what the transport established and what the CONNECT packet claims
//! into one authenticated pigeon, or a CONNACK refusal. Certificate
//! sessions present username = pigeon id and password = device bearer
//! token; PSK sessions arrive with identity and token already resolved by
//! the handshake. Either way the token is then proven by issuing `GET
//! /device/pigeons/:id/shadow` with it: dovecote's Durable Object is the
//! only thing that can verify the Ed25519 signature, a 200 both
//! authenticates and seeds the retained shadow, and a 401 refuses the
//! session (and, for PSK, evicts the cached entry that let the handshake
//! through). The identity may appear in up to three places (PSK identity,
//! username, client id) and every present one must agree. Lands with the
//! broker's implementation task.
