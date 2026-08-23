//! Environment-variable configuration, with loft's one exception for the
//! secret: `PIGEONHOLE_SERVICE_SECRET` (the value of dovecote's
//! `COAP_SERVICE_SECRET`, the terminator service gate) is read from a
//! `LoadCredential=` file under `$CREDENTIALS_DIRECTORY` in preference to
//! the environment, so the production unit never carries it in
//! `/proc/self/environ`. The TLS key and chain arrive the same way. Non-
//! secret settings: `PIGEONHOLE_LISTEN` (default `0.0.0.0:8883`),
//! `PIGEONHOLE_DOVECOTE_URL`, `PIGEONHOLE_TLS_CERT`, `PIGEONHOLE_TLS_KEY`,
//! `PIGEONHOLE_PSK_TTL_SECS`, `PIGEONHOLE_LOG`. A missing secret or an
//! unreadable key refuses to start rather than serving a degraded listener.
//! The credential-resolution function and its tests are carried over from
//! loft's `config.rs`. Lands with the broker's implementation task.
