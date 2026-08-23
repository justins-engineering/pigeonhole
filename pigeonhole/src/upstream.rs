//! The two upstream legs to dovecote: a `reqwest` client for the device
//! routes (distinctive `pigeonhole/<version>` user agent, 30 s request and
//! 10 s connect timeouts, HTTP/2 pooling) and the WebSocket dial for the
//! shadow feed (`tokio-tungstenite`, `Authorization: Bearer` on the upgrade,
//! which is what the device endpoint requires). Both carry the device's
//! own bearer token and nothing else: the broker never holds a dashboard,
//! org, or flock credential. Lands with the broker's implementation task.
