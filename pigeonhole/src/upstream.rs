//! The two upstream legs to dovecote: a `reqwest` client for the device
//! routes (distinctive `pigeonhole/<version>` user agent, 10 s publish and
//! connect timeouts so a slow edge can never outlast a keepalive window,
//! HTTP/2 pooling) and the device WebSocket dial (`tokio-tungstenite`,
//! `Authorization: Bearer` on the upgrade) with deliberately small buffers
//! (4 KiB read and write, 64 KiB max message: the library's 128 KiB
//! defaults would cost a gigabyte at the session ceiling). Both legs carry
//! the device's own bearer token and nothing else: the bridge never holds
//! a dashboard, org, or flock credential. Lands with the broker's
//! implementation task.
