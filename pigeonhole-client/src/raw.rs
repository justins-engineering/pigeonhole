//! Framed connection: open a TLS stream, then `send` and `recv` whole
//! `mqtt_proto` packets with `pigeonhole_wire::framing`'s size cap applied
//! on the receive side. No session logic, no keepalive, no acknowledgement
//! tracking: whatever the caller sends goes on the wire as given, which is
//! exactly what the broker's harness needs to prove refusals (wrong pigeon
//! id in a topic, oversize packet, QoS 2 on a v5 session, a CONNECT that
//! disagrees with its PSK identity). Lands with the client crate's
//! implementation task.
