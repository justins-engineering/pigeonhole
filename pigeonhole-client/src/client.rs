//! The typed client. `PigeonClient::connect` takes a pigeon's id, the
//! broker endpoint (`mqtts://host:8883`) and either a bearer token
//! (certificate mode: username = id, password = token) or a PSK pair, runs
//! CONNECT/CONNACK, keeps the session alive, and tracks QoS 1 publishes to
//! their PUBACK. Typed operations mirror the device routes one-to-one:
//! `report_telemetry`, `report_shadow`, `upload_log_chunk`, and
//! `subscribe_shadow_target`, which yields each retained or pushed shadow
//! as the raw JSON the platform sent. Backoff and reconnection are the
//! caller's policy; this layer reports a dropped session rather than hiding
//! it. Lands with the client crate's implementation task.
