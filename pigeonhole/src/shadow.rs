//! The device WebSocket, the session's spine: dialled at CONNECT (the
//! upgrade is the session's authentication, ADR D), its snapshot-on-accept
//! frame seeds the retained `pigeon/shadow/target` value, its
//! `shadow_update` frames refresh it (the `shadow` member lifted as a raw
//! JSON slice, never re-serialized), and QoS 0 telemetry rides it as
//! `telemetry` frames. A retained PUBLISH is delivered only when
//! `target_version` changed since the last delivery (`updated_at` bumps on
//! device report-backs too, so it is not the change key). Liveness is the
//! bridge's job, the DO never pings: a protocol-level WS ping per 60 s of
//! feed silence, two missed pongs reconnects; flowing telemetry frames
//! substitute. Reconnect backs off 1 s to 60 s with jitter; close code
//! 4009 (socket held by someone else) is terminal for this session's feed;
//! 4004 (token revoked) and 4005 (pigeon deleted), which dovecote sends on
//! refresh and delete, end the MQTT session itself with no redial; 4029
//! (billable frame while fuse-paused) parks the feed at a fuse-scale
//! backoff, since the upgrade would answer 429 until the account resumes. An
//! inbound `shell_cmd` frame is answered immediately with a `shell_output`
//! saying shell is not available over MQTT. Lands with the broker's
//! implementation task.
