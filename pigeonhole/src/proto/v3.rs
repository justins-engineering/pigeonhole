//! MQTT 3.1.1 adapter. Handles the protocol's own limits: no negative
//! acknowledgement exists, so the bridge's "retry later" outcomes become a
//! closed connection and the client's own reconnect-and-retransmit is the
//! retry; a QoS 2 PUBLISH is accepted with the full PUBREC/PUBREL/PUBCOMP
//! exchange over at-least-once upstream semantics, because 3.1.1 has no way
//! to refuse the QoS without refusing the client. Lands with the broker's
//! implementation task.
