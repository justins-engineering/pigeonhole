//! One task per connection: the MQTT session state machine over a
//! version-neutral event model (`proto::v3` and `proto::v5` translate to
//! and from it). The reader half never stops reading, so PINGREQ, PUBACK
//! and DISCONNECT flow even while upstream is slow; it decodes size-capped
//! packets, answers pings itself, and enforces the in-flight QoS 1 caps as
//! a protocol matter (`limits::RECEIVE_MAXIMUM` packets and
//! `limits::MAX_INFLIGHT_BYTES` of payload, whichever first; v5 DISCONNECT
//! 0x93, a v3.1.1 grace ceiling before close). QoS 1 publishes are bridged
//! one at a time in arrival order; QoS 0 frames bypass that queue onto the
//! WS, so ordering is guaranteed within a QoS class, not across classes. A writer half serialises acks, retained
//! shadow pushes and PINGRESP from one outbound channel; a keepalive timer
//! closes a silent peer at 1.5x keepalive. Holds the session's will,
//! bridged on ungraceful exit only when no newer session for the same
//! pigeon exists in the registry (the takeover-reconnect case must not
//! report a connected device offline), and its registry entry, which a
//! later CONNECT takes over (the MQTT counterpart of the device WS's 4009
//! rule). On SIGTERM the session drains: in-flight publishes finish and
//! ack, then v5 sessions get DISCONNECT 0x8B. Lands with the broker's
//! implementation task.
