//! One task per connection: the MQTT session state machine over a
//! version-neutral event model (`proto::v3` and `proto::v5` translate to
//! and from it). A reader half decodes size-capped packets; publishes go
//! through a bounded queue (`RECEIVE_MAXIMUM`) the bridge drains in arrival
//! order, so ordering per session is preserved and a slow upstream applies
//! backpressure instead of growing memory; a writer half serialises acks,
//! retained shadow pushes and PINGRESP from one outbound channel; a
//! keepalive timer closes a silent peer at 1.5x keepalive. Holds the
//! session's will (bridged on ungraceful exit), its shadow feed, and its
//! registry entry, which a later CONNECT for the same pigeon takes over
//! (the MQTT counterpart of the device WebSocket's 4009 rule). Lands with
//! the broker's implementation task.
