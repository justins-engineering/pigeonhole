//! Protocol-version adapters. The session layer never sees an
//! `mqtt_proto::v3` or `v5` packet directly; each adapter decodes its
//! version's packets into the shared session events and encodes the
//! session's replies back, including the version's own way of saying no
//! (a v3.1.1 session can only be closed; a v5 session gets a reason code).
//! `v3` ships first; `v5` lands in the MQTT 5 task with CONNACK properties
//! (Maximum QoS 1, Receive Maximum, Maximum Packet Size, Server Keep Alive,
//! Session Expiry Interval 0) and the PUBACK/DISCONNECT reason codes from
//! the bridge's ack table.

pub mod v3;
pub mod v5;
