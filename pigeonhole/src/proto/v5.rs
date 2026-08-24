//! MQTT 5 adapter. Reason codes carry the bridge's ack table to the device
//! honestly, CONNACK properties advertise what this broker is (Maximum QoS
//! 1, no shared subscriptions, no topic aliases, Session Expiry Interval 0),
//! a QoS 2 PUBLISH is the protocol error the spec makes it once Maximum QoS
//! 1 was advertised, and session takeover and token rotation get their
//! named DISCONNECT reasons. The primary protocol target; lands with the
//! broker's implementation task.
