//! MQTT 3.1.1 adapter, beside the primary v5 one for the clients that
//! speak 3.1.1 today (Zephyr's in-tree client among them). Handles the
//! protocol's own limits: no negative acknowledgement exists, so the
//! bridge's "retry later" outcomes become a closed connection and the
//! client's own reconnect-and-retransmit is the retry; and with no Maximum
//! QoS advertisement, a QoS 2 PUBLISH is refused by closing the connection
//! (the bridge never sends PUBREC, so it never enters an exchange it
//! cannot honor exactly-once). Lands with the broker's implementation
//! task.
