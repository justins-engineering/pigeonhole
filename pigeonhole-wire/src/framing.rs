//! Size-capped reading and writing of MQTT packets over tokio IO, shared by
//! the broker's session reader and the client's raw connection. The reader
//! decodes the fixed header first and refuses the packet once the remaining
//! length exceeds `limits::MAX_PACKET_BYTES`, before any body bytes are read,
//! so a hostile or broken peer cannot make either end allocate for a packet
//! it will reject. The codec itself is `mqtt_proto` (v3 and v5 packet
//! types); this module only adds the cap and the per-packet read/write
//! calls. Lands with the wire crate's implementation task.
