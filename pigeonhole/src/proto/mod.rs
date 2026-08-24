//! Protocol-version adapters. The session layer never sees an
//! `mqtt_proto::v3` or `v5` packet directly; each adapter decodes its
//! version's packets into the shared session events and encodes the
//! session's replies back, including the version's own way of saying no
//! (a v3.1.1 session can only be closed; a v5 session gets a reason code).
//! Both ship with the broker task; v5 is the primary target per the owner's
//! ruling, with `v3` beside it for the Zephyr-class clients that speak
//! 3.1.1 today.

pub mod v3;
pub mod v5;
