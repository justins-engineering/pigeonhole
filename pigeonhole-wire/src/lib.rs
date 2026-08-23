//! The contract between a PidgeIoT MQTT client and the `pigeonhole` broker,
//! kept in one crate so neither side can drift: the per-pigeon topic scheme
//! and its authorization rule, the payload shapes (defined locally and
//! named after their paired `capsules` types, the same arrangement loft's
//! `wire.rs` uses, because `capsules` compiles for Workers and a native
//! service should not inherit that), the size limits both ends enforce, and
//! the size-capped packet framing over tokio IO. Nothing here does IO of its
//! own beyond framing, and nothing here knows about dovecote's routes; the
//! broker's bridge owns that mapping. `docs/design.md` ADR C and ADR B are
//! the decision records for what lives here.

pub mod framing;
pub mod limits;
pub mod payload;
pub mod topics;
