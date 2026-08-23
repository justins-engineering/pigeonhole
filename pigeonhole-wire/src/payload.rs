//! Payload shapes, byte-identical to the HTTP bodies the bridge forwards
//! them as. Defined here rather than imported from `capsules` for the reason
//! loft's `wire.rs` gives: that crate is built for Workers and a native
//! service should not inherit its dependency set for a handful of fields.
//! Each type names its paired `capsules` definition; the PidgeIoT
//! repository's `docs/api.md` is the authority when the two disagree. The
//! shadow target is deliberately carried as an opaque JSON slice end to end
//! (the broker lifts it out of a `shadow_update` frame with
//! `serde_json::value::RawValue` and never re-serializes it), so only the
//! device-to-platform shapes get typed definitions here, and those land with
//! the implementation task.
