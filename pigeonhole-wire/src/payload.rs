//! Payload shapes, byte-identical to the HTTP bodies the bridge forwards
//! them as. Defined here rather than imported from `capsules` for the reason
//! loft's `wire.rs` gives: that crate is built for Workers and a native
//! service should not inherit its dependency set for a handful of fields.
//! Each type names its paired `capsules` definition; the PidgeIoT
//! repository's `docs/api.md` is the authority when the two disagree.
//!
//! The shadow target is carried as an opaque JSON slice end to end: the
//! broker lifts it out of a `shadow_update` frame and publishes those exact
//! bytes, so the only thing it decodes is the version that decides whether a
//! push is a change ([`TargetVersion`]). The typed [`PigeonShadow`] exists
//! for clients that do want the fields.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One telemetry report: the flat string map `POST
/// /device/pigeons/:id/telemetry` takes. Ordered rather than hashed so a
/// serialized report is reproducible, which keeps test expectations stable.
pub type Metrics = BTreeMap<String, String>;

/// Body of `pigeon/shadow/report`, paired with
/// `capsules::PigeonShadowReportRequest`. `current_config` stays a
/// `serde_json::Value` because the device decides its own config shape and
/// the platform stores it verbatim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowReport {
  pub current_config: serde_json::Value,
  pub current_version: i32,
}

/// The retained `pigeon/shadow/target` payload, paired with
/// `capsules::PigeonShadow`.
///
/// `target_config` and `current_config` are JSON strings *containing* JSON
/// text (`capsules::JsonString`), not nested objects: the same asymmetry the
/// HTTP shadow routes have on the way out. `updated_at` is unix seconds
/// rather than RFC 3339 for the same reason it is on the platform side, that
/// Zephyr firmware parses it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PigeonShadow {
  pub target_version: i32,
  pub current_version: i32,
  pub target_config: String,
  pub current_config: String,
  pub updated_at: i64,
}

/// The one field the bridge reads out of a shadow. It is deliberately its
/// own type with everything else ignored: a shadow that gains a field must
/// not stop the feed from working out whether the target changed, and
/// nothing here should tempt the bridge into re-serializing what it was
/// handed.
///
/// `target_version` alone is the change key. `updated_at` bumps on every
/// shadow write, device report-backs included, so keying on it would re-push
/// the target every time the device reported its own state back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct TargetVersion {
  pub target_version: i32,
}

impl TargetVersion {
  /// Reads the change key out of raw shadow bytes. `None` means the bytes
  /// are not a shadow the bridge understands, which the caller treats as
  /// "cannot tell whether this changed" rather than as a version.
  pub fn read(shadow_json: &[u8]) -> Option<i32> {
    serde_json::from_slice::<TargetVersion>(shadow_json)
      .ok()
      .map(|v| v.target_version)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  /// The exact bytes `docs/api.md` shows a `shadow_update` frame carrying.
  const SHADOW_JSON: &str = r#"{"target_version":2,"current_version":1,"target_config":"{\"telemetry_interval\":30}","current_config":"{\"telemetry_interval\":60}","updated_at":1784390937}"#;

  #[test]
  fn the_documented_shadow_shape_decodes_with_its_json_string_fields_intact() {
    let shadow: PigeonShadow = serde_json::from_str(SHADOW_JSON).expect("documented shape");
    assert_eq!(shadow.target_version, 2);
    assert_eq!(shadow.current_version, 1);
    assert_eq!(shadow.updated_at, 1784390937);
    assert_eq!(shadow.target_config, r#"{"telemetry_interval":30}"#);
    let inner: serde_json::Value =
      serde_json::from_str(&shadow.target_config).expect("inner json text");
    assert_eq!(inner["telemetry_interval"], 30);
  }

  #[test]
  fn the_change_key_reads_from_a_shadow_carrying_unknown_fields() {
    let with_extra = r#"{"target_version":7,"current_version":1,"target_config":"{}","current_config":"{}","updated_at":1,"something_new":true}"#;
    assert_eq!(TargetVersion::read(with_extra.as_bytes()), Some(7));
  }

  #[test]
  fn the_change_key_is_none_for_bytes_that_are_not_a_shadow() {
    assert_eq!(TargetVersion::read(b"not json"), None);
    assert_eq!(TargetVersion::read(b"{}"), None);
    assert_eq!(TargetVersion::read(b"[]"), None);
  }

  #[test]
  fn a_shadow_report_serializes_as_the_device_route_documents_it() {
    let report = ShadowReport {
      current_config: serde_json::json!({ "telemetry_interval": 60 }),
      current_version: 1,
    };
    let encoded = serde_json::to_string(&report).expect("encodes");
    assert_eq!(
      encoded,
      r#"{"current_config":{"telemetry_interval":60},"current_version":1}"#
    );
  }

  #[test]
  fn metrics_serialize_as_a_flat_string_map() {
    let mut metrics = Metrics::new();
    metrics.insert("temp".to_string(), "21.5".to_string());
    metrics.insert("status".to_string(), "ok".to_string());
    let encoded = serde_json::to_string(&metrics).expect("encodes");
    assert_eq!(encoded, r#"{"status":"ok","temp":"21.5"}"#);
  }
}
