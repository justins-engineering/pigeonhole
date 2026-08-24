//! The topic scheme. Every topic is session-scoped: the pigeon is fixed by
//! the authenticated connection, so the id does not appear in the topic (the
//! shape ThingsBoard uses with `v1/devices/me/...`, and the reason is the
//! same here, a device link should not carry a 64-character id on every
//! publish when the session already names the pigeon). Topics are rooted at
//! `pigeon/`; three publish leaves map one-to-one onto dovecote's device
//! routes and one retained leaf carries the platform's target shadow down.
//! Authorization is therefore just "is this one of the known leaves": there
//! is no id in the topic to compare, because the TLS/PSK handshake already
//! bound the connection to exactly one pigeon (`docs/design.md` ADR C).

/// Root segment of every topic.
pub const ROOT: &str = "pigeon";

/// Device to platform. Payload: the flat JSON string map `POST
/// /device/pigeons/:id/telemetry` takes.
pub const TELEMETRY: &str = "pigeon/telemetry";

/// Device to platform. Payload: `capsules::PigeonShadowReportRequest` JSON.
pub const SHADOW_REPORT: &str = "pigeon/shadow/report";

/// Device to platform. Payload: one raw dictionary-log chunk.
pub const LOGS: &str = "pigeon/logs";

/// Platform to device, retained. Payload: `capsules::PigeonShadow` JSON
/// exactly as the device shadow GET returns it.
pub const SHADOW_TARGET: &str = "pigeon/shadow/target";

/// Topics a session may publish to.
pub const PUBLISH_TOPICS: &[&str] = &[TELEMETRY, SHADOW_REPORT, LOGS];

/// Subscription filters accepted; every one resolves to `SHADOW_TARGET`.
pub const SUBSCRIBE_FILTERS: &[&str] = &[SHADOW_TARGET, "pigeon/shadow/#", "pigeon/#"];

/// A leaf a session may publish to, and everything the bridge needs to turn
/// one into a call on a device route. The route leaf and content type live
/// here rather than in the bridge, so a topic cannot be added on one side
/// without the other noticing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublishTopic {
  Telemetry,
  ShadowReport,
  Logs,
}

impl PublishTopic {
  /// Exact match only. Wildcards are not legal in a PUBLISH topic name, and
  /// a near miss is a client bug worth refusing rather than guessing at.
  pub fn parse(topic: &str) -> Option<PublishTopic> {
    match topic {
      TELEMETRY => Some(PublishTopic::Telemetry),
      SHADOW_REPORT => Some(PublishTopic::ShadowReport),
      LOGS => Some(PublishTopic::Logs),
      _ => None,
    }
  }

  pub fn as_str(self) -> &'static str {
    match self {
      PublishTopic::Telemetry => TELEMETRY,
      PublishTopic::ShadowReport => SHADOW_REPORT,
      PublishTopic::Logs => LOGS,
    }
  }

  /// The `/device/pigeons/:id/<leaf>` segment this topic bridges onto.
  pub fn route_leaf(self) -> &'static str {
    match self {
      PublishTopic::Telemetry => "telemetry",
      PublishTopic::ShadowReport => "shadow",
      PublishTopic::Logs => "logs",
    }
  }

  /// What the device route expects. Log chunks are opaque bytes; the other
  /// two are the JSON bodies their routes document.
  pub fn content_type(self) -> &'static str {
    match self {
      PublishTopic::Telemetry | PublishTopic::ShadowReport => "application/json",
      PublishTopic::Logs => "application/octet-stream",
    }
  }
}

/// What a SUBSCRIBE filter resolves to. The three accepted spellings all
/// mean the shadow target; the two refusals stay apart because MQTT 5
/// answers them with different reason codes, and a shared subscription is a
/// fan-out request this broker has no second subscriber to satisfy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscribeOutcome {
  ShadowTarget,
  SharedNotSupported,
  NotAuthorized,
}

/// Classifies one requested filter. The shared prefix is checked first: a
/// shared filter wrapping an accepted one is still a fan-out request.
pub fn classify_filter(filter: &str) -> SubscribeOutcome {
  if filter.starts_with("$share/") {
    return SubscribeOutcome::SharedNotSupported;
  }
  if SUBSCRIBE_FILTERS.contains(&filter) {
    return SubscribeOutcome::ShadowTarget;
  }
  SubscribeOutcome::NotAuthorized
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn every_publish_topic_round_trips_through_its_name() {
    for name in PUBLISH_TOPICS {
      let parsed = PublishTopic::parse(name).expect("listed topic parses");
      assert_eq!(parsed.as_str(), *name);
    }
  }

  #[test]
  fn publish_topics_are_rooted_and_distinct_from_the_retained_leaf() {
    for name in PUBLISH_TOPICS {
      assert!(name.starts_with(ROOT), "{name} is rooted at {ROOT}");
      assert_ne!(*name, SHADOW_TARGET, "a device may not publish the target");
    }
    assert!(PublishTopic::parse(SHADOW_TARGET).is_none());
  }

  #[test]
  fn route_leaves_and_content_types_match_the_device_routes() {
    assert_eq!(PublishTopic::Telemetry.route_leaf(), "telemetry");
    assert_eq!(PublishTopic::ShadowReport.route_leaf(), "shadow");
    assert_eq!(PublishTopic::Logs.route_leaf(), "logs");
    assert_eq!(
      PublishTopic::Logs.content_type(),
      "application/octet-stream"
    );
    assert_eq!(PublishTopic::Telemetry.content_type(), "application/json");
  }

  #[test]
  fn every_listed_filter_resolves_to_the_shadow_target() {
    for filter in SUBSCRIBE_FILTERS {
      assert_eq!(classify_filter(filter), SubscribeOutcome::ShadowTarget);
    }
  }

  #[test]
  fn shared_filters_are_refused_as_unsupported_not_as_unauthorized() {
    assert_eq!(
      classify_filter("$share/group/pigeon/shadow/target"),
      SubscribeOutcome::SharedNotSupported
    );
    assert_eq!(
      classify_filter("$share/group/anything"),
      SubscribeOutcome::SharedNotSupported
    );
  }

  #[test]
  fn near_misses_are_refused() {
    for filter in [
      "pigeon/shadow",
      "pigeon/shadow/target/",
      "/pigeon/shadow/target",
      "#",
      "+/+",
      "pigeon/+",
      "pigeon/telemetry",
      "",
    ] {
      assert_eq!(
        classify_filter(filter),
        SubscribeOutcome::NotAuthorized,
        "{filter} must not be granted"
      );
    }
  }

  proptest::proptest! {
    /// Only the listed leaves are publishable, whatever a client sends.
    #[test]
    fn arbitrary_strings_parse_only_when_they_are_a_listed_leaf(topic in ".{0,64}") {
      let parsed = PublishTopic::parse(&topic);
      proptest::prop_assert_eq!(parsed.is_some(), PUBLISH_TOPICS.contains(&topic.as_str()));
      if let Some(parsed) = parsed {
        proptest::prop_assert_eq!(parsed.as_str(), topic.as_str());
      }
    }

    /// Same rule for subscriptions, plus the shared-filter carve-out.
    #[test]
    fn arbitrary_filters_are_granted_only_when_listed(filter in ".{0,64}") {
      let outcome = classify_filter(&filter);
      let expected = if filter.starts_with("$share/") {
        SubscribeOutcome::SharedNotSupported
      } else if SUBSCRIBE_FILTERS.contains(&filter.as_str()) {
        SubscribeOutcome::ShadowTarget
      } else {
        SubscribeOutcome::NotAuthorized
      };
      proptest::prop_assert_eq!(outcome, expected);
    }
  }
}
