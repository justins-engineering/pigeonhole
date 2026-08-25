//! The protocol matrices, run against a real broker on both versions.
//!
//! Most of what can go wrong in a broker is a sequence rather than a
//! function, so these drive whole exchanges: connect, publish, watch what
//! the edge was asked for, and check what came back. Where the two versions
//! genuinely differ, the test says which one it is asserting about instead
//! of being written twice.

mod harness;

use std::time::Duration;

use harness::{Answer, Harness, PIGEON, TOKEN, V};
use pigeonhole_wire::{limits, topics};

#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_session_is_authenticated_by_the_device_socket_upgrade() {
  let h = Harness::start().await;
  for version in V::both() {
    let mut client = h.session(version).await;
    // The upgrade carried the token the CONNECT presented, which is the
    // whole of the authentication.
    h.state
      .wait_for("the device socket to open", |s| s.upgrades() >= 1)
      .await;
    client.disconnect().await;
    assert!(client.closed().await, "{}", version.name());
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_the_platform_rejects_refuses_the_connect_on_both_versions() {
  let h = Harness::start().await;
  h.state.valid_tokens.lock().expect("lock").clear();
  for version in V::both() {
    let mut client = h.raw_session(version).await;
    client
      .send_connect(PIGEON, Some(PIGEON), Some("not-the-token"))
      .await;
    let expected = if version == V::V5 { 0x86 } else { 0x04 };
    assert_eq!(
      client.next().await,
      Answer::ConnackRefused(expected),
      "{} bad credentials",
      version.name()
    );
    assert!(client.closed().await);
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_identity_that_disagrees_with_itself_is_refused_as_an_identifier_problem() {
  let h = Harness::start().await;
  for version in V::both() {
    let mut client = h.raw_session(version).await;
    client
      .send_connect(harness::OTHER_PIGEON, Some(PIGEON), Some(TOKEN))
      .await;
    let expected = if version == V::V5 { 0x85 } else { 0x02 };
    assert_eq!(client.next().await, Answer::ConnackRefused(expected));
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_identity_is_named_by_where_it_arrived() {
  let h = Harness::start().await;
  for version in V::both() {
    // As a username, a malformed identity is a credential problem.
    let mut as_username = h.raw_session(version).await;
    as_username
      .send_connect("", Some("not-a-pigeon"), Some(TOKEN))
      .await;
    let expected = if version == V::V5 { 0x86 } else { 0x04 };
    assert_eq!(as_username.next().await, Answer::ConnackRefused(expected));

    // As a client id alone, it is an identifier problem.
    let mut as_client_id = h.raw_session(version).await;
    as_client_id
      .send_connect("not-a-pigeon", None, Some(TOKEN))
      .await;
    let expected = if version == V::V5 { 0x85 } else { 0x02 };
    assert_eq!(as_client_id.next().await, Answer::ConnackRefused(expected));
  }
  // Neither reached the edge: the shape check is local, so garbage costs no
  // upstream call.
  assert_eq!(h.state.upgrades(), 0);
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn each_publish_leaf_reaches_its_own_route_with_the_bytes_that_were_published() {
  let h = Harness::start().await;
  for version in V::both() {
    let mut client = h.session(version).await;
    let before = h.state.requests().len();

    client
      .publish(topics::TELEMETRY, br#"{"temp":"21.5"}"#, 1, Some(1))
      .await;
    assert_eq!(
      client.next().await,
      Answer::Puback { pid: 1, reason: 0 },
      "{} telemetry acked",
      version.name()
    );

    client
      .publish(
        topics::SHADOW_REPORT,
        br#"{"current_config":{},"current_version":1}"#,
        1,
        Some(2),
      )
      .await;
    assert_eq!(client.next().await, Answer::Puback { pid: 2, reason: 0 });

    client
      .publish(
        topics::LOGS,
        b"\x00\x01\x02 raw dictionary chunk",
        1,
        Some(3),
      )
      .await;
    assert_eq!(client.next().await, Answer::Puback { pid: 3, reason: 0 });

    let requests = h.state.requests();
    let seen = &requests[before..];
    assert_eq!(seen.len(), 3, "{}", version.name());
    assert_eq!(seen[0].leaf, "telemetry");
    assert_eq!(seen[0].content_type, "application/json");
    assert_eq!(seen[0].body, br#"{"temp":"21.5"}"#);
    assert_eq!(seen[0].bearer.as_deref(), Some(TOKEN));
    assert_eq!(seen[0].pigeon, PIGEON);
    assert_eq!(seen[1].leaf, "shadow");
    assert_eq!(seen[2].leaf, "logs");
    assert_eq!(
      seen[2].content_type, "application/octet-stream",
      "a log chunk is opaque bytes, not JSON"
    );
    assert_eq!(seen[2].body, b"\x00\x01\x02 raw dictionary chunk");
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_publish_topic_ends_the_session() {
  let h = Harness::start().await;
  for version in V::both() {
    let mut client = h.session(version).await;
    client.publish("pigeon/not-a-leaf", b"{}", 0, None).await;
    if version == V::V5 {
      assert_eq!(
        client.next().await,
        Answer::Disconnect(0x90),
        "v5 names the topic as the problem"
      );
    }
    assert!(client.closed().await, "{}", version.name());
  }
  // Nothing was forwarded on the way out.
  assert!(h.state.requests().is_empty());
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn every_accepted_filter_is_granted_and_everything_else_is_refused() {
  let h = Harness::start().await;
  for version in V::both() {
    let mut client = h.session(version).await;
    client
      .subscribe(
        7,
        &[
          (topics::SHADOW_TARGET, 1),
          ("pigeon/shadow/#", 1),
          ("pigeon/#", 1),
          ("pigeon/telemetry", 1),
          ("#", 1),
          ("$share/group/pigeon/shadow/target", 1),
        ],
      )
      .await;

    // 3.1.1 has one failure byte for every reason; MQTT 5 distinguishes
    // "not authorized" from "shared subscriptions not supported".
    let (refused, shared) = if version == V::V5 {
      (0x87, 0x9E)
    } else {
      (0x80, 0x80)
    };
    assert_eq!(
      client.next().await,
      Answer::Suback {
        pid: 7,
        codes: vec![1, 1, 1, refused, refused, shared],
      },
      "{}",
      version.name()
    );
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_qos2_publish_is_refused_spec_faithfully_on_each_version() {
  let h = Harness::start().await;
  for version in V::both() {
    let mut client = h.session(version).await;
    client.publish(topics::TELEMETRY, b"{}", 2, Some(9)).await;
    if version == V::V5 {
      // Maximum QoS 1 was advertised, so this is the protocol error the
      // spec makes it.
      assert_eq!(client.next().await, Answer::Disconnect(0x9B));
    }
    assert!(
      client.closed().await,
      "{} refuses rather than shimming",
      version.name()
    );
  }
  // No PUBREC was ever sent, so no QoS 2 exchange was entered.
  assert!(h.state.requests().is_empty());
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_will_above_the_advertised_maximum_qos_is_refused_on_v5_only() {
  let h = Harness::start().await;

  let mut v5 = h.raw_session(V::V5).await;
  v5.send_connect_full(
    PIGEON,
    Some(PIGEON),
    Some(TOKEN),
    60,
    Some((topics::TELEMETRY, b"{}", 2)),
  )
  .await;
  assert_eq!(v5.next().await, Answer::ConnackRefused(0x9B));

  // 3.1.1 advertises no Maximum QoS, so there is nothing for the will to
  // exceed, and delivery is one POST whatever it declared.
  let mut v3 = h.raw_session(V::V3).await;
  v3.send_connect_full(
    PIGEON,
    Some(PIGEON),
    Some(TOKEN),
    60,
    Some((topics::TELEMETRY, b"{}", 2)),
  )
  .await;
  assert_eq!(v3.next().await, Answer::ConnackAccepted);

  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_will_naming_a_topic_this_session_cannot_publish_to_is_refused() {
  let h = Harness::start().await;
  for version in V::both() {
    let mut client = h.raw_session(version).await;
    client
      .send_connect_full(
        PIGEON,
        Some(PIGEON),
        Some(TOKEN),
        60,
        Some(("pigeon/somewhere-else", b"{}", 0)),
      )
      .await;
    let expected = if version == V::V5 { 0x90 } else { 0x05 };
    assert_eq!(client.next().await, Answer::ConnackRefused(expected));
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_permanent_refusal_is_acked_so_the_client_stops_retrying_it() {
  let h = Harness::start().await;
  for (status, v5_reason) in [(400u16, 0x99u8), (404, 0x80), (413, 0x80)] {
    for version in V::both() {
      h.state
        .telemetry_status
        .store(status, std::sync::atomic::Ordering::SeqCst);
      let mut client = h.session(version).await;
      client.publish(topics::TELEMETRY, b"{}", 1, Some(1)).await;
      let expected = if version == V::V5 { v5_reason } else { 0 };
      assert_eq!(
        client.next().await,
        Answer::Puback {
          pid: 1,
          reason: expected
        },
        "{} acks a {status}",
        version.name()
      );
      // And the session lives: the client can publish something else.
      client.ping().await;
      assert_eq!(client.next().await, Answer::Pingresp);
    }
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_credential_mid_session_ends_it_on_both_versions() {
  let h = Harness::start().await;
  for version in V::both() {
    h.state
      .telemetry_status
      .store(401, std::sync::atomic::Ordering::SeqCst);
    let mut client = h.session(version).await;
    client.publish(topics::TELEMETRY, b"{}", 1, Some(1)).await;
    if version == V::V5 {
      assert_eq!(client.next().await, Answer::Disconnect(0x87));
    }
    assert!(client.closed().await, "{}", version.name());
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_html_bodied_403_reads_as_edge_security_rather_than_revocation() {
  let h = Harness::start().await;
  h.state
    .telemetry_status
    .store(403, std::sync::atomic::Ordering::SeqCst);
  *h.state.refusal_body.lock().expect("lock") =
    "<!DOCTYPE html><html><head><title>Attention Required</title></head>".to_string();

  let mut client = h.session(V::V5).await;
  client.publish(topics::TELEMETRY, b"{}", 1, Some(1)).await;
  assert_eq!(
    client.next().await,
    Answer::Disconnect(0x89),
    "server busy, not not-authorized"
  );
  assert!(client.closed().await);
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_bodied_403_still_reads_as_revocation() {
  let h = Harness::start().await;
  h.state
    .telemetry_status
    .store(403, std::sync::atomic::Ordering::SeqCst);
  let mut client = h.session(V::V5).await;
  client.publish(topics::TELEMETRY, b"{}", 1, Some(1)).await;
  assert_eq!(client.next().await, Answer::Disconnect(0x87));
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_free_tier_fuse_keeps_a_v5_session_and_closes_a_v3_one() {
  let h = Harness::start().await;
  h.state
    .telemetry_status
    .store(429, std::sync::atomic::Ordering::SeqCst);

  let mut v5 = h.session(V::V5).await;
  v5.publish(topics::TELEMETRY, b"{}", 1, Some(1)).await;
  assert_eq!(
    v5.next().await,
    Answer::Puback {
      pid: 1,
      reason: 0x97
    },
    "the client learns the reason and requeues"
  );
  v5.ping().await;
  assert_eq!(v5.next().await, Answer::Pingresp, "the session survives");

  let mut v3 = h.session(V::V3).await;
  v3.publish(topics::TELEMETRY, b"{}", 1, Some(1)).await;
  assert!(v3.closed().await, "3.1.1 has only the close to signal with");

  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retryable_upstream_failure_withholds_the_ack_and_ends_the_session() {
  let h = Harness::start().await;
  for version in V::both() {
    h.state
      .telemetry_status
      .store(503, std::sync::atomic::Ordering::SeqCst);
    let mut client = h.session(version).await;
    client.publish(topics::TELEMETRY, b"{}", 1, Some(1)).await;
    if version == V::V5 {
      assert_eq!(client.next().await, Answer::Disconnect(0x89));
    }
    assert!(client.closed().await, "{}", version.name());
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_ping_is_answered_while_a_publish_is_stalled_upstream() {
  let h = Harness::start().await;
  for version in V::both() {
    // Long enough that a reader which waited on the publish would fail this.
    h.state
      .publish_delay
      .store(2_000, std::sync::atomic::Ordering::SeqCst);
    let mut client = h.session(version).await;

    client.publish(topics::TELEMETRY, b"{}", 1, Some(1)).await;
    client.ping().await;

    assert_eq!(
      client.next_within(Duration::from_millis(800)).await,
      Answer::Pingresp,
      "{}: the reader never stops",
      version.name()
    );
    assert_eq!(
      client.next().await,
      Answer::Puback { pid: 1, reason: 0 },
      "and the publish still lands"
    );
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_inflight_budget_is_enforced_with_a_reason_code_not_by_pausing_the_socket() {
  let h = Harness::start().await;
  h.state
    .publish_delay
    .store(30_000, std::sync::atomic::Ordering::SeqCst);

  let mut client = h.session(V::V5).await;
  // One past the Receive Maximum the CONNACK advertised.
  for pid in 1..=(limits::RECEIVE_MAXIMUM + 1) {
    client.publish(topics::TELEMETRY, b"{}", 1, Some(pid)).await;
  }
  assert_eq!(
    client.next().await,
    Answer::Disconnect(0x93),
    "the client is told it went over, not silently stalled"
  );
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversize_publish_is_refused() {
  let h = Harness::start().await;
  for version in V::both() {
    let mut client = h.session(version).await;
    let payload = vec![b'x'; limits::MAX_PAYLOAD_BYTES + 1];
    client.publish(topics::LOGS, &payload, 1, Some(1)).await;
    if version == V::V5 {
      assert_eq!(client.next().await, Answer::Disconnect(0x95));
    }
    assert!(client.closed().await, "{}", version.name());
  }
  assert!(
    h.state.requests().is_empty(),
    "nothing oversize reached the edge"
  );
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_packet_over_the_framing_cap_is_refused_from_its_header() {
  let h = Harness::start().await;
  let mut client = h.session(V::V5).await;
  // A fixed header promising far more than the cap, with no body behind it:
  // if the refusal were not made from the header alone, this would hang.
  client
    .connection
    .send_bytes(&[0x30, 0xFF, 0xFF, 0x3F])
    .await
    .expect("sends a header");
  assert_eq!(client.next().await, Answer::Disconnect(0x95));
  assert!(client.closed().await);
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_publish_flood_is_braked_before_it_reaches_the_platforms_own_limit() {
  let h = Harness::start().await;
  let mut client = h.session(V::V5).await;
  for pid in 1..=(limits::PUBLISH_RATE_MAX as u16 + 1) {
    client.publish(topics::TELEMETRY, b"{}", 0, None).await;
    let _ = pid;
  }
  assert_eq!(
    client.next().await,
    Answer::Disconnect(0x96),
    "the rate cap sits under the Durable Object's own frame limit"
  );
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_connect_on_one_connection_is_a_protocol_error() {
  let h = Harness::start().await;
  let mut client = h.session(V::V5).await;
  client.send_connect(PIGEON, Some(PIGEON), Some(TOKEN)).await;
  assert_eq!(client.next().await, Answer::Disconnect(0x82));
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_keepalive_that_expires_closes_the_session() {
  let h = Harness::start().await;
  for version in V::both() {
    let mut client = h.raw_session(version).await;
    // 1.5x of one second, so the test waits about as long as the rule.
    client
      .send_connect_full(PIGEON, Some(PIGEON), Some(TOKEN), 1, None)
      .await;
    assert_eq!(client.next().await, Answer::ConnackAccepted);
    if version == V::V5 {
      assert_eq!(
        client.next().await,
        Answer::Disconnect(0x8D),
        "v5 says why it closed"
      );
    }
    assert!(client.closed().await, "{}", version.name());
  }
  h.shutdown().await;
}

/// The hole this closes: the listener's cipher list ended in `:DEFAULT`,
/// which OpenSSL treats as an initialiser rather than something to append,
/// so the broker offered PSK suites and nothing else at TLS 1.2. Every TLS
/// 1.3 client was fine, because their suites come from a different setter,
/// which is why a passing certificate handshake check hid it. The clients
/// certificate mode exists for are the ones that broke.
#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_client_with_no_tls13_can_still_connect() {
  let h = Harness::start().await;

  let connection = h
    .connect_tls12()
    .await
    .expect("a TLS 1.2 certificate client completes the handshake");
  let mut client = harness::Client {
    connection,
    version: V::V5,
  };
  client.send_connect(PIGEON, Some(PIGEON), Some(TOKEN)).await;
  assert_eq!(
    client.next().await,
    Answer::ConnackAccepted,
    "a device with no TLS 1.3 is exactly what certificate mode is for"
  );

  // A working session, not just a handshake. Every first-party device is a
  // TLS 1.2 client, so this covers the whole path a real pigeon takes rather
  // than only the byte that used to fail.
  client
    .publish(topics::TELEMETRY, br#"{"tls":"1.2"}"#, 1, Some(1))
    .await;
  assert_eq!(client.next().await, Answer::Puback { pid: 1, reason: 0 });

  client.subscribe(2, &[(topics::SHADOW_TARGET, 1)]).await;
  assert_eq!(
    client.next().await,
    Answer::Suback {
      pid: 2,
      codes: vec![1]
    }
  );
  match client.next().await {
    Answer::Publish { topic, retain, .. } => {
      assert_eq!(topic, topics::SHADOW_TARGET);
      assert!(retain, "the retained target reaches a TLS 1.2 client too");
    }
    other => panic!("expected the retained target, got {other:?}"),
  }

  h.shutdown().await;
}

/// PSK stays ahead of the certificate suites in server preference, which is
/// the rule the fix had to preserve: a device offering both should land on
/// PSK rather than on a chain it may have no room to verify.
#[tokio::test(flavor = "multi_thread")]
async fn psk_still_wins_over_the_certificate_suites_for_a_tls12_client() {
  use pigeonhole::tls::{CERT_CIPHER_LIST, PSK_CIPHER_LIST};

  let configured = format!("{PSK_CIPHER_LIST}:{CERT_CIPHER_LIST}");
  let psk_last = configured
    .split(':')
    .position(|suite| suite.starts_with("PSK-"))
    .and_then(|first| {
      configured
        .split(':')
        .enumerate()
        .filter(|(_, suite)| suite.starts_with("PSK-"))
        .map(|(i, _)| i)
        .max()
        .map(|last| (first, last))
    })
    .expect("PSK suites are configured");
  let cert_first = configured
    .split(':')
    .position(|suite| suite.starts_with("ECDHE-"))
    .expect("certificate suites are configured");
  assert!(
    psk_last.1 < cert_first,
    "every PSK suite must precede every certificate suite: {configured}"
  );
}
