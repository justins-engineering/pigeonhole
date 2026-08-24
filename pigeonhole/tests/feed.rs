//! The device WebSocket feed, the close codes it acts on, and the session
//! endings that depend on it.
//!
//! The feed is the session's spine rather than a side channel: it is what
//! authenticated the session, what carries the retained shadow, and where
//! QoS 0 telemetry goes. These drive it from the platform's side, which is
//! the only side that can send a 4004.

mod harness;

use std::sync::atomic::Ordering;
use std::time::Duration;

use harness::{Answer, Harness, PIGEON, TOKEN, V, WsCommand, shadow_value};
use pigeonhole_wire::topics;

#[tokio::test(flavor = "multi_thread")]
async fn subscribing_delivers_the_shadow_the_platform_already_had() {
  let h = Harness::start().await;
  h.state.set_shadow(3);
  for version in V::both() {
    let mut client = h.session(version).await;
    client.subscribe(1, &[(topics::SHADOW_TARGET, 1)]).await;
    assert_eq!(
      client.next().await,
      Answer::Suback {
        pid: 1,
        codes: vec![1]
      }
    );
    match client.next().await {
      Answer::Publish {
        topic,
        payload,
        retain,
      } => {
        assert_eq!(topic, topics::SHADOW_TARGET);
        assert!(retain, "the shadow target is retained");
        // The bytes are the Durable Object's own, not a re-serialization.
        let shadow: serde_json::Value = serde_json::from_slice(&payload).expect("shadow json");
        assert_eq!(shadow["target_version"], 3);
        assert_eq!(shadow["target_config"], "{\"telemetry_interval\":30}");
      }
      other => panic!(
        "{}: expected a retained publish, got {other:?}",
        version.name()
      ),
    }
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_arrives_only_when_the_target_version_changed() {
  let h = Harness::start().await;
  h.state.set_shadow(1);
  let mut client = h.session(V::V5).await;
  client.subscribe(1, &[("pigeon/shadow/#", 1)]).await;
  assert_eq!(
    client.next().await,
    Answer::Suback {
      pid: 1,
      codes: vec![1]
    }
  );
  assert!(matches!(client.next().await, Answer::Publish { .. }));

  // The same target again, which is what a device report-back produces: the
  // shadow is rewritten and `updated_at` moves, but the target did not.
  h.state.command(WsCommand::PushShadow(shadow_value(1)));
  client.silent_for(Duration::from_millis(400)).await;

  h.state.command(WsCommand::PushShadow(shadow_value(2)));
  match client.next().await {
    Answer::Publish { payload, .. } => {
      let shadow: serde_json::Value = serde_json::from_slice(&payload).expect("shadow json");
      assert_eq!(shadow["target_version"], 2);
    }
    other => panic!("expected the new target, got {other:?}"),
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_subscription_arriving_late_still_gets_the_current_target() {
  let h = Harness::start().await;
  h.state.set_shadow(5);
  let mut client = h.session(V::V5).await;
  // Nothing was subscribed when the snapshot arrived, so the value had to
  // be held for whoever asked next.
  tokio::time::sleep(Duration::from_millis(200)).await;
  client.subscribe(1, &[("pigeon/#", 0)]).await;
  assert_eq!(
    client.next().await,
    Answer::Suback {
      pid: 1,
      codes: vec![0]
    }
  );
  match client.next().await {
    Answer::Publish { payload, .. } => {
      let shadow: serde_json::Value = serde_json::from_slice(&payload).expect("shadow json");
      assert_eq!(shadow["target_version"], 5);
    }
    other => panic!("expected the retained target, got {other:?}"),
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn qos0_telemetry_rides_the_socket_the_session_already_holds() {
  let h = Harness::start().await;
  for version in V::both() {
    let before = h.state.frames().len();
    let mut client = h.session(version).await;
    client
      .publish(topics::TELEMETRY, br#"{"temp":"21.5"}"#, 0, None)
      .await;

    h.state
      .wait_for("a telemetry frame", |s| s.frames().len() > before)
      .await;
    let frame: serde_json::Value =
      serde_json::from_str(&h.state.frames()[before]).expect("frame json");
    assert_eq!(frame["type"], "telemetry");
    assert_eq!(frame["metrics"]["temp"], "21.5");
    assert!(
      h.state.requests().is_empty(),
      "{}: the fast path costs no Worker request",
      version.name()
    );
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn qos0_falls_back_to_the_route_when_the_feed_is_down() {
  let h = Harness::start().await;
  let mut client = h.session(V::V5).await;

  // 4009: something else holds this pigeon's socket, so the feed is
  // terminal for this session and must not fight for it.
  h.state.command(WsCommand::Close(4009));
  tokio::time::sleep(Duration::from_millis(300)).await;

  client
    .publish(topics::TELEMETRY, br#"{"temp":"9"}"#, 0, None)
    .await;
  h.state
    .wait_for("the fallback POST", |s| !s.requests().is_empty())
    .await;
  assert_eq!(h.state.requests()[0].leaf, "telemetry");
  assert_eq!(h.state.requests()[0].body, br#"{"temp":"9"}"#);

  // And the session itself is untouched: losing a feed is not losing a
  // session.
  client.ping().await;
  assert_eq!(client.next().await, Answer::Pingresp);
  // The feed is not redialled, because redialling would close whoever holds
  // the socket and they would close this one back.
  assert_eq!(h.state.upgrades(), 1);

  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fuse_paused_feed_drops_qos0_rather_than_buying_a_guaranteed_refusal() {
  let h = Harness::start().await;
  let mut client = h.session(V::V5).await;

  // Every route would answer 429 now, and the upgrade would too.
  h.state.upgrade_status.store(429, Ordering::SeqCst);
  h.state.command(WsCommand::Close(4029));
  tokio::time::sleep(Duration::from_millis(400)).await;

  client
    .publish(topics::TELEMETRY, br#"{"temp":"9"}"#, 0, None)
    .await;
  tokio::time::sleep(Duration::from_millis(400)).await;
  assert!(
    h.state.requests().is_empty(),
    "a POST here would be one Worker plus one Durable Object request bought for a guaranteed 429"
  );

  // The v5 session survives the fuse, which is the point of answering 0x97
  // rather than closing.
  client.ping().await;
  assert_eq!(client.next().await, Answer::Pingresp);
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_token_revoked_close_ends_the_session_without_a_redial() {
  let h = Harness::start().await;
  for (code, version) in [(4004u16, V::V5), (4005, V::V5), (4004, V::V3)] {
    let mut client = h.session(version).await;
    let upgrades = h.state.upgrades();
    h.state.command(WsCommand::Close(code));
    if version == V::V5 {
      assert_eq!(
        client.next().await,
        Answer::Disconnect(0x87),
        "close {code} ends the session as not-authorized"
      );
    }
    assert!(client.closed().await, "close {code} on {}", version.name());
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
      h.state.upgrades(),
      upgrades,
      "a dead credential is not redialled"
    );
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ordinary_close_is_redialled() {
  let h = Harness::start().await;
  let mut client = h.session(V::V5).await;
  assert_eq!(h.state.upgrades(), 1);

  h.state.command(WsCommand::Close(1001));
  h.state
    .wait_for("the feed to come back", |s| s.upgrades() >= 2)
    .await;

  client.ping().await;
  assert_eq!(client.next().await, Answer::Pingresp, "the session lived");
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_429_on_the_upgrade_refuses_the_connect_as_a_billing_state_not_a_credential_one() {
  let h = Harness::start().await;
  h.state.upgrade_status.store(429, Ordering::SeqCst);
  for version in V::both() {
    let mut client = h.raw_session(version).await;
    client.send_connect(PIGEON, Some(PIGEON), Some(TOKEN)).await;
    let expected = if version == V::V5 { 0x97 } else { 0x03 };
    assert_eq!(
      client.next().await,
      Answer::ConnackRefused(expected),
      "{}: valid credentials, come back later",
      version.name()
    );
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shell_command_gets_an_honest_answer_instead_of_a_timeout() {
  let h = Harness::start().await;
  let _client = h.session(V::V5).await;
  let before = h.state.frames().len();

  h.state
    .command(WsCommand::ShellCmd("request-1".to_string()));
  h.state
    .wait_for("the shell reply", |s| s.frames().len() > before)
    .await;

  let reply: serde_json::Value =
    serde_json::from_str(&h.state.frames()[before]).expect("frame json");
  assert_eq!(reply["type"], "shell_output");
  assert_eq!(reply["request_id"], "request-1");
  assert_eq!(reply["exit_code"], -1);
  assert_eq!(reply["output"], "shell not available over MQTT");
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_newer_session_takes_the_pigeon_over() {
  let h = Harness::start().await;
  let mut first = h.session(V::V5).await;
  let mut second = h.session(V::V5).await;

  assert_eq!(
    first.next().await,
    Answer::Disconnect(0x8E),
    "the superseded session is told it was taken over"
  );
  assert!(first.closed().await);

  second.ping().await;
  assert_eq!(second.next().await, Answer::Pingresp);
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_will_is_bridged_when_the_device_really_went_away() {
  let h = Harness::start().await;
  for version in V::both() {
    let before = h.state.requests().len();
    let mut client = h.raw_session(version).await;
    client
      .send_connect_full(
        PIGEON,
        Some(PIGEON),
        Some(TOKEN),
        60,
        Some((topics::TELEMETRY, br#"{"status":"gone"}"#, 1)),
      )
      .await;
    assert_eq!(client.next().await, Answer::ConnackAccepted);

    // Dropped, not disconnected: an ungraceful exit is what a will is for.
    client.abort().await;

    h.state
      .wait_for("the will", |s| s.requests().len() > before)
      .await;
    let will = &h.state.requests()[before];
    assert_eq!(will.leaf, "telemetry");
    assert_eq!(will.body, br#"{"status":"gone"}"#);
    assert_eq!(
      will.bearer.as_deref(),
      Some(TOKEN),
      "{}: a will is an ordinary bridged publish, carrying the session's own token",
      version.name()
    );
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_graceful_disconnect_discards_the_will() {
  let h = Harness::start().await;
  let mut client = h.raw_session(V::V5).await;
  client
    .send_connect_full(
      PIGEON,
      Some(PIGEON),
      Some(TOKEN),
      60,
      Some((topics::TELEMETRY, br#"{"status":"gone"}"#, 0)),
    )
    .await;
  assert_eq!(client.next().await, Answer::ConnackAccepted);
  client.disconnect().await;
  assert!(client.closed().await);

  tokio::time::sleep(Duration::from_millis(400)).await;
  assert!(
    h.state.requests().is_empty(),
    "a device that said goodbye is not offline"
  );
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_will_is_suppressed_when_a_newer_session_holds_the_pigeon() {
  let h = Harness::start().await;
  let mut first = h.raw_session(V::V5).await;
  first
    .send_connect_full(
      PIGEON,
      Some(PIGEON),
      Some(TOKEN),
      60,
      Some((topics::TELEMETRY, br#"{"status":"gone"}"#, 0)),
    )
    .await;
  assert_eq!(first.next().await, Answer::ConnackAccepted);

  // The reconnect-before-timeout case: the device is back before its old
  // session noticed it was gone.
  let mut second = h.session(V::V5).await;
  assert_eq!(first.next().await, Answer::Disconnect(0x8E));
  assert!(first.closed().await);

  tokio::time::sleep(Duration::from_millis(500)).await;
  assert!(
    h.state.requests().is_empty(),
    "reporting a connected device offline is the failure this rule prevents"
  );

  second.ping().await;
  assert_eq!(second.next().await, Answer::Pingresp);
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_credential_that_stopped_existing_skips_the_will() {
  let h = Harness::start().await;
  let mut client = h.raw_session(V::V5).await;
  client
    .send_connect_full(
      PIGEON,
      Some(PIGEON),
      Some(TOKEN),
      60,
      Some((topics::TELEMETRY, br#"{"status":"gone"}"#, 0)),
    )
    .await;
  assert_eq!(client.next().await, Answer::ConnackAccepted);

  h.state.command(WsCommand::Close(4005));
  assert_eq!(client.next().await, Answer::Disconnect(0x87));
  assert!(client.closed().await);

  tokio::time::sleep(Duration::from_millis(400)).await;
  assert!(
    h.state.requests().is_empty(),
    "a will here would only earn a guaranteed 401"
  );
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shutdown_finishes_what_is_in_flight_and_says_it_is_going_away() {
  let h = Harness::start().await;
  let mut client = h.session(V::V5).await;

  // Long enough that a shutdown which simply dropped the session would lose
  // this publish rather than acking it.
  h.state.publish_delay.store(1_200, Ordering::SeqCst);
  client.publish(topics::TELEMETRY, b"{}", 1, Some(1)).await;
  tokio::time::sleep(Duration::from_millis(100)).await;

  h.broker.begin_shutdown();

  assert_eq!(
    client.next().await,
    Answer::Puback { pid: 1, reason: 0 },
    "the in-flight publish is finished and acked"
  );
  assert_eq!(
    client.next().await,
    Answer::Disconnect(0x8B),
    "then the client is told the server is shutting down"
  );
  assert!(client.closed().await);
  h.shutdown().await;
}
