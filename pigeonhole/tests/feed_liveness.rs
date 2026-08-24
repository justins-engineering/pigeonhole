//! Feed liveness: the path that finds a socket which is up as far as the
//! kernel is concerned and dead as far as anything useful is concerned.
//!
//! Its own test binary because the ping interval is process-wide
//! configuration, and the default is a minute, which is not a thing a test
//! can wait for. The interval is a real operational knob rather than a test
//! hook: a fleet on a link that goes half-open often wants to find a dead
//! socket sooner.

mod harness;

use std::time::Duration;

use harness::{Answer, Harness, V, WsCommand};

#[tokio::test(flavor = "multi_thread")]
async fn unanswered_pings_make_the_bridge_replace_a_half_open_socket() {
  // Set before the broker starts, so the feed reads it on its first sleep.
  // SAFETY: this is the only test in this binary and nothing else has run.
  unsafe {
    std::env::set_var("PIGEONHOLE_FEED_PING_SECS", "1");
  }

  let h = Harness::start().await;
  let mut client = h.session(V::V5).await;
  assert_eq!(h.state.upgrades(), 1);

  // The socket stays open and the platform stops reading it. Nothing about
  // the connection looks wrong from the outside: writes are absorbed, and
  // this is exactly why the liveness timer keys on inbound silence rather
  // than on outbound activity.
  h.state.command(WsCommand::GoSilent);

  // Two missed pings, then a reconnect.
  h.state
    .wait_for("the feed to be replaced", |s| s.upgrades() >= 2)
    .await;

  // The session itself never noticed: a feed is replaceable, a session is
  // not.
  client.ping().await;
  assert_eq!(client.next().await, Answer::Pingresp);

  // And the new socket works: a push arrives over it.
  h.state
    .command(WsCommand::PushShadow(harness::shadow_value(9)));
  client
    .subscribe(1, &[(pigeonhole_wire::topics::SHADOW_TARGET, 1)])
    .await;
  assert_eq!(
    client.next().await,
    Answer::Suback {
      pid: 1,
      codes: vec![1]
    }
  );
  match client.next_within(Duration::from_secs(10)).await {
    Answer::Publish { payload, .. } => {
      let shadow: serde_json::Value = serde_json::from_slice(&payload).expect("shadow json");
      assert!(shadow["target_version"].is_number());
    }
    other => panic!("expected a retained publish over the new socket, got {other:?}"),
  }

  h.shutdown().await;
}
