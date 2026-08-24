//! PSK sessions and the admission brakes.
//!
//! The brakes exist so that a credential flood costs the flooder more than
//! it costs dovecote: every refusal a device earns locally is a Worker
//! request and a Durable Object wake that never happens.

mod harness;
use std::sync::atomic::Ordering;

use harness::{Answer, Harness, PIGEON, PSK_SECRET, TOKEN, V};
use pigeonhole::quota::MAX_IDENTITY_FAILURES;

#[tokio::test(flavor = "multi_thread")]
async fn a_psk_handshake_resolves_the_pigeons_credentials_and_authenticates_it() {
  let h = Harness::start().await;
  let connection = h
    .connect_psk(PIGEON, PSK_SECRET)
    .await
    .expect("the handshake resolves through the internal credential route");

  let mut client = harness::Client {
    connection,
    version: V::V5,
  };
  // A PSK session may leave the username out entirely: the handshake
  // already named the pigeon, and the password is ignored.
  client.send_connect("", None, None).await;
  assert_eq!(client.next().await, Answer::ConnackAccepted);

  h.state
    .wait_for("the device socket", |s| s.upgrades() >= 1)
    .await;
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_psk_session_whose_username_disagrees_with_its_identity_is_refused() {
  let h = Harness::start().await;
  let connection = h.connect_psk(PIGEON, PSK_SECRET).await.expect("handshake");
  let mut client = harness::Client {
    connection,
    version: V::V5,
  };
  client
    .send_connect("", Some(harness::OTHER_PIGEON), None)
    .await;
  assert_eq!(client.next().await, Answer::ConnackRefused(0x85));
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_psk_identity_never_reaches_mqtt() {
  let h = Harness::start().await;
  let unknown = harness::OTHER_PIGEON;
  assert!(
    h.connect_psk(unknown, PSK_SECRET).await.is_err(),
    "an identity the platform does not know fails the handshake itself"
  );
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_psk_identity_that_is_not_a_pigeon_id_costs_no_upstream_lookup() {
  let h = Harness::start().await;
  assert!(h.connect_psk("not-a-pigeon", PSK_SECRET).await.is_err());
  assert_eq!(
    h.state.upgrades(),
    0,
    "the shape check is local, so garbage never reaches the edge"
  );
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_psk_entry_is_evicted_when_its_token_is_refused() {
  let h = Harness::start().await;
  // The cache is about to serve a pair whose token the platform has already
  // rotated away, which is exactly what a refresh inside the TTL produces.
  h.state.psk_entries.lock().expect("lock").insert(
    PIGEON.to_string(),
    (PSK_SECRET.to_string(), "the-rotated-away-token".to_string()),
  );

  let connection = h.connect_psk(PIGEON, PSK_SECRET).await.expect("handshake");
  let mut client = harness::Client {
    connection,
    version: V::V5,
  };
  client.send_connect("", None, None).await;
  assert_eq!(
    client.next().await,
    Answer::ConnackRefused(0x86),
    "the upgrade refuses the revoked token"
  );

  // The platform now hands out the current pair. A cache that had not
  // evicted the stale entry would keep refusing until the TTL expired.
  h.state.psk_entries.lock().expect("lock").insert(
    PIGEON.to_string(),
    (PSK_SECRET.to_string(), TOKEN.to_string()),
  );
  let connection = h.connect_psk(PIGEON, PSK_SECRET).await.expect("handshake");
  let mut client = harness::Client {
    connection,
    version: V::V5,
  };
  client.send_connect("", None, None).await;
  assert_eq!(client.next().await, Answer::ConnackAccepted);
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_bad_credential_is_answered_without_asking_the_platform_again() {
  let h = Harness::start().await;
  h.state.valid_tokens.lock().expect("lock").clear();

  let mut first = h.raw_session(V::V5).await;
  first
    .send_connect(PIGEON, Some(PIGEON), Some("wrong"))
    .await;
  assert_eq!(first.next().await, Answer::ConnackRefused(0x86));
  let attempts = h.state.recording.upgrade_attempts.load(Ordering::SeqCst);
  assert_eq!(attempts, 1);

  let mut second = h.raw_session(V::V5).await;
  second
    .send_connect(PIGEON, Some(PIGEON), Some("wrong"))
    .await;
  assert_eq!(second.next().await, Answer::ConnackRefused(0x86));
  assert_eq!(
    h.state.recording.upgrade_attempts.load(Ordering::SeqCst),
    attempts,
    "the negative cache answered the retry, so the edge was never asked twice"
  );
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_identity_that_spends_its_failure_budget_is_parked_locally() {
  let h = Harness::start().await;
  h.state.valid_tokens.lock().expect("lock").clear();

  // A distinct password each time, so the negative cache cannot be what
  // stops it: the budget is per identity, whatever the password.
  for attempt in 0..MAX_IDENTITY_FAILURES {
    let mut client = h.raw_session(V::V5).await;
    client
      .send_connect(PIGEON, Some(PIGEON), Some(&format!("guess-{attempt}")))
      .await;
    assert_eq!(client.next().await, Answer::ConnackRefused(0x86));
  }
  let attempts = h.state.recording.upgrade_attempts.load(Ordering::SeqCst);
  assert_eq!(attempts, MAX_IDENTITY_FAILURES);

  // Even the right token is now refused for the rest of the window, and the
  // platform is not asked about any of it.
  h.state
    .valid_tokens
    .lock()
    .expect("lock")
    .insert(TOKEN.to_string());
  let mut parked = h.raw_session(V::V5).await;
  parked.send_connect(PIGEON, Some(PIGEON), Some(TOKEN)).await;
  assert_eq!(parked.next().await, Answer::ConnackRefused(0x86));
  assert_eq!(
    h.state.recording.upgrade_attempts.load(Ordering::SeqCst),
    attempts,
    "a parked identity costs the platform nothing"
  );

  // A different pigeon is unaffected: the brake is per identity.
  h.state.psk_entries.lock().expect("lock").insert(
    harness::OTHER_PIGEON.to_string(),
    (PSK_SECRET.to_string(), TOKEN.to_string()),
  );
  let mut other = h.raw_session(V::V5).await;
  other
    .send_connect(
      harness::OTHER_PIGEON,
      Some(harness::OTHER_PIGEON),
      Some(TOKEN),
    )
    .await;
  assert_eq!(other.next().await, Answer::ConnackAccepted);
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn one_source_connecting_faster_than_its_rate_is_braked() {
  let h = Harness::start().await;
  h.state.valid_tokens.lock().expect("lock").clear();

  // Distinct identities each time, so neither the per-identity budget nor
  // the negative cache is what stops it.
  for attempt in 0..pigeonhole::quota::MAX_CONNECTS_PER_SOURCE {
    let identity = format!("{:0>60}{attempt:04x}", "");
    let mut client = h.raw_session(V::V5).await;
    client
      .send_connect(&identity, Some(&identity), Some(TOKEN))
      .await;
    assert_eq!(client.next().await, Answer::ConnackRefused(0x86));
  }
  let attempts = h.state.recording.upgrade_attempts.load(Ordering::SeqCst);

  let identity = format!("{:0>60}{:04x}", "", 0xffff);
  let mut braked = h.raw_session(V::V5).await;
  braked
    .send_connect(&identity, Some(&identity), Some(TOKEN))
    .await;
  assert_eq!(
    braked.next().await,
    Answer::ConnackRefused(0x89),
    "server busy, not a credential verdict: the brake is about the source, not the pigeon"
  );
  assert_eq!(
    h.state.recording.upgrade_attempts.load(Ordering::SeqCst),
    attempts,
    "a braked CONNECT costs the platform nothing"
  );

  // The global refusal brake, which needs many distinct sources by
  // construction, is covered where it can be reached: `quota`'s own tests.
  h.shutdown().await;
}
