//! The typed client against a real broker: the happy paths the example
//! demonstrates, proven rather than described.

mod harness;

use harness::{Harness, PIGEON, PSK_SECRET, TOKEN, WsCommand, shadow_value};
use pigeonhole_client::client::{ClientConfig, PigeonClient, ProtocolVersion};
use pigeonhole_client::raw::Transport;
use pigeonhole_wire::payload::{Metrics, ShadowReport};

fn certificate_config(h: &Harness, version: ProtocolVersion) -> ClientConfig {
  ClientConfig {
    endpoint: h.endpoint.clone(),
    transport: Transport::Certificate {
      ca_pem: Some(h.ca_pem()),
      server_name: Some("localhost".to_string()),
    },
    pigeon_id: PIGEON.to_string(),
    token: Some(TOKEN.to_string()),
    version,
    keep_alive: 60,
  }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_typed_client_reports_and_subscribes_on_both_versions() {
  let h = Harness::start().await;
  h.state.set_shadow(4);

  for version in [ProtocolVersion::V500, ProtocolVersion::V311] {
    let before = h.state.requests().len();
    let (client, mut shadows) = PigeonClient::connect(certificate_config(&h, version))
      .await
      .expect("connects");

    client
      .subscribe_shadow_target(1)
      .await
      .expect("subscription granted");
    let shadow = shadows.next().await.expect("the retained target arrives");
    assert_eq!(shadow.parsed.target_version, 4);
    // The raw bytes are kept alongside the parsed form, because they are
    // what the platform actually sent.
    assert!(shadow.raw.starts_with(b"{"));

    let mut metrics = Metrics::new();
    metrics.insert("temp".to_string(), "21.5".to_string());
    client
      .report_telemetry(&metrics, 1)
      .await
      .expect("telemetry accepted");

    client
      .report_shadow(
        &ShadowReport {
          current_config: serde_json::json!({ "telemetry_interval": 30 }),
          current_version: 4,
        },
        1,
      )
      .await
      .expect("report accepted");

    client
      .upload_log_chunk(b"\x01\x02opaque", 1)
      .await
      .expect("log chunk accepted");

    let requests = h.state.requests();
    let leaves: Vec<&str> = requests[before..].iter().map(|r| r.leaf.as_str()).collect();
    assert_eq!(leaves, vec!["telemetry", "shadow", "logs"]);

    client.disconnect().await.expect("disconnects");
  }
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_pushed_target_reaches_the_typed_stream() {
  let h = Harness::start().await;
  h.state.set_shadow(1);
  let (client, mut shadows) = PigeonClient::connect(certificate_config(&h, ProtocolVersion::V500))
    .await
    .expect("connects");
  client.subscribe_shadow_target(1).await.expect("subscribed");
  assert_eq!(
    shadows
      .next()
      .await
      .expect("retained")
      .parsed
      .target_version,
    1
  );

  h.state.command(WsCommand::PushShadow(shadow_value(2)));
  assert_eq!(
    shadows.next().await.expect("pushed").parsed.target_version,
    2
  );
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_psk_session_needs_no_token_at_all() {
  let h = Harness::start().await;
  let (client, _shadows) = PigeonClient::connect(ClientConfig::psk(
    h.endpoint.clone(),
    PIGEON.to_string(),
    PSK_SECRET.to_string(),
  ))
  .await
  .expect("connects on the handshake's own credentials");

  let mut metrics = Metrics::new();
  metrics.insert("uptime".to_string(), "12".to_string());
  client
    .report_telemetry(&metrics, 1)
    .await
    .expect("telemetry accepted");
  assert_eq!(
    h.state.requests()[0].bearer.as_deref(),
    Some(TOKEN),
    "the token came from the PSK lookup, not from the client"
  );
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_session_says_why_rather_than_timing_out() {
  let h = Harness::start().await;
  h.state.valid_tokens.lock().expect("lock").clear();
  let error = PigeonClient::connect(certificate_config(&h, ProtocolVersion::V500))
    .await
    .expect_err("refused");
  let message = format!("{error}");
  assert!(
    message.contains("BadUserNameOrPassword"),
    "the refusal names itself: {message}"
  );
  h.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_qos1_publish_that_the_platform_refuses_surfaces_the_reason() {
  let h = Harness::start().await;
  h.state
    .telemetry_status
    .store(400, std::sync::atomic::Ordering::SeqCst);
  let (client, _shadows) = PigeonClient::connect(certificate_config(&h, ProtocolVersion::V500))
    .await
    .expect("connects");

  let mut metrics = Metrics::new();
  metrics.insert("temp".to_string(), "nonsense".to_string());
  let error = client
    .report_telemetry(&metrics, 1)
    .await
    .expect_err("refused");
  assert!(
    format!("{error}").contains("PayloadFormatInvalid"),
    "{error}"
  );
  h.shutdown().await;
}
