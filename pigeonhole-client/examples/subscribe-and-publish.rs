//! A pigeon's whole MQTT life in one file: connect, subscribe to the shadow
//! target the platform keeps for it, report telemetry, and print each target
//! that arrives.
//!
//! Run it against a local broker with the dev certificate:
//!
//! ```sh
//! PIGEONHOLE_ENDPOINT=mqtts://127.0.0.1:8883 \
//! PIGEONHOLE_CA=scripts/dev-cert/ca.pem \
//! PIGEONHOLE_SERVER_NAME=localhost \
//! PIGEONHOLE_PIGEON_ID=<pigeon id> \
//! PIGEONHOLE_TOKEN=<device token> \
//!   cargo run -p pigeonhole-client --example subscribe-and-publish
//! ```
//!
//! Or in PSK mode, where the handshake resolves the pigeon's credentials and
//! no token is needed:
//!
//! ```sh
//! PIGEONHOLE_ENDPOINT=mqtts://127.0.0.1:8883 \
//! PIGEONHOLE_PIGEON_ID=<pigeon id> \
//! PIGEONHOLE_PSK=<tls_psk_secret> \
//!   cargo run -p pigeonhole-client --example subscribe-and-publish
//! ```
//!
//! Credentials come from the environment and are never printed.

use std::path::PathBuf;
use std::time::Duration;

use pigeonhole_client::client::{ClientConfig, PigeonClient, ProtocolVersion};
use pigeonhole_client::raw::{Endpoint, Transport};
use pigeonhole_wire::payload::{Metrics, ShadowReport};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let endpoint = Endpoint::parse(&required("PIGEONHOLE_ENDPOINT")?)?;
  let pigeon_id = required("PIGEONHOLE_PIGEON_ID")?;

  // The ClientHello decides which credential the session uses, so the
  // presence of a PSK is what picks the mode here too.
  let (transport, token) = match std::env::var("PIGEONHOLE_PSK").ok() {
    Some(secret) => (
      Transport::Psk {
        identity: pigeon_id.clone(),
        secret,
      },
      None,
    ),
    None => (
      Transport::Certificate {
        ca_pem: std::env::var("PIGEONHOLE_CA").ok().map(PathBuf::from),
        server_name: std::env::var("PIGEONHOLE_SERVER_NAME").ok(),
        // A device with no TLS 1.3 sets this; most hosts leave it off.
        tls12_only: std::env::var("PIGEONHOLE_TLS12_ONLY").is_ok(),
      },
      Some(required("PIGEONHOLE_TOKEN")?),
    ),
  };

  let version = match std::env::var("PIGEONHOLE_VERSION").as_deref() {
    Ok("3.1.1") | Ok("3") => ProtocolVersion::V311,
    _ => ProtocolVersion::V500,
  };

  let config = ClientConfig {
    endpoint,
    transport,
    pigeon_id: pigeon_id.clone(),
    token,
    version,
    keep_alive: 60,
  };

  println!("connecting as {pigeon_id}");
  let (client, mut shadows) = PigeonClient::connect(config).await?;
  println!("connected");

  // Subscribing at QoS 1 asks for the current target, which arrives right
  // away: the retained value is the platform's own live shadow, not a copy
  // the broker composed.
  client.subscribe_shadow_target(1).await?;
  println!("subscribed to {}", pigeonhole_wire::topics::SHADOW_TARGET);

  let mut metrics = Metrics::new();
  metrics.insert("temp".to_string(), "21.5".to_string());
  metrics.insert("status".to_string(), "ok".to_string());

  // QoS 1 returns when the platform has accepted the report. QoS 0 would
  // return as soon as the packet was written, and would ride the broker's
  // already-open socket to the platform rather than an HTTP request.
  client.report_telemetry(&metrics, 1).await?;
  println!("telemetry accepted");

  println!("waiting for shadow targets, ctrl-c to stop");
  loop {
    tokio::select! {
      shadow = shadows.next() => match shadow {
        Some(shadow) => {
          println!(
            "target_version={} current_version={} target_config={}",
            shadow.parsed.target_version, shadow.parsed.current_version, shadow.parsed.target_config
          );
          // Confirming a target is what closes the loop the shadow exists
          // for: the dashboard can then see what the device is actually
          // running.
          let report = ShadowReport {
            current_config: serde_json::from_str(&shadow.parsed.target_config)
              .unwrap_or(serde_json::json!({})),
            current_version: shadow.parsed.target_version,
          };
          client.report_shadow(&report, 1).await?;
          println!("reported back at version {}", shadow.parsed.target_version);
        }
        None => {
          println!("the session ended");
          return Ok(());
        }
      },
      _ = tokio::signal::ctrl_c() => {
        println!("disconnecting");
        client.disconnect().await?;
        // Give the goodbye a moment to reach the wire.
        tokio::time::sleep(Duration::from_millis(100)).await;
        return Ok(());
      }
    }
  }
}

fn required(name: &str) -> Result<String, String> {
  std::env::var(name).map_err(|_| format!("{name} is not set"))
}
