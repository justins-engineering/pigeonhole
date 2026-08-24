//! The two upstream legs to dovecote: a `reqwest` client for the device
//! routes and the device WebSocket dial.
//!
//! Both carry the device's own bearer token and nothing else. The bridge
//! never holds a dashboard, org, or flock credential, and a wrongly
//! forwarded publish still dies at the owning Durable Object, which verifies
//! the token per request exactly as it does for a direct HTTPS device
//! (`docs/design.md` ADR G).

use std::time::Duration;

use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// Read and write buffers per upstream socket. The library's 128 KiB
/// defaults would cost about a gigabyte of buffers alone at the connection
/// ceiling, on a box already carrying other services' memory caps; shadow
/// frames are hundreds of bytes to a few KiB, so 4 KiB is generous.
const WS_BUFFER_BYTES: usize = 4 * 1024;
/// Ceiling on one inbound frame. The Durable Object's own frame cap is
/// 16 KiB, so this is headroom rather than a limit anything should meet.
const WS_MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Below any 1.5x keepalive deadline this broker will ever enforce, so a
/// slow edge can never masquerade as client silence and close a healthy
/// session.
pub const PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub type DeviceSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// The part of an upstream HTTP response the ack policy needs. The body is
/// kept because a 403's shape is what separates an edge-mitigation page from
/// one of dovecote's own refusals.
#[derive(Debug, Clone)]
pub struct UpstreamResponse {
  pub status: u16,
  pub body: Vec<u8>,
}

/// Why a device WebSocket upgrade did not produce a socket.
#[derive(Debug)]
pub enum UpgradeFailure {
  /// The edge answered, with this status and body.
  Status { status: u16, body: Vec<u8> },
  /// Nothing came back that could be read as an answer.
  Transport(String),
}

/// The device routes and the device socket, both reached with one pigeon's
/// bearer token. A trait so the session can be driven against an in-process
/// mock without a network.
pub trait Upstream: Send + Sync + 'static {
  fn publish(
    &self,
    pigeon_id: &str,
    leaf: &str,
    content_type: &'static str,
    bearer: &str,
    body: Vec<u8>,
  ) -> impl std::future::Future<Output = Result<UpstreamResponse, String>> + Send;

  fn dial_device_ws(
    &self,
    pigeon_id: &str,
    bearer: &str,
  ) -> impl std::future::Future<Output = Result<DeviceSocket, UpgradeFailure>> + Send;
}

pub struct Dovecote {
  client: reqwest::Client,
  base_url: String,
}

impl Dovecote {
  pub fn new(base_url: &str) -> Result<Dovecote, String> {
    let client = reqwest::Client::builder()
      // A distinctive user agent, for the reason loft carries one: default
      // library agents trip edge bot heuristics into HTML 403s, which this
      // broker would then have to classify as edge security rather than as
      // an auth verdict.
      .user_agent(concat!("pigeonhole/", env!("CARGO_PKG_VERSION")))
      .timeout(PUBLISH_TIMEOUT)
      .connect_timeout(CONNECT_TIMEOUT)
      .build()
      .map_err(|e| format!("upstream client build: {e}"))?;
    Ok(Dovecote {
      client,
      base_url: base_url.trim_end_matches('/').to_string(),
    })
  }

  /// The device WebSocket URL for a pigeon, with the base URL's scheme
  /// mapped to its WebSocket form.
  fn device_ws_url(&self, pigeon_id: &str) -> String {
    let base = if let Some(rest) = self.base_url.strip_prefix("https://") {
      format!("wss://{rest}")
    } else if let Some(rest) = self.base_url.strip_prefix("http://") {
      format!("ws://{rest}")
    } else {
      self.base_url.clone()
    };
    format!("{base}/device/pigeons/{pigeon_id}/ws")
  }
}

impl Upstream for Dovecote {
  async fn publish(
    &self,
    pigeon_id: &str,
    leaf: &str,
    content_type: &'static str,
    bearer: &str,
    body: Vec<u8>,
  ) -> Result<UpstreamResponse, String> {
    let url = format!("{}/device/pigeons/{}/{}", self.base_url, pigeon_id, leaf);
    let response = self
      .client
      .post(&url)
      .header("Authorization", format!("Bearer {bearer}"))
      .header("Content-Type", content_type)
      .body(body)
      .send()
      .await
      .map_err(|e| format!("upstream: {e}"))?;

    let status = response.status().as_u16();
    let body = response
      .bytes()
      .await
      .map_err(|e| format!("upstream body: {e}"))?
      .to_vec();
    Ok(UpstreamResponse { status, body })
  }

  async fn dial_device_ws(
    &self,
    pigeon_id: &str,
    bearer: &str,
  ) -> Result<DeviceSocket, UpgradeFailure> {
    let url = self.device_ws_url(pigeon_id);
    let mut request = url
      .as_str()
      .into_client_request()
      .map_err(|e| UpgradeFailure::Transport(format!("ws request: {e}")))?;
    let value = format!("Bearer {bearer}")
      .parse()
      .map_err(|e| UpgradeFailure::Transport(format!("ws authorization header: {e}")))?;
    request.headers_mut().insert("Authorization", value);

    let config = WebSocketConfig::default()
      .read_buffer_size(WS_BUFFER_BYTES)
      .write_buffer_size(WS_BUFFER_BYTES)
      .max_message_size(Some(WS_MAX_MESSAGE_BYTES));

    match tokio_tungstenite::connect_async_with_config(request, Some(config), true).await {
      Ok((socket, _)) => Ok(socket),
      Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
        let status = response.status().as_u16();
        let body = response.body().clone().unwrap_or_default();
        Err(UpgradeFailure::Status { status, body })
      }
      Err(e) => Err(UpgradeFailure::Transport(e.to_string())),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn the_device_socket_url_follows_the_base_urls_scheme() {
    let prod = Dovecote::new("https://api.pidgeiot.com").expect("client");
    assert_eq!(
      prod.device_ws_url("abc"),
      "wss://api.pidgeiot.com/device/pigeons/abc/ws"
    );
    let dev = Dovecote::new("http://127.0.0.1:8787/").expect("client");
    assert_eq!(
      dev.device_ws_url("abc"),
      "ws://127.0.0.1:8787/device/pigeons/abc/ws"
    );
  }
}
