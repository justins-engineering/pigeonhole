//! Framed connection: open a TLS stream, then `send` and `recv` whole
//! `mqtt_proto` packets with `pigeonhole_wire::framing`'s size cap applied on
//! the receive side. No session logic, no keepalive, no acknowledgement
//! tracking: whatever the caller sends goes on the wire as given, which is
//! exactly what the broker's harness needs to prove refusals (an unknown
//! publish topic, an oversize packet, QoS 2 on a v5 session, a CONNECT that
//! disagrees with its PSK identity).

use std::path::PathBuf;
use std::pin::Pin;
use std::time::Duration;

use mqtt_proto::{v3, v5};
use openssl::ssl::Ssl;
use pigeonhole_wire::framing::{self, RawPacket};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use crate::{ClientError, tls};

/// Where the broker is. Accepts the `mqtts://host:port` form a pigeon's
/// `connector.Mqtt.endpoint` carries, and a bare `host:port` for a broker
/// dialled directly (the harness and the dev loop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
  pub host: String,
  pub port: u16,
}

impl Endpoint {
  pub fn parse(endpoint: &str) -> Result<Endpoint, ClientError> {
    let rest = match endpoint.split_once("://") {
      // The scheme names the transport, and there is only one: TLS. A
      // cleartext scheme is refused rather than silently upgraded, so a
      // misconfigured device fails loudly instead of half-working.
      Some(("mqtts", rest)) => rest,
      Some((scheme, _)) => {
        return Err(ClientError::Endpoint(format!(
          "unsupported scheme {scheme:?}, pigeonhole speaks mqtts only"
        )));
      }
      None => endpoint,
    };
    let rest = rest.trim_end_matches('/');
    let (host, port) = rest.rsplit_once(':').ok_or_else(|| {
      ClientError::Endpoint("endpoint needs an explicit port, e.g. mqtts://host:8883".to_string())
    })?;
    if host.is_empty() {
      return Err(ClientError::Endpoint("endpoint has no host".to_string()));
    }
    let port = port
      .parse::<u16>()
      .map_err(|_| ClientError::Endpoint(format!("{port:?} is not a port")))?;
    Ok(Endpoint {
      host: host.to_string(),
      port,
    })
  }
}

/// Which handshake to run. The two carry different credentials because they
/// authenticate differently: a certificate session proves who the *server*
/// is and presents the device token inside CONNECT, while a PSK session
/// proves both ends from the shared key before CONNECT is written.
#[derive(Debug, Clone)]
pub enum Transport {
  Certificate {
    /// Trust anchor. `None` uses the system store.
    ca_pem: Option<PathBuf>,
    /// Name to verify the chain against, when it differs from the dialled
    /// host (a dev certificate reached over a loopback address).
    server_name: Option<String>,
  },
  Psk {
    identity: String,
    secret: String,
  },
}

impl Transport {
  pub fn certificate() -> Transport {
    Transport::Certificate {
      ca_pem: None,
      server_name: None,
    }
  }
}

/// A TLS connection carrying whole MQTT packets, and nothing above that.
pub struct RawConnection {
  stream: SslStream<TcpStream>,
}

impl RawConnection {
  /// Dials the broker and completes the TLS handshake. Nothing MQTT has
  /// happened yet when this returns: no CONNECT is sent for the caller.
  pub async fn connect(
    endpoint: &Endpoint,
    transport: &Transport,
  ) -> Result<RawConnection, ClientError> {
    let tcp = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
      .await
      .map_err(|e| ClientError::Endpoint(format!("connect {}: {e}", endpoint.host)))?;
    // MQTT packets are small and often latency-sensitive; a delayed ack plus
    // Nagle turns a PUBACK round trip into tens of milliseconds.
    let _ = tcp.set_nodelay(true);

    let ssl = match transport {
      Transport::Certificate {
        ca_pem,
        server_name,
      } => {
        let context = tls::certificate_context(ca_pem.as_deref())
          .map_err(|e| ClientError::Tls(format!("client context: {e}")))?;
        let mut ssl =
          Ssl::new(&context).map_err(|e| ClientError::Tls(format!("ssl object: {e}")))?;
        let name = server_name.as_deref().unwrap_or(endpoint.host.as_str());
        ssl
          .set_hostname(name)
          .map_err(|e| ClientError::Tls(format!("sni: {e}")))?;
        // Verification of the name in the chain is separate from SNI, and
        // omitting it is the classic way a "verified" client accepts any
        // valid certificate for any host.
        ssl
          .param_mut()
          .set_host(name)
          .map_err(|e| ClientError::Tls(format!("hostname verification: {e}")))?;
        ssl
      }
      Transport::Psk { identity, secret } => {
        let context = tls::psk_context(identity, secret)
          .map_err(|e| ClientError::Tls(format!("psk context: {e}")))?;
        Ssl::new(&context).map_err(|e| ClientError::Tls(format!("ssl object: {e}")))?
      }
    };

    let mut stream =
      SslStream::new(ssl, tcp).map_err(|e| ClientError::Tls(format!("tls stream: {e}")))?;
    Pin::new(&mut stream)
      .connect()
      .await
      .map_err(|e| ClientError::Tls(format!("handshake: {e}")))?;

    Ok(RawConnection { stream })
  }

  /// Writes bytes verbatim. The escape hatch the harness needs for packets
  /// no codec would produce.
  pub async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), ClientError> {
    framing::write_packet(&mut self.stream, bytes).await?;
    Ok(())
  }

  pub async fn send_v3(&mut self, packet: &v3::Packet) -> Result<(), ClientError> {
    let encoded = packet
      .encode()
      .map_err(|e| ClientError::Codec(e.to_string()))?;
    self.send_bytes(encoded.as_ref()).await
  }

  pub async fn send_v5(&mut self, packet: &v5::Packet) -> Result<(), ClientError> {
    let encoded = packet
      .encode()
      .map_err(|e| ClientError::Codec(e.to_string()))?;
    self.send_bytes(encoded.as_ref()).await
  }

  pub async fn recv(&mut self) -> Result<RawPacket, ClientError> {
    Ok(framing::read_packet(&mut self.stream).await?)
  }

  pub async fn recv_v3(&mut self) -> Result<v3::Packet, ClientError> {
    Ok(self.recv().await?.decode_v3()?)
  }

  pub async fn recv_v5(&mut self) -> Result<v5::Packet, ClientError> {
    Ok(self.recv().await?.decode_v5()?)
  }

  /// `None` when nothing arrived in time, which a test uses to assert that
  /// the broker stayed quiet as well as that it answered.
  pub async fn recv_within(&mut self, within: Duration) -> Result<Option<RawPacket>, ClientError> {
    match tokio::time::timeout(within, self.recv()).await {
      Ok(result) => result.map(Some),
      Err(_) => Ok(None),
    }
  }

  pub async fn recv_v3_within(
    &mut self,
    within: Duration,
  ) -> Result<Option<v3::Packet>, ClientError> {
    match self.recv_within(within).await? {
      Some(raw) => Ok(Some(raw.decode_v3()?)),
      None => Ok(None),
    }
  }

  pub async fn recv_v5_within(
    &mut self,
    within: Duration,
  ) -> Result<Option<v5::Packet>, ClientError> {
    match self.recv_within(within).await? {
      Some(raw) => Ok(Some(raw.decode_v5()?)),
      None => Ok(None),
    }
  }

  /// Waits for the broker to close the connection, ignoring any packets it
  /// sends first. `true` if it closed within the deadline.
  ///
  /// Packets are drained rather than treated as a failure because a refusal
  /// on MQTT 5 is a DISCONNECT *then* a close, and the same assertion has to
  /// hold on 3.1.1, where the close is the whole message.
  pub async fn closed_within(&mut self, within: Duration) -> Result<bool, ClientError> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
      let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
      if remaining.is_zero() {
        return Ok(false);
      }
      match tokio::time::timeout(remaining, self.recv()).await {
        Ok(Ok(_)) => continue,
        Ok(Err(ClientError::Framing(e))) if e.is_disconnect() => return Ok(true),
        Ok(Err(e)) => return Err(e),
        Err(_) => return Ok(false),
      }
    }
  }

  /// Splits into halves so a session can read and write concurrently. Used
  /// by the typed client; the harness keeps the whole connection.
  pub fn split(
    self,
  ) -> (
    ReadHalf<SslStream<TcpStream>>,
    WriteHalf<SslStream<TcpStream>>,
  ) {
    tokio::io::split(self.stream)
  }

  /// Drops the connection without an MQTT DISCONNECT, which is what a
  /// will-delivery test needs: an ungraceful exit.
  pub async fn abort(mut self) {
    let _ = self.stream.shutdown().await;
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn endpoint_accepts_the_minted_connector_form() {
    let endpoint = Endpoint::parse("mqtts://mqtt.pidgeiot.com:8883").expect("parses");
    assert_eq!(endpoint.host, "mqtt.pidgeiot.com");
    assert_eq!(endpoint.port, 8883);
  }

  #[test]
  fn endpoint_accepts_a_bare_host_and_port() {
    let endpoint = Endpoint::parse("127.0.0.1:18883").expect("parses");
    assert_eq!(endpoint.host, "127.0.0.1");
    assert_eq!(endpoint.port, 18883);
  }

  #[test]
  fn endpoint_tolerates_a_trailing_slash() {
    assert_eq!(
      Endpoint::parse("mqtts://broker:8883/").expect("parses"),
      Endpoint::parse("broker:8883").expect("parses")
    );
  }

  #[test]
  fn a_cleartext_scheme_is_refused_rather_than_upgraded() {
    let err = Endpoint::parse("mqtt://broker:1883").expect_err("no cleartext");
    assert!(format!("{err}").contains("mqtts"));
  }

  #[test]
  fn an_endpoint_without_a_port_is_refused() {
    assert!(Endpoint::parse("mqtts://broker").is_err());
    assert!(Endpoint::parse("mqtts://broker:").is_err());
    assert!(Endpoint::parse("mqtts://:8883").is_err());
  }
}
