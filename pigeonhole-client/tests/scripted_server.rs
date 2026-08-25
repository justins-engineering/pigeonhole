//! The raw layer against a scripted TLS server: both handshakes the broker
//! will serve, and a CONNECT/CONNACK round trip on both protocol versions.
//!
//! The server here is scripted rather than a broker: it answers one exchange
//! and stops. That is the point of the raw layer, and it lets this test
//! prove the client's own TLS and framing before a broker exists to blame.

use std::pin::Pin;
use std::time::Duration;

use mqtt_proto::{Protocol, v3, v5};
use openssl::pkey::PKey;
use openssl::ssl::{Ssl, SslContext, SslContextBuilder, SslMethod, SslVersion};
use openssl::x509::X509;
use pigeonhole_client::raw::{Endpoint, RawConnection, Transport};
use pigeonhole_client::tls::PSK_CIPHER_LIST;
use pigeonhole_wire::framing;
use tokio::net::TcpListener;
use tokio_openssl::SslStream;

const IDENTITY: &str = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";
const SECRET: &str = "a-short-psk-secret";

struct DevCert {
  cert_pem: String,
  key_pem: String,
}

fn dev_cert() -> DevCert {
  let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("cert");
  DevCert {
    cert_pem: issued.cert.pem(),
    key_pem: issued.signing_key.serialize_pem(),
  }
}

fn certificate_server_context(cert: &DevCert) -> SslContext {
  let mut builder = SslContextBuilder::new(SslMethod::tls_server()).expect("builder");
  builder
    .set_min_proto_version(Some(SslVersion::TLS1_2))
    .expect("min version");
  let x509 = X509::from_pem(cert.cert_pem.as_bytes()).expect("cert pem");
  let key = PKey::private_key_from_pem(cert.key_pem.as_bytes()).expect("key pem");
  builder.set_certificate(&x509).expect("certificate");
  builder.set_private_key(&key).expect("private key");
  builder.build()
}

fn psk_server_context() -> SslContext {
  let mut builder = SslContextBuilder::new(SslMethod::tls_server()).expect("builder");
  builder
    .set_min_proto_version(Some(SslVersion::TLS1_2))
    .expect("min version");
  builder
    .set_max_proto_version(Some(SslVersion::TLS1_2))
    .expect("max version");
  builder
    .set_cipher_list(PSK_CIPHER_LIST)
    .expect("psk suites");
  builder.set_psk_server_callback(|_ssl, identity, psk_out| {
    let Some(identity) = identity else {
      return Ok(0);
    };
    if identity != IDENTITY.as_bytes() || SECRET.len() > psk_out.len() {
      return Ok(0);
    }
    psk_out[..SECRET.len()].copy_from_slice(SECRET.as_bytes());
    Ok(SECRET.len())
  });
  builder.build()
}

/// Accepts one connection, reads one packet, and answers with the given
/// bytes. Returns what it read so the test can assert on the CONNECT.
async fn scripted_once(
  listener: TcpListener,
  context: SslContext,
  reply: Vec<u8>,
) -> framing::RawPacket {
  let (tcp, _) = listener.accept().await.expect("accept");
  let ssl = Ssl::new(&context).expect("ssl");
  let mut stream = SslStream::new(ssl, tcp).expect("stream");
  Pin::new(&mut stream).accept().await.expect("handshake");
  let packet = framing::read_packet(&mut stream).await.expect("read");
  framing::write_packet(&mut stream, &reply)
    .await
    .expect("write");
  packet
}

async fn bind() -> (TcpListener, Endpoint) {
  let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
  let port = listener.local_addr().expect("addr").port();
  (
    listener,
    Endpoint {
      host: "127.0.0.1".to_string(),
      port,
    },
  )
}

#[tokio::test]
async fn certificate_mode_round_trips_a_v3_connect_and_connack() {
  let cert = dev_cert();
  let (listener, endpoint) = bind().await;

  let connack = v3::Packet::Connack(v3::Connack {
    session_present: false,
    code: v3::ConnectReturnCode::Accepted,
  });
  let reply = connack.encode().expect("encode").as_ref().to_vec();
  let server = tokio::spawn(scripted_once(
    listener,
    certificate_server_context(&cert),
    reply,
  ));

  let ca = tempfile(&cert.cert_pem);
  let mut client = RawConnection::connect(
    &endpoint,
    &Transport::Certificate {
      ca_pem: Some(ca.clone()),
      server_name: Some("localhost".to_string()),
      tls12_only: false,
    },
  )
  .await
  .expect("connects");

  let connect = v3::Packet::Connect(v3::Connect {
    protocol: Protocol::V311,
    clean_session: true,
    keep_alive: 60,
    client_id: IDENTITY.into(),
    last_will: None,
    username: Some(IDENTITY.into()),
    password: Some(b"device-token".as_slice().into()),
  });
  client.send_v3(&connect).await.expect("sends");

  let answered = client
    .recv_v3_within(Duration::from_secs(5))
    .await
    .expect("reads")
    .expect("a connack arrives");
  assert_eq!(answered, connack);

  let seen = server.await.expect("server task");
  assert_eq!(seen.connect_protocol().expect("protocol"), Protocol::V311);
  assert_eq!(seen.decode_v3().expect("decodes"), connect);

  std::fs::remove_file(&ca).ok();
}

#[tokio::test]
async fn certificate_mode_round_trips_a_v5_connect_and_connack() {
  let cert = dev_cert();
  let (listener, endpoint) = bind().await;

  let connack = v5::Packet::Connack(v5::Connack {
    session_present: false,
    reason_code: v5::ConnectReasonCode::Success,
    properties: v5::ConnackProperties {
      max_qos: Some(mqtt_proto::QoS::Level1),
      ..Default::default()
    },
  });
  let reply = connack.encode().expect("encode").as_ref().to_vec();
  let server = tokio::spawn(scripted_once(
    listener,
    certificate_server_context(&cert),
    reply,
  ));

  let ca = tempfile(&cert.cert_pem);
  let mut client = RawConnection::connect(
    &endpoint,
    &Transport::Certificate {
      ca_pem: Some(ca.clone()),
      server_name: Some("localhost".to_string()),
      tls12_only: false,
    },
  )
  .await
  .expect("connects");

  let connect = v5::Packet::Connect(v5::Connect {
    protocol: Protocol::V500,
    clean_start: true,
    keep_alive: 60,
    properties: Default::default(),
    client_id: IDENTITY.into(),
    last_will: None,
    username: Some(IDENTITY.into()),
    password: Some(b"device-token".as_slice().into()),
  });
  client.send_v5(&connect).await.expect("sends");

  let answered = client
    .recv_v5_within(Duration::from_secs(5))
    .await
    .expect("reads")
    .expect("a connack arrives");
  assert_eq!(answered, connack);

  let seen = server.await.expect("server task");
  assert_eq!(seen.connect_protocol().expect("protocol"), Protocol::V500);

  std::fs::remove_file(&ca).ok();
}

#[tokio::test]
async fn psk_mode_completes_a_handshake_and_carries_a_packet() {
  let (listener, endpoint) = bind().await;
  let reply = v3::Packet::Pingresp
    .encode()
    .expect("encode")
    .as_ref()
    .to_vec();
  let server = tokio::spawn(scripted_once(listener, psk_server_context(), reply));

  let mut client = RawConnection::connect(
    &endpoint,
    &Transport::Psk {
      identity: IDENTITY.to_string(),
      secret: SECRET.to_string(),
    },
  )
  .await
  .expect("psk handshake");

  client.send_v3(&v3::Packet::Pingreq).await.expect("sends");
  let answered = client
    .recv_v3_within(Duration::from_secs(5))
    .await
    .expect("reads")
    .expect("a pingresp arrives");
  assert_eq!(answered, v3::Packet::Pingresp);

  let seen = server.await.expect("server task");
  assert_eq!(seen.decode_v3().expect("decodes"), v3::Packet::Pingreq);
}

#[tokio::test]
async fn a_wrong_psk_secret_fails_the_handshake_before_any_mqtt() {
  let (listener, endpoint) = bind().await;
  let context = psk_server_context();
  tokio::spawn(async move {
    let Ok((tcp, _)) = listener.accept().await else {
      return;
    };
    let ssl = Ssl::new(&context).expect("ssl");
    let mut stream = SslStream::new(ssl, tcp).expect("stream");
    // The handshake is expected to fail; the server just has to try.
    let _ = Pin::new(&mut stream).accept().await;
  });

  let result = RawConnection::connect(
    &endpoint,
    &Transport::Psk {
      identity: IDENTITY.to_string(),
      secret: "not-the-secret".to_string(),
    },
  )
  .await;
  assert!(result.is_err(), "a bad PSK must not reach MQTT at all");
}

/// Writes a PEM to a unique path; the CA has to be a file because that is
/// how OpenSSL takes a trust anchor.
fn tempfile(contents: &str) -> std::path::PathBuf {
  use std::sync::atomic::{AtomicU64, Ordering};
  static COUNTER: AtomicU64 = AtomicU64::new(0);
  let n = COUNTER.fetch_add(1, Ordering::Relaxed);
  let path = std::env::temp_dir().join(format!(
    "pigeonhole-client-test-{}-{n}.pem",
    std::process::id()
  ));
  std::fs::write(&path, contents).expect("write pem");
  path
}
