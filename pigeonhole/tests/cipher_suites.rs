//! Which ciphersuites the listener will actually select, driven by OpenSSL
//! clients with explicit cipher lists rather than by the typed client.
//!
//! These exist because a suite can sit in a configured list and never be
//! chosen: OpenSSL's security level excludes `PSK-AES128-CCM8` at selection
//! time while leaving it in the parsed list, and `openssl ciphers` prints it
//! identically at every level. Nothing short of a negotiation answers the
//! question, so these negotiate.

mod harness;

use std::pin::Pin;

use harness::{Harness, PIGEON, PSK_SECRET};
use openssl::ssl::{Ssl, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

/// Completes a TLS 1.2 handshake with an explicit cipher list and reports
/// the suite that was negotiated, or `None` if the handshake failed.
async fn negotiated(h: &Harness, cipher_list: &str, psk: bool) -> Option<String> {
  let mut builder = SslContextBuilder::new(SslMethod::tls_client()).expect("builder");
  builder
    .set_min_proto_version(Some(SslVersion::TLS1_2))
    .expect("min");
  // Pinned to 1.2 on purpose: TLS 1.3 suites come from a different setter,
  // so an unpinned client would silently test the wrong thing.
  builder
    .set_max_proto_version(Some(SslVersion::TLS1_2))
    .expect("max");
  builder.set_cipher_list(cipher_list).expect("cipher list");

  if psk {
    let identity = PIGEON.to_string();
    let secret = PSK_SECRET.to_string();
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_psk_client_callback(move |_ssl, _hint, identity_out, psk_out| {
      let id = identity.as_bytes();
      identity_out[..id.len()].copy_from_slice(id);
      identity_out[id.len()] = 0;
      psk_out[..secret.len()].copy_from_slice(secret.as_bytes());
      Ok(secret.len())
    });
  } else {
    builder.set_ca_file(h.ca_pem()).expect("ca");
    builder.set_verify(SslVerifyMode::PEER);
  }

  let context = builder.build();
  let mut ssl = Ssl::new(&context).expect("ssl");
  if !psk {
    ssl.set_hostname("localhost").expect("sni");
    ssl.param_mut().set_host("localhost").expect("verify host");
  }

  let tcp = TcpStream::connect((h.endpoint.host.as_str(), h.endpoint.port))
    .await
    .expect("tcp");
  let mut stream = SslStream::new(ssl, tcp).expect("stream");
  match Pin::new(&mut stream).connect().await {
    Ok(()) => Some(
      stream
        .ssl()
        .current_cipher()
        .expect("cipher")
        .name()
        .to_string(),
    ),
    Err(_) => None,
  }
}

/// The suite the whole exercise is about. A constrained device offering only
/// CCM8 has to be servable, which means the security level has to be relaxed
/// for it, since the default level refuses to select it.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_offering_only_ccm8_gets_ccm8() {
  let h = Harness::start().await;
  assert_eq!(
    negotiated(&h, "PSK-AES128-CCM8:@SECLEVEL=0", true)
      .await
      .as_deref(),
    Some("PSK-AES128-CCM8"),
    "the constrained-device suite has to be selectable, not merely listed"
  );
  h.shutdown().await;
}

/// CCM8 is first in the configured PSK list and server preference is set, so
/// a client offering both gets CCM8. Before the relaxation this landed on
/// GCM, which looked like preference working and was actually CCM8 being
/// silently unselectable.
#[tokio::test(flavor = "multi_thread")]
async fn ccm8_beats_gcm_because_it_is_ranked_first() {
  let h = Harness::start().await;
  assert_eq!(
    negotiated(
      &h,
      "PSK-AES128-CCM8:PSK-AES128-GCM-SHA256:@SECLEVEL=0",
      true
    )
    .await
    .as_deref(),
    Some("PSK-AES128-CCM8"),
    "server preference decides, and CCM8 is ranked ahead of GCM"
  );
  h.shutdown().await;
}

/// The suites that already worked keep working, at whatever level they are
/// selected under.
#[tokio::test(flavor = "multi_thread")]
async fn the_other_psk_suites_are_unaffected() {
  let h = Harness::start().await;
  assert_eq!(
    negotiated(&h, "PSK-AES128-GCM-SHA256:@SECLEVEL=0", true)
      .await
      .as_deref(),
    Some("PSK-AES128-GCM-SHA256")
  );
  assert_eq!(
    negotiated(&h, "PSK-AES128-CBC-SHA256:@SECLEVEL=0", true)
      .await
      .as_deref(),
    Some("PSK-AES128-CBC-SHA256")
  );
  h.shutdown().await;
}

/// A certificate client offers no PSK suite, so nothing relaxes for it and
/// it negotiates exactly as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_client_is_untouched_by_the_psk_relaxation() {
  let h = Harness::start().await;
  assert_eq!(
    negotiated(&h, "ECDHE-ECDSA-AES128-GCM-SHA256", false)
      .await
      .as_deref(),
    Some("ECDHE-ECDSA-AES128-GCM-SHA256"),
    "the certificate path keeps working and keeps its own floor"
  );
  h.shutdown().await;
}

/// The floor is held where it matters: a certificate client asking for a
/// weak group is refused, which is the default security level doing its job
/// on a connection the relaxation must never reach.
#[tokio::test(flavor = "multi_thread")]
async fn a_certificate_client_offering_a_weak_group_is_still_refused() {
  let h = Harness::start().await;

  let mut builder = SslContextBuilder::new(SslMethod::tls_client()).expect("builder");
  builder
    .set_min_proto_version(Some(SslVersion::TLS1_2))
    .expect("min");
  builder
    .set_max_proto_version(Some(SslVersion::TLS1_2))
    .expect("max");
  builder
    .set_cipher_list("ECDHE-ECDSA-AES128-GCM-SHA256")
    .expect("cipher list");
  builder.set_ca_file(h.ca_pem()).expect("ca");
  builder.set_verify(SslVerifyMode::NONE);
  // A group the default security level will not accept. If the relaxation
  // ever leaked onto the certificate path, this would start succeeding.
  let weak_groups = builder.set_groups_list("P-192");

  if weak_groups.is_err() {
    // This OpenSSL will not even name the weak group, which is the same
    // property being asserted, reached earlier.
    h.shutdown().await;
    return;
  }

  let context = builder.build();
  let mut ssl = Ssl::new(&context).expect("ssl");
  ssl.set_hostname("localhost").expect("sni");
  let tcp = TcpStream::connect((h.endpoint.host.as_str(), h.endpoint.port))
    .await
    .expect("tcp");
  let mut stream = SslStream::new(ssl, tcp).expect("stream");
  assert!(
    Pin::new(&mut stream).connect().await.is_err(),
    "a weak group must stay refused on the certificate path"
  );
  h.shutdown().await;
}
