//! Client-side OpenSSL contexts for the two transport modes the broker
//! serves on one port: certificate mode (server chain verified against a CA
//! the caller supplies, or the system store; hostname verification on) and
//! PSK mode (identity = pigeon id, key = the UTF-8 bytes of
//! `tls_psk_secret`, TLS 1.2, the same PSK ciphersuites the broker offers).
//! Mirrors what the Zephyr device library configures through its sec tag so
//! a behaviour proven here with the Rust client holds for the firmware.

use std::path::Path;

use openssl::error::ErrorStack;
use openssl::ssl::{SslContext, SslContextBuilder, SslMethod, SslVerifyMode, SslVersion};

/// Constrained-device PSK suites, most-preferred first, identical to the
/// list the broker and `loft` offer. CCM_8 (8-byte tag) is the cellular-IoT
/// standard suite; the GCM and CBC variants cover clients built without CCM.
pub const PSK_CIPHER_LIST: &str = "PSK-AES128-CCM8:PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256";

/// Certificate mode. `ca_pem` pins the trust anchor (the dev CA locally, or
/// ISRG Root X2 against production); `None` falls back to the system store.
///
/// Peer verification is unconditional. A client that skips it turns the one
/// thing a certificate is for into decoration, and this client is also the
/// harness that proves the broker's chain is servable.
/// `tls12_only` caps the client at TLS 1.2, which is not a preference but a
/// description: Zephyr's MQTT transport opens an `IPPROTO_TLS_1_2` socket
/// unconditionally, so every first-party device is one of these. A broker
/// that only serves 1.3 certificate suites looks perfectly healthy until
/// such a client dials it, which is how this broker shipped a listener the
/// entire fleet could not have connected to.
pub fn certificate_context(
  ca_pem: Option<&Path>,
  tls12_only: bool,
) -> Result<SslContext, ErrorStack> {
  let mut builder = SslContextBuilder::new(SslMethod::tls_client())?;
  builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
  if tls12_only {
    builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
  }
  builder.set_verify(SslVerifyMode::PEER);
  match ca_pem {
    Some(path) => builder.set_ca_file(path)?,
    None => builder.set_default_verify_paths()?,
  }
  Ok(builder.build())
}

/// PSK mode. The identity and secret are captured by the handshake callback,
/// so one context serves exactly one pigeon; that suits a device, and the
/// harness builds a fresh context per connection anyway.
///
/// Capped at TLS 1.2 for the reason `loft` caps there: the classic PSK
/// ciphersuite family is a 1.2 concept, and 1.3's external-PSK story is a
/// different mechanism the constrained stacks on the other end do not speak.
pub fn psk_context(identity: &str, secret: &str) -> Result<SslContext, ErrorStack> {
  let identity = identity.to_string();
  let secret = secret.to_string();

  let mut builder = SslContextBuilder::new(SslMethod::tls_client())?;
  builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
  builder.set_max_proto_version(Some(SslVersion::TLS1_2))?;
  builder.set_cipher_list(PSK_CIPHER_LIST)?;
  // A PSK handshake authenticates through the shared key and carries no
  // certificate to verify.
  builder.set_verify(SslVerifyMode::NONE);

  builder.set_psk_client_callback(move |_ssl, _hint, identity_out, psk_out| {
    // Both buffers are OpenSSL's, sized by the library; a secret or identity
    // that does not fit is a provisioning error, and failing the handshake
    // is better than sending a truncated credential.
    let identity_bytes = identity.as_bytes();
    if identity_bytes.len() + 1 > identity_out.len() || secret.len() > psk_out.len() {
      return Ok(0);
    }
    identity_out[..identity_bytes.len()].copy_from_slice(identity_bytes);
    // OpenSSL reads the identity as a C string.
    identity_out[identity_bytes.len()] = 0;
    // The PSK bytes convention is the raw UTF-8 of the secret string, which
    // is what the Zephyr client registers with `tls_credential_add`.
    psk_out[..secret.len()].copy_from_slice(secret.as_bytes());
    Ok(secret.len())
  });

  Ok(builder.build())
}
