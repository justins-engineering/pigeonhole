//! The listener's OpenSSL context: one context serving both handshakes on
//! one port, TLS 1.2 minimum, so the ClientHello decides which credential a
//! device arrives with.
//!
//! Load-bearing details, each one a device behaviour rather than a
//! preference. PSK suites are listed first with server preference set, so a
//! TLS 1.2 client offering both PSK and ECDHE lands on PSK rather than on a
//! chain it has no room to verify. The maximum send fragment is dropped to
//! 4096 bytes so small-buffer mbedTLS builds can read the chain and a large
//! retained shadow; the `openssl` crate has no binding for that, so it is
//! one raw `SSL_CTX_ctrl` call. `SSL_MODE_RELEASE_BUFFERS` returns idle
//! buffers, which matters at a ceiling of thousands of mostly idle sessions.
//!
//! Two things the handshake checks settled, both worth stating because they
//! were assumed the other way. A TLS 1.3 capable client always lands on TLS
//! 1.3 and the certificate, whatever its 1.2 cipher list says, because
//! version negotiation happens before ciphersuite selection: the server
//! preference above decides between PSK and ECDHE only among TLS 1.2
//! clients, which is what the constrained devices are. And OpenSSL does not
//! route a TLS 1.3 external PSK through the 1.2 callback below, so no
//! session reaches this code by that path; a 1.3 client offering a PSK gets
//! an ordinary certificate handshake and, presenting no CONNECT password,
//! is refused there. Both are checked in `docs/infra/mqtt-broker.md`.
//!
//! A PSK handshake stashes (identity, bearer token) in the connection's
//! ex_data for `auth` to pick up. The callback is synchronous and may miss
//! the resolver cache, which is the one `block_in_place` in the process and
//! the reason the runtime is multi-threaded everywhere.

use std::path::Path;
use std::sync::{Arc, LazyLock};

use openssl::error::ErrorStack;
use openssl::ex_data::Index;
use openssl::ssl::{
  Ssl, SslContext, SslContextBuilder, SslMethod, SslMode, SslOptions, SslVersion,
};

use crate::psk::PskResolver;

/// Constrained-device PSK suites, most-preferred first. CCM_8 (8-byte tag)
/// is the cellular-IoT standard suite; the GCM and CBC variants cover
/// clients built without CCM. Same list `loft` offers, so a pigeon's PSK
/// works against either terminator.
pub const PSK_CIPHER_LIST: &str = "PSK-AES128-CCM8:PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256";

/// Records the size of the largest TLS record the server will emit.
/// OpenSSL's `SSL_CTX_set_max_send_fragment` has no binding in the `openssl`
/// crate, so the control code is named here from OpenSSL's own `ssl.h`.
const SSL_CTRL_SET_MAX_SEND_FRAGMENT: std::ffi::c_int = 52;

/// Small enough for the mbedTLS builds on the other end: `native_sim` caps
/// content at 7168 bytes, and a device that cannot read a record cannot read
/// the chain that record carries.
const MAX_SEND_FRAGMENT: usize = 4096;

/// After a successful PSK exchange the callback stashes (identity, bearer
/// token) here, so the session builds itself from what was actually
/// authenticated rather than from what the CONNECT then claims.
pub static PSK_SESSION_INDEX: LazyLock<Index<Ssl, (String, String)>> =
  LazyLock::new(|| Ssl::new_ex_index().expect("ssl ex index"));

/// Builds the listener's context. The certificate chain and key are
/// required: there is no cleartext listener to fall back to, so a broker
/// without a servable chain must not start.
pub fn build_listener_context(
  cert_chain: &Path,
  private_key: &Path,
  resolver: Arc<PskResolver>,
) -> Result<SslContext, ErrorStack> {
  let mut builder = SslContextBuilder::new(SslMethod::tls_server())?;
  builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;

  builder.set_certificate_chain_file(cert_chain)?;
  builder.set_private_key_file(private_key, openssl::ssl::SslFiletype::PEM)?;
  builder.check_private_key()?;

  // PSK suites first, and server preference set so that order is the one
  // that decides among TLS 1.2 clients. Without the preference flag the
  // client's order wins, and a dual-capable device would land on a
  // certificate suite it may have no room to verify.
  builder.set_cipher_list(&format!("{PSK_CIPHER_LIST}:DEFAULT"))?;
  builder.set_options(SslOptions::CIPHER_SERVER_PREFERENCE);

  builder.set_mode(SslMode::RELEASE_BUFFERS);
  set_max_send_fragment(&mut builder, MAX_SEND_FRAGMENT)?;

  builder.set_psk_server_callback(move |ssl, identity, psk_out| {
    psk_callback(&resolver, ssl, identity, psk_out)
  });

  Ok(builder.build())
}

/// One `SSL_CTX_ctrl` call standing in for the binding the crate does not
/// have. The pointer comes from the builder itself and the call only records
/// a size, so there is nothing here to outlive the context.
fn set_max_send_fragment(builder: &mut SslContextBuilder, bytes: usize) -> Result<(), ErrorStack> {
  let result = unsafe {
    openssl_sys::SSL_CTX_ctrl(
      builder.as_ptr(),
      SSL_CTRL_SET_MAX_SEND_FRAGMENT,
      bytes as std::ffi::c_long,
      std::ptr::null_mut(),
    )
  };
  if result == 1 {
    Ok(())
  } else {
    Err(ErrorStack::get())
  }
}

fn psk_callback(
  resolver: &PskResolver,
  ssl: &mut openssl::ssl::SslRef,
  identity: Option<&[u8]>,
  psk_out: &mut [u8],
) -> Result<usize, ErrorStack> {
  // Returning Ok(0) aborts the handshake. OpenSSL answers an unknown
  // identity with alert 115 and a wrong key with a bad-record-mac alert, so
  // a prober can tell the two apart; that is OpenSSL's behaviour rather than
  // a choice available here, and it costs nothing, because a pigeon id is a
  // 256-bit Durable Object id and there is nothing to enumerate.
  let Some(identity) = identity else {
    return Ok(0);
  };
  let Ok(identity) = std::str::from_utf8(identity) else {
    tracing::debug!("rejecting a non-UTF-8 PSK identity");
    return Ok(0);
  };
  // Checked locally before any lookup, so garbage costs no upstream call and
  // never reaches a log line raw.
  if !crate::auth::identity_shape_ok(identity) {
    tracing::debug!("rejecting a PSK identity that is not a pigeon id");
    return Ok(0);
  }

  // A cached blocking lookup against dovecote. `block_in_place` is what lets
  // a synchronous handshake callback do it without stalling the runtime.
  let resolved = tokio::task::block_in_place(|| resolver.resolve(identity));
  let Some(entry) = resolved else {
    tracing::info!(identity, "PSK identity rejected");
    return Ok(0);
  };

  // The PSK bytes convention is the raw UTF-8 of the secret string, matching
  // what the Zephyr device library registers with `tls_credential_add`.
  let len = entry.psk.len();
  if len > psk_out.len() {
    tracing::error!(identity, "PSK secret longer than OpenSSL's PSK buffer");
    return Ok(0);
  }
  psk_out[..len].copy_from_slice(entry.psk.as_bytes());
  ssl.set_ex_data(*PSK_SESSION_INDEX, (identity.to_string(), entry.token));
  Ok(len)
}

/// Pulls the handshake-authenticated (identity, bearer token) pair off a
/// completed connection. `None` means the connection arrived by certificate,
/// and its credentials are whatever the CONNECT carries.
pub fn psk_session(ssl: &openssl::ssl::SslRef) -> Option<(String, String)> {
  ssl.ex_data(*PSK_SESSION_INDEX).cloned()
}
