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

use foreign_types::ForeignTypeRef;
use openssl::error::ErrorStack;
use openssl::ex_data::Index;
use openssl::ssl::{
  ClientHelloResponse, Ssl, SslAlert, SslContext, SslContextBuilder, SslMethod, SslMode,
  SslOptions, SslRef, SslVersion,
};

use crate::psk::PskResolver;

/// Constrained-device PSK suites, most-preferred first. CCM_8 (8-byte tag)
/// is the cellular-IoT standard suite; the GCM and CBC variants cover
/// clients built without CCM. Same list `loft` offers, so a pigeon's PSK
/// works against either terminator.
pub const PSK_CIPHER_LIST: &str = "PSK-AES128-CCM8:PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256";

/// TLS 1.2 certificate suites, named one by one rather than deferred to
/// `DEFAULT`.
///
/// `DEFAULT` cannot be appended to a list: OpenSSL treats it as an
/// initialiser, so anything before it survives and it itself contributes
/// nothing. A list ending in `:DEFAULT` therefore offers only the suites
/// spelled out ahead of it, which for this broker meant PSK only, and every
/// TLS 1.2 certificate client got a handshake failure. TLS 1.3 clients were
/// unaffected because their suites come from a different setter, which is
/// exactly why that hole survived a certificate handshake check.
///
/// ECDSA first because the production chain is all-ECDSA (P-256 leaf under
/// an ECDSA intermediate anchored at ISRG Root X2). The RSA pair is
/// headroom for a self-hosted deployment whose certificate is RSA.
pub const CERT_CIPHER_LIST: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-CHACHA20-POLY1305:\
ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES256-GCM-SHA384";

// Reads the ciphersuites a ClientHello offered, as raw two-byte code
// points. The `openssl` crate binds the ClientHello callback but not this
// accessor, so it is one hand-written extern, the same shim pattern the
// maximum-send-fragment control below uses.
unsafe extern "C" {
  fn SSL_client_hello_get0_ciphers(
    s: *mut openssl_sys::SSL,
    out: *mut *const std::ffi::c_uchar,
  ) -> usize;
}

/// `TLS_PSK_WITH_AES_128_CCM_8`. The only suite this broker serves that
/// OpenSSL's default security level refuses to *select*, which is why it is
/// the only one that costs a relaxation.
const PSK_AES128_CCM8: u16 = 0xC0A8;

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
  builder.set_cipher_list(&format!("{PSK_CIPHER_LIST}:{CERT_CIPHER_LIST}"))?;
  builder.set_options(SslOptions::CIPHER_SERVER_PREFERENCE);

  builder.set_mode(SslMode::RELEASE_BUFFERS);
  set_max_send_fragment(&mut builder, MAX_SEND_FRAGMENT)?;

  // Relax the security level for the connections that need it, and only
  // those. See `relaxes_security_level` for what "need" means and why the
  // certificate path is untouched.
  builder.set_client_hello_callback(relax_for_ccm8);

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

/// OpenSSL's default security level will not *select* `PSK-AES128-CCM8`,
/// though it parses the name and lists it. Serving the constrained-device
/// suite therefore needs the level lowered, and lowering it on the context
/// would lower it for the certificate handshakes sharing that context too.
///
/// This lowers it per connection instead, and only for a ClientHello that
/// actually offered CCM8. A certificate client never does, so its floor is
/// the default one and nothing about its handshake changes. The one
/// theoretical leak, a hello offering CCM8 that then negotiates a
/// certificate suite at the lowered floor, cannot happen: CCM8 is ranked
/// first under server preference, so a hello offering it selects it.
fn relax_for_ccm8(
  ssl: &mut SslRef,
  _alert: &mut SslAlert,
) -> Result<ClientHelloResponse, ErrorStack> {
  if offered_ciphers(ssl).is_some_and(relaxes_security_level) {
    ssl.set_security_level(0);
  }
  Ok(ClientHelloResponse::SUCCESS)
}

/// The raw offered-cipher bytes from the ClientHello being processed.
fn offered_ciphers(ssl: &SslRef) -> Option<&[u8]> {
  let mut out: *const std::ffi::c_uchar = std::ptr::null();
  // Safety: called only from the ClientHello callback, where OpenSSL
  // guarantees the hello is being parsed and the returned pointer is valid
  // for the duration of the callback. The slice borrows from `ssl` and
  // cannot outlive it.
  let len = unsafe { SSL_client_hello_get0_ciphers(ssl.as_ptr(), &mut out) };
  if out.is_null() || len == 0 {
    return None;
  }
  Some(unsafe { std::slice::from_raw_parts(out, len) })
}

/// Whether an offered-cipher list contains a suite that only a lowered
/// security level can select. Split out from the callback because this is
/// where the parsing lives, and parsing two-byte big-endian code points out
/// of an attacker-supplied buffer is the part worth testing directly.
fn relaxes_security_level(offered: &[u8]) -> bool {
  offered
    .chunks_exact(2)
    .any(|code| u16::from_be_bytes([code[0], code[1]]) == PSK_AES128_CCM8)
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

#[cfg(test)]
mod tests {
  use super::*;

  /// The code points, from the IANA registry and confirmed against
  /// OpenSSL's own table. `0x00A8` is GCM, not CCM8; the two are one byte
  /// apart in the prefix and reading one as the other has already cost this
  /// project a wrong conclusion.
  const CCM8: [u8; 2] = [0xC0, 0xA8];
  const GCM: [u8; 2] = [0x00, 0xA8];
  const CBC: [u8; 2] = [0x00, 0xAE];
  const ECDHE_ECDSA_AES128_GCM: [u8; 2] = [0xC0, 0x2B];

  fn offered(suites: &[[u8; 2]]) -> Vec<u8> {
    suites.iter().flatten().copied().collect()
  }

  #[test]
  fn only_a_hello_offering_ccm8_earns_the_relaxation() {
    assert!(relaxes_security_level(&offered(&[CCM8])));
    assert!(relaxes_security_level(&offered(&[GCM, CCM8, CBC])));
    assert!(relaxes_security_level(&offered(&[
      ECDHE_ECDSA_AES128_GCM,
      CCM8
    ])));
  }

  #[test]
  fn a_certificate_only_hello_keeps_the_default_floor() {
    assert!(!relaxes_security_level(&offered(&[ECDHE_ECDSA_AES128_GCM])));
  }

  #[test]
  fn the_psk_suites_that_already_worked_earn_nothing() {
    // GCM and CBC are selectable at the default level, so they cost no
    // relaxation and must not trigger one.
    assert!(!relaxes_security_level(&offered(&[GCM])));
    assert!(!relaxes_security_level(&offered(&[CBC])));
    assert!(!relaxes_security_level(&offered(&[GCM, CBC])));
  }

  #[test]
  fn the_gcm_code_point_is_not_mistaken_for_ccm8() {
    assert!(
      !relaxes_security_level(&offered(&[GCM])),
      "0x00A8 is TLS_PSK_WITH_AES_128_GCM_SHA256, not CCM8"
    );
  }

  #[test]
  fn a_truncated_or_empty_list_is_read_without_panicking() {
    assert!(!relaxes_security_level(&[]));
    // An odd trailing byte is malformed; chunks_exact drops it rather than
    // reading past the end.
    assert!(!relaxes_security_level(&[0xC0]));
    assert!(relaxes_security_level(&[0xC0, 0xA8, 0xC0]));
  }

  #[test]
  fn a_byte_swapped_ccm8_does_not_match() {
    // Guards the endianness: 0xA8C0 is not a suite this broker serves.
    assert!(!relaxes_security_level(&[0xA8, 0xC0]));
  }
}
