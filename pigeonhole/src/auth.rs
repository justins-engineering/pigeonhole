//! Turns what the transport established and what the CONNECT packet claims
//! into one authenticated pigeon, or a refusal.
//!
//! The identity's shape is checked locally first (64 lowercase hex), so
//! garbage never costs an upstream call or lands raw in a log line, and
//! every place the identity may appear (PSK identity, username, client id)
//! must agree. The verification itself is not here: it is the device
//! WebSocket upgrade with the presented bearer token, one round trip that
//! authenticates the session, opens its feed, and seeds the retained shadow
//! at the same time (`docs/design.md` ADR D).

use crate::proto::ConnackOutcome;

/// A pigeon id is the hex form of its Durable Object id.
pub const PIGEON_ID_LEN: usize = 64;

/// Why a CONNECT was refused, in the vocabulary the brakes and the CONNACK
/// mapping both need. Kept apart from `ConnackOutcome` because one extra
/// distinction matters here that the wire does not carry: whether the
/// refusal is the credential's fault, and therefore cacheable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRefusal {
  /// The credential was rejected, or was not a credential at all.
  BadCredentials,
  /// The identity resolves but is refused by policy.
  NotAuthorized,
  /// The identity was missing, malformed, or disagreed with itself.
  ClientIdNotValid,
  /// The edge could not be reached, erred, or answered with something that
  /// was not an auth verdict (an edge-mitigation page, say). Retryable, and
  /// deliberately not the same thing as a credential failure.
  ServerUnavailable,
  /// The account's message allowance is spent. Valid credentials.
  QuotaExceeded,
}

impl AuthRefusal {
  /// Whether this refusal will still be true in ten seconds. Only permanent
  /// refusals go in the negative cache: caching a server-side blip would
  /// keep a healthy device out for the TTL after the blip had passed.
  pub fn is_permanent(self) -> bool {
    match self {
      AuthRefusal::BadCredentials | AuthRefusal::NotAuthorized | AuthRefusal::ClientIdNotValid => {
        true
      }
      AuthRefusal::ServerUnavailable | AuthRefusal::QuotaExceeded => false,
    }
  }

  pub fn connack(self) -> ConnackOutcome {
    match self {
      AuthRefusal::BadCredentials => ConnackOutcome::BadCredentials,
      AuthRefusal::NotAuthorized => ConnackOutcome::NotAuthorized,
      AuthRefusal::ClientIdNotValid => ConnackOutcome::ClientIdNotValid,
      AuthRefusal::ServerUnavailable => ConnackOutcome::ServerUnavailable,
      AuthRefusal::QuotaExceeded => ConnackOutcome::QuotaExceeded,
    }
  }

  /// The stats line groups refusals by cause; an edge-shaped answer is
  /// counted separately so a WAF event does not read as a fleet credential
  /// failure.
  pub fn label(self) -> &'static str {
    match self {
      AuthRefusal::BadCredentials => "bad-credentials",
      AuthRefusal::NotAuthorized => "not-authorized",
      AuthRefusal::ClientIdNotValid => "bad-identity",
      AuthRefusal::ServerUnavailable => "edge-unavailable",
      AuthRefusal::QuotaExceeded => "allowance-spent",
    }
  }
}

/// True for exactly the shape a pigeon id has. Lowercase only: the ids
/// dovecote mints are lowercase, and accepting mixed case would let two
/// spellings of one pigeon look like two identities to the brakes.
pub fn identity_shape_ok(identity: &str) -> bool {
  identity.len() == PIGEON_ID_LEN
    && identity
      .bytes()
      .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The identity a CONNECT settled on, once the three places it may appear
/// have been reconciled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity(pub String);

/// Reconciles the identity across the PSK handshake, the username and the
/// client id. All the ones that are present must agree; an absent one says
/// nothing.
///
/// Which refusal a malformed identity earns depends on where it arrived: as
/// a username it is a credential problem, and as a client id it is an
/// identifier problem. The distinction is what tells a device whether to
/// re-provision or to fix its client id.
pub fn resolve_identity(
  psk_identity: Option<&str>,
  username: Option<&str>,
  client_id: &str,
) -> Result<Identity, AuthRefusal> {
  let client_id = if client_id.is_empty() {
    None
  } else {
    Some(client_id)
  };
  let candidates: Vec<&str> = [psk_identity, username, client_id]
    .into_iter()
    .flatten()
    .collect();

  let Some(first) = candidates.first().copied() else {
    return Err(AuthRefusal::ClientIdNotValid);
  };
  if candidates.iter().any(|c| *c != first) {
    return Err(AuthRefusal::ClientIdNotValid);
  }
  if !identity_shape_ok(first) {
    // A PSK identity that got this far already resolved upstream, so a
    // malformed one can only have come from the CONNECT itself.
    return Err(if psk_identity.is_none() && username.is_some() {
      AuthRefusal::BadCredentials
    } else {
      AuthRefusal::ClientIdNotValid
    });
  }
  Ok(Identity(first.to_string()))
}

/// Classifies the answer the device WebSocket upgrade gave, which is what
/// authenticates a session.
///
/// A 403 is split by its body: dovecote's own refusals are plain text,
/// while an edge-mitigation page is HTML with mitigation headers. Reading a
/// WAF challenge as a credential failure would send a whole fleet off to
/// re-provision over an edge event, so it maps with 5xx to retryable.
pub fn classify_upgrade(status: u16, body_looks_like_html: bool) -> Result<(), AuthRefusal> {
  match status {
    101 => Ok(()),
    401 => Err(AuthRefusal::BadCredentials),
    403 if body_looks_like_html => Err(AuthRefusal::ServerUnavailable),
    403 => Err(AuthRefusal::NotAuthorized),
    429 => Err(AuthRefusal::QuotaExceeded),
    _ => Err(AuthRefusal::ServerUnavailable),
  }
}

/// Whether a response body reads as an edge-mitigation page rather than as
/// one of dovecote's plain-text refusals.
pub fn looks_like_html(body: &[u8]) -> bool {
  let head = &body[..body.len().min(256)];
  let text = String::from_utf8_lossy(head).to_ascii_lowercase();
  text.contains("<!doctype html") || text.contains("<html")
}

#[cfg(test)]
mod tests {
  use super::*;

  const ID: &str = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";
  const OTHER: &str = "bb11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";

  #[test]
  fn only_a_64_character_lowercase_hex_string_is_an_identity() {
    assert!(identity_shape_ok(ID));
    assert!(!identity_shape_ok(&ID.to_uppercase()));
    assert!(!identity_shape_ok(&ID[..63]));
    assert!(!identity_shape_ok(&format!("{ID}0")));
    assert!(!identity_shape_ok(""));
    assert!(!identity_shape_ok(&"g".repeat(64)));
    assert!(!identity_shape_ok(&format!("{}../", &ID[..61])));
  }

  #[test]
  fn a_certificate_session_takes_its_identity_from_the_username() {
    assert_eq!(
      resolve_identity(None, Some(ID), "").expect("resolves"),
      Identity(ID.to_string())
    );
    assert_eq!(
      resolve_identity(None, Some(ID), ID).expect("resolves"),
      Identity(ID.to_string())
    );
  }

  #[test]
  fn a_psk_session_may_leave_the_username_out_entirely() {
    assert_eq!(
      resolve_identity(Some(ID), None, "").expect("resolves"),
      Identity(ID.to_string())
    );
    assert_eq!(
      resolve_identity(Some(ID), Some(ID), ID).expect("resolves"),
      Identity(ID.to_string())
    );
  }

  #[test]
  fn a_client_id_alone_is_enough() {
    assert_eq!(
      resolve_identity(None, None, ID).expect("resolves"),
      Identity(ID.to_string())
    );
  }

  #[test]
  fn any_disagreement_between_the_three_places_refuses() {
    for (psk, username, client_id) in [
      (Some(ID), Some(OTHER), ""),
      (Some(ID), None, OTHER),
      (None, Some(ID), OTHER),
      (Some(ID), Some(ID), OTHER),
    ] {
      assert_eq!(
        resolve_identity(psk, username, client_id),
        Err(AuthRefusal::ClientIdNotValid),
        "{psk:?}/{username:?}/{client_id:?} must not resolve"
      );
    }
  }

  #[test]
  fn no_identity_anywhere_refuses_as_an_identifier_problem() {
    assert_eq!(
      resolve_identity(None, None, ""),
      Err(AuthRefusal::ClientIdNotValid)
    );
  }

  #[test]
  fn a_malformed_identity_is_named_by_where_it_arrived() {
    assert_eq!(
      resolve_identity(None, Some("not-a-pigeon"), ""),
      Err(AuthRefusal::BadCredentials),
      "arriving as a username makes it a credential problem"
    );
    assert_eq!(
      resolve_identity(None, None, "not-a-pigeon"),
      Err(AuthRefusal::ClientIdNotValid),
      "arriving only as a client id makes it an identifier problem"
    );
  }

  #[test]
  fn refusals_that_could_change_in_a_moment_are_not_cacheable() {
    assert!(AuthRefusal::BadCredentials.is_permanent());
    assert!(AuthRefusal::NotAuthorized.is_permanent());
    assert!(AuthRefusal::ClientIdNotValid.is_permanent());
    assert!(!AuthRefusal::ServerUnavailable.is_permanent());
    assert!(
      !AuthRefusal::QuotaExceeded.is_permanent(),
      "an allowance resets, and a plan change resets it sooner"
    );
  }

  #[test]
  fn the_upgrade_status_decides_the_refusal() {
    assert_eq!(classify_upgrade(101, false), Ok(()));
    assert_eq!(
      classify_upgrade(401, false),
      Err(AuthRefusal::BadCredentials)
    );
    assert_eq!(
      classify_upgrade(403, false),
      Err(AuthRefusal::NotAuthorized)
    );
    assert_eq!(
      classify_upgrade(429, false),
      Err(AuthRefusal::QuotaExceeded)
    );
    for status in [500, 502, 503, 504, 400, 404] {
      assert_eq!(
        classify_upgrade(status, false),
        Err(AuthRefusal::ServerUnavailable),
        "{status} is not an auth verdict"
      );
    }
  }

  #[test]
  fn an_html_bodied_403_is_edge_security_rather_than_a_credential_failure() {
    assert_eq!(
      classify_upgrade(403, true),
      Err(AuthRefusal::ServerUnavailable)
    );
    assert!(looks_like_html(b"<!DOCTYPE html><html><head>"));
    assert!(looks_like_html(b"\n  <html lang=\"en\">"));
    assert!(!looks_like_html(b"unauthorized"));
    assert!(!looks_like_html(b""));
  }
}
