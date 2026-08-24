//! Environment-variable configuration, with loft's one exception for the
//! secret: `PIGEONHOLE_SERVICE_SECRET` (the value of dovecote's
//! `COAP_SERVICE_SECRET`, the terminator service gate) is read from a
//! `LoadCredential=` file under `$CREDENTIALS_DIRECTORY` in preference to
//! the environment, so the production unit never carries it in
//! `/proc/self/environ`. The TLS key and chain arrive the same way, as paths
//! the unit points at `%d`.
//!
//! A missing secret or an unreadable key refuses to start rather than
//! serving a degraded listener. There is no cleartext fallback to degrade
//! to: without a usable certificate and key there is no listener at all.

use std::path::{Path, PathBuf};
use std::time::Duration;

/// Name of the shared secret on both sides. Dovecote calls its half
/// `COAP_SERVICE_SECRET`; the name is historical and the value is one gate,
/// so this is deliberately a different name for the same string.
const SERVICE_SECRET_VAR: &str = "PIGEONHOLE_SERVICE_SECRET";

#[derive(Clone)]
pub struct Config {
  /// TLS listen address. Dual-stack by default, which is what lets one
  /// listener serve the A and the AAAA record; an operator on a v4-only box
  /// sets `0.0.0.0:8883`.
  pub listen: String,
  /// Dovecote base URL, e.g. https://api.pidgeiot.com (prod) or
  /// http://127.0.0.1:8787 (dev wrangler).
  pub dovecote_url: String,
  /// Shared service secret gating dovecote's internal PSK route.
  pub service_secret: String,
  /// Server certificate chain, PEM, leaf first.
  pub tls_cert: PathBuf,
  /// Private key for the chain's leaf, PEM.
  pub tls_key: PathBuf,
  /// Positive PSK cache TTL.
  pub psk_cache_ttl: Duration,
}

/// Written by hand so the shared secret can never reach a log line, a panic
/// message, or an error report through a derived formatter.
impl std::fmt::Debug for Config {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("Config")
      .field("listen", &self.listen)
      .field("dovecote_url", &self.dovecote_url)
      .field("service_secret", &"<redacted>")
      .field("tls_cert", &self.tls_cert)
      .field("tls_key", &self.tls_key)
      .field("psk_cache_ttl", &self.psk_cache_ttl)
      .finish()
  }
}

impl Config {
  pub fn from_env() -> Result<Config, String> {
    let credentials_dir = std::env::var("CREDENTIALS_DIRECTORY").ok();
    let env_secret = std::env::var(SERVICE_SECRET_VAR).ok();
    let service_secret = resolve_service_secret(
      credentials_dir.as_deref().map(Path::new),
      env_secret.as_deref(),
    )?;
    if service_secret.trim().is_empty() {
      return Err(format!("{SERVICE_SECRET_VAR} is empty"));
    }

    let tls_cert = required_path("PIGEONHOLE_TLS_CERT")?;
    let tls_key = required_path("PIGEONHOLE_TLS_KEY")?;

    Ok(Config {
      listen: env_or("PIGEONHOLE_LISTEN", "[::]:8883"),
      dovecote_url: env_or("PIGEONHOLE_DOVECOTE_URL", "https://api.pidgeiot.com")
        .trim_end_matches('/')
        .to_string(),
      service_secret,
      tls_cert,
      tls_key,
      psk_cache_ttl: std::env::var("PIGEONHOLE_PSK_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(crate::psk::DEFAULT_POSITIVE_TTL),
    })
  }
}

/// A TLS path is required and must exist now: a broker that starts without a
/// servable chain would accept connections it can only fail, and the failure
/// would land on devices rather than on the deploy.
fn required_path(key: &str) -> Result<PathBuf, String> {
  let value = std::env::var(key).map_err(|_| format!("{key} is not set"))?;
  let path = PathBuf::from(value);
  if !path.is_file() {
    return Err(format!(
      "{key} points at {}, which is not a readable file",
      path.display()
    ));
  }
  Ok(path)
}

fn env_or(key: &str, default: &str) -> String {
  std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Resolves the shared dovecote secret, preferring a systemd credential file
/// over the plain env var. `credentials_dir` is `$CREDENTIALS_DIRECTORY`
/// when systemd set one up for this unit (any `LoadCredential=` makes it set
/// the directory, even if this particular credential was not configured, so
/// its presence alone does not guarantee the file exists); `env_secret` is
/// the variable's value. Both arrive as plain values rather than being read
/// here, so the precedence logic is testable without mutating process state.
///
/// A credential file wins when both are present: if a unit is set up with
/// `LoadCredential=`, that is the deployment's intended source of truth, and
/// honoring a stray env var instead would silently ignore it.
fn resolve_service_secret(
  credentials_dir: Option<&Path>,
  env_secret: Option<&str>,
) -> Result<String, String> {
  if let Some(dir) = credentials_dir {
    let path = dir.join(SERVICE_SECRET_VAR);
    match std::fs::read_to_string(&path) {
      // LoadCredential= copies the source file's bytes verbatim, trailing
      // newline included if the provisioned file has one, so trim it rather
      // than let an operator's shell habits become part of the credential.
      Ok(contents) => return Ok(contents.trim_end_matches('\n').to_string()),
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
        // The directory exists but nothing loaded this name; fall through.
      }
      Err(e) => {
        return Err(format!(
          "failed to read credential {SERVICE_SECRET_VAR} from {}: {e}",
          path.display()
        ));
      }
    }
  }
  env_secret
    .map(str::to_string)
    .ok_or_else(|| format!("{SERVICE_SECRET_VAR} is not set (the shared secret with dovecote)"))
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::atomic::{AtomicU64, Ordering};

  /// A fresh scratch directory per test: tests run in parallel in one
  /// process, so a shared fixed path would race.
  fn scratch_dir() -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir =
      std::env::temp_dir().join(format!("pigeonhole-config-test-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
  }

  #[test]
  fn the_secret_never_reaches_a_formatted_config() {
    let config = Config {
      listen: "[::]:8883".to_string(),
      dovecote_url: "https://api.pidgeiot.com".to_string(),
      service_secret: "the-actual-secret-value".to_string(),
      tls_cert: PathBuf::from("/run/credentials/cert.pem"),
      tls_key: PathBuf::from("/run/credentials/key.pem"),
      psk_cache_ttl: Duration::from_secs(60),
    };
    let rendered = format!("{config:?}");
    assert!(!rendered.contains("the-actual-secret-value"));
    assert!(rendered.contains("redacted"));
  }

  #[test]
  fn credential_file_wins_over_env_var() {
    let dir = scratch_dir();
    std::fs::write(dir.join(SERVICE_SECRET_VAR), "from-credential\n").expect("write credential");
    let resolved = resolve_service_secret(Some(&dir), Some("from-env")).expect("resolves");
    assert_eq!(resolved, "from-credential");
  }

  #[test]
  fn credential_file_trailing_newline_is_trimmed() {
    let dir = scratch_dir();
    std::fs::write(dir.join(SERVICE_SECRET_VAR), "shhh\n").expect("write credential");
    assert_eq!(
      resolve_service_secret(Some(&dir), None).expect("resolves"),
      "shhh"
    );
  }

  #[test]
  fn missing_credential_file_falls_back_to_env_var() {
    let dir = scratch_dir();
    let resolved = resolve_service_secret(Some(&dir), Some("from-env")).expect("falls back");
    assert_eq!(resolved, "from-env");
  }

  #[test]
  fn no_credentials_dir_uses_env_var() {
    assert_eq!(
      resolve_service_secret(None, Some("from-env")).expect("resolves"),
      "from-env"
    );
  }

  #[test]
  fn neither_source_is_an_error_naming_the_variable() {
    let err = resolve_service_secret(None, None).expect_err("must fail closed");
    assert!(err.contains(SERVICE_SECRET_VAR), "{err}");
  }

  #[test]
  fn an_unreadable_credential_file_is_an_error_not_a_silent_fallback() {
    // A directory where the file should be provokes a non-NotFound io error
    // without touching permissions.
    let dir = scratch_dir();
    std::fs::create_dir_all(dir.join(SERVICE_SECRET_VAR)).expect("shadow with a directory");
    let err = resolve_service_secret(Some(&dir), Some("from-env"))
      .expect_err("must not silently fall back");
    assert!(err.contains(SERVICE_SECRET_VAR), "{err}");
  }
}
