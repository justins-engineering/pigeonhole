//! PSK identity to (secret, bearer token) resolution against dovecote's
//! service-internal route (`GET /internal/device-psk/:pigeon_id`), gated by
//! `PIGEONHOLE_SERVICE_SECRET` and, on dovecote's side, by the VPS egress
//! address. A copy of loft's resolver: blocking `ureq` client, 60 s positive
//! and 10 s negative caches, and a stale-positive grace while dovecote is
//! unreachable.
//!
//! Staleness after a rotation cuts both ways, and neither way leaks: a
//! device still running the OLD PSK completes the handshake against a stale
//! entry, but the session's device WebSocket upgrade then 401s with the
//! revoked token, the entry is evicted and the CONNECT is refused; a device
//! that already has the NEW PSK fails the handshake until the entry expires,
//! which is availability-only and self-heals. There is deliberately no
//! push-invalidation path from dovecote: the design is one-directional, and
//! the window is not worth a channel.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

/// Body of a successful lookup, paired with `capsules::CoapPskLookup`. The
/// route's original CoAP-flavoured name is served alongside the neutral one;
/// this is the neutral caller.
///
/// `identity` is never read (the caller already knows what it asked about)
/// and is kept so the struct states the whole message; unknown fields are
/// ignored so dovecote can add to the response without breaking the broker.
#[derive(Debug, Clone, Deserialize)]
struct DevicePskLookup {
  #[allow(dead_code)]
  identity: String,
  secret: String,
  token: String,
}

/// One resolved credential pair: the PSK that keys the handshake and the
/// bearer token presented upstream on the session's behalf. They are
/// deliberately distinct strings, minted and rotated together: the token is
/// far longer than the 32 bytes constrained PSK stacks are guaranteed to
/// accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PskEntry {
  pub psk: String,
  pub token: String,
}

/// Blocking lookup source. `Ok(None)` is an authoritative "no such
/// identity"; `Err` is a transport or 5xx failure, treated as indeterminate
/// rather than negative so a dovecote blip cannot negative-cache a real
/// pigeon.
pub trait PskSource: Send + Sync {
  fn fetch(&self, identity: &str) -> Result<Option<PskEntry>, String>;
}

impl<F> PskSource for F
where
  F: Fn(&str) -> Result<Option<PskEntry>, String> + Send + Sync,
{
  fn fetch(&self, identity: &str) -> Result<Option<PskEntry>, String> {
    self(identity)
  }
}

/// Dovecote-backed source. Synchronous by design: a TLS PSK callback is a
/// synchronous callback invoked mid-handshake, so callers on the tokio
/// runtime wrap [`PskResolver::resolve`] in `block_in_place`.
pub struct DovecotePskSource {
  agent: ureq::Agent,
  base_url: String,
  service_secret: String,
}

impl DovecotePskSource {
  pub fn new(base_url: &str, service_secret: String) -> DovecotePskSource {
    DovecotePskSource {
      agent: ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .user_agent(concat!("pigeonhole/", env!("CARGO_PKG_VERSION")))
        .build(),
      base_url: base_url.trim_end_matches('/').to_string(),
      service_secret,
    }
  }
}

impl PskSource for DovecotePskSource {
  fn fetch(&self, identity: &str) -> Result<Option<PskEntry>, String> {
    let url = format!("{}/internal/device-psk/{}", self.base_url, identity);
    match self
      .agent
      .get(&url)
      .set("Authorization", &format!("Bearer {}", self.service_secret))
      .call()
    {
      Ok(resp) => {
        let lookup: DevicePskLookup = resp
          .into_json()
          .map_err(|e| format!("psk lookup body parse: {e}"))?;
        Ok(Some(PskEntry {
          psk: lookup.secret,
          token: lookup.token,
        }))
      }
      // 404: a known-shape id with no PSK-bearing pigeon behind it. 400: a
      // string that cannot be a pigeon id at all. Both are authoritative, so
      // a garbage-identity flood cannot bypass the negative cache.
      Err(ureq::Error::Status(404 | 400, _)) => Ok(None),
      // 401/403 mean OUR service secret or allowlist entry is wrong, which
      // is indeterminate for the device and must not poison the cache for a
      // real identity.
      Err(ureq::Error::Status(status, _)) => Err(format!("psk lookup: upstream {status}")),
      Err(e) => Err(format!("psk lookup transport: {e}")),
    }
  }
}

enum Entry {
  Known { entry: PskEntry, fetched: Instant },
  Unknown { fetched: Instant },
}

pub struct PskResolver {
  source: Box<dyn PskSource>,
  cache: Mutex<HashMap<String, Entry>>,
  positive_ttl: Duration,
  negative_ttl: Duration,
  /// How long a stale positive may still be served while the source is
  /// unreachable: availability over freshness for a transient dovecote blip,
  /// bounded so a rotated PSK cannot linger indefinitely.
  stale_grace: Duration,
}

pub const DEFAULT_POSITIVE_TTL: Duration = Duration::from_secs(60);
pub const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(10);
pub const DEFAULT_STALE_GRACE: Duration = Duration::from_secs(300);

impl PskResolver {
  pub fn new(source: Box<dyn PskSource>, positive_ttl: Duration) -> PskResolver {
    PskResolver {
      source,
      cache: Mutex::new(HashMap::new()),
      positive_ttl,
      negative_ttl: DEFAULT_NEGATIVE_TTL,
      stale_grace: DEFAULT_STALE_GRACE,
    }
  }

  /// Resolves an identity to its credential pair. `None` means "reject the
  /// handshake": unknown identity, or source unreachable with no usable
  /// stale entry.
  pub fn resolve(&self, identity: &str) -> Option<PskEntry> {
    let now = Instant::now();

    {
      let cache = self.cache.lock().expect("psk cache lock");
      match cache.get(identity) {
        Some(Entry::Known { entry, fetched })
          if now.duration_since(*fetched) < self.positive_ttl =>
        {
          return Some(entry.clone());
        }
        Some(Entry::Unknown { fetched }) if now.duration_since(*fetched) < self.negative_ttl => {
          return None;
        }
        _ => {}
      }
    }

    match self.source.fetch(identity) {
      Ok(Some(entry)) => {
        self.cache.lock().expect("psk cache lock").insert(
          identity.to_string(),
          Entry::Known {
            entry: entry.clone(),
            fetched: now,
          },
        );
        Some(entry)
      }
      Ok(None) => {
        self
          .cache
          .lock()
          .expect("psk cache lock")
          .insert(identity.to_string(), Entry::Unknown { fetched: now });
        None
      }
      Err(e) => {
        tracing::warn!(identity, error = %e, "PSK source unreachable");
        let cache = self.cache.lock().expect("psk cache lock");
        match cache.get(identity) {
          Some(Entry::Known { entry, fetched })
            if now.duration_since(*fetched) < self.stale_grace =>
          {
            tracing::warn!(identity, "serving stale PSK entry (source unreachable)");
            Some(entry.clone())
          }
          _ => None,
        }
      }
    }
  }

  /// Drops an entry after its token was refused upstream, so the next
  /// handshake for this identity refetches rather than repeating a rotation
  /// the cache has not noticed yet.
  pub fn evict(&self, identity: &str) {
    self.cache.lock().expect("psk cache lock").remove(identity);
  }

  #[cfg(test)]
  fn with_ttls(
    source: Box<dyn PskSource>,
    positive_ttl: Duration,
    negative_ttl: Duration,
    stale_grace: Duration,
  ) -> PskResolver {
    PskResolver {
      source,
      cache: Mutex::new(HashMap::new()),
      positive_ttl,
      negative_ttl,
      stale_grace,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::Arc;
  use std::sync::atomic::{AtomicUsize, Ordering};

  fn entry(psk: &str) -> PskEntry {
    PskEntry {
      psk: psk.to_string(),
      token: format!("token-{psk}"),
    }
  }

  fn counting_source(
    hits: Arc<AtomicUsize>,
    result: impl Fn(&str) -> Result<Option<PskEntry>, String> + Send + Sync + 'static,
  ) -> Box<dyn PskSource> {
    Box::new(move |identity: &str| {
      hits.fetch_add(1, Ordering::SeqCst);
      result(identity)
    })
  }

  #[test]
  fn positive_lookups_are_cached() {
    let hits = Arc::new(AtomicUsize::new(0));
    let resolver = PskResolver::new(
      counting_source(hits.clone(), |_| Ok(Some(entry("secret1")))),
      Duration::from_secs(60),
    );
    assert_eq!(resolver.resolve("pigeon-a"), Some(entry("secret1")));
    assert_eq!(resolver.resolve("pigeon-a"), Some(entry("secret1")));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn positive_entries_expire() {
    let hits = Arc::new(AtomicUsize::new(0));
    let resolver = PskResolver::with_ttls(
      counting_source(hits.clone(), |_| Ok(Some(entry("s")))),
      Duration::ZERO,
      Duration::ZERO,
      Duration::ZERO,
    );
    resolver.resolve("a");
    resolver.resolve("a");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
  }

  #[test]
  fn negative_lookups_are_cached_briefly() {
    let hits = Arc::new(AtomicUsize::new(0));
    let resolver = PskResolver::new(
      counting_source(hits.clone(), |_| Ok(None)),
      Duration::from_secs(60),
    );
    assert_eq!(resolver.resolve("nope"), None);
    assert_eq!(resolver.resolve("nope"), None);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn source_error_without_stale_entry_rejects_and_is_not_cached() {
    let hits = Arc::new(AtomicUsize::new(0));
    let resolver = PskResolver::new(
      counting_source(hits.clone(), |_| Err("down".into())),
      Duration::from_secs(60),
    );
    assert_eq!(resolver.resolve("a"), None);
    assert_eq!(resolver.resolve("a"), None);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
  }

  #[test]
  fn source_error_serves_stale_positive_within_grace() {
    let hits = Arc::new(AtomicUsize::new(0));
    let flaky_hits = hits.clone();
    let source = Box::new(move |_: &str| {
      let n = flaky_hits.fetch_add(1, Ordering::SeqCst);
      if n == 0 {
        Ok(Some(entry("orig")))
      } else {
        Err("down".into())
      }
    });
    let resolver = PskResolver::with_ttls(
      source,
      Duration::ZERO,
      Duration::ZERO,
      Duration::from_secs(300),
    );
    assert_eq!(resolver.resolve("a"), Some(entry("orig")));
    assert_eq!(resolver.resolve("a"), Some(entry("orig")));
    assert_eq!(hits.load(Ordering::SeqCst), 2);
  }

  #[test]
  fn eviction_after_a_refused_token_forces_a_refetch() {
    let hits = Arc::new(AtomicUsize::new(0));
    let resolver = PskResolver::new(
      counting_source(hits.clone(), |_| Ok(Some(entry("s")))),
      Duration::from_secs(60),
    );
    resolver.resolve("a");
    resolver.resolve("a");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    resolver.evict("a");
    resolver.resolve("a");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
  }
}
