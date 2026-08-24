//! Connection admission: a global ceiling, a per-source fair share (IPv4 per
//! address, IPv6 per /64), and an RAII permit released on every teardown
//! path; a copy of loft's `quota.rs` with its tests. On top of it, the
//! MQTT-specific brakes the session layer consults: CONNECT attempts per
//! source per rolling window, a negative authentication cache keyed by
//! (identity, sha256(password)), a per-identity failure budget, and a global
//! brake counting refused CONNECTs.
//!
//! All of it is bounded and expiring, accelerators rather than state: losing
//! every counter here costs extra upstream lookups and nothing else, and
//! none of it can make the bridge answer differently from what dovecote
//! would (`docs/design.md` ADR G).
//!
//! The global brake counts refusals only, deliberately. A ceiling on all
//! CONNECTs sized for floods would turn a post-drain fleet reconnect into
//! minutes of spurious refusals, while successful reconnects are already
//! bounded by the permit table and the per-source caps.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::auth::AuthRefusal;

/// Ceiling on concurrent connections, the figure the VPS memory budget in
/// `docs/design.md` section 9 is computed against.
pub const MAX_CONNECTIONS: usize = 4096;
/// Fair share for one source: generous enough for a fleet behind a single
/// carrier-grade NAT address, small enough that filling the table takes at
/// least 16 distinct addresses.
pub const MAX_CONNECTIONS_PER_IP: usize = 256;

/// CONNECT packets one source may send per [`CONNECT_WINDOW`].
pub const MAX_CONNECTS_PER_SOURCE: usize = 30;
/// Refused CONNECTs across all sources per [`CONNECT_WINDOW`] before the
/// broker stops admitting new pre-auth connections for the rest of it.
pub const MAX_REFUSALS_GLOBAL: usize = 120;
pub const CONNECT_WINDOW: Duration = Duration::from_secs(10);

/// How long a refusal answers for the same credential pair without asking
/// dovecote again.
pub const NEGATIVE_AUTH_TTL: Duration = Duration::from_secs(10);

/// Refusals for one pigeon id, whatever password each carried, before that
/// id is parked locally for the rest of [`IDENTITY_BUDGET_WINDOW`].
pub const MAX_IDENTITY_FAILURES: usize = 10;
pub const IDENTITY_BUDGET_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct ConnQuota {
  max_total: usize,
  max_per_ip: usize,
  counts: Arc<Mutex<Counts>>,
}

#[derive(Default)]
struct Counts {
  total: usize,
  per_ip: HashMap<IpAddr, usize>,
}

impl ConnQuota {
  pub fn new(max_total: usize, max_per_ip: usize) -> ConnQuota {
    ConnQuota {
      max_total,
      max_per_ip,
      counts: Arc::new(Mutex::new(Counts::default())),
    }
  }

  /// Cheap probe for a listener's pre-work fast path; admission itself is
  /// always decided by `try_acquire`.
  pub fn is_full(&self) -> bool {
    let counts = self.counts.lock().expect("quota lock");
    counts.total >= self.max_total
  }

  pub fn held(&self) -> usize {
    self.counts.lock().expect("quota lock").total
  }

  /// Admits `ip` unless the table or the address's fair share is exhausted.
  /// The share is counted per [`bucket`], not per literal address. Dropping
  /// the permit is the only release path.
  pub fn try_acquire(&self, ip: IpAddr) -> Option<ConnPermit> {
    let ip = bucket(ip);
    let mut counts = self.counts.lock().expect("quota lock");
    if counts.total >= self.max_total {
      return None;
    }
    // Read-then-insert rather than entry(): a refused address must not leave
    // a zero-count entry behind, or address churn grows the map unbounded.
    let held = counts.per_ip.get(&ip).copied().unwrap_or(0);
    if held >= self.max_per_ip {
      return None;
    }
    counts.per_ip.insert(ip, held + 1);
    counts.total += 1;
    drop(counts);
    Some(ConnPermit {
      counts: Arc::clone(&self.counts),
      ip,
    })
  }
}

/// Fair-share bucket for a source address. IPv4 counts per address; IPv6
/// counts per /64, since a v6 endpoint typically controls at least its whole
/// /64 and per-/128 counting would let one host dodge the share by rotating
/// interface identifiers. V4-mapped v6 sources (a v4 peer seen through a
/// dual-stack socket) count with their embedded v4 address, so the same host
/// lands in the same bucket whichever family observed it.
fn bucket(ip: IpAddr) -> IpAddr {
  match ip {
    IpAddr::V4(_) => ip,
    IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
      Some(v4) => IpAddr::V4(v4),
      None => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (!0u128 << 64))),
    },
  }
}

/// One admitted connection's claim on the table. Held by the connection's
/// task, so its Drop runs on every exit path.
pub struct ConnPermit {
  counts: Arc<Mutex<Counts>>,
  ip: IpAddr,
}

impl Drop for ConnPermit {
  fn drop(&mut self) {
    let mut counts = self.counts.lock().expect("quota lock");
    counts.total -= 1;
    if let Some(held) = counts.per_ip.get_mut(&self.ip) {
      *held -= 1;
      if *held == 0 {
        counts.per_ip.remove(&self.ip);
      }
    }
  }
}

/// Why a CONNECT was refused before it reached dovecote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Brake {
  /// This source is sending CONNECTs faster than the per-source rate.
  SourceRate,
  /// Enough refusals recently that new pre-auth connections are paused.
  GlobalRefusals,
  /// This pigeon id has spent its failure budget.
  IdentityParked,
}

/// The MQTT admission brakes. Separate from [`ConnQuota`] because they count
/// attempts over time rather than concurrent holders, and because a session
/// consults them at a different moment: after the handshake, when a CONNECT
/// names an identity.
pub struct Admission {
  state: Mutex<AdmissionState>,
}

struct AdmissionState {
  per_source_connects: HashMap<IpAddr, VecDeque<Instant>>,
  global_refusals: VecDeque<Instant>,
  identity_failures: HashMap<String, VecDeque<Instant>>,
  negative_auth: HashMap<(String, [u8; 32]), (Instant, AuthRefusal)>,
  last_sweep: Instant,
}

impl Default for Admission {
  fn default() -> Admission {
    Admission::new()
  }
}

impl Admission {
  pub fn new() -> Admission {
    Admission {
      state: Mutex::new(AdmissionState {
        per_source_connects: HashMap::new(),
        global_refusals: VecDeque::new(),
        identity_failures: HashMap::new(),
        negative_auth: HashMap::new(),
        last_sweep: Instant::now(),
      }),
    }
  }

  /// Whether a newly accepted connection should be allowed to start its
  /// handshake at all. False only while the global refusal brake is on.
  pub fn accepting(&self, now: Instant) -> bool {
    let mut state = self.state.lock().expect("admission lock");
    prune(&mut state.global_refusals, now, CONNECT_WINDOW);
    state.global_refusals.len() < MAX_REFUSALS_GLOBAL
  }

  /// Records a CONNECT arriving from `source` and reports whether it may
  /// proceed. Called once per CONNECT packet, before any credential work.
  pub fn admit_connect(&self, source: IpAddr, identity: &str, now: Instant) -> Result<(), Brake> {
    let source = bucket(source);
    let mut state = self.state.lock().expect("admission lock");
    state.sweep_if_due(now);

    prune(&mut state.global_refusals, now, CONNECT_WINDOW);
    if state.global_refusals.len() >= MAX_REFUSALS_GLOBAL {
      return Err(Brake::GlobalRefusals);
    }

    if let Some(failures) = state.identity_failures.get_mut(identity) {
      prune(failures, now, IDENTITY_BUDGET_WINDOW);
      if failures.len() >= MAX_IDENTITY_FAILURES {
        return Err(Brake::IdentityParked);
      }
    }

    let attempts = state.per_source_connects.entry(source).or_default();
    prune(attempts, now, CONNECT_WINDOW);
    if attempts.len() >= MAX_CONNECTS_PER_SOURCE {
      return Err(Brake::SourceRate);
    }
    attempts.push_back(now);
    Ok(())
  }

  /// A refusal this credential pair already earned, if it is still fresh.
  /// Saves an upstream round trip for a device retrying with a credential
  /// that was wrong a moment ago.
  pub fn cached_refusal(
    &self,
    identity: &str,
    password: &[u8],
    now: Instant,
  ) -> Option<AuthRefusal> {
    let key = (identity.to_string(), digest(password));
    let state = self.state.lock().expect("admission lock");
    match state.negative_auth.get(&key) {
      Some((at, refusal)) if now.duration_since(*at) < NEGATIVE_AUTH_TTL => Some(*refusal),
      _ => None,
    }
  }

  /// Feeds one refusal into all three brakes at once, so a flood is counted
  /// however it is shaped: one identity with many passwords, many identities
  /// from one source, or many sources at once.
  pub fn note_refusal(&self, identity: &str, password: &[u8], refusal: AuthRefusal, now: Instant) {
    let mut state = self.state.lock().expect("admission lock");
    state.sweep_if_due(now);
    state.global_refusals.push_back(now);
    state
      .identity_failures
      .entry(identity.to_string())
      .or_default()
      .push_back(now);
    // A retryable refusal is not the device's fault, so it must not answer
    // for the credential later: caching a server-side blip would keep a
    // healthy device out after the blip passed.
    if refusal.is_permanent() {
      state
        .negative_auth
        .insert((identity.to_string(), digest(password)), (now, refusal));
    }
  }

  /// A refusal with no usable identity behind it. Only the global brake
  /// counts it: there is nothing to key a per-identity budget or a negative
  /// cache entry on, and inventing a key from garbage would let a flood
  /// grow the maps it was supposed to be bounded by.
  pub fn note_anonymous_refusal(&self, now: Instant) {
    let mut state = self.state.lock().expect("admission lock");
    state.sweep_if_due(now);
    state.global_refusals.push_back(now);
  }

  /// A successful CONNECT clears this identity's failure budget: whatever
  /// the earlier refusals were, the credential works now.
  pub fn note_success(&self, identity: &str, password: &[u8]) {
    let mut state = self.state.lock().expect("admission lock");
    state.identity_failures.remove(identity);
    state
      .negative_auth
      .remove(&(identity.to_string(), digest(password)));
  }
}

impl AdmissionState {
  /// Drops expired entries so the maps stay bounded by what was seen in the
  /// window rather than by everything ever seen. Sweeping on a timer rather
  /// than per call keeps the common path a few pushes and a comparison.
  fn sweep_if_due(&mut self, now: Instant) {
    if now.duration_since(self.last_sweep) < CONNECT_WINDOW {
      return;
    }
    self.last_sweep = now;
    self.per_source_connects.retain(|_, attempts| {
      prune(attempts, now, CONNECT_WINDOW);
      !attempts.is_empty()
    });
    self.identity_failures.retain(|_, failures| {
      prune(failures, now, IDENTITY_BUDGET_WINDOW);
      !failures.is_empty()
    });
    self
      .negative_auth
      .retain(|_, (at, _)| now.duration_since(*at) < NEGATIVE_AUTH_TTL);
  }
}

fn prune(window: &mut VecDeque<Instant>, now: Instant, keep: Duration) {
  while let Some(front) = window.front() {
    if now.duration_since(*front) >= keep {
      window.pop_front();
    } else {
      break;
    }
  }
}

/// Passwords are hashed before they are used as a cache key so the device
/// token never sits in a map in the clear.
fn digest(password: &[u8]) -> [u8; 32] {
  let mut hasher = Sha256::new();
  hasher.update(password);
  hasher.finalize().into()
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::Ipv4Addr;

  fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
  }

  const ID: &str = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";

  #[test]
  fn per_ip_share_refuses_one_source_but_not_others() {
    let quota = ConnQuota::new(8, 2);
    let _a = quota.try_acquire(ip(1)).expect("first");
    let _b = quota.try_acquire(ip(1)).expect("second");
    assert!(quota.try_acquire(ip(1)).is_none(), "fair share exhausted");
    assert!(
      quota.try_acquire(ip(2)).is_some(),
      "other sources unaffected"
    );
  }

  #[test]
  fn global_ceiling_refuses_even_fresh_sources() {
    let quota = ConnQuota::new(2, 2);
    let _a = quota.try_acquire(ip(1)).expect("first");
    let _b = quota.try_acquire(ip(2)).expect("second");
    assert!(quota.is_full());
    assert!(quota.try_acquire(ip(3)).is_none());
  }

  #[test]
  fn dropping_a_permit_releases_both_counts() {
    let quota = ConnQuota::new(1, 1);
    let permit = quota.try_acquire(ip(1)).expect("first");
    assert!(quota.is_full());
    assert!(quota.try_acquire(ip(1)).is_none());
    drop(permit);
    assert!(!quota.is_full());
    assert!(quota.try_acquire(ip(1)).is_some());
  }

  #[test]
  fn ipv6_sources_share_their_slash64_bucket() {
    let quota = ConnQuota::new(8, 1);
    let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().expect("addr");
    let same_prefix: IpAddr = "2001:db8:1:2::bbbb".parse().expect("addr");
    let other_prefix: IpAddr = "2001:db8:1:3::1".parse().expect("addr");
    let _held = quota.try_acquire(a).expect("first in /64");
    assert!(
      quota.try_acquire(same_prefix).is_none(),
      "rotating interface ids must not dodge the share"
    );
    assert!(
      quota.try_acquire(other_prefix).is_some(),
      "a different /64 is a different bucket"
    );
  }

  #[test]
  fn v4_mapped_sources_count_with_their_v4_address() {
    let quota = ConnQuota::new(8, 1);
    let v4: IpAddr = "203.0.113.7".parse().expect("addr");
    let mapped: IpAddr = "::ffff:203.0.113.7".parse().expect("addr");
    let _held = quota.try_acquire(v4).expect("v4");
    assert!(
      quota.try_acquire(mapped).is_none(),
      "the mapped form is the same host"
    );
  }

  #[test]
  fn refusals_and_releases_leave_no_per_ip_residue() {
    let quota = ConnQuota::new(1, 1);
    let permit = quota.try_acquire(ip(1)).expect("admit");
    assert!(quota.try_acquire(ip(2)).is_none(), "table full");
    drop(permit);
    let counts = quota.counts.lock().expect("quota lock");
    assert!(counts.per_ip.is_empty(), "no zero-count entries");
    assert_eq!(counts.total, 0);
  }

  #[test]
  fn a_source_may_connect_up_to_its_rate_then_is_braked() {
    let admission = Admission::new();
    let now = Instant::now();
    for _ in 0..MAX_CONNECTS_PER_SOURCE {
      admission
        .admit_connect(ip(1), ID, now)
        .expect("within rate");
    }
    assert_eq!(
      admission.admit_connect(ip(1), ID, now),
      Err(Brake::SourceRate)
    );
    assert!(
      admission.admit_connect(ip(2), ID, now).is_ok(),
      "the rate is per source"
    );
  }

  #[test]
  fn the_source_rate_window_slides() {
    let admission = Admission::new();
    let now = Instant::now();
    for _ in 0..MAX_CONNECTS_PER_SOURCE {
      admission
        .admit_connect(ip(1), ID, now)
        .expect("within rate");
    }
    let later = now + CONNECT_WINDOW + Duration::from_millis(1);
    assert!(
      admission.admit_connect(ip(1), ID, later).is_ok(),
      "a window later the source is free again"
    );
  }

  #[test]
  fn an_identity_is_parked_after_its_failure_budget_whatever_the_source() {
    let admission = Admission::new();
    let now = Instant::now();
    for i in 0..MAX_IDENTITY_FAILURES {
      // A distinct password each time: the budget is per identity, so a
      // password sweep must not slip through it.
      admission.note_refusal(
        ID,
        format!("guess-{i}").as_bytes(),
        AuthRefusal::BadCredentials,
        now,
      );
    }
    assert_eq!(
      admission.admit_connect(ip(9), ID, now),
      Err(Brake::IdentityParked),
      "a fresh source does not clear the identity's budget"
    );
    assert!(
      admission.admit_connect(ip(9), "bb22", now).is_ok(),
      "other identities are unaffected"
    );
  }

  #[test]
  fn a_success_clears_the_identitys_budget() {
    let admission = Admission::new();
    let now = Instant::now();
    for i in 0..MAX_IDENTITY_FAILURES {
      admission.note_refusal(
        ID,
        format!("guess-{i}").as_bytes(),
        AuthRefusal::BadCredentials,
        now,
      );
    }
    admission.note_success(ID, b"the-real-token");
    assert!(admission.admit_connect(ip(9), ID, now).is_ok());
  }

  #[test]
  fn the_global_brake_counts_refusals_not_connects() {
    let admission = Admission::new();
    let now = Instant::now();
    // Successful connects, however many, never arm the brake: a post-drain
    // fleet reconnect must not refuse itself.
    for i in 0..MAX_REFUSALS_GLOBAL * 2 {
      let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, (i % 200) as u8));
      let _ = admission.admit_connect(source, &format!("id-{i}"), now);
    }
    assert!(admission.accepting(now), "successes do not arm the brake");

    for i in 0..MAX_REFUSALS_GLOBAL {
      admission.note_refusal(&format!("id-{i}"), b"x", AuthRefusal::BadCredentials, now);
    }
    assert!(!admission.accepting(now), "refusals do");
    let later = now + CONNECT_WINDOW + Duration::from_millis(1);
    assert!(admission.accepting(later), "and the brake releases");
  }

  #[test]
  fn an_anonymous_refusal_arms_the_global_brake_without_growing_the_maps() {
    let admission = Admission::new();
    let now = Instant::now();
    for _ in 0..MAX_REFUSALS_GLOBAL {
      admission.note_anonymous_refusal(now);
    }
    assert!(!admission.accepting(now));
    let state = admission.state.lock().expect("admission lock");
    assert!(state.identity_failures.is_empty());
    assert!(state.negative_auth.is_empty());
  }

  #[test]
  fn a_permanent_refusal_is_cached_per_credential_pair() {
    let admission = Admission::new();
    let now = Instant::now();
    admission.note_refusal(ID, b"wrong", AuthRefusal::BadCredentials, now);
    assert_eq!(
      admission.cached_refusal(ID, b"wrong", now),
      Some(AuthRefusal::BadCredentials)
    );
    assert_eq!(
      admission.cached_refusal(ID, b"a-different-token", now),
      None,
      "a fresh credential is not answered from the cache"
    );
    let later = now + NEGATIVE_AUTH_TTL + Duration::from_millis(1);
    assert_eq!(admission.cached_refusal(ID, b"wrong", later), None);
  }

  #[test]
  fn a_retryable_refusal_is_not_cached() {
    let admission = Admission::new();
    let now = Instant::now();
    admission.note_refusal(ID, b"good", AuthRefusal::ServerUnavailable, now);
    assert_eq!(
      admission.cached_refusal(ID, b"good", now),
      None,
      "an edge blip must not lock a healthy device out for the TTL"
    );
  }

  #[test]
  fn expired_entries_are_swept_rather_than_accumulating() {
    let admission = Admission::new();
    let now = Instant::now();
    for i in 0..64 {
      let source = IpAddr::V4(Ipv4Addr::new(203, 0, 113, i));
      let _ = admission.admit_connect(source, &format!("id-{i}"), now);
      admission.note_refusal(&format!("id-{i}"), b"x", AuthRefusal::BadCredentials, now);
    }
    let later = now + IDENTITY_BUDGET_WINDOW + Duration::from_secs(1);
    let _ = admission.admit_connect(ip(1), ID, later);
    let state = admission.state.lock().expect("admission lock");
    assert!(state.per_source_connects.len() <= 1, "sources swept");
    assert!(state.identity_failures.is_empty(), "identities swept");
    assert!(state.negative_auth.is_empty(), "negative cache swept");
  }
}
