//! One task per connection: the MQTT session state machine over a
//! version-neutral event model, with `proto::v3` and `proto::v5` translating
//! to and from it.
//!
//! The reader half never stops reading. PINGREQ, PUBACK and DISCONNECT flow
//! even while upstream is slow, because the in-flight QoS 1 budget is
//! enforced as a protocol matter (a reason code, then a close) rather than
//! by pausing the socket, which would starve keepalive and turn a slow edge
//! into a fleet of dead sessions.
//!
//! QoS 1 publishes are bridged one at a time in arrival order, so a PUBACK
//! means the platform's own answer. QoS 0 bypasses that queue onto the
//! device WebSocket: ordering is guaranteed within a QoS class, not across
//! classes, because a stalled POST must not delay the fast path.
//!
//! The session holds its will, bridged on an ungraceful exit only when no
//! newer session for the same pigeon exists in the registry, and its
//! registry entry, which a later CONNECT takes over.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use pigeonhole_wire::framing::{self, FramingError};
use pigeonhole_wire::limits;
use pigeonhole_wire::topics::{self, PublishTopic, SubscribeOutcome};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Notify, mpsc, watch};
use tokio_openssl::SslStream;

use crate::auth::{self, AuthRefusal};
use crate::bridge::{self, PublishJob, PublishResult, Verdict};
use crate::proto::{self, ConnackOutcome, DisconnectReason, Inbound, Outbound, SubResult, Version};
use crate::psk::PskResolver;
use crate::quota::{Admission, Brake, ConnPermit};
use crate::shadow::{self, Feed, FeedEnd, FeedEvent, FeedState};
use crate::upstream::{UpgradeFailure, Upstream};

/// How long a connection has to send its CONNECT once TLS is up. Separate
/// from the handshake deadline: a peer that completes a handshake and then
/// says nothing is holding a slot for free.
const CONNECT_DEADLINE: Duration = Duration::from_secs(10);
/// Total time a session may spend finishing its in-flight publishes on
/// shutdown before it is told the broker is going away regardless.
const DRAIN_BUDGET: Duration = Duration::from_secs(15);
/// Outbound packets that may queue for a client that is not reading. Beyond
/// this the client is not keeping up and the session ends rather than
/// growing a buffer.
const WRITE_QUEUE_DEPTH: usize = 64;

type Reader = ReadHalf<SslStream<TcpStream>>;
type Writer = WriteHalf<SslStream<TcpStream>>;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

/// Counters for the periodic stats line. Every one is a number an operator
/// would want before knowing which question to ask.
#[derive(Default)]
pub struct Stats {
  pub sessions_open: AtomicUsize,
  pub sessions_accepted: AtomicU64,
  pub connects_refused: AtomicU64,
  pub publishes_bridged: AtomicU64,
  pub publish_failures: AtomicU64,
  /// 403s that were an edge-mitigation page rather than an auth verdict,
  /// counted apart so a WAF event does not read as a credential failure.
  pub edge_shaped_refusals: AtomicU64,
  pub feeds_open: AtomicUsize,
  pub shadow_pushes: AtomicU64,
}

impl Stats {
  pub fn summary(&self) -> String {
    format!(
      "sessions={} accepted={} refused={} publishes={} publish_errors={} edge_403s={} feeds={} pushes={}",
      self.sessions_open.load(Ordering::Relaxed),
      self.sessions_accepted.load(Ordering::Relaxed),
      self.connects_refused.load(Ordering::Relaxed),
      self.publishes_bridged.load(Ordering::Relaxed),
      self.publish_failures.load(Ordering::Relaxed),
      self.edge_shaped_refusals.load(Ordering::Relaxed),
      self.feeds_open.load(Ordering::Relaxed),
      self.shadow_pushes.load(Ordering::Relaxed),
    )
  }
}

/// Which session currently holds each pigeon. The MQTT counterpart of the
/// Durable Object's one-socket-per-pigeon rule, and the one thing that lets
/// a dying session tell "the device is gone" from "the device reconnected".
#[derive(Default)]
pub struct Registry {
  holders: Mutex<std::collections::HashMap<String, Holder>>,
}

struct Holder {
  session_id: u64,
  takeover: Arc<Notify>,
}

impl Registry {
  /// Claims a pigeon for a session, returning the superseded session's
  /// takeover signal if there was one.
  pub fn claim(&self, pigeon: &str, session_id: u64, takeover: Arc<Notify>) -> Option<Arc<Notify>> {
    let mut holders = self.holders.lock().expect("registry lock");
    let previous = holders.insert(
      pigeon.to_string(),
      Holder {
        session_id,
        takeover,
      },
    );
    previous.map(|holder| holder.takeover)
  }

  /// Releases the claim, but only if this session still holds it: a session
  /// that was taken over must not evict its successor on the way out.
  pub fn release(&self, pigeon: &str, session_id: u64) {
    let mut holders = self.holders.lock().expect("registry lock");
    if holders.get(pigeon).map(|h| h.session_id) == Some(session_id) {
      holders.remove(pigeon);
    }
  }

  /// Whether any session holds this pigeon.
  pub fn claimed(&self, pigeon: &str) -> bool {
    self
      .holders
      .lock()
      .expect("registry lock")
      .contains_key(pigeon)
  }

  pub fn holds(&self, pigeon: &str, session_id: u64) -> bool {
    self
      .holders
      .lock()
      .expect("registry lock")
      .get(pigeon)
      .map(|h| h.session_id)
      == Some(session_id)
  }
}

pub struct SessionContext<U: Upstream> {
  pub upstream: Arc<U>,
  pub registry: Arc<Registry>,
  pub admission: Arc<Admission>,
  pub resolver: Arc<PskResolver>,
  pub stats: Arc<Stats>,
  pub shutdown: watch::Receiver<bool>,
}

/// How a session ended, which is what decides whether its will is bridged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionEnd {
  /// The client said goodbye. Its will is discarded unless it asked for it.
  Graceful { deliver_will: bool },
  /// The socket dropped, the peer went silent, or the broker faulted the
  /// session. The device is gone as far as anyone can tell.
  Ungraceful,
  /// A newer session for this pigeon arrived.
  TakenOver,
  /// The credential or the pigeon stopped existing. A will here would only
  /// earn a guaranteed 401 at the Durable Object.
  CredentialGone,
  /// The broker is going away, not the device.
  Shutdown,
}

impl SessionEnd {
  fn wants_will(self) -> bool {
    match self {
      SessionEnd::Graceful { deliver_will } => deliver_will,
      SessionEnd::Ungraceful => true,
      // A takeover means the device reconnected, which is the case the
      // suppression rule exists for; the registry check would catch it too.
      SessionEnd::TakenOver | SessionEnd::CredentialGone | SessionEnd::Shutdown => false,
    }
  }
}

/// Runs one accepted connection to completion. The permit is held for the
/// whole call so every exit path releases it.
pub async fn run<U: Upstream>(
  ctx: Arc<SessionContext<U>>,
  stream: SslStream<TcpStream>,
  peer: SocketAddr,
  _permit: ConnPermit,
) {
  // What the handshake established, if it was a PSK one. A certificate
  // session has nothing here and presents its credential inside CONNECT.
  let psk = crate::tls::psk_session(stream.ssl());
  let (mut reader, mut writer) = tokio::io::split(stream);

  let accepted = match handshake(&ctx, &mut reader, &mut writer, peer, psk).await {
    Some(accepted) => accepted,
    None => {
      let _ = writer.shutdown().await;
      return;
    }
  };

  ctx.stats.sessions_open.fetch_add(1, Ordering::Relaxed);
  ctx.stats.sessions_accepted.fetch_add(1, Ordering::Relaxed);
  serve(&ctx, accepted, reader, writer).await;
  ctx.stats.sessions_open.fetch_sub(1, Ordering::Relaxed);
}

/// Everything the handshake settled, handed to the session loop.
struct Accepted {
  version: Version,
  pigeon_id: String,
  token: String,
  keep_alive: u16,
  will: Option<proto::Will>,
  feed: Feed,
  feed_events: mpsc::Receiver<FeedEvent>,
  session_id: u64,
  takeover: Arc<Notify>,
}

/// Reads the CONNECT, settles the identity, opens the device socket (which
/// is the authentication), and answers. `None` means the connection was
/// refused and the caller should close.
async fn handshake<U: Upstream>(
  ctx: &Arc<SessionContext<U>>,
  reader: &mut Reader,
  writer: &mut Writer,
  peer: SocketAddr,
  psk: Option<(String, String)>,
) -> Option<Accepted> {
  let raw = match tokio::time::timeout(CONNECT_DEADLINE, framing::read_packet(reader)).await {
    Ok(Ok(raw)) => raw,
    Ok(Err(e)) => {
      if !e.is_disconnect() {
        tracing::debug!(%peer, error = %e, "no readable CONNECT");
      }
      return None;
    }
    Err(_) => {
      tracing::debug!(%peer, "handshake completed but no CONNECT followed");
      return None;
    }
  };

  // The protocol version decides every codec from here, and only a CONNECT
  // carries it. Anything else first is a protocol error with no version to
  // report it in, so the connection just closes.
  let version = match raw.connect_protocol() {
    Ok(protocol) => match Version::from_protocol(protocol) {
      Some(version) => version,
      None => {
        refuse_unsupported_version(writer).await;
        return None;
      }
    },
    Err(_) if raw.packet_type() == framing::CONNECT_PACKET_TYPE => {
      // A CONNECT whose protocol name or level did not parse. The spec asks
      // for the 3.1.1-shaped refusal here, since no other format is known
      // to be readable by the peer.
      refuse_unsupported_version(writer).await;
      return None;
    }
    Err(_) => return None,
  };

  let connect = match proto::decode(version, &raw) {
    Ok(Inbound::Connect(connect)) => connect,
    Err(_) => {
      // The version parsed, so the peer can read a CONNACK; only the rest of
      // the packet did not.
      refuse(ctx, writer, version, ConnackOutcome::MalformedPacket, None).await;
      return None;
    }
    Ok(_) => {
      // The first packet must be a CONNECT. Nothing has been negotiated, so
      // there is no session to send a reason code into.
      return None;
    }
  };

  let now = Instant::now();
  let psk_identity = psk.as_ref().map(|(identity, _)| identity.as_str());

  // Length caps before shape, so an absurd username is refused by size
  // rather than being walked character by character.
  if connect.client_id.len() > limits::MAX_CLIENT_ID_BYTES
    || connect
      .username
      .as_ref()
      .is_some_and(|u| u.len() > limits::MAX_CLIENT_ID_BYTES)
    || connect
      .password
      .as_ref()
      .is_some_and(|p| p.len() > limits::MAX_PASSWORD_BYTES)
  {
    ctx.admission.note_anonymous_refusal(now);
    refuse(ctx, writer, version, ConnackOutcome::ClientIdNotValid, None).await;
    return None;
  }

  let identity = match auth::resolve_identity(
    psk_identity,
    connect.username.as_deref(),
    &connect.client_id,
  ) {
    Ok(identity) => identity.0,
    Err(refusal) => {
      // No usable identity means nothing to key the per-identity budget on;
      // only the global refusal brake counts this one.
      ctx.admission.note_anonymous_refusal(now);
      refuse(ctx, writer, version, refusal.connack(), None).await;
      return None;
    }
  };

  // 3.1.1 requires a client id when the client asked to resume a session,
  // and answers 0x02 when one is missing. MQTT 5 has no such rule: a server
  // assigns an id instead, and this one binds sessions by handshake anyway.
  if version == Version::V311 && connect.client_id.is_empty() && !connect.clean_start {
    ctx.admission.note_anonymous_refusal(now);
    refuse(ctx, writer, version, ConnackOutcome::ClientIdNotValid, None).await;
    return None;
  }

  if let Err(brake) = ctx.admission.admit_connect(peer.ip(), &identity, now) {
    let outcome = match brake {
      Brake::IdentityParked => ConnackOutcome::BadCredentials,
      Brake::SourceRate | Brake::GlobalRefusals => ConnackOutcome::ServerBusy,
    };
    tracing::debug!(%peer, ?brake, "CONNECT braked");
    ctx.stats.connects_refused.fetch_add(1, Ordering::Relaxed);
    refuse(ctx, writer, version, outcome, None).await;
    return None;
  }

  // A PSK handshake already resolved this pigeon's bearer token; a
  // certificate session presents it as the CONNECT password.
  let token = match &psk {
    Some((_, token)) => token.clone(),
    None => match connect
      .password
      .as_ref()
      .and_then(|p| std::str::from_utf8(p).ok())
    {
      Some(token) if !token.is_empty() => token.to_string(),
      _ => {
        ctx
          .admission
          .note_refusal(&identity, b"", AuthRefusal::BadCredentials, now);
        ctx.stats.connects_refused.fetch_add(1, Ordering::Relaxed);
        refuse(ctx, writer, version, ConnackOutcome::BadCredentials, None).await;
        return None;
      }
    },
  };

  if let Some(refusal) = ctx
    .admission
    .cached_refusal(&identity, token.as_bytes(), now)
  {
    ctx.stats.connects_refused.fetch_add(1, Ordering::Relaxed);
    refuse(ctx, writer, version, refusal.connack(), None).await;
    return None;
  }

  // A will is accepted only for a topic this session could publish to
  // itself: it is delivered as an ordinary bridged publish, so anything
  // else would be a topic the bridge has no route for.
  if let Some(will) = &connect.will {
    if PublishTopic::parse(&will.topic).is_none() {
      refuse(
        ctx,
        writer,
        version,
        ConnackOutcome::WillTopicInvalid,
        Some("a will may only name this session's own publish topics"),
      )
      .await;
      return None;
    }
    // Only v5 advertises a Maximum QoS, so only v5 can refuse a will above
    // it. On 3.1.1 the declared QoS is moot: delivery is one POST either way.
    if version == Version::V500 && will.qos > 1 {
      refuse(ctx, writer, version, ConnackOutcome::QoSNotSupported, None).await;
      return None;
    }
  }

  // The upgrade is the authentication: 101 accepts the session, opens its
  // feed, and seeds the retained shadow, all in one round trip.
  let socket = match ctx.upstream.dial_device_ws(&identity, &token).await {
    Ok(socket) => socket,
    Err(failure) => {
      let refusal = match &failure {
        UpgradeFailure::Status { status, body } => {
          auth::classify_upgrade(*status, auth::looks_like_html(body))
            .err()
            .unwrap_or(AuthRefusal::ServerUnavailable)
        }
        UpgradeFailure::Transport(e) => {
          tracing::debug!(pigeon = %identity, error = %e, "device socket dial failed");
          AuthRefusal::ServerUnavailable
        }
      };
      // A 401 on a PSK session means the cache served a rotated pair, so the
      // entry goes rather than refusing every device for the rest of the TTL.
      if psk.is_some() && matches!(refusal, AuthRefusal::BadCredentials) {
        ctx.resolver.evict(&identity);
      }
      if matches!(refusal, AuthRefusal::ServerUnavailable) {
        ctx
          .stats
          .edge_shaped_refusals
          .fetch_add(1, Ordering::Relaxed);
      }
      ctx
        .admission
        .note_refusal(&identity, token.as_bytes(), refusal, now);
      ctx.stats.connects_refused.fetch_add(1, Ordering::Relaxed);
      tracing::info!(pigeon = %identity, refusal = refusal.label(), "CONNECT refused");
      refuse(ctx, writer, version, refusal.connack(), None).await;
      return None;
    }
  };

  ctx.admission.note_success(&identity, token.as_bytes());

  // Zero means the client wants no keepalive of its own, which is not the
  // same as wanting none at all: an idle socket still has to be reclaimed.
  let keep_alive = if connect.keep_alive == 0 {
    limits::MAX_KEEPALIVE_SECS
  } else {
    connect.keep_alive.min(limits::MAX_KEEPALIVE_SECS)
  };

  let session_id = NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed);
  let takeover = Arc::new(Notify::new());
  if let Some(superseded) = ctx
    .registry
    .claim(&identity, session_id, Arc::clone(&takeover))
  {
    superseded.notify_waiters();
  }

  let connack = proto::encode(
    version,
    &Outbound::Connack {
      outcome: ConnackOutcome::Accepted,
      server_keep_alive: keep_alive,
      receive_max: limits::RECEIVE_MAXIMUM,
      reason: None,
    },
  );
  match connack {
    Ok(Some(bytes)) => {
      if framing::write_packet(writer, &bytes).await.is_err() {
        ctx.registry.release(&identity, session_id);
        return None;
      }
    }
    _ => {
      ctx.registry.release(&identity, session_id);
      return None;
    }
  }

  let (feed, feed_events) = shadow::spawn(
    Arc::clone(&ctx.upstream),
    identity.clone(),
    token.clone(),
    socket,
  );
  ctx.stats.feeds_open.fetch_add(1, Ordering::Relaxed);

  tracing::info!(
    pigeon = %identity,
    version = version.as_str(),
    keep_alive,
    // Recorded rather than honored: sessions are stateless, so a client
    // asking to resume one is answered session_present=0 either way.
    clean_start = connect.clean_start,
    client_receive_max = connect.receive_max,
    transport = if psk.is_some() { "psk" } else { "certificate" },
    "session accepted"
  );

  Some(Accepted {
    version,
    pigeon_id: identity,
    token,
    keep_alive,
    will: connect.will.clone(),
    feed,
    feed_events,
    session_id,
    takeover,
  })
}

/// Writes a refusal in whatever form this version has for it, then leaves
/// the caller to close.
async fn refuse<U: Upstream>(
  ctx: &Arc<SessionContext<U>>,
  writer: &mut Writer,
  version: Version,
  outcome: ConnackOutcome,
  reason: Option<&'static str>,
) {
  let _ = &ctx;
  if let Ok(Some(bytes)) = proto::encode(
    version,
    &Outbound::Connack {
      outcome,
      server_keep_alive: 0,
      receive_max: limits::RECEIVE_MAXIMUM,
      reason,
    },
  ) {
    let _ = framing::write_packet(writer, &bytes).await;
  }
}

/// A CONNECT naming a version this broker does not serve is answered in the
/// 3.1.1 format: it is the only one the peer is known to be able to read,
/// and the spec names it for exactly this case.
async fn refuse_unsupported_version(writer: &mut Writer) {
  if let Ok(Some(bytes)) = proto::v3::encode(&Outbound::Connack {
    outcome: ConnackOutcome::UnsupportedVersion,
    server_keep_alive: 0,
    receive_max: 0,
    reason: None,
  }) {
    let _ = framing::write_packet(writer, &bytes).await;
  }
}

/// Per-session state the loop mutates. Held in one place so the reader's
/// checks and the feed's pushes cannot disagree about it.
struct SessionState {
  /// The shadow the feed last reported, as the Durable Object's own bytes.
  latest_shadow: Option<(Bytes, i32)>,
  /// The QoS the subscription was granted at, if there is one.
  granted_qos: Option<u8>,
  /// The last `target_version` actually delivered. Per connection, dying
  /// with the socket: a duplicate suppressor, not stored state.
  last_delivered: Option<i32>,
  outbound_pid: u16,
  publish_window: VecDeque<Instant>,
  inflight_count: usize,
  inflight_bytes: usize,
}

impl SessionState {
  fn new() -> SessionState {
    SessionState {
      latest_shadow: None,
      granted_qos: None,
      last_delivered: None,
      outbound_pid: 0,
      publish_window: VecDeque::new(),
      inflight_count: 0,
      inflight_bytes: 0,
    }
  }

  fn next_pid(&mut self) -> u16 {
    // Packet id 0 is not a valid id in either version.
    self.outbound_pid = self.outbound_pid.wrapping_add(1);
    if self.outbound_pid == 0 {
      self.outbound_pid = 1;
    }
    self.outbound_pid
  }

  /// Counts one inbound publish against the session's rate ceiling, which
  /// sits under the Durable Object's own frame limit so the QoS 0 fast path
  /// can never trip it.
  fn within_publish_rate(&mut self, now: Instant) -> bool {
    let window = Duration::from_secs(limits::PUBLISH_RATE_WINDOW_SECS);
    while let Some(front) = self.publish_window.front() {
      if now.duration_since(*front) >= window {
        self.publish_window.pop_front();
      } else {
        break;
      }
    }
    if self.publish_window.len() >= limits::PUBLISH_RATE_MAX as usize {
      return false;
    }
    self.publish_window.push_back(now);
    true
  }

  /// Whether one more in-flight QoS 1 publish fits, by count and by bytes.
  /// The byte cap is what bounds the flood worst case: counting packets
  /// alone would allow full-size packets per session, past the box's budget
  /// fleet-wide.
  fn accepts_inflight(&self, version: Version, bytes: usize) -> bool {
    let count_cap = match version {
      Version::V500 => limits::RECEIVE_MAXIMUM as usize,
      // 3.1.1 has no Receive Maximum to advertise, so a client cannot know
      // the limit; it gets a grace ceiling before the close.
      Version::V311 => limits::RECEIVE_MAXIMUM_V3_GRACE as usize,
    };
    self.inflight_count < count_cap && self.inflight_bytes + bytes <= limits::MAX_INFLIGHT_BYTES
  }
}

async fn serve<U: Upstream>(
  ctx: &Arc<SessionContext<U>>,
  mut accepted: Accepted,
  mut reader: Reader,
  writer: Writer,
) -> SessionEnd {
  let version = accepted.version;
  let can_signal = proto::can_signal_after_connack(version);
  let pigeon_id = accepted.pigeon_id.clone();

  let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(WRITE_QUEUE_DEPTH);
  let writer_task = tokio::spawn(run_writer(writer, write_rx));

  // Sized above every in-flight ceiling, so the reader's own cap is what
  // refuses a flood and this send can never be the thing that blocks it.
  let (job_tx, job_rx) = mpsc::channel::<PublishJob>(limits::RECEIVE_MAXIMUM_V3_GRACE as usize + 8);
  let (result_tx, mut result_rx) = mpsc::channel::<PublishResult>(WRITE_QUEUE_DEPTH);
  let qos1 = tokio::spawn(bridge::run_queue(
    Arc::clone(&ctx.upstream),
    pigeon_id.clone(),
    accepted.token.clone(),
    job_rx,
    result_tx.clone(),
  ));

  // QoS 0 keeps its own queue so a stalled POST cannot delay it behind the
  // sequential QoS 1 path. Small and lossy on purpose: fire and forget.
  let (fast_tx, fast_rx) = mpsc::channel::<PublishJob>(16);
  let qos0 = tokio::spawn(bridge::run_queue(
    Arc::clone(&ctx.upstream),
    pigeon_id.clone(),
    accepted.token.clone(),
    fast_rx,
    result_tx,
  ));

  let mut state = SessionState::new();
  let mut shutdown = ctx.shutdown.clone();
  let keepalive_limit = keepalive_deadline(accepted.keep_alive);
  let mut deadline = tokio::time::Instant::now() + keepalive_limit;

  let end = loop {
    tokio::select! {
      biased;

      _ = accepted.takeover.notified() => {
        send(&write_tx, version, &Outbound::Disconnect {
          reason: DisconnectReason::SessionTakenOver,
          text: None,
        });
        break SessionEnd::TakenOver;
      }

      changed = shutdown.changed() => {
        if changed.is_ok() && *shutdown.borrow() {
          break SessionEnd::Shutdown;
        }
      }

      Some(result) = result_rx.recv() => {
        state.inflight_count = state.inflight_count.saturating_sub(1);
        state.inflight_bytes = state.inflight_bytes.saturating_sub(result.queued_bytes);
        if let Some(end) = apply_result(ctx, &write_tx, version, can_signal, result) {
          break end;
        }
      }

      Some(event) = accepted.feed_events.recv() => {
        match event {
          FeedEvent::Target { shadow, target_version } => {
            state.latest_shadow = Some((shadow, target_version));
            push_shadow_if_new(ctx, &write_tx, version, &mut state);
          }
          FeedEvent::StateChanged(feed_state) => accepted.feed.set_state(feed_state),
          FeedEvent::Ended(end) => {
            send(&write_tx, version, &Outbound::Disconnect {
              reason: DisconnectReason::NotAuthorized,
              text: Some(end.reason_text()),
            });
            tracing::info!(pigeon = %pigeon_id, reason = end.reason_text(), "session ended by the platform");
            break match end {
              FeedEnd::TokenRevoked | FeedEnd::PigeonDeleted => SessionEnd::CredentialGone,
            };
          }
        }
      }

      packet = tokio::time::timeout_at(deadline, framing::read_packet(&mut reader)) => {
        let raw = match packet {
          Ok(Ok(raw)) => raw,
          Ok(Err(e)) => break read_fault(&write_tx, version, e),
          Err(_) => {
            send(&write_tx, version, &Outbound::Disconnect {
              reason: DisconnectReason::KeepAliveTimeout,
              text: None,
            });
            tracing::debug!(pigeon = %pigeon_id, "keepalive expired");
            break SessionEnd::Ungraceful;
          }
        };
        deadline = tokio::time::Instant::now() + keepalive_limit;

        let event = match proto::decode(version, &raw) {
          Ok(event) => event,
          Err(_) => {
            send(&write_tx, version, &Outbound::Disconnect {
              reason: DisconnectReason::MalformedPacket,
              text: None,
            });
            break SessionEnd::Ungraceful;
          }
        };

        match handle(ctx, &mut accepted, &mut state, &write_tx, &job_tx, &fast_tx, event) {
          Step::Continue => {}
          Step::End(end) => break end,
        }
      }
    }
  };

  // Shutdown is the one ending that waits: in-flight publishes finish and
  // are acked, so a deploy or a certificate renewal is a small redelivery
  // window rather than a loss event.
  if end == SessionEnd::Shutdown {
    drop(job_tx);
    drop(fast_tx);
    drain(
      ctx,
      &write_tx,
      version,
      can_signal,
      &mut result_rx,
      &mut state,
    )
    .await;
    send(
      &write_tx,
      version,
      &Outbound::Disconnect {
        reason: DisconnectReason::ServerShuttingDown,
        text: None,
      },
    );
  }

  accepted.feed.shutdown();
  ctx.stats.feeds_open.fetch_sub(1, Ordering::Relaxed);
  drop(write_tx);
  let _ = writer_task.await;
  qos1.abort();
  qos0.abort();

  if !ctx.registry.holds(&pigeon_id, accepted.session_id) {
    tracing::debug!(pigeon = %pigeon_id, "session was superseded before it ended");
  }
  ctx.registry.release(&pigeon_id, accepted.session_id);

  if let Some(will) = accepted.will.as_ref() {
    deliver_will(ctx, &pigeon_id, &accepted.token, will, end).await;
  }

  end
}

/// Bridges a will, unless something says not to.
///
/// The suppression rule is the one that matters in practice: a device that
/// reconnects before its old session's keepalive expires would otherwise be
/// reported offline by the session it already replaced.
async fn deliver_will<U: Upstream>(
  ctx: &Arc<SessionContext<U>>,
  pigeon_id: &str,
  token: &str,
  will: &proto::Will,
  end: SessionEnd,
) {
  if !end.wants_will() {
    return;
  }
  let Some(topic) = PublishTopic::parse(&will.topic) else {
    return;
  };
  // This session released its own claim before getting here, so a claim
  // still standing can only be a newer session's.
  if ctx.registry.claimed(pigeon_id) {
    tracing::debug!(pigeon = %pigeon_id, "will suppressed: a newer session holds this pigeon");
    return;
  }
  let result = bridge::bridge_one(
    ctx.upstream.as_ref(),
    pigeon_id,
    token,
    PublishJob {
      topic,
      payload: will.payload.clone(),
      pid: None,
      queued_bytes: 0,
    },
  )
  .await;
  tracing::info!(pigeon = %pigeon_id, verdict = ?result.verdict, "will bridged");
}

enum Step {
  Continue,
  End(SessionEnd),
}

#[allow(clippy::too_many_arguments)]
fn handle<U: Upstream>(
  ctx: &Arc<SessionContext<U>>,
  accepted: &mut Accepted,
  state: &mut SessionState,
  write_tx: &mpsc::Sender<Vec<u8>>,
  job_tx: &mpsc::Sender<PublishJob>,
  fast_tx: &mpsc::Sender<PublishJob>,
  event: Inbound,
) -> Step {
  let version = accepted.version;
  match event {
    // PINGRESP is written from the reader, never queued behind a publish:
    // answering a ping is the one thing that must not depend on upstream.
    Inbound::Pingreq => {
      send(write_tx, version, &Outbound::Pingresp);
      Step::Continue
    }

    Inbound::Disconnect { deliver_will } => Step::End(SessionEnd::Graceful { deliver_will }),

    Inbound::Puback { pid } => {
      tracing::trace!(pigeon = %accepted.pigeon_id, pid, "retained shadow acknowledged");
      // The only publishes this broker sends are retained shadows, and it
      // does not retransmit them, so an ack is bookkeeping the client is
      // free to send and the broker has nothing to reconcile it against.
      Step::Continue
    }

    Inbound::Connect(_) => {
      send(
        write_tx,
        version,
        &Outbound::Disconnect {
          reason: DisconnectReason::ProtocolError,
          text: Some("a second CONNECT on one connection"),
        },
      );
      Step::End(SessionEnd::Ungraceful)
    }

    Inbound::Unexpected(what) => {
      tracing::debug!(pigeon = %accepted.pigeon_id, what, "unexpected packet");
      send(
        write_tx,
        version,
        &Outbound::Disconnect {
          reason: DisconnectReason::ProtocolError,
          text: None,
        },
      );
      Step::End(SessionEnd::Ungraceful)
    }

    Inbound::Subscribe { pid, filters } => {
      let mut results = Vec::with_capacity(filters.len());
      let mut granted = None;
      for (filter, requested_qos) in &filters {
        let result = match topics::classify_filter(filter) {
          SubscribeOutcome::ShadowTarget => {
            // A QoS 2 subscription is granted at 1, which both versions
            // allow, rather than refused: the client asked for at most 2.
            let qos = (*requested_qos).min(1);
            granted = Some(qos);
            if qos == 0 {
              SubResult::GrantedQos0
            } else {
              SubResult::GrantedQos1
            }
          }
          SubscribeOutcome::SharedNotSupported => SubResult::SharedNotSupported,
          SubscribeOutcome::NotAuthorized => SubResult::NotAuthorized,
        };
        results.push(result);
      }
      send(write_tx, version, &Outbound::Suback { pid, results });

      if let Some(qos) = granted {
        state.granted_qos = Some(qos);
        // A new subscription always gets the current value, whatever was
        // delivered to an earlier one: this is the retained delivery the
        // client subscribed for.
        state.last_delivered = None;
        push_shadow_if_new(ctx, write_tx, version, state);
      }
      Step::Continue
    }

    Inbound::Unsubscribe { pid, filters } => {
      let count = filters.len();
      if filters
        .iter()
        .any(|f| topics::classify_filter(f) == SubscribeOutcome::ShadowTarget)
      {
        state.granted_qos = None;
        state.last_delivered = None;
      }
      send(write_tx, version, &Outbound::Unsuback { pid, count });
      Step::Continue
    }

    Inbound::Publish(publish) => {
      handle_publish(ctx, accepted, state, write_tx, job_tx, fast_tx, publish)
    }
  }
}

#[allow(clippy::too_many_arguments)]
fn handle_publish<U: Upstream>(
  ctx: &Arc<SessionContext<U>>,
  accepted: &mut Accepted,
  state: &mut SessionState,
  write_tx: &mpsc::Sender<Vec<u8>>,
  job_tx: &mpsc::Sender<PublishJob>,
  fast_tx: &mpsc::Sender<PublishJob>,
  publish: proto::PublishRequest,
) -> Step {
  let version = accepted.version;

  let fault = |reason: DisconnectReason, text: Option<&'static str>| {
    send(write_tx, version, &Outbound::Disconnect { reason, text });
    Step::End(SessionEnd::Ungraceful)
  };

  // The retain flag on an inbound publish is accepted and ignored: the one
  // retained topic here is fed by the pigeon's own Durable Object, not by a
  // device. `dup` likewise, since a redelivery bridges like any other
  // publish and the route behind it is idempotent per report.
  if publish.retain || publish.dup {
    tracing::trace!(
      pigeon = %accepted.pigeon_id,
      retain = publish.retain,
      dup = publish.dup,
      "inbound publish flags ignored"
    );
  }

  // Topic Alias Maximum was advertised as 0, so an alias is a protocol
  // error rather than something to look up.
  if publish.topic_alias.is_some() {
    return fault(DisconnectReason::TopicAliasInvalid, None);
  }

  // QoS 2 is refused rather than shimmed. On v5 this is the protocol error
  // the spec makes it once Maximum QoS 1 was advertised; on 3.1.1 there was
  // no advertisement to make, so the connection closes. Either way no
  // PUBREC is ever sent, so the broker never enters an exchange it cannot
  // honor exactly once.
  if publish.qos > 1 {
    return fault(
      DisconnectReason::QoSNotSupported,
      Some("this broker offers QoS 0 and 1"),
    );
  }

  if publish.payload.len() > limits::MAX_PAYLOAD_BYTES {
    return fault(DisconnectReason::PacketTooLarge, None);
  }

  if !state.within_publish_rate(Instant::now()) {
    return fault(DisconnectReason::MessageRateTooHigh, None);
  }

  let Some(topic) = PublishTopic::parse(&publish.topic) else {
    // Not authorization in the deciding sense: a wrongly forwarded publish
    // would still carry only this pigeon's token and die at the Durable
    // Object. This is the pre-filter that keeps it from being sent at all.
    return fault(DisconnectReason::TopicNameInvalid, None);
  };

  let bytes = publish.payload.len();

  if publish.qos == 0 {
    route_qos0(ctx, accepted, fast_tx, topic, publish.payload);
    return Step::Continue;
  }

  let Some(pid) = publish.pid else {
    return fault(
      DisconnectReason::ProtocolError,
      Some("QoS 1 without a packet id"),
    );
  };

  if !state.accepts_inflight(version, bytes) {
    return fault(DisconnectReason::ReceiveMaximumExceeded, None);
  }

  state.inflight_count += 1;
  state.inflight_bytes += bytes;
  let job = PublishJob {
    topic,
    payload: publish.payload,
    pid: Some(pid),
    queued_bytes: bytes,
  };
  if job_tx.try_send(job).is_err() {
    // The queue is sized above every in-flight ceiling, so a full one means
    // the accounting and the queue have diverged rather than that a client
    // outran its budget.
    state.inflight_count = state.inflight_count.saturating_sub(1);
    state.inflight_bytes = state.inflight_bytes.saturating_sub(bytes);
    return fault(DisconnectReason::ServerBusy, None);
  }
  Step::Continue
}

/// Sends a QoS 0 publish by the cheapest path that is open.
fn route_qos0<U: Upstream>(
  ctx: &Arc<SessionContext<U>>,
  accepted: &Accepted,
  fast_tx: &mpsc::Sender<PublishJob>,
  topic: PublishTopic,
  payload: Bytes,
) {
  // Only telemetry has a frame form; a shadow report or a log chunk goes
  // over its route whatever QoS asked for it.
  if topic == PublishTopic::Telemetry {
    match accepted.feed.state() {
      FeedState::Up if shadow::is_object_shaped(&payload) => {
        if accepted.feed.send_telemetry(payload.clone()) {
          return;
        }
      }
      // The allowance is spent and the upgrade would answer 429, so a POST
      // here would be one Worker plus one Durable Object request bought for
      // a guaranteed refusal, per report, for the rest of the period.
      FeedState::FusePaused => {
        tracing::trace!(pigeon = %accepted.pigeon_id, "QoS 0 telemetry dropped while fuse-paused");
        return;
      }
      _ => {}
    }
  }

  let job = PublishJob {
    topic,
    payload,
    pid: None,
    queued_bytes: 0,
  };
  if fast_tx.try_send(job).is_err() {
    ctx.stats.publish_failures.fetch_add(1, Ordering::Relaxed);
    tracing::debug!(pigeon = %accepted.pigeon_id, "QoS 0 publish dropped, fast path full");
  }
}

/// Acts on one bridged publish: acknowledges it where the version can, and
/// reports whether the session ends.
fn apply_result<U: Upstream>(
  ctx: &Arc<SessionContext<U>>,
  write_tx: &mpsc::Sender<Vec<u8>>,
  version: Version,
  can_signal: bool,
  result: PublishResult,
) -> Option<SessionEnd> {
  ctx.stats.publishes_bridged.fetch_add(1, Ordering::Relaxed);
  if result.edge_shaped {
    ctx
      .stats
      .edge_shaped_refusals
      .fetch_add(1, Ordering::Relaxed);
  }
  if !matches!(result.verdict, Verdict::Accepted) {
    ctx.stats.publish_failures.fetch_add(1, Ordering::Relaxed);
  }

  if let (Some(pid), Some(outcome)) = (result.pid, result.verdict.ack()) {
    send(write_tx, version, &Outbound::Puback { pid, outcome });
  }

  match result.verdict.ends_session(can_signal) {
    Some(reason) => {
      send(
        write_tx,
        version,
        &Outbound::Disconnect { reason, text: None },
      );
      Some(match result.verdict {
        Verdict::CredentialRevoked => SessionEnd::CredentialGone,
        _ => SessionEnd::Ungraceful,
      })
    }
    None => None,
  }
}

/// Delivers the retained shadow if the target changed since the last one
/// this connection sent. `target_version` alone is the change key:
/// `updated_at` bumps on every shadow write, device report-backs included,
/// so keying on it would re-push the target on the device's own reports.
fn push_shadow_if_new<U: Upstream>(
  ctx: &Arc<SessionContext<U>>,
  write_tx: &mpsc::Sender<Vec<u8>>,
  version: Version,
  state: &mut SessionState,
) {
  let Some(qos) = state.granted_qos else {
    return;
  };
  let Some((shadow, target_version)) = state.latest_shadow.clone() else {
    return;
  };
  if state.last_delivered == Some(target_version) {
    return;
  }
  let pid = if qos == 0 {
    None
  } else {
    Some(state.next_pid())
  };
  send(
    write_tx,
    version,
    &Outbound::Publish {
      topic: topics::SHADOW_TARGET.to_string(),
      payload: shadow,
      qos,
      pid,
      retain: true,
    },
  );
  state.last_delivered = Some(target_version);
  ctx.stats.shadow_pushes.fetch_add(1, Ordering::Relaxed);
}

/// Finishes what is already in flight, acking each one, within a budget.
async fn drain<U: Upstream>(
  ctx: &Arc<SessionContext<U>>,
  write_tx: &mpsc::Sender<Vec<u8>>,
  version: Version,
  can_signal: bool,
  results: &mut mpsc::Receiver<PublishResult>,
  state: &mut SessionState,
) {
  let deadline = tokio::time::Instant::now() + DRAIN_BUDGET;
  while state.inflight_count > 0 {
    match tokio::time::timeout_at(deadline, results.recv()).await {
      Ok(Some(result)) => {
        state.inflight_count = state.inflight_count.saturating_sub(1);
        state.inflight_bytes = state.inflight_bytes.saturating_sub(result.queued_bytes);
        if apply_result(ctx, write_tx, version, can_signal, result).is_some() {
          return;
        }
      }
      Ok(None) => return,
      Err(_) => {
        tracing::warn!("drain budget spent with publishes still in flight");
        return;
      }
    }
  }
}

/// Turns a read failure into an ending, telling the client why where the
/// version allows and where the failure is worth naming.
fn read_fault(
  write_tx: &mpsc::Sender<Vec<u8>>,
  version: Version,
  error: FramingError,
) -> SessionEnd {
  match error {
    FramingError::TooLarge { .. } => {
      send(
        write_tx,
        version,
        &Outbound::Disconnect {
          reason: DisconnectReason::PacketTooLarge,
          text: None,
        },
      );
    }
    FramingError::Malformed(_) => {
      send(
        write_tx,
        version,
        &Outbound::Disconnect {
          reason: DisconnectReason::MalformedPacket,
          text: None,
        },
      );
    }
    // The peer is already gone; there is nobody to tell.
    FramingError::Eof | FramingError::Io(_) => {}
  }
  SessionEnd::Ungraceful
}

/// Queues one packet for the writer. A full queue means the client has
/// stopped reading, which the session cannot fix by waiting.
fn send(write_tx: &mpsc::Sender<Vec<u8>>, version: Version, outbound: &Outbound) {
  match proto::encode(version, outbound) {
    Ok(Some(bytes)) => {
      if write_tx.try_send(bytes).is_err() {
        tracing::debug!("outbound queue full, dropping a packet for a stalled client");
      }
    }
    // This version has no way to say it, and the close that follows is the
    // message.
    Ok(None) => {}
    Err(e) => tracing::error!(error = %e, "failed to encode an outbound packet"),
  }
}

async fn run_writer(mut writer: Writer, mut packets: mpsc::Receiver<Vec<u8>>) {
  while let Some(bytes) = packets.recv().await {
    if framing::write_packet(&mut writer, &bytes).await.is_err() {
      break;
    }
  }
  let _ = writer.shutdown().await;
}

/// Silence past 1.5x the negotiated keepalive closes the session, which is
/// the spec's own allowance. The 10 s upstream publish timeout sits far
/// below any deadline this produces, so a slow edge can never look like a
/// silent client.
fn keepalive_deadline(keep_alive: u16) -> Duration {
  Duration::from_millis(u64::from(keep_alive) * 1500)
}

#[cfg(test)]
mod tests {
  use super::*;

  const ID: &str = "aa11bb22cc33dd44ee55ff6600778899aabbccddeeff00112233445566778899";

  #[test]
  fn the_keepalive_deadline_is_one_and_a_half_times_what_was_negotiated() {
    assert_eq!(keepalive_deadline(60), Duration::from_secs(90));
    assert_eq!(keepalive_deadline(10), Duration::from_secs(15));
    assert_eq!(
      keepalive_deadline(limits::MAX_KEEPALIVE_SECS),
      Duration::from_secs(2700)
    );
  }

  #[test]
  fn the_upstream_timeout_stays_below_every_keepalive_deadline() {
    // The shortest deadline a client can negotiate is 1.5 s, which is under
    // the publish timeout; the invariant that matters is the default case,
    // where a slow edge must not look like a silent client.
    assert!(crate::upstream::PUBLISH_TIMEOUT < keepalive_deadline(60));
  }

  #[test]
  fn the_inflight_budget_is_bounded_by_bytes_as_well_as_by_count() {
    let mut state = SessionState::new();
    // Well under the packet count cap, but the byte cap is what stops it.
    let big = limits::MAX_INFLIGHT_BYTES / 2 + 1;
    assert!(state.accepts_inflight(Version::V500, big));
    state.inflight_count += 1;
    state.inflight_bytes += big;
    assert!(
      !state.accepts_inflight(Version::V500, big),
      "the byte cap trips before the packet count does"
    );
  }

  #[test]
  fn v3_gets_a_grace_ceiling_because_it_cannot_be_told_the_real_one() {
    let mut state = SessionState::new();
    state.inflight_count = limits::RECEIVE_MAXIMUM as usize;
    assert!(
      !state.accepts_inflight(Version::V500, 1),
      "v5 was told the limit and is held to it"
    );
    assert!(
      state.accepts_inflight(Version::V311, 1),
      "3.1.1 has no Receive Maximum to have been told"
    );
    state.inflight_count = limits::RECEIVE_MAXIMUM_V3_GRACE as usize;
    assert!(!state.accepts_inflight(Version::V311, 1));
  }

  #[test]
  fn the_publish_rate_window_slides_rather_than_resetting() {
    let mut state = SessionState::new();
    let now = Instant::now();
    for _ in 0..limits::PUBLISH_RATE_MAX {
      assert!(state.within_publish_rate(now));
    }
    assert!(!state.within_publish_rate(now));
    let later = now + Duration::from_secs(limits::PUBLISH_RATE_WINDOW_SECS + 1);
    assert!(state.within_publish_rate(later));
  }

  #[test]
  fn the_publish_rate_stays_under_the_durable_objects_own_frame_limit() {
    // The Durable Object closes a socket at 50 frames per 10 s. The QoS 0
    // fast path turns publishes into frames one for one, so this broker's
    // ceiling has to sit below it or the fast path would trip the platform's
    // own limit.
    assert!(limits::PUBLISH_RATE_MAX < 50);
    assert_eq!(limits::PUBLISH_RATE_WINDOW_SECS, 10);
  }

  #[test]
  fn outbound_packet_ids_never_land_on_zero() {
    let mut state = SessionState::new();
    state.outbound_pid = u16::MAX;
    assert_eq!(state.next_pid(), 1);
    assert_eq!(state.next_pid(), 2);
  }

  #[test]
  fn a_will_is_bridged_only_when_the_device_really_went_away() {
    assert!(SessionEnd::Ungraceful.wants_will());
    assert!(SessionEnd::Graceful { deliver_will: true }.wants_will());
    assert!(
      !SessionEnd::Graceful {
        deliver_will: false
      }
      .wants_will()
    );
    assert!(
      !SessionEnd::TakenOver.wants_will(),
      "a takeover means the device reconnected"
    );
    assert!(
      !SessionEnd::CredentialGone.wants_will(),
      "a will here would only earn a guaranteed 401"
    );
    assert!(
      !SessionEnd::Shutdown.wants_will(),
      "the broker went away, not the fleet"
    );
  }

  #[test]
  fn the_registry_hands_the_superseded_session_its_takeover_signal() {
    let registry = Registry::default();
    let first = Arc::new(Notify::new());
    assert!(registry.claim(ID, 1, Arc::clone(&first)).is_none());
    assert!(registry.holds(ID, 1));

    let second = Arc::new(Notify::new());
    let superseded = registry
      .claim(ID, 2, second)
      .expect("the first is superseded");
    assert!(Arc::ptr_eq(&superseded, &first));
    assert!(registry.holds(ID, 2));
    assert!(!registry.holds(ID, 1));
  }

  #[test]
  fn a_superseded_session_does_not_evict_its_successor_on_the_way_out() {
    let registry = Registry::default();
    registry.claim(ID, 1, Arc::new(Notify::new()));
    registry.claim(ID, 2, Arc::new(Notify::new()));
    registry.release(ID, 1);
    assert!(
      registry.holds(ID, 2),
      "the newer session still holds the pigeon"
    );
    registry.release(ID, 2);
    assert!(!registry.claimed(ID));
  }
}
