//! The device WebSocket, the session's spine: dialled at CONNECT (the
//! upgrade is the session's authentication, ADR D), its snapshot-on-accept
//! frame seeds the retained `pigeon/shadow/target` value, its
//! `shadow_update` frames refresh it, and QoS 0 telemetry rides it as
//! `telemetry` frames.
//!
//! The shadow is carried as the bytes the Durable Object sent, lifted out of
//! the frame as a raw JSON slice and never re-serialized: the retained value
//! is the platform's own state, not a copy the broker composed.
//!
//! Liveness is the bridge's job, because the Durable Object never pings: a
//! protocol-level ping per 60 s of INBOUND silence, two missed pongs
//! reconnects. Inbound only. A half-open path absorbs outbound writes into
//! the send buffer for minutes and telemetry frames get no response, so
//! sending proves nothing and must not reset the timer.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::value::RawValue;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::upstream::{DeviceSocket, UpgradeFailure, Upstream};

/// Inbound silence before the bridge pings, in seconds.
const PING_AFTER_SILENCE_SECS: u64 = 60;
/// Missed pongs before the socket counts as half-open.
const MISSED_PONGS_BEFORE_RECONNECT: u32 = 2;
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Redial delay while the account's allowance is spent. The upgrade would
/// answer 429 until it resets, so a hot redial buys nothing and costs a
/// Worker request each time.
const FUSE_BACKOFF: Duration = Duration::from_secs(300);

/// Durable Object close codes the feed acts on, from `docs/api.md`.
const CLOSE_TOKEN_REVOKED: u16 = 4004;
const CLOSE_PIGEON_DELETED: u16 = 4005;
const CLOSE_REPLACED: u16 = 4009;
const CLOSE_FUSE_PAUSED: u16 = 4029;

/// Where QoS 0 telemetry goes, which the session reads per publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedState {
  /// The socket is up: telemetry rides it as a frame.
  Up,
  /// The socket is down or terminally closed: telemetry falls back to the
  /// POST, which is the same route with one more hop.
  Down,
  /// The account's allowance is spent. Telemetry is dropped rather than
  /// POSTed into a guaranteed 429, one Worker plus one Durable Object
  /// request apiece for the rest of the billing period.
  FusePaused,
}

/// What the feed tells its session.
#[derive(Debug)]
pub enum FeedEvent {
  /// A new shadow arrived. `shadow` is the Durable Object's own bytes.
  Target {
    shadow: Bytes,
    target_version: i32,
  },
  StateChanged(FeedState),
  /// The credential behind this session stopped existing. The session ends;
  /// there is nothing to redial with.
  Ended(FeedEnd),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedEnd {
  TokenRevoked,
  PigeonDeleted,
}

impl FeedEnd {
  pub fn reason_text(self) -> &'static str {
    match self {
      FeedEnd::TokenRevoked => "token revoked",
      FeedEnd::PigeonDeleted => "pigeon deleted",
    }
  }
}

/// What the session asks of the feed.
#[derive(Debug)]
pub enum FeedCommand {
  /// The metrics object from a QoS 0 `pigeon/telemetry` publish, verbatim.
  Telemetry(Bytes),
  Shutdown,
}

/// The session's handle on its feed.
pub struct Feed {
  commands: mpsc::Sender<FeedCommand>,
  state: FeedState,
}

impl Feed {
  pub fn state(&self) -> FeedState {
    self.state
  }

  pub fn set_state(&mut self, state: FeedState) {
    self.state = state;
  }

  /// Sends telemetry over the feed. `false` means the frame could not be
  /// queued and the caller should fall back to the POST.
  pub fn send_telemetry(&self, metrics: Bytes) -> bool {
    self
      .commands
      .try_send(FeedCommand::Telemetry(metrics))
      .is_ok()
  }

  pub fn shutdown(&self) {
    let _ = self.commands.try_send(FeedCommand::Shutdown);
  }
}

/// Starts the feed on an already-open socket. The socket came from the
/// CONNECT-time upgrade, which is what authenticated the session, so the
/// feed never has to authenticate anything itself.
pub fn spawn<U: Upstream>(
  upstream: Arc<U>,
  pigeon_id: String,
  token: String,
  socket: DeviceSocket,
) -> (Feed, mpsc::Receiver<FeedEvent>) {
  // Bounded: a session that cannot keep up with its own telemetry should
  // drop QoS 0 frames, which is what QoS 0 means, rather than grow a queue.
  let (command_tx, command_rx) = mpsc::channel(16);
  let (event_tx, event_rx) = mpsc::channel(16);

  tokio::spawn(run(
    upstream, pigeon_id, token, socket, command_rx, event_tx,
  ));

  (
    Feed {
      commands: command_tx,
      state: FeedState::Up,
    },
    event_rx,
  )
}

async fn run<U: Upstream>(
  upstream: Arc<U>,
  pigeon_id: String,
  token: String,
  initial: DeviceSocket,
  mut commands: mpsc::Receiver<FeedCommand>,
  events: mpsc::Sender<FeedEvent>,
) {
  let mut socket = Some(initial);
  let mut attempt: u32 = 0;
  let mut fuse_paused = false;

  loop {
    let live = match socket.take() {
      Some(live) => live,
      None => {
        let delay = if fuse_paused {
          jittered(FUSE_BACKOFF)
        } else {
          attempt = attempt.saturating_add(1);
          jittered(backoff(attempt))
        };
        tokio::select! {
          _ = tokio::time::sleep(delay) => {}
          command = commands.recv() => match command {
            Some(FeedCommand::Shutdown) | None => return,
            // Telemetry arriving while the feed is down was already routed
            // to the POST or dropped by the session; nothing to do here.
            Some(FeedCommand::Telemetry(_)) => {}
          },
        }

        match upstream.dial_device_ws(&pigeon_id, &token).await {
          Ok(reconnected) => {
            attempt = 0;
            if events
              .send(FeedEvent::StateChanged(FeedState::Up))
              .await
              .is_err()
            {
              return;
            }
            reconnected
          }
          // The credential is gone. Nothing to redial with, and the session
          // it authenticated ends with it.
          Err(UpgradeFailure::Status { status: 401, .. }) => {
            let _ = events.send(FeedEvent::Ended(FeedEnd::TokenRevoked)).await;
            return;
          }
          Err(failure) => {
            fuse_paused = matches!(failure, UpgradeFailure::Status { status: 429, .. });
            tracing::debug!(pigeon = %pigeon_id, ?failure, "device feed redial refused");
            continue;
          }
        }
      }
    };

    match serve(live, &mut commands, &events, &pigeon_id).await {
      Outcome::Shutdown => return,
      Outcome::Ended(end) => {
        let _ = events.send(FeedEvent::Ended(end)).await;
        return;
      }
      Outcome::Terminal(reason) => {
        // Something else holds this pigeon's socket. Redialling would close
        // theirs and theirs would close ours, a fight with no winner, so the
        // feed stays down and QoS 0 telemetry falls back to the POST. It
        // re-arms only when a new MQTT session dials its own.
        tracing::warn!(pigeon = %pigeon_id, reason, "device feed is terminal for this session");
        let _ = events.send(FeedEvent::StateChanged(FeedState::Down)).await;
        while let Some(command) = commands.recv().await {
          if matches!(command, FeedCommand::Shutdown) {
            return;
          }
        }
        return;
      }
      Outcome::Retry {
        fuse_paused: paused,
      } => {
        fuse_paused = paused;
        let state = if paused {
          FeedState::FusePaused
        } else {
          FeedState::Down
        };
        if events.send(FeedEvent::StateChanged(state)).await.is_err() {
          return;
        }
      }
    }
  }
}

enum Outcome {
  /// The session asked the feed to stop.
  Shutdown,
  /// The credential or the pigeon is gone; the session ends with it.
  Ended(FeedEnd),
  /// This session's feed cannot be re-established.
  Terminal(&'static str),
  Retry {
    fuse_paused: bool,
  },
}

/// Serves one socket until it closes or the session ends.
async fn serve(
  mut socket: DeviceSocket,
  commands: &mut mpsc::Receiver<FeedCommand>,
  events: &mpsc::Sender<FeedEvent>,
  pigeon_id: &str,
) -> Outcome {
  let mut missed_pongs = 0u32;

  loop {
    let silence = tokio::time::sleep(ping_after_silence());
    tokio::pin!(silence);

    tokio::select! {
      command = commands.recv() => match command {
        None | Some(FeedCommand::Shutdown) => {
          let _ = socket.close(None).await;
          return Outcome::Shutdown;
        }
        Some(FeedCommand::Telemetry(metrics)) => {
          if socket.send(Message::Text(telemetry_frame(&metrics).into())).await.is_err() {
            return Outcome::Retry { fuse_paused: false };
          }
        }
      },

      message = socket.next() => {
        // Any inbound frame is proof the path is alive, which is the only
        // thing that resets the liveness timer.
        missed_pongs = 0;
        match message {
          None => return Outcome::Retry { fuse_paused: false },
          Some(Err(e)) => {
            tracing::debug!(pigeon = %pigeon_id, error = %e, "device feed read failed");
            return Outcome::Retry { fuse_paused: false };
          }
          Some(Ok(Message::Close(frame))) => {
            let code = frame.as_ref().map(|f| u16::from(f.code)).unwrap_or(0);
            return match code {
              CLOSE_TOKEN_REVOKED => Outcome::Ended(FeedEnd::TokenRevoked),
              CLOSE_PIGEON_DELETED => Outcome::Ended(FeedEnd::PigeonDeleted),
              CLOSE_REPLACED => Outcome::Terminal("another connection holds this pigeon's socket"),
              CLOSE_FUSE_PAUSED => Outcome::Retry { fuse_paused: true },
              _ => Outcome::Retry { fuse_paused: false },
            };
          }
          Some(Ok(Message::Text(text))) => {
            if let Some(event) = handle_frame(text.as_str(), &mut socket, pigeon_id).await {
              if events.send(event).await.is_err() {
                let _ = socket.close(None).await;
                return Outcome::Shutdown;
              }
            }
          }
          // Pongs and anything else inbound have already done their one job,
          // which was to arrive.
          Some(Ok(_)) => {}
        }
      },

      _ = &mut silence => {
        if missed_pongs >= MISSED_PONGS_BEFORE_RECONNECT {
          tracing::info!(pigeon = %pigeon_id, "device feed unanswered, reconnecting");
          return Outcome::Retry { fuse_paused: false };
        }
        missed_pongs += 1;
        if socket.send(Message::Ping(Bytes::new())).await.is_err() {
          return Outcome::Retry { fuse_paused: false };
        }
      },
    }
  }
}

/// Handles one text frame, answering it on the socket where that is the
/// whole response, and returning an event where the session needs to know.
async fn handle_frame(text: &str, socket: &mut DeviceSocket, pigeon_id: &str) -> Option<FeedEvent> {
  let frame: InboundFrame = match serde_json::from_str(text) {
    Ok(frame) => frame,
    Err(e) => {
      tracing::debug!(pigeon = %pigeon_id, error = %e, "unreadable device feed frame");
      return None;
    }
  };

  match frame.kind.as_str() {
    "shadow_update" => {
      let shadow = frame.shadow?;
      let bytes = Bytes::from(shadow.get().as_bytes().to_vec());
      let target_version = pigeonhole_wire::payload::TargetVersion::read(&bytes)?;
      Some(FeedEvent::Target {
        shadow: bytes,
        target_version,
      })
    }
    // The dashboard's shell route sees a connected device because this
    // socket is open, so it deserves an honest answer rather than a timeout.
    "shell_cmd" => {
      let request_id = frame.request_id?;
      let reply = serde_json::json!({
        "type": "shell_output",
        "request_id": request_id,
        "output": "shell not available over MQTT",
        "exit_code": -1,
        "truncated": false,
      });
      let _ = socket.send(Message::Text(reply.to_string().into())).await;
      None
    }
    _ => None,
  }
}

#[derive(Deserialize)]
struct InboundFrame {
  #[serde(rename = "type")]
  kind: String,
  #[serde(default)]
  shadow: Option<Box<RawValue>>,
  #[serde(default)]
  request_id: Option<String>,
}

/// Wraps a QoS 0 telemetry payload in the frame the Durable Object expects.
/// The metrics object is spliced in as the bytes the device published, so
/// the frame path stays as literal a copy as the POST path is.
fn telemetry_frame(metrics: &[u8]) -> String {
  let mut frame = String::with_capacity(metrics.len() + 32);
  frame.push_str("{\"type\":\"telemetry\",\"metrics\":");
  frame.push_str(&String::from_utf8_lossy(metrics));
  frame.push('}');
  frame
}

/// Whether a payload is shaped like the JSON object the frame path splices
/// it into. Not a parse, and not authorization: it exists because a frame
/// the Durable Object cannot read closes the socket, so one malformed
/// publish would otherwise cost the session its feed. A QoS 0 publish has no
/// acknowledgement to carry a refusal, so dropping it is within contract.
pub fn is_object_shaped(payload: &[u8]) -> bool {
  let trimmed = payload.trim_ascii();
  trimmed.first() == Some(&b'{') && trimmed.last() == Some(&b'}')
}

/// Inbound silence before the bridge pings. Read from the environment
/// because a fleet on a link that goes half-open often may want to find a
/// dead socket sooner than a minute, and because the default is far too long
/// to exercise. Read per use rather than cached: it happens once per minute
/// per session at most.
fn ping_after_silence() -> Duration {
  let secs = std::env::var("PIGEONHOLE_FEED_PING_SECS")
    .ok()
    .and_then(|value| value.parse::<u64>().ok())
    .filter(|secs| *secs > 0)
    .unwrap_or(PING_AFTER_SILENCE_SECS);
  Duration::from_secs(secs)
}

fn backoff(attempt: u32) -> Duration {
  let seconds = BACKOFF_MIN.as_secs().saturating_mul(1u64 << attempt.min(6));
  Duration::from_secs(seconds.min(BACKOFF_MAX.as_secs()))
}

/// Spreads reconnects so a fleet that lost its feed together does not come
/// back in lockstep. Derived from the clock rather than from a random number
/// generator, which is one dependency this needs no more precision than.
fn jittered(base: Duration) -> Duration {
  let nanos = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .map(|d| d.subsec_nanos() as u64)
    .unwrap_or(0);
  let spread = base.as_millis() as u64 / 2;
  if spread == 0 {
    return base;
  }
  base + Duration::from_millis(nanos % spread)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn the_telemetry_frame_splices_the_published_bytes_in_unchanged() {
    let frame = telemetry_frame(br#"{"temp":"21.5","status":"ok"}"#);
    assert_eq!(
      frame,
      r#"{"type":"telemetry","metrics":{"temp":"21.5","status":"ok"}}"#
    );
    let parsed: serde_json::Value = serde_json::from_str(&frame).expect("valid frame");
    assert_eq!(parsed["metrics"]["temp"], "21.5");
  }

  #[test]
  fn the_object_shape_check_admits_what_the_route_would_and_refuses_the_rest() {
    assert!(is_object_shaped(b"{}"));
    assert!(is_object_shaped(b"  {\"a\":\"b\"}\n"));
    assert!(!is_object_shaped(b"[1,2]"));
    assert!(!is_object_shaped(b"\"a string\""));
    assert!(!is_object_shaped(b""));
    assert!(!is_object_shaped(b"not json"));
  }

  #[test]
  fn backoff_climbs_to_the_ceiling_and_stops() {
    assert_eq!(backoff(0), Duration::from_secs(1));
    assert_eq!(backoff(1), Duration::from_secs(2));
    assert_eq!(backoff(5), Duration::from_secs(32));
    assert_eq!(backoff(6), BACKOFF_MAX);
    assert_eq!(backoff(30), BACKOFF_MAX);
  }

  #[test]
  fn jitter_only_ever_adds_and_stays_inside_half_the_base() {
    for base in [BACKOFF_MIN, BACKOFF_MAX, FUSE_BACKOFF] {
      let jittered = jittered(base);
      assert!(jittered >= base);
      assert!(jittered <= base + base / 2);
    }
  }

  #[test]
  fn a_shadow_update_yields_the_durable_objects_own_bytes() {
    let text = r#"{"type":"shadow_update","shadow":{"target_version":4,"current_version":1,"target_config":"{}","current_config":"{}","updated_at":17}}"#;
    let frame: InboundFrame = serde_json::from_str(text).expect("frame");
    let shadow = frame.shadow.expect("shadow member");
    assert_eq!(
      pigeonhole_wire::payload::TargetVersion::read(shadow.get().as_bytes()),
      Some(4)
    );
    // The bytes are the ones that arrived, not a re-serialization.
    assert!(shadow.get().starts_with(r#"{"target_version":4"#));
  }

  #[test]
  fn an_unknown_frame_type_is_ignored_rather_than_treated_as_a_fault() {
    let frame: InboundFrame =
      serde_json::from_str(r#"{"type":"something_new","extra":1}"#).expect("frame");
    assert_eq!(frame.kind, "something_new");
    assert!(frame.shadow.is_none());
  }
}
