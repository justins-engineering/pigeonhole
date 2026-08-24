//! Publish translation and the acknowledgement policy that makes a PUBACK
//! mean something.
//!
//! What an ack says, per leaf: telemetry, "authenticated and durably queued"
//! (the route's 202, whose queue consumer retries the Durable Object write
//! until it lands); shadow report and logs, "the write completed" (the 200).
//! A close means "retry later, or re-authenticate". Payload bytes are copied
//! to the route as they arrived and never parsed: what the payload means is
//! the Durable Object's business, and a bridge that judged it would be
//! deciding something with meaning (`docs/design.md` ADR G).

use std::sync::Arc;

use bytes::Bytes;
use pigeonhole_wire::topics::PublishTopic;
use tokio::sync::mpsc;

use crate::proto::{AckOutcome, DisconnectReason};
use crate::upstream::Upstream;

/// What one upstream answer means for the session. Every arm is a row of the
/// ack table; the version adapters decide how to say each one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
  /// The platform took it.
  Accepted,
  /// Refused for good. Acked deliberately: the report will never be
  /// accepted as sent, so acking stops a client retrying it forever, and
  /// v5 carries the reason.
  PermanentlyRejected(AckOutcome),
  /// The account's message allowance is spent. Delayed, not lost: a v5
  /// session is acked 0x97 and lives on so the client can requeue, while a
  /// v3.1.1 session gets the close that is its only signal.
  FusePaused,
  /// The credential stopped working. The session ends.
  CredentialRevoked,
  /// Worth trying again later. No ack, and the session ends so the client's
  /// own reconnect becomes the retry.
  Retryable,
}

impl Verdict {
  /// Maps one upstream status to the table. `body` decides the one case a
  /// status alone cannot: a 403 from dovecote is plain text, while an
  /// edge-mitigation page is HTML, and reading a WAF challenge as a
  /// credential failure would send a fleet off to re-provision over an edge
  /// event.
  pub fn classify(status: u16, body: &[u8]) -> Verdict {
    match status {
      200..=299 => Verdict::Accepted,
      // The report is malformed, addressed at nothing, or too big. None of
      // those change by being sent again.
      400 => Verdict::PermanentlyRejected(AckOutcome::PayloadFormatInvalid),
      404 | 413 => Verdict::PermanentlyRejected(AckOutcome::UnspecifiedError),
      401 => Verdict::CredentialRevoked,
      403 if crate::auth::looks_like_html(body) => Verdict::Retryable,
      403 => Verdict::CredentialRevoked,
      429 => Verdict::FusePaused,
      _ => Verdict::Retryable,
    }
  }

  /// Whether an edge-shaped answer was seen, which the stats line counts
  /// separately so an edge event does not read as a fleet credential
  /// failure.
  pub fn is_edge_shaped(status: u16, body: &[u8]) -> bool {
    status == 403 && crate::auth::looks_like_html(body)
  }

  /// The reason a session ends on this verdict, or `None` if it survives.
  pub fn ends_session(self, can_signal: bool) -> Option<DisconnectReason> {
    match self {
      Verdict::Accepted | Verdict::PermanentlyRejected(_) => None,
      // Only a version that can carry a reason code can keep the session:
      // on 3.1.1 the close is the whole message.
      Verdict::FusePaused if can_signal => None,
      Verdict::FusePaused => Some(DisconnectReason::QuotaExceeded),
      Verdict::CredentialRevoked => Some(DisconnectReason::NotAuthorized),
      Verdict::Retryable => Some(DisconnectReason::ServerBusy),
    }
  }

  /// What to acknowledge with, or `None` when withholding the ack is the
  /// message.
  pub fn ack(self) -> Option<AckOutcome> {
    match self {
      Verdict::Accepted => Some(AckOutcome::Success),
      Verdict::PermanentlyRejected(outcome) => Some(outcome),
      Verdict::FusePaused => Some(AckOutcome::QuotaExceeded),
      Verdict::CredentialRevoked => Some(AckOutcome::NotAuthorized),
      Verdict::Retryable => None,
    }
  }
}

/// One publish waiting to be bridged.
#[derive(Debug)]
pub struct PublishJob {
  pub topic: PublishTopic,
  pub payload: Bytes,
  /// `None` for QoS 0, which has nothing to acknowledge.
  pub pid: Option<u16>,
  /// Bytes this job is holding against the session's in-flight budget.
  pub queued_bytes: usize,
}

/// What the bridge did with one job.
#[derive(Debug)]
pub struct PublishResult {
  pub pid: Option<u16>,
  pub verdict: Verdict,
  pub queued_bytes: usize,
  pub edge_shaped: bool,
}

/// Bridges one publish and reports the verdict. A transport failure is a
/// retryable verdict rather than an error: from the session's side, "the
/// edge did not answer" and "the edge answered 502" mean the same thing.
pub async fn bridge_one<U: Upstream>(
  upstream: &U,
  pigeon_id: &str,
  bearer: &str,
  job: PublishJob,
) -> PublishResult {
  let response = upstream
    .publish(
      pigeon_id,
      job.topic.route_leaf(),
      job.topic.content_type(),
      bearer,
      job.payload.to_vec(),
    )
    .await;

  let (verdict, edge_shaped) = match response {
    Ok(response) => (
      Verdict::classify(response.status, &response.body),
      Verdict::is_edge_shaped(response.status, &response.body),
    ),
    Err(e) => {
      tracing::debug!(pigeon = %pigeon_id, error = %e, "upstream publish failed");
      (Verdict::Retryable, false)
    }
  };

  PublishResult {
    pid: job.pid,
    verdict,
    queued_bytes: job.queued_bytes,
    edge_shaped,
  }
}

/// Runs a session's QoS 1 publishes one at a time in arrival order, which is
/// what makes a PUBACK mean the platform's own answer and keeps rapid
/// reports from a device in the order it sent them.
///
/// QoS 0 deliberately does not come through here: a stalled POST must not
/// delay the fast path, so ordering is guaranteed within a QoS class rather
/// than across classes.
pub async fn run_queue<U: Upstream>(
  upstream: Arc<U>,
  pigeon_id: String,
  bearer: String,
  mut jobs: mpsc::Receiver<PublishJob>,
  results: mpsc::Sender<PublishResult>,
) {
  while let Some(job) = jobs.recv().await {
    let result = bridge_one(upstream.as_ref(), &pigeon_id, &bearer, job).await;
    if results.send(result).await.is_err() {
      return;
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const HTML: &[u8] = b"<!DOCTYPE html><html><head><title>Attention Required</title>";
  const PLAIN: &[u8] = b"forbidden";

  #[test]
  fn every_success_shape_the_device_routes_use_is_accepted() {
    // 200 is the shadow and log routes; 202 is telemetry behind the queue.
    for status in [200, 201, 202, 204] {
      assert_eq!(Verdict::classify(status, b""), Verdict::Accepted);
    }
  }

  #[test]
  fn a_permanent_refusal_is_acked_so_the_client_stops_retrying_it() {
    assert_eq!(
      Verdict::classify(400, b"invalid telemetry"),
      Verdict::PermanentlyRejected(AckOutcome::PayloadFormatInvalid)
    );
    for status in [404, 413] {
      assert_eq!(
        Verdict::classify(status, b""),
        Verdict::PermanentlyRejected(AckOutcome::UnspecifiedError)
      );
    }
    assert!(Verdict::classify(400, b"").ack().is_some());
    assert!(Verdict::classify(400, b"").ends_session(true).is_none());
    assert!(Verdict::classify(400, b"").ends_session(false).is_none());
  }

  #[test]
  fn a_revoked_credential_ends_the_session_on_both_versions() {
    for status in [401, 403] {
      let verdict = Verdict::classify(status, PLAIN);
      assert_eq!(verdict, Verdict::CredentialRevoked);
      assert_eq!(
        verdict.ends_session(true),
        Some(DisconnectReason::NotAuthorized)
      );
      assert_eq!(
        verdict.ends_session(false),
        Some(DisconnectReason::NotAuthorized)
      );
    }
  }

  #[test]
  fn an_html_bodied_403_is_edge_security_and_reads_as_retryable() {
    assert_eq!(Verdict::classify(403, HTML), Verdict::Retryable);
    assert!(Verdict::is_edge_shaped(403, HTML));
    assert!(!Verdict::is_edge_shaped(403, PLAIN));
    assert!(!Verdict::is_edge_shaped(503, HTML));
  }

  #[test]
  fn the_fuse_keeps_a_v5_session_and_closes_a_v3_one() {
    let verdict = Verdict::classify(429, b"");
    assert_eq!(verdict, Verdict::FusePaused);
    assert_eq!(verdict.ack(), Some(AckOutcome::QuotaExceeded));
    assert_eq!(
      verdict.ends_session(true),
      None,
      "a v5 client learns the reason and requeues"
    );
    assert_eq!(
      verdict.ends_session(false),
      Some(DisconnectReason::QuotaExceeded),
      "a 3.1.1 client has only the close to go on"
    );
  }

  #[test]
  fn everything_retryable_withholds_the_ack_and_ends_the_session() {
    for status in [500, 502, 503, 504, 418] {
      let verdict = Verdict::classify(status, b"");
      assert_eq!(verdict, Verdict::Retryable);
      assert_eq!(verdict.ack(), None, "{status} must not be acked");
      assert_eq!(
        verdict.ends_session(true),
        Some(DisconnectReason::ServerBusy)
      );
    }
  }
}
