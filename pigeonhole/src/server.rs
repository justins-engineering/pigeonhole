//! Standing the broker up: the TLS context, the admission loop, the stats
//! line, and a shutdown that drains rather than drops.
//!
//! Split from the binary so a test can start a real broker in-process on an
//! ephemeral port. The only difference between that broker and the one the
//! unit runs is which config it was handed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Context;
use openssl::ssl::{Ssl, SslContext};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_openssl::SslStream;

use crate::config::Config;
use crate::psk::{DovecotePskSource, PskResolver};
use crate::quota::{self, Admission, ConnQuota};
use crate::session::{self, Registry, SessionContext, Stats};
use crate::upstream::Dovecote;

/// Wall clock a connection has to finish its TLS handshake. A peer that
/// opens a socket and stalls mid-handshake is holding a slot for free, and a
/// slow real device is still far inside this.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);
/// How often the one-line summary is logged.
const STATS_INTERVAL: Duration = Duration::from_secs(60);
/// How long a shutdown waits for sessions to finish draining. Sits above the
/// session's own drain budget, and the unit's `TimeoutStopSec` sits above
/// this, so systemd never kills the process mid-drain.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(20);

/// A running broker.
pub struct Broker {
  /// Where it actually bound, which matters when the config asked for port
  /// zero.
  pub local_addr: SocketAddr,
  pub stats: Arc<Stats>,
  shutdown: watch::Sender<bool>,
  accept_loop: JoinHandle<()>,
}

impl Broker {
  /// Stops accepting, lets sessions drain, and waits for them.
  pub async fn shutdown(self) {
    let _ = self.shutdown.send(true);
    let _ = self.accept_loop.await;
    let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
    while self.stats.sessions_open.load(Ordering::Relaxed) > 0
      && tokio::time::Instant::now() < deadline
    {
      tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tracing::info!(summary = %self.stats.summary(), "pigeonhole stopped");
  }

  /// Fires the shutdown without waiting, for a caller that wants to watch
  /// the drain from the outside.
  pub fn begin_shutdown(&self) {
    let _ = self.shutdown.send(true);
  }
}

pub async fn start(config: Config) -> anyhow::Result<Broker> {
  let resolver = Arc::new(PskResolver::new(
    Box::new(DovecotePskSource::new(
      &config.dovecote_url,
      config.service_secret.clone(),
    )),
    config.psk_cache_ttl,
  ));

  let tls_context =
    crate::tls::build_listener_context(&config.tls_cert, &config.tls_key, Arc::clone(&resolver))
      .context("building the listener's TLS context")?;

  let upstream = Arc::new(Dovecote::new(&config.dovecote_url).map_err(anyhow::Error::msg)?);

  let (shutdown_tx, shutdown_rx) = watch::channel(false);
  let stats = Arc::new(Stats::default());
  let ctx = Arc::new(SessionContext {
    upstream,
    registry: Arc::new(Registry::default()),
    admission: Arc::new(Admission::new()),
    resolver,
    stats: Arc::clone(&stats),
    shutdown: shutdown_rx.clone(),
  });

  let quota = ConnQuota::new(quota::MAX_CONNECTIONS, quota::MAX_CONNECTIONS_PER_IP);
  let listener = TcpListener::bind(&config.listen)
    .await
    .with_context(|| format!("binding {}", config.listen))?;
  let local_addr = listener.local_addr().context("reading the bound address")?;

  tracing::info!(
    listen = %local_addr,
    dovecote = %config.dovecote_url,
    "pigeonhole listening (TLS only, certificate and PSK on one port)"
  );

  tokio::spawn(report_stats(
    Arc::clone(&stats),
    quota.clone(),
    shutdown_rx.clone(),
  ));

  let accept_loop = tokio::spawn(accept_loop(listener, tls_context, ctx, quota, shutdown_rx));

  Ok(Broker {
    local_addr,
    stats,
    shutdown: shutdown_tx,
    accept_loop,
  })
}

async fn accept_loop(
  listener: TcpListener,
  tls_context: SslContext,
  ctx: Arc<SessionContext<Dovecote>>,
  quota: ConnQuota,
  mut shutdown: watch::Receiver<bool>,
) {
  loop {
    tokio::select! {
      changed = shutdown.changed() => {
        if changed.is_err() || *shutdown.borrow() {
          tracing::info!("no longer accepting: draining sessions");
          return;
        }
      }
      accepted = listener.accept() => {
        let (tcp, peer) = match accepted {
          Ok(accepted) => accepted,
          Err(e) => {
            tracing::warn!(error = %e, "accept failed");
            continue;
          }
        };

        // The global brake counts refused CONNECTs only, so this is off
        // except while something is actually being refused in volume. A
        // ceiling on all connections sized for floods would turn a
        // post-drain fleet reconnect into minutes of spurious refusals.
        if !ctx.admission.accepting(std::time::Instant::now()) {
          drop(tcp);
          continue;
        }

        let Some(permit) = quota.try_acquire(peer.ip()) else {
          let cause = if quota.is_full() {
            "the admission table is full"
          } else {
            "this source's fair share is exhausted"
          };
          tracing::debug!(%peer, cause, "connection refused");
          drop(tcp);
          continue;
        };

        let ssl = match Ssl::new(&tls_context) {
          Ok(ssl) => ssl,
          Err(e) => {
            tracing::error!(error = %e, "failed to build an SSL object");
            continue;
          }
        };
        let ctx = Arc::clone(&ctx);
        tokio::spawn(async move {
          let _ = tcp.set_nodelay(true);
          let mut stream = match SslStream::new(ssl, tcp) {
            Ok(stream) => stream,
            Err(e) => {
              tracing::error!(error = %e, "failed to wrap a connection in TLS");
              return;
            }
          };
          // No byte of application data is read before this completes, and
          // there is no cleartext listener anywhere for one to arrive on.
          match tokio::time::timeout(
            HANDSHAKE_DEADLINE,
            std::pin::Pin::new(&mut stream).accept(),
          )
          .await
          {
            Ok(Ok(())) => session::run(ctx, stream, peer, permit).await,
            Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
            Err(_) => tracing::debug!(%peer, "TLS handshake deadline expired"),
          }
        });
      }
    }
  }
}

async fn report_stats(stats: Arc<Stats>, quota: ConnQuota, mut shutdown: watch::Receiver<bool>) {
  let mut ticker = tokio::time::interval(STATS_INTERVAL);
  ticker.tick().await;
  loop {
    tokio::select! {
      _ = ticker.tick() => tracing::info!(
        summary = %stats.summary(),
        connections = quota.held(),
        "stats"
      ),
      changed = shutdown.changed() => {
        if changed.is_err() || *shutdown.borrow() {
          return;
        }
      }
    }
  }
}
