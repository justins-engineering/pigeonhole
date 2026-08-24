//! pigeonhole, PidgeIoT's MQTT bridge. One TLS listener on 8883 serving both
//! certificate and PSK handshakes, per-pigeon sessions whose topics are
//! session-scoped (the handshake fixes the pigeon, so the id is not in the
//! topic), and a bridge that turns each publish into the matching HTTP call
//! on dovecote's device routes with the device's own bearer token, so every
//! decision with meaning stays at the edge (ADR G, the thin-bridge rule).
//!
//! The other upstream leg is the pigeon's device WebSocket, opened at
//! CONNECT on the device's behalf: it is the session's authentication, the
//! retained-shadow feed, and the QoS 0 telemetry fast path.
//!
//! Concurrency model: one tokio task per session on the multi-thread
//! runtime, which the PSK callback's cache-miss lookup requires because it
//! runs under `block_in_place`. Configured entirely by environment
//! variables, the same set whether run as the hardened systemd unit
//! (`infra/pigeonhole.service`) or the container example (`Dockerfile` plus
//! `infra/docker-compose.yml`). `docs/design.md` is the decision record;
//! `docs/infra/mqtt-broker.md` is the runbook.

mod auth;
mod bridge;
mod config;
mod proto;
mod psk;
mod quota;
mod session;
mod shadow;
mod tls;
mod upstream;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use openssl::ssl::Ssl;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_openssl::SslStream;

use crate::config::Config;
use crate::psk::{DovecotePskSource, PskResolver};
use crate::quota::{Admission, ConnQuota};
use crate::session::{Registry, SessionContext, Stats};
use crate::upstream::Dovecote;

/// Wall clock a connection has to finish its TLS handshake. A peer that
/// opens a socket and stalls mid-handshake is holding a slot for free, and a
/// slow real device is still far inside this.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(30);
/// How often the one-line summary is logged.
const STATS_INTERVAL: Duration = Duration::from_secs(60);

fn main() -> anyhow::Result<()> {
  init_tracing();

  let config = Config::from_env().map_err(anyhow::Error::msg)?;

  // Multi-threaded everywhere, not as a throughput choice: the PSK
  // handshake callback is synchronous and may miss its cache, and the
  // `block_in_place` that lets it do a lookup without stalling the runtime
  // exists only on this flavour.
  let runtime = tokio::runtime::Builder::new_multi_thread()
    .enable_all()
    .build()
    .context("building the tokio runtime")?;

  runtime.block_on(serve(config))
}

fn init_tracing() {
  let filter = tracing_subscriber::EnvFilter::try_from_env("PIGEONHOLE_LOG")
    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
  tracing_subscriber::fmt()
    .with_env_filter(filter)
    .with_target(false)
    .init();
}

async fn serve(config: Config) -> anyhow::Result<()> {
  let resolver = Arc::new(PskResolver::new(
    Box::new(DovecotePskSource::new(
      &config.dovecote_url,
      config.service_secret.clone(),
    )),
    config.psk_cache_ttl,
  ));

  let tls_context =
    tls::build_listener_context(&config.tls_cert, &config.tls_key, Arc::clone(&resolver))
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
    shutdown: shutdown_rx,
  });

  let quota = ConnQuota::new(quota::MAX_CONNECTIONS, quota::MAX_CONNECTIONS_PER_IP);
  let listener = TcpListener::bind(&config.listen)
    .await
    .with_context(|| format!("binding {}", config.listen))?;

  tracing::info!(
    listen = %config.listen,
    dovecote = %config.dovecote_url,
    "pigeonhole listening (TLS only, certificate and PSK on one port)"
  );

  tokio::spawn(report_stats(
    Arc::clone(&stats),
    quota.clone(),
    shutdown_tx.subscribe(),
  ));

  let signals = shutdown_tx.subscribe();
  loop {
    tokio::select! {
      _ = wait_for_shutdown(), if !*signals.borrow() => {
        tracing::info!("shutting down: draining sessions");
        let _ = shutdown_tx.send(true);
        break;
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
          // No byte of application data is read before this completes.
          // There is no cleartext listener anywhere for one to arrive on.
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

  // Sessions drain on their own once the flag is set; the unit's
  // TimeoutStopSec sits above the drain budget so systemd does not kill the
  // process mid-drain.
  let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
  while stats
    .sessions_open
    .load(std::sync::atomic::Ordering::Relaxed)
    > 0
    && tokio::time::Instant::now() < deadline
  {
    tokio::time::sleep(Duration::from_millis(100)).await;
  }
  tracing::info!(summary = %stats.summary(), "pigeonhole stopped");
  Ok(())
}

async fn wait_for_shutdown() {
  let ctrl_c = async {
    let _ = tokio::signal::ctrl_c().await;
  };

  #[cfg(unix)]
  let terminate = async {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
      Ok(mut signal) => {
        signal.recv().await;
      }
      Err(e) => {
        tracing::error!(error = %e, "cannot listen for SIGTERM");
        std::future::pending::<()>().await;
      }
    }
  };
  #[cfg(not(unix))]
  let terminate = std::future::pending::<()>();

  tokio::select! {
    _ = ctrl_c => {}
    _ = terminate => {}
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
