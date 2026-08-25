//! The broker's binary: read the environment, start the listener, and wait
//! for a signal. Everything else lives in the library beside it, so the
//! integration harness can stand a real broker up in-process rather than
//! testing a shape that only resembles one.
//!
//! `pigeonhole --check` stops after proving the configuration is servable
//! and never binds the port, so an operator can validate a fresh install or
//! a renewed certificate from the same credential set the unit uses before
//! restarting into it.

use std::sync::Arc;

use anyhow::Context;
use openssl::nid::Nid;
use openssl::x509::X509;

use pigeonhole::config::Config;
use pigeonhole::psk::{DovecotePskSource, PskResolver};
use pigeonhole::server;
use pigeonhole::tls;

fn main() -> anyhow::Result<()> {
  init_tracing();

  let config = Config::from_env().map_err(anyhow::Error::msg)?;

  if std::env::args().nth(1).as_deref() == Some("--check") {
    return check(&config);
  }

  // Multi-threaded everywhere, not as a throughput choice: the PSK
  // handshake callback is synchronous and may miss its cache, and the
  // `block_in_place` that lets it do a lookup without stalling the runtime
  // exists only on this flavour.
  let runtime = tokio::runtime::Builder::new_multi_thread()
    .enable_all()
    .build()
    .context("building the tokio runtime")?;

  runtime.block_on(async move {
    let broker = server::start(config).await?;
    wait_for_shutdown().await;
    tracing::info!("shutting down: draining sessions");
    broker.shutdown().await;
    Ok(())
  })
}

/// Everything `server::start` would do short of binding: the listen address
/// resolves, the chain and key parse and match each other, and the PSK
/// resolver constructs. The leaf's validity window is printed because the
/// unit loads the chain at start and a renewal that failed to land is
/// otherwise found only by the restart that was meant to pick it up.
fn check(config: &Config) -> anyhow::Result<()> {
  use std::net::ToSocketAddrs;

  let listen = config
    .listen
    .to_socket_addrs()
    .with_context(|| format!("PIGEONHOLE_LISTEN {:?} is not an address", config.listen))?
    .next()
    .context("PIGEONHOLE_LISTEN resolves to nothing")?;

  let resolver = Arc::new(PskResolver::new(
    Box::new(DovecotePskSource::new(
      &config.dovecote_url,
      config.service_secret.clone(),
    )),
    config.psk_cache_ttl,
  ));
  tls::build_listener_context(&config.tls_cert, &config.tls_key, resolver)
    .context("building the listener's TLS context")?;

  let pem = std::fs::read(&config.tls_cert)
    .with_context(|| format!("reading {}", config.tls_cert.display()))?;
  let leaf = X509::from_pem(&pem).context("parsing the chain's first certificate")?;
  let subject = leaf
    .subject_name()
    .entries_by_nid(Nid::COMMONNAME)
    .next()
    .and_then(|entry| entry.data().to_string().ok())
    .unwrap_or_default();

  println!(
    "ok listen={listen} dovecote={} cert={} subject={subject:?} not_before={} not_after={}",
    config.dovecote_url,
    config.tls_cert.display(),
    leaf.not_before(),
    leaf.not_after(),
  );
  Ok(())
}

fn init_tracing() {
  let filter = tracing_subscriber::EnvFilter::try_from_env("PIGEONHOLE_LOG")
    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
  tracing_subscriber::fmt()
    .with_env_filter(filter)
    .with_target(false)
    .init();
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
