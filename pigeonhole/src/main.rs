//! The broker's binary: read the environment, start the listener, and wait
//! for a signal. Everything else lives in the library beside it, so the
//! integration harness can stand a real broker up in-process rather than
//! testing a shape that only resembles one.

use anyhow::Context;

use pigeonhole::config::Config;
use pigeonhole::server;

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

  runtime.block_on(async move {
    let broker = server::start(config).await?;
    wait_for_shutdown().await;
    tracing::info!("shutting down: draining sessions");
    broker.shutdown().await;
    Ok(())
  })
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
