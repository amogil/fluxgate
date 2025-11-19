use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use clap::Parser;
use fluxgate::{
    config::{ConfigManager, DEFAULT_CONFIG_PATH},
    init_tracing,
    proxy::start_proxy_server,
};
use tokio::signal;
use tracing::{info, warn};

#[cfg(unix)]
use tokio::{
    io::AsyncWriteExt,
    net::{UnixListener, UnixStream},
};

#[cfg(unix)]
use tracing::error;

/// Requirement: CLI1, CLI2, CLI3, CLI4 - Command-line interface
#[derive(Parser)]
#[command(
    name = "fluxgate",
    about = "Fluxgate proxy service",
    disable_version_flag = true
)]
struct Cli {
    /// Requirement: CLI2 - Override configuration path
    #[arg(long = "config", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
}

/// Requirement: CLI1 - Start proxy with default config if no arguments
#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    run_proxy(cli.config).await
}

async fn initialize_reload_server(
    config_path: PathBuf,
    config_manager: &ConfigManager,
) -> Option<ReloadServer> {
    #[cfg(unix)]
    {
        match ReloadServer::bind(config_path, config_manager.clone()).await {
            Ok(server) => Some(server),
            Err(err) => {
                warn!(
                    error = %err,
                    "Reload control interface disabled due to initialization failure"
                );
                None
            }
        }
    }
    #[cfg(not(unix))]
    {
        warn!("Configuration reload is not supported on this platform");
        None
    }
}

async fn run_proxy(config_path: PathBuf) -> Result<()> {
    info!(
        path = %config_path.display(),
        "Starting fluxgate proxy with configuration path"
    );

    let config_manager = ConfigManager::initialize(Some(config_path.clone())).await;
    let _reload_server_guard = initialize_reload_server(config_path, &config_manager).await;

    // Requirement: C4.2 - Only log initialization message if config was loaded from file
    if !config_manager.started_with_defaults() {
        info!(
            path = %config_manager.config_path().display(),
            "Fluxgate proxy initialized"
        );
    }

    // Requirement: OP1 - Graceful shutdown on SIGTERM or SIGINT
    // Create shutdown signal for graceful shutdown
    #[cfg(unix)]
    let shutdown_signal = async {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate()).expect("Failed to listen for SIGTERM");

        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Shutdown signal received (SIGINT); shutting down proxy");
            }
            _ = sigterm.recv() => {
                info!("Shutdown signal received (SIGTERM); shutting down proxy");
            }
        }
    };

    #[cfg(not(unix))]
    let shutdown_signal = async {
        signal::ctrl_c()
            .await
            .expect("Failed to listen for shutdown signal");
        info!("Shutdown signal received; shutting down proxy");
    };

    // Start the proxy server
    start_proxy_server(config_manager, shutdown_signal).await?;

    Ok(())
}

#[cfg(unix)]
fn reload_socket_path(config_path: &Path) -> PathBuf {
    use std::env;

    let system_tmp_dir = env::temp_dir();
    let dir = config_path
        .parent()
        .map(|p| {
            // Remove leading slash for absolute paths to avoid absolute paths in tmp
            let dir_str = p.to_string_lossy();
            if dir_str.starts_with('/') {
                dir_str.strip_prefix('/').unwrap_or(&dir_str).to_string()
            } else {
                dir_str.to_string()
            }
        })
        .unwrap_or_else(|| ".".to_string());
    let base = config_path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("fluxgate");

    let mut socket_path = system_tmp_dir.join("fluxgate");
    if dir != "." {
        socket_path.push(dir);
    }
    socket_path.push(format!("{}.reload.sock", base));
    socket_path
}

#[cfg(unix)]
struct ReloadServer {
    path: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join_handle: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
fn prepare_socket_path(config_path: &Path) -> Result<PathBuf> {
    use std::fs;

    let path = reload_socket_path(config_path);

    // Create parent directory if it doesn't exist
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create reload socket directory: {}",
                parent.display()
            )
        })?;
    }

    // Remove stale socket if it exists
    if path.exists() {
        if let Err(err) = fs::remove_file(&path) {
            warn!(
                error = %err,
                path = %path.display(),
                "Failed to remove stale reload socket before binding"
            );
        }
    }
    Ok(path)
}

#[cfg(unix)]
async fn create_reload_listener(socket_path: &Path) -> Result<UnixListener> {
    UnixListener::bind(socket_path)
        .with_context(|| format!("Failed to bind reload socket {}", socket_path.display()))
}

#[cfg(unix)]
async fn start_reload_handler(
    listener: UnixListener,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    manager: ConfigManager,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((mut stream, _addr)) => {
                            handle_reload_request(&manager, &mut stream).await;
                        }
                        Err(err) => {
                            error!(error = %err, "Reload control socket accept failed");
                            break;
                        }
                    }
                }
            }
        }
    })
}

#[cfg(unix)]
async fn handle_reload_request(manager: &ConfigManager, stream: &mut UnixStream) {
    let reload_result = manager.reload().await;
    let message = match reload_result {
        Ok(_) => "ok\n".to_string(),
        Err(err) => {
            error!(error = %err, "Configuration reload failed");
            format!("error: {err}\n")
        }
    };
    if let Err(err) = stream.write_all(message.as_bytes()).await {
        error!(error = %err, "Failed to write reload response");
    }
}

#[cfg(unix)]
impl ReloadServer {
    async fn bind(config_path: PathBuf, manager: ConfigManager) -> Result<Self> {
        let socket_path = prepare_socket_path(&config_path)?;
        let listener = create_reload_listener(&socket_path).await?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let join_handle = start_reload_handler(listener, shutdown_rx, manager).await;

        Ok(Self {
            path: socket_path,
            shutdown: Some(shutdown_tx),
            join_handle,
        })
    }
}

#[cfg(unix)]
impl Drop for ReloadServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.join_handle.abort();
        if let Err(err) = std::fs::remove_file(&self.path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    error = %err,
                    path = %self.path.display(),
                    "Failed to remove reload control socket on drop"
                );
            }
        }
    }
}
