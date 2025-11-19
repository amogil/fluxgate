//! Fluxgate library entry point exposing shared modules.

use std::env;
use std::io;

pub mod config;
pub mod proxy;

/// Initialize global tracing subscribers using environment configuration.
/// Requirement: O1, O2, C5 - Initialize logging with environment variable overrides (C5: only observability overrides)
pub fn init_tracing() {
    // Requirement: C5 - Configuration not controlled via env vars (except observability)
    // Requirement: O1 - Default log level is TRACE when FLUXGATE_LOG is not set
    // Requirement: O7 - Filter out DEBUG/TRACE logs from reqwest and hyper to avoid Some(...) format violations
    // Filter out DEBUG logs from axum and tower_http to avoid noise, keep only TRACE+ from fluxgate
    let env_filter = env::var("FLUXGATE_LOG")
        .ok()
        .and_then(|value| tracing_subscriber::EnvFilter::try_new(value).ok())
        .unwrap_or_else(|| {
            // Default: TRACE for fluxgate, but filter out DEBUG from axum/tower_http
            // Also filter out reqwest and hyper DEBUG/TRACE logs to avoid Some(...) format violations (O7)
            tracing_subscriber::EnvFilter::new(
                "trace,axum=info,tower_http=info,reqwest=warn,hyper=warn,hyper_util=warn",
            )
        });
    let mut fmt_builder = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(io::stdout)
        .with_ansi(false)
        .with_target(false); // Requirement: O9 - Do not include component prefixes in log messages

    if let Ok(style) = env::var("FLUXGATE_LOG_STYLE") {
        match style.to_ascii_lowercase().as_str() {
            "never" => {}
            "always" => fmt_builder = fmt_builder.with_ansi(true),
            _ => {}
        }
    }

    fmt_builder.init();
}
