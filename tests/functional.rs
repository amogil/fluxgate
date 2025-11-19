#[path = "functional/common.rs"]
mod common;

#[path = "functional/cli.rs"]
mod cli;

#[path = "functional/auth.rs"]
mod auth;

#[path = "functional/proxy_flow.rs"]
mod proxy_flow;

#[path = "functional/resilience.rs"]
mod resilience;

#[path = "functional/shutdown.rs"]
mod shutdown;

#[path = "functional/hot_reload.rs"]
mod hot_reload;

#[path = "functional/observability.rs"]
mod observability;

#[path = "functional/config_loading.rs"]
mod config_loading;

#[path = "functional/config_validation.rs"]
mod config_validation;

#[path = "functional/config_edge.rs"]
mod config_edge;

#[path = "functional/error_handling.rs"]
mod error_handling;
