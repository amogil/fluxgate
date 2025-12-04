//! Configuration management for Fluxgate.
//!
//! This module provides typed configuration loading, validation, and runtime reload
//! capabilities backed by a broadcast channel. Configuration is sourced from a YAML
//! file on disk, with a default fallback applied when the file is missing or invalid.
//!
//! Requirements: C1, C2, C3, C4, C5, C6, C7, C8, C9, C10, C11, C12, C13, C14, C15, C16

pub mod jwt;

pub use jwt::{is_jwt_format, validate_jwt_token, JwtError};

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
    time::SystemTime,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{fs, sync::watch, time::Duration};
use tracing::{error, info, warn};

/// Requirement: C1, C7 - Default configuration file name and reference config location
/// Default configuration file name used when no explicit path is provided.
/// Reference configuration is at config/fluxgate.yaml (C7).
pub const DEFAULT_CONFIG_PATH: &str = "fluxgate.yaml";

/// Supported configuration schema version.
pub const SUPPORTED_CONFIG_VERSION: u8 = 1;

/// Default value for upstream request timeout in milliseconds.
/// Requirement: C8 - Default value for optional upstreams.request_timeout_ms
const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 120_000;

/// Default value for server bind address.
/// Requirement: C8 - Default value for optional server.bind_address
const DEFAULT_BIND_ADDRESS: &str = "0.0.0.0:8080";

/// Default value for server max connections.
/// Requirement: C8 - Default value for optional server.max_connections
const DEFAULT_MAX_CONNECTIONS: u32 = 1_024;

// Serde requires functions for default values, not constants
fn default_request_timeout_ms() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_MS
}

fn default_bind_address() -> String {
    DEFAULT_BIND_ADDRESS.to_string()
}

fn default_max_connections() -> u32 {
    DEFAULT_MAX_CONNECTIONS
}

/// Proxy configuration shared across the application.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    pub version: u8,
    /// Requirement: C8 - Optional section with default values for bind_address and max_connections
    #[serde(default)]
    pub server: ServerConfig,
    pub upstreams: Option<UpstreamsConfig>,
    pub api_keys: Option<ApiKeysConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: SUPPORTED_CONFIG_VERSION,
            server: ServerConfig {
                bind_address: default_bind_address(),
                max_connections: default_max_connections(),
            },
            upstreams: None,
            api_keys: None,
        }
    }
}

/// Result of authentication containing API key id and permitted upstreams.
#[derive(Debug, Clone)]
pub struct AuthenticationResult {
    pub api_key: Option<String>,
    pub permitted_upstreams: Vec<String>,
}

impl Config {
    /// Authenticate a client API key or JWT token and return the API key id and list of permitted upstreams.
    /// Returns None if authentication fails.
    ///
    /// Requirement: F17.1 - First attempt to authenticate as static API key, then as JWT token
    /// When `api_keys.static[].upstreams` is empty or omitted and upstreams are configured,
    /// the API key has access to all configured upstreams. When `api_keys.static[].upstreams`
    /// is empty and no upstreams are configured, returns an empty list (which will result in HTTP 401).
    /// JWT tokens from `api_keys.jwt` have access to all configured upstreams.
    /// Requirement: F2, F3, F17.1, F18-F24 - Authenticate API key or JWT token and return permitted upstreams
    pub fn authenticate(&self, token: &str) -> Option<AuthenticationResult> {
        let api_keys = self.api_keys.as_ref()?;

        // Requirement: F17.1 - First attempt to authenticate as static API key
        if let Some(key) = api_keys.static_.iter().find(|k| k.key == token) {
            // Determine permitted upstreams based on API key configuration
            let permitted_upstreams = match &key.upstreams {
                Some(upstreams) if !upstreams.is_empty() => {
                    // Non-empty explicit list: use as-is
                    upstreams.clone()
                }
                _ => {
                    // Empty list or omitted (None): if upstreams are configured, give access to all;
                    // otherwise, no access
                    self.upstreams
                        .as_ref()
                        .and_then(|upstreams_config| {
                            if upstreams_config.upstreams.is_empty() {
                                None
                            } else {
                                Some(
                                    upstreams_config
                                        .upstreams
                                        .keys()
                                        .map(|name| name.to_string())
                                        .collect(),
                                )
                            }
                        })
                        .unwrap_or_default()
                }
            };

            return Some(AuthenticationResult {
                api_key: key.id.clone(),
                permitted_upstreams,
            });
        }

        // Requirement: F17.1 - If not a static key, attempt to parse as JWT token
        if !is_jwt_format(token) {
            return None;
        }

        // Get JWT keys from configuration
        let jwt_keys: Vec<(String, String)> = api_keys
            .jwt
            .as_ref()
            .map(|jwt_list| {
                jwt_list
                    .iter()
                    .map(|jwt_key| (jwt_key.id.clone(), jwt_key.key.clone()))
                    .collect()
            })
            .unwrap_or_default();

        if jwt_keys.is_empty() {
            return None;
        }

        // Requirement: F18-F24 - Validate JWT token
        let jwt_id = match validate_jwt_token(token, &jwt_keys) {
            Ok(id) => id,
            Err(_) => return None,
        };

        // Requirement: F3 - JWT tokens have access to all configured upstreams
        let permitted_upstreams = self
            .upstreams
            .as_ref()
            .map(|upstreams_config| {
                upstreams_config
                    .upstreams
                    .keys()
                    .map(|name| name.to_string())
                    .collect()
            })
            .unwrap_or_default();

        Some(AuthenticationResult {
            api_key: Some(jwt_id),
            permitted_upstreams,
        })
    }

    /// Get upstream configuration by name.
    pub fn get_upstream(&self, name: &str) -> Option<&UpstreamEntry> {
        self.upstreams.as_ref()?.upstreams.get(name)
    }

    /// Find upstream by matching request path against request_path values.
    /// Returns the upstream name with the longest matching request_path prefix.
    /// Only considers upstreams that are in the permitted list (or all if permitted is empty).
    /// Requirement: F2 - Find upstream by matching request_path (longest match)
    pub fn find_upstream_by_path(
        &self,
        request_path: &str,
        permitted_upstreams: &[String],
    ) -> Option<String> {
        let upstreams = self.upstreams.as_ref()?;
        if upstreams.upstreams.is_empty() {
            return None;
        }

        // Normalize trailing slashes for matching (but preserve original for forwarding)
        // Do this once before the loop for efficiency
        let normalized_path = request_path.trim_end_matches('/');
        let normalized_path_with_slash = if normalized_path.is_empty() {
            "/"
        } else {
            normalized_path
        };

        // Convert permitted_upstreams to HashSet for O(1) lookup instead of O(n)
        // Only build HashSet if we have permitted upstreams to check
        let permitted_set: std::collections::HashSet<&str> = if !permitted_upstreams.is_empty() {
            permitted_upstreams.iter().map(|s| s.as_str()).collect()
        } else {
            std::collections::HashSet::new()
        };

        let mut best_match: Option<(&String, &UpstreamEntry, usize)> = None;

        for (name, upstream) in &upstreams.upstreams {
            // Check if this upstream is permitted - O(1) lookup with HashSet
            if !permitted_set.is_empty() && !permitted_set.contains(name.as_str()) {
                continue;
            }

            // Normalize upstream request_path for comparison
            // Note: This is still done per-iteration, but it's a fast operation
            // and caching would require additional memory overhead
            let upstream_path = upstream.request_path.trim_end_matches('/');
            let upstream_path_normalized = if upstream_path.is_empty() {
                "/"
            } else {
                upstream_path
            };

            // Check if request_path starts with upstream's request_path
            if normalized_path_with_slash.starts_with(upstream_path_normalized) {
                let match_length = upstream_path_normalized.len();
                // Update best match if this is longer
                if best_match
                    .as_ref()
                    .map(|(_, _, len)| *len < match_length)
                    .unwrap_or(true)
                {
                    best_match = Some((name, upstream, match_length));
                }
            }
        }

        best_match.map(|(name, _, _)| name.clone())
    }

    /// Get the global upstream request timeout.
    pub fn upstream_timeout(&self) -> Option<u64> {
        self.upstreams.as_ref().map(|u| u.request_timeout_ms)
    }

    /// Check if the configuration has any upstreams configured.
    pub fn has_upstreams(&self) -> bool {
        self.upstreams
            .as_ref()
            .map(|u| !u.upstreams.is_empty())
            .unwrap_or(false)
    }

    /// Requirement: C2, C8, C15, C16 - Validate configuration before activation
    /// Validate configuration invariants before the configuration becomes active.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let mut reasons = Vec::new();

        if self.version != SUPPORTED_CONFIG_VERSION {
            reasons.push(format!(
                "version must equal {}, got {}",
                SUPPORTED_CONFIG_VERSION, self.version
            ));
        }

        if self.server.bind_address.trim().is_empty() {
            reasons.push("server.bind_address must not be empty".to_string());
        } else if self.server.bind_address.len() > 256 {
            reasons.push("server.bind_address is too long (maximum 256 characters)".to_string());
        }

        if self.server.max_connections == 0 {
            reasons.push("server.max_connections must be greater than zero".to_string());
        }

        // Validate upstreams if present
        if let Some(upstreams) = &self.upstreams {
            if upstreams.request_timeout_ms == 0 {
                reasons.push("upstreams.request_timeout_ms must be greater than zero".to_string());
            }

            // Track request_path values to ensure uniqueness
            let mut request_paths: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();

            for (name, upstream) in &upstreams.upstreams {
                if upstream.target_url.trim().is_empty() {
                    reasons.push(format!("upstreams.{}.target_url must not be empty", name));
                } else if let Err(err) = reqwest::Url::parse(&upstream.target_url) {
                    reasons.push(format!(
                        "upstreams.{}.target_url is not a valid URL: {}",
                        name, err
                    ));
                } else if let Ok(url) = reqwest::Url::parse(&upstream.target_url) {
                    let scheme = url.scheme();
                    if scheme != "http" && scheme != "https" {
                        reasons.push(format!(
                            "upstreams.{}.target_url must use http or https scheme, got: {}",
                            name, scheme
                        ));
                    }
                }

                // api_key must be non-empty only when api_keys are configured (authentication is enabled)
                if self
                    .api_keys
                    .as_ref()
                    .map(|keys| !keys.static_.is_empty())
                    .unwrap_or(false)
                    && upstream.api_key.trim().is_empty()
                {
                    reasons.push(format!(
                        "upstreams.{}.api_key must not be empty when authentication is enabled",
                        name
                    ));
                }

                // Validate request_path
                if upstream.request_path.trim().is_empty() {
                    reasons.push(format!("upstreams.{}.request_path must not be empty", name));
                } else {
                    let request_path = upstream.request_path.trim();
                    // Validate that request_path is a valid HTTP path (starts with /, no host, port, scheme, or query)
                    if !request_path.starts_with('/') {
                        reasons.push(format!(
                            "upstreams.{}.request_path must start with '/', got: {}",
                            name, request_path
                        ));
                    } else if request_path.contains("://") {
                        reasons.push(format!(
                            "upstreams.{}.request_path must not contain scheme (://), got: {}",
                            name, request_path
                        ));
                    } else if request_path.contains('?') {
                        reasons.push(format!(
                            "upstreams.{}.request_path must not contain query string (?), got: {}",
                            name, request_path
                        ));
                    } else {
                        // Check for port separator pattern (colon followed by digits, not in path segment)
                        // Allow : in path segments like /api/v1:2 but not /api:8080
                        let path_after_slash = &request_path[1..];
                        if let Some(colon_pos) = path_after_slash.find(':') {
                            // Check if it looks like a port (digits after colon)
                            let after_colon = &path_after_slash[colon_pos + 1..];
                            if after_colon
                                .chars()
                                .next()
                                .is_some_and(|c| c.is_ascii_digit())
                            {
                                reasons.push(format!(
                                    "upstreams.{}.request_path must not contain port separator (:), got: {}",
                                    name, request_path
                                ));
                            }
                        }
                    }

                    // Check for uniqueness
                    if let Some(existing_upstream) = request_paths.get(request_path) {
                        reasons.push(format!(
                            "upstreams.{}.request_path '{}' is not unique; already used by upstream '{}'",
                            name, request_path, existing_upstream
                        ));
                    } else {
                        request_paths.insert(request_path.to_string(), name.clone());
                    }
                }
            }
        }

        // Validate api_keys if present
        if let Some(api_keys) = &self.api_keys {
            let upstream_names: std::collections::HashSet<_> = self
                .upstreams
                .as_ref()
                .map(|u| u.upstreams.keys().collect())
                .unwrap_or_default();

            // Requirement: C16 - Track keys and ids for uniqueness validation
            let mut seen_keys: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            let mut seen_ids: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();

            for (index, api_key) in api_keys.static_.iter().enumerate() {
                if api_key.key.trim().is_empty() {
                    reasons.push(format!("api_keys.static[{}].key must not be empty", index));
                } else {
                    // Requirement: C16 - Check key uniqueness
                    let key_trimmed = api_key.key.trim();
                    if let Some(existing_index) = seen_keys.get(key_trimmed) {
                        reasons.push(format!(
                            "api_keys.static[{}].key '{}' is not unique; already used by api_keys.static[{}]",
                            index, key_trimmed, existing_index
                        ));
                    } else {
                        seen_keys.insert(key_trimmed.to_string(), index);
                    }
                }

                // Requirement: C16 - Validate id if specified (optional field)
                if let Some(id) = &api_key.id {
                    if id.trim().is_empty() {
                        reasons.push(format!(
                            "api_keys.static[{}].id must not be empty when specified",
                            index
                        ));
                    } else {
                        // Requirement: C16 - Check id uniqueness
                        let id_trimmed = id.trim();
                        if let Some(existing_index) = seen_ids.get(id_trimmed) {
                            reasons.push(format!(
                                "api_keys.static[{}].id '{}' is not unique; already used by api_keys.static[{}]",
                                index, id_trimmed, existing_index
                            ));
                        } else {
                            seen_ids.insert(id_trimmed.to_string(), index);
                        }
                    }
                }

                if let Some(upstreams) = &api_key.upstreams {
                    for upstream_name in upstreams {
                        if !upstream_names.contains(upstream_name) {
                            reasons.push(format!(
                                "api_keys.static[{}].upstreams contains unknown upstream '{}'",
                                index, upstream_name
                            ));
                        }
                    }
                }
            }

            // Requirement: C16.1, C16.2 - Validate JWT keys
            if let Some(jwt_keys) = &api_keys.jwt {
                let mut jwt_seen_ids: std::collections::HashMap<String, usize> =
                    std::collections::HashMap::new();

                for (index, jwt_key) in jwt_keys.iter().enumerate() {
                    // Requirement: C16.1 - Validate id is present, non-empty, and unique
                    if jwt_key.id.trim().is_empty() {
                        reasons.push(format!("api_keys.jwt[{}].id must not be empty", index));
                    } else {
                        let id_trimmed = jwt_key.id.trim();
                        if let Some(existing_index) = jwt_seen_ids.get(id_trimmed) {
                            reasons.push(format!(
                                "api_keys.jwt[{}].id '{}' is not unique; already used by api_keys.jwt[{}]",
                                index, id_trimmed, existing_index
                            ));
                        } else {
                            jwt_seen_ids.insert(id_trimmed.to_string(), index);
                        }
                    }

                    // Requirement: C16.2 - Validate key is present and non-empty
                    if jwt_key.key.trim().is_empty() {
                        reasons.push(format!("api_keys.jwt[{}].key must not be empty", index));
                    } else if jwt_key.key.len() < 32 {
                        // Requirement: C16.3 - Validate key has minimum length of 32 bytes (RFC 7518)
                        reasons.push(format!(
                            "api_keys.jwt[{}].key must be at least 32 bytes (got {} bytes)",
                            index,
                            jwt_key.key.len()
                        ));
                    }
                    // Note: JWT keys don't need to be unique (C16.2)
                }
            }
        }

        if reasons.is_empty() {
            Ok(())
        } else {
            Err(ValidationError { reasons })
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerConfig {
    /// Requirement: C8 - Optional field with default value 0.0.0.0:8080
    #[serde(default = "default_bind_address")]
    pub bind_address: String,
    /// Requirement: C8 - Optional field with default value 1024
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: default_bind_address(),
            max_connections: default_max_connections(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpstreamConfig {
    pub base_url: String,
    pub request_timeout_ms: u64,
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpstreamsConfig {
    /// Requirement: C8 - Optional field with default value 120000
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(flatten)]
    pub upstreams: HashMap<String, UpstreamEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UpstreamEntry {
    pub target_url: String,
    pub api_key: String,
    pub request_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKeysConfig {
    #[serde(rename = "static", default)]
    pub static_: Vec<StaticApiKey>,
    #[serde(rename = "jwt")]
    pub jwt: Option<Vec<JwtApiKey>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StaticApiKey {
    pub id: Option<String>,
    pub key: String,
    pub upstreams: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JwtApiKey {
    pub id: String,
    pub key: String,
}

/// Errors raised while loading configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration from {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse configuration from {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("configuration validation failed for {path}: {source}")]
    Validation {
        path: PathBuf,
        #[source]
        source: ValidationError,
    },
}

/// Validation failure containing the list of violated invariants.
#[derive(Debug, Error, Clone)]
#[error("configuration validation failed: {reasons:?}")]
pub struct ValidationError {
    reasons: Vec<String>,
}

impl ValidationError {
    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }
}

/// Handle used to consume configuration updates at runtime.
#[derive(Clone)]
pub struct ConfigManager {
    inner: Arc<ConfigManagerInner>,
}

struct ConfigManagerInner {
    path: PathBuf,
    sender: watch::Sender<Config>,
    state: std::sync::RwLock<Config>,
    #[allow(dead_code)]
    watcher_shutdown: tokio::sync::oneshot::Sender<()>,
    // Requirement: F17 - Track if we started with defaults to avoid redundant warnings
    started_with_defaults: std::sync::atomic::AtomicBool,
}

impl ConfigManagerInner {
    fn apply_config(&self, config: Config) {
        {
            let mut guard = self.state.write().expect("configuration state poisoned");
            *guard = config.clone();
        }
        // Requirement: F17 - Clear the flag when we successfully load a config
        // This ensures that if the file later disappears, we'll warn about it
        self.started_with_defaults
            .store(false, std::sync::atomic::Ordering::Relaxed);
        if let Err(err) = self.sender.send(config) {
            error!("Failed to publish new configuration: {err}");
        }
    }
}

impl ConfigManager {
    /// Load configuration from disk, falling back to defaults when the file is missing or invalid.
    /// Requirement: C1, C4 - Load configuration from file with default fallback
    pub async fn initialize<P: Into<Option<PathBuf>>>(path: P) -> Self {
        let path = path
            .into()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));

        let (initial_config, started_with_defaults) = match load_checked_config(&path).await {
            Ok(config) => {
                // Requirement: O3 - Log configuration loading at INFO level
                info!(
                    path = %path.display(),
                    status = "applied",
                    "Loaded configuration"
                );
                (config, false)
            }
            Err(err) => {
                warn!(
                    path = %path.display(),
                    error = %err,
                    "Using default configuration due to load failure"
                );
                (Config::default(), true)
            }
        };

        let (sender, _receiver) = watch::channel(initial_config.clone());
        let (watcher_shutdown_tx, watcher_shutdown_rx) = tokio::sync::oneshot::channel();

        // Requirement: C17 - Initialize watcher state to prevent false positive reload messages
        // If config was loaded from file, initialize the watcher state with current file state
        let (initial_mtime, initial_hash) = if !started_with_defaults {
            // Config was loaded successfully, initialize watcher state to prevent false positives
            match initialize_watcher_state(&path).await {
                Ok((mtime, hash)) => (Some(mtime), Some(hash)),
                Err(_) => {
                    // If we can't read the file state now, watcher will initialize on first check
                    (None, None)
                }
            }
        } else {
            // Started with defaults, no file to track
            (None, None)
        };

        let inner = Arc::new(ConfigManagerInner {
            path: path.clone(),
            sender,
            state: std::sync::RwLock::new(initial_config),
            watcher_shutdown: watcher_shutdown_tx,
            started_with_defaults: std::sync::atomic::AtomicBool::new(started_with_defaults),
        });

        // Start background file watcher task
        let inner_clone = Arc::clone(&inner);
        tokio::spawn(config_file_watcher(
            inner_clone,
            watcher_shutdown_rx,
            initial_mtime,
            initial_hash,
        ));

        Self { inner }
    }

    /// Current active configuration value.
    pub fn current(&self) -> Config {
        self.inner
            .state
            .read()
            .expect("configuration state poisoned")
            .clone()
    }

    /// Subscribe to configuration updates; the caller receives the latest value immediately.
    pub fn subscribe(&self) -> watch::Receiver<Config> {
        self.inner.sender.subscribe()
    }

    /// Requirement: C3, C6, C9, C10, C11, C12, C13, C14 - Hot reload configuration
    /// Reload configuration from disk, validating prior to broadcasting the update.
    ///
    /// Errors are logged and bubbled to the caller; the active configuration remains unchanged.
    pub async fn reload(&self) -> Result<(), ConfigError> {
        match load_checked_config(&self.inner.path).await {
            Ok(config) => {
                // Requirement: C14, O3 - Log configuration changes at INFO level
                info!(
                    path = %self.inner.path.display(),
                    status = "applied",
                    "Reloaded configuration"
                );
                self.inner.apply_config(config);
                Ok(())
            }
            Err(err) => {
                let (status, cause) = config_error_outcome(&err);
                // Requirement: C14, O3, O4 - Log configuration reload failures at INFO/WARNING level
                info!(
                    path = %self.inner.path.display(),
                    error = %err,
                    status,
                    cause,
                    "Configuration reload failed; keeping previous settings"
                );
                error!(
                    path = %self.inner.path.display(),
                    error = %err,
                    "Configuration reload failed; keeping previous settings"
                );
                Err(err)
            }
        }
    }

    /// Path of the configuration backing file.
    pub fn config_path(&self) -> &Path {
        &self.inner.path
    }

    /// Requirement: C4.2 - Check if configuration was loaded from file or started with defaults
    /// Returns true if the configuration was successfully loaded from a file at startup,
    /// false if default configuration was used due to load failure.
    pub fn started_with_defaults(&self) -> bool {
        self.inner
            .started_with_defaults
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Initialize watcher state by reading the current file metadata and content hash.
/// Requirement: C17 - Initialize watcher state to prevent false positive reload messages
async fn initialize_watcher_state(path: &Path) -> Result<(SystemTime, u64), std::io::Error> {
    let metadata = fs::metadata(path).await?;
    let mtime = metadata.modified()?;
    let content = fs::read_to_string(path).await?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    content.hash(&mut hasher);
    let hash = hasher.finish();
    Ok((mtime, hash))
}

/// Background task that polls the configuration file for changes and automatically reloads.
/// This task runs in a separate background thread as required by C10.
/// Requirement: C17 - Use initialized state to prevent false positive reload messages
async fn config_file_watcher(
    inner: Arc<ConfigManagerInner>,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
    initial_mtime: Option<SystemTime>,
    initial_hash: Option<u64>,
) {
    let mut last_mtime = initial_mtime;
    let mut last_content_hash = initial_hash;
    let poll_interval = Duration::from_secs(1);
    let mut not_found_log_count: u32 = 0;
    let mut permission_denied_log_count: u32 = 0;

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                info!("Configuration file watcher shutting down");
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                // Check if file has changed
                match check_file_changed(&inner.path, &mut last_mtime, &mut last_content_hash).await {
                    Ok(true) => {
                        // File changed, attempt to reload
                        // Reset error counters since file is accessible
                        not_found_log_count = 0;
                        permission_denied_log_count = 0;
                        match load_checked_config(&inner.path).await {
                            Ok(new_config) => {
                                info!(
                                    path = %inner.path.display(),
                                    status = "applied",
                                    "Configuration file changed, reloaded automatically"
                                );
                                inner.apply_config(new_config);
                            }
                            Err(err) => {
                                warn!(
                                    path = %inner.path.display(),
                                    error = %err,
                                    "Configuration file changed but validation failed; keeping previous settings"
                                );
                            }
                        }
                    }
                    Ok(false) => {
                        // No change detected, continue polling
                        // Reset error counters since file is accessible
                        not_found_log_count = 0;
                        permission_denied_log_count = 0;
                    }
                    Err(err) => {
                        // File access error - log warning but continue polling
                        // This handles cases where file is temporarily inaccessible
                        if err.kind() == std::io::ErrorKind::NotFound {
                            // Requirement: F17 - Don't log warning if we started with defaults
                            // Only log if we previously had a valid config file that became inaccessible
                            let started_with_defaults = inner.started_with_defaults.load(std::sync::atomic::Ordering::Relaxed);
                            if !started_with_defaults {
                                // Only log once to avoid spam when file doesn't exist
                                if not_found_log_count == 0 {
                                    warn!(
                                        path = %inner.path.display(),
                                        "Configuration file not found during polling; continuing with last valid configuration"
                                    );
                                }
                                not_found_log_count = not_found_log_count.wrapping_add(1);
                            }
                            // If started_with_defaults is true, silently continue without logging
                        } else if err.kind() == std::io::ErrorKind::PermissionDenied {
                            // Only log once to avoid spam when permission is denied
                            if permission_denied_log_count == 0 {
                                warn!(
                                    path = %inner.path.display(),
                                    "Configuration file access denied during polling; continuing with last valid configuration"
                                );
                            }
                            permission_denied_log_count = permission_denied_log_count.wrapping_add(1);
                        } else {
                            // Other I/O errors - log but don't spam
                            // Only log occasionally to avoid log spam
                            static ERROR_COUNT: AtomicU32 = AtomicU32::new(0);
                            let count = ERROR_COUNT.fetch_add(1, Ordering::Relaxed);
                            // Use manual modulo check for compatibility with older Rust versions in Docker
                            if count % 20 == 0 {
                                warn!(
                                    path = %inner.path.display(),
                                    error = %err,
                                    "Error checking configuration file during polling (logged every 20th occurrence)"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Check if the configuration file has changed by comparing modification time and content hash.
/// Returns Ok(true) if changed, Ok(false) if unchanged, Err for I/O errors.
async fn check_file_changed(
    path: &Path,
    last_mtime: &mut Option<SystemTime>,
    last_content_hash: &mut Option<u64>,
) -> Result<bool, std::io::Error> {
    let metadata = fs::metadata(path).await?;
    let current_mtime = metadata.modified()?;

    // Check modification time first (fast check)
    if let Some(prev_mtime) = *last_mtime {
        if current_mtime == prev_mtime {
            return Ok(false);
        }
    }

    // Modification time changed or first check - verify content hash
    let content = fs::read_to_string(path).await?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    content.hash(&mut hasher);
    let current_hash = hasher.finish();

    if let Some(prev_hash) = *last_content_hash {
        if current_hash == prev_hash {
            // mtime changed but content is the same (e.g., file was touched)
            *last_mtime = Some(current_mtime);
            return Ok(false);
        }
    }

    // Content actually changed
    *last_mtime = Some(current_mtime);
    *last_content_hash = Some(current_hash);
    Ok(true)
}

async fn load_checked_config(path: &Path) -> Result<Config, ConfigError> {
    let raw = fs::read_to_string(path)
        .await
        .map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;

    let document =
        serde_yaml::from_str::<serde_yaml::Value>(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;

    if let Err(source) = validate_config_version(&document) {
        return Err(ConfigError::Validation {
            path: path.to_path_buf(),
            source,
        });
    }

    let config =
        serde_yaml::from_value::<Config>(document).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;

    config
        .validate()
        .map_err(|source| ConfigError::Validation {
            path: path.to_path_buf(),
            source,
        })?;

    Ok(config)
}

fn config_error_outcome(err: &ConfigError) -> (&'static str, &'static str) {
    match err {
        ConfigError::Validation { .. } => ("rejected", "validation"),
        ConfigError::Parse { .. } => ("failed", "parse"),
        ConfigError::Read { .. } => ("failed", "io"),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn validate_config_version(value: &serde_yaml::Value) -> Result<(), ValidationError> {
    let Some(mapping) = value.as_mapping() else {
        return Err(ValidationError {
            reasons: vec!["configuration root must be a mapping".to_string()],
        });
    };

    let Some(version_value) = mapping.get(serde_yaml::Value::String("version".to_string())) else {
        return Err(ValidationError {
            reasons: vec!["version is required and must be set to 1".to_string()],
        });
    };

    match version_value {
        serde_yaml::Value::Number(num) => {
            if let Some(actual) = num.as_u64() {
                if actual == SUPPORTED_CONFIG_VERSION as u64 {
                    return Ok(());
                }

                return Err(ValidationError {
                    reasons: vec![format!(
                        "version must equal {}, got {}",
                        SUPPORTED_CONFIG_VERSION, actual
                    )],
                });
            }

            Err(ValidationError {
                reasons: vec!["version must be an unsigned integer value".to_string()],
            })
        }
        _ => Err(ValidationError {
            reasons: vec!["version must be an unsigned integer value".to_string()],
        }),
    }
}
