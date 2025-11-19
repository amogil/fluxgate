//! High-performance HTTP proxy implementation.
//!
//! This module provides efficient request forwarding to upstream services
//! with minimal latency and memory overhead while preserving the original
//! request semantics for method, URI, body, and headers. The proxy only
//! rewrites the `Authorization` and `Host` headers when forwarding to upstream,
//! and strips hop-by-hop headers mandated by RFC 7230.
//!
//! Requirements: F1, F2, F3, F4, F6, F7, F8, F9, F10, F11, F12, F13, F14, P1, P2, P3, P4

use anyhow::{Context, Result};
use axum::http::HeaderMap;
use axum::{
    body::Body,
    extract::{connect_info::ConnectInfo, Request, State},
    http::{
        header::{HeaderName, AUTHORIZATION, CONNECTION, HOST, UPGRADE},
        method::Method,
        StatusCode, Uri, Version,
    },
    response::{IntoResponse, Response},
};
use futures_util::TryStreamExt;
use http_body::Frame;
use http_body_util::StreamBody;
use reqwest::{Client, Url};
use std::{
    io,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, RwLock,
    },
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{info, trace, warn};

use crate::config::ConfigManager;

/// Application state shared across all proxy handlers
#[derive(Clone)]
pub struct ProxyState {
    #[allow(dead_code)]
    config_manager: ConfigManager,
    config_receiver: tokio::sync::watch::Receiver<crate::config::Config>,
    http_client: Client,
    connection_limiter: ConnectionLimiter,
}

impl ProxyState {
    /// Requirement: P1, P2, P3 - Create new proxy state with optimized HTTP client
    /// Configure HTTP client for high performance with connection pooling
    pub fn new(config_manager: ConfigManager) -> Self {
        // Requirement: P1, P2 - Low latency and horizontal scaling via connection pooling
        // Requirement: P3 - Low memory footprint via connection reuse
        // Configure HTTP client for high performance
        let http_client = Client::builder()
            .pool_max_idle_per_host(100) // Connection pooling
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(60))
            .user_agent("fluxgate/1.0")
            .build()
            .expect("Failed to create HTTP client");

        let config_receiver = config_manager.subscribe();
        let initial_config = config_receiver.borrow().clone();
        let connection_limiter =
            ConnectionLimiter::new(initial_config.server.max_connections.max(1));

        Self {
            config_manager,
            config_receiver,
            http_client,
            connection_limiter,
        }
    }
}

/// Create the main proxy router with all middleware
/// Requirement: F10 - All error responses must be properly formatted and delivered to clients
/// Requirement: O5 - Only one log message per request (from proxy_handler), TraceLayer removed to avoid duplicate logging
pub fn create_router(state: ProxyState) -> axum::Router {
    axum::Router::new()
        .fallback(proxy_handler)
        .with_state(state)
}

/// Main proxy handler that forwards authenticated requests to upstreams
///
/// Requirements: F1, F2, F3, F4, F6, F7, F8, F9, F10, F11, F12, F13, F14
/// Requirement: G11 - Requirements are numbered and ordered sequentially
async fn proxy_handler(
    State(state): State<ProxyState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    let start_time = std::time::Instant::now();
    let method = req.method().clone();
    let uri = req.uri().clone();

    // Build full request URL for logging (Requirement: O6)
    // Format: "/path?query" (path and query only, method is logged separately)
    // Optimize: avoid unnecessary string allocation when query is empty
    let url = match uri.query() {
        Some(query) if !query.is_empty() => format!("{}?{}", uri.path(), query),
        _ => uri.path().to_string(),
    };

    // Get request body length from headers (Requirement: O6)
    let request_body_length = get_body_length_from_headers(req.headers());

    // Track request metadata for final logging
    let client_ip = client_addr.ip();
    let mut api_key: Option<String> = None;

    // Requirement: F11 - Support HTTP/1.1 and HTTP/2 only, reject others with HTTP 505
    // Enforce supported HTTP versions
    let client_http_version = req.version();
    if !matches!(client_http_version, Version::HTTP_11 | Version::HTTP_2) {
        let duration_ms = start_time.elapsed().as_millis();
        let status = StatusCode::HTTP_VERSION_NOT_SUPPORTED;
        log_request_completion(
            client_ip,
            &method,
            &url,
            request_body_length,
            None,
            None,
            None,
            duration_ms,
            status,
            None,
        );
        return status.into_response();
    }

    // Requirement: F14 - Reject CONNECT and Upgrade-based requests
    // Reject CONNECT and Upgrade-based requests that the proxy does not support
    if is_connect_or_upgrade_request(req.method(), req.headers()) {
        let duration_ms = start_time.elapsed().as_millis();
        let status = StatusCode::NOT_IMPLEMENTED;
        log_request_completion(
            client_ip,
            &method,
            &url,
            request_body_length,
            None,
            None,
            None,
            duration_ms,
            status,
            None,
        );
        return status.into_response();
    }

    // Requirement: F6, OP2 - Return HTTP 400 for malformed requests (including request smuggling)
    // Ensure malformed requests with missing host header are rejected early
    let host_header_valid = req
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    if !host_header_valid {
        let duration_ms = start_time.elapsed().as_millis();
        let status = StatusCode::BAD_REQUEST;
        log_request_completion(
            client_ip,
            &method,
            &url,
            request_body_length,
            None,
            None,
            None,
            duration_ms,
            status,
            None,
        );
        return status.into_response();
    }

    // Get current configuration
    // Note: We clone here because config is used across await points
    // The clone is relatively cheap as Config uses Arc internally for shared data
    let config = state.config_receiver.borrow().clone();
    let max_connections = config.server.max_connections.max(1);
    state.connection_limiter.ensure_limit(max_connections);
    
    // Extract upstream timeout before await point to avoid repeated calls
    let upstream_timeout_ms = config
        .upstream_timeout()
        .unwrap_or(120_000)
        .max(1);

    // Requirement: F8 - Return HTTP 503 when connection limit reached
    // Try to acquire connection permit - reject with 503 if limit reached
    let _permit = match state.connection_limiter.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            let duration_ms = start_time.elapsed().as_millis();
            let status = StatusCode::SERVICE_UNAVAILABLE;
            log_request_completion(
                client_ip,
                &method,
                &url,
                request_body_length,
                None,
                None,
                None,
                duration_ms,
                status,
                None,
            );
            return status.into_response();
        }
    };

    // Requirement: F2, F3 - Authenticate requests and handle failures
    // Check if authentication is required (api_keys are configured - static or JWT)
    let requires_auth = config
        .api_keys
        .as_ref()
        .map(|keys| {
            !keys.static_.is_empty()
                || keys
                    .jwt
                    .as_ref()
                    .map(|jwt| !jwt.is_empty())
                    .unwrap_or(false)
        })
        .unwrap_or(false);

    let permitted_upstream_names: Vec<String> = if requires_auth {
        // Requirement: F3, F5 - Validate Authorization header (Bearer scheme only)
        // Extract and validate Authorization header - only Bearer tokens are supported
        let auth_header_value = match req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
        {
            Some(value) => value,
            None => {
                let duration_ms = start_time.elapsed().as_millis();
                let status = StatusCode::UNAUTHORIZED;
                log_request_completion(
                    client_ip,
                    &method,
                    &url,
                    request_body_length,
                    None,
                    None,
                    None,
                    duration_ms,
                    status,
                    None,
                );
                return status.into_response();
            }
        };

        // Requirement: F5 - Only accept Bearer authentication scheme
        // Reject non-Bearer authentication schemes
        let auth_token_value = match auth_header_value.strip_prefix("Bearer ") {
            Some(token) => token,
            None => {
                let duration_ms = start_time.elapsed().as_millis();
                let status = StatusCode::UNAUTHORIZED;
                log_request_completion(
                    client_ip,
                    &method,
                    &url,
                    request_body_length,
                    None,
                    None,
                    None,
                    duration_ms,
                    status,
                    None,
                );
                return status.into_response();
            }
        };

        // Authenticate token and get permitted upstreams
        let auth_result = match config.authenticate(auth_token_value) {
            Some(result) => result,
            None => {
                let duration_ms = start_time.elapsed().as_millis();
                let status = StatusCode::UNAUTHORIZED;
                log_request_completion(
                    client_ip,
                    &method,
                    &url,
                    request_body_length,
                    None,
                    None,
                    None,
                    duration_ms,
                    status,
                    None,
                );
                return status.into_response();
            }
        };

        api_key = auth_result.api_key.clone();
        let permitted = auth_result.permitted_upstreams;

        if permitted.is_empty() {
            let duration_ms = start_time.elapsed().as_millis();
            let status = StatusCode::UNAUTHORIZED;
            log_request_completion(
                client_ip,
                &method,
                &url,
                request_body_length,
                api_key.as_deref(),
                None,
                None,
                duration_ms,
                status,
                None,
            );
            return status.into_response();
        }

        permitted
    } else {
        // No authentication required - allow access to all upstreams
        // For backward compatibility, use all configured upstreams
        let permitted = config
            .upstreams
            .as_ref()
            .map(|u| {
                u.upstreams
                    .keys()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        permitted
    };

    if permitted_upstream_names.is_empty() {
        let duration_ms = start_time.elapsed().as_millis();
        let status = StatusCode::SERVICE_UNAVAILABLE;
        log_request_completion(
            client_ip,
            &method,
            &url,
            request_body_length,
            api_key.as_deref(),
            None,
            None,
            duration_ms,
            status,
            None,
        );
        return status.into_response();
    }

    // Requirement: F2 - Route requests by matching request_path (longest match)
    // Find upstream by matching request path against request_path values
    let request_path = uri.path();
    let upstream_name_str =
        match config.find_upstream_by_path(request_path, &permitted_upstream_names) {
            Some(name) => name,
            None => {
                let duration_ms = start_time.elapsed().as_millis();
                let status = StatusCode::NOT_FOUND;
                log_request_completion(
                    client_ip,
                    &method,
                    &url,
                    request_body_length,
                    api_key.as_deref(),
                    None,
                    None,
                    duration_ms,
                    status,
                    None,
                );
                return status.into_response();
            }
        };

    let upstream_name = Some(upstream_name_str.clone());

    let upstream_config = match config.get_upstream(&upstream_name_str) {
        Some(config) => config,
        None => {
            let duration_ms = start_time.elapsed().as_millis();
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            log_request_completion(
                client_ip,
                &method,
                &url,
                request_body_length,
                api_key.as_deref(),
                None,
                upstream_name.as_deref(),
                duration_ms,
                status,
                None,
            );
            return status.into_response();
        }
    };

    // Extract upstream API key before await point
    let upstream_api_key = upstream_config.api_key.clone();

    // Build upstream URL
    let upstream_url = match build_upstream_url(upstream_config, &uri) {
        Ok(url) => url,
        Err(_) => {
            let duration_ms = start_time.elapsed().as_millis();
            let status = StatusCode::BAD_REQUEST;
            log_request_completion(
                client_ip,
                &method,
                &url,
                request_body_length,
                api_key.as_deref(),
                None,
                upstream_name.as_deref(),
                duration_ms,
                status,
                None,
            );
            return status.into_response();
        }
    };

    // Convert to string for logging before moving the URL
    let upstream_url_str = upstream_url.to_string();

    // Requirement: F1 - Extract host and port from upstream URL for Host header
    // Extract host and port before moving upstream_url into request
    // Host header format: "host" or "host:port" (port only included if non-standard)
    // Optimize: pre-allocate string capacity to avoid reallocations
    let host_header_value = if let Some(host) = upstream_url.host_str() {
        match upstream_url.port() {
            Some(port_num) => {
                // Port is explicitly specified - include it in Host header
                let mut s = String::with_capacity(host.len() + 6);
                s.push_str(host);
                s.push(':');
                s.push_str(&port_num.to_string());
                s
            }
            None => {
                // No explicit port - check if it's a non-standard port via default ports
                let scheme = upstream_url.scheme();
                let default_port = match scheme {
                    "https" => 443,
                    "http" => 80,
                    _ => 80, // Default to HTTP port for unknown schemes
                };
                // If port_or_known_default returns something different from default, include it
                match upstream_url.port_or_known_default() {
                    Some(actual_port) if actual_port != default_port => {
                        let mut s = String::with_capacity(host.len() + 6);
                        s.push_str(host);
                        s.push(':');
                        s.push_str(&actual_port.to_string());
                        s
                    }
                    _ => host.to_string(),
                }
            }
        }
    } else {
        String::new()
    };

    // Prepare the request for forwarding
    let (parts, body) = req.into_parts();

    // Create upstream request with zero-copy where possible
    let mut upstream_req = state.http_client.request(parts.method, upstream_url);

    // Requirement: F1 - Forward headers, preserving original except Authorization and Host
    // Forward headers, filtering out hop-by-hop headers
    for (key, value) in parts.headers.iter() {
        if !is_hop_by_hop_header(key) {
            // Skip client Authorization header - we'll inject upstream credentials
            if key == AUTHORIZATION {
                continue;
            }
            // Skip client Host header - we'll set it from upstream target URL
            if key == HOST {
                continue;
            }
            upstream_req = upstream_req.header(key, value);
        }
    }

    upstream_req = upstream_req.timeout(Duration::from_millis(upstream_timeout_ms));

    // Requirement: F1 - Set Host header to correct value derived from upstream's target URL
    if !host_header_value.is_empty() {
        upstream_req = upstream_req.header(HOST, host_header_value);
    }

    // Requirement: F1, F2 - Replace Authorization header with upstream credentials
    // Add upstream API key if configured
    if !upstream_api_key.is_empty() {
        upstream_req =
            upstream_req.header(AUTHORIZATION, format!("Bearer {}", upstream_api_key));
    }

    // Requirement: F13, P4 - Stream request body without loading into memory
    // Forward the body efficiently as a stream
    let upstream_req = upstream_req.body(stream_request_body(body));

    // Execute upstream request
    let upstream_response = match upstream_req.send().await {
        Ok(resp) => resp,
        Err(err) => {
            let duration_ms = start_time.elapsed().as_millis();
            // Requirement: F9 - Return HTTP 504 on upstream timeout
            let status = if err.is_timeout() {
                StatusCode::GATEWAY_TIMEOUT
            } else {
                // Requirement: F7 - Return HTTP 502 on upstream connection failures
                StatusCode::BAD_GATEWAY
            };
            log_request_completion(
                client_ip,
                &method,
                &url,
                request_body_length,
                api_key.as_deref(),
                None,
                upstream_name.as_deref(),
                duration_ms,
                status,
                None,
            );
            return status.into_response();
        }
    };

    // Requirement: F12 - Use same HTTP protocol version for upstream
    // Enforce protocol symmetry with upstreams where possible
    let upstream_http_version = upstream_response.version();
    if upstream_http_version != client_http_version {
        let duration_ms = start_time.elapsed().as_millis();
        let status = StatusCode::BAD_GATEWAY;
        // Get response body length from upstream response headers
        let response_body_length = get_body_length_from_headers(upstream_response.headers());
        log_request_completion(
            client_ip,
            &method,
            &url,
            request_body_length,
            api_key.as_deref(),
            Some(&upstream_url_str),
            upstream_name.as_deref(),
            duration_ms,
            status,
            response_body_length,
        );
        return status.into_response();
    }

    // Build response from upstream
    let status = upstream_response.status();
    // Clone headers before moving upstream_response (needed for header forwarding)
    let headers = upstream_response.headers().clone();
    // Get response body length from upstream response headers (Requirement: O6)
    let response_body_length = get_body_length_from_headers(&headers);
    let upstream_stream = upstream_response.bytes_stream();
    let response_body = Body::new(StreamBody::new(upstream_stream.map_ok(Frame::data)));

    let processing_time = start_time.elapsed();

    // Requirement: O5 - Log every request at TRACE level when processing is complete
    log_request_completion(
        client_ip,
        &method,
        &url,
        request_body_length,
        api_key.as_deref(),
        Some(&upstream_url_str),
        upstream_name.as_deref(),
        processing_time.as_millis(),
        status,
        response_body_length,
    );

    // Requirement: F4 - Forward upstream response status, headers, and body
    // Return response with upstream headers and body
    let mut response = Response::new(response_body);
    *response.status_mut() = status;

    // Copy headers from upstream response
    // Optimize: avoid cloning entire HeaderMap, clone only individual headers as needed
    let response_headers = response.headers_mut();
    for (key, value) in headers.iter() {
        if !is_hop_by_hop_header(key) {
            response_headers.insert(key.clone(), value.clone());
        }
    }

    response
}

/// Check if header should not be forwarded (hop-by-hop headers)
/// Requirement: F1 - Strip hop-by-hop headers per RFC 7230
pub fn is_hop_by_hop_header(header_name: &HeaderName) -> bool {
    matches!(
        header_name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Determine whether the request attempts to use CONNECT or HTTP/1.1 Upgrade
/// semantics that are not supported by the proxy.
/// Requirement: F13 - Reject CONNECT and Upgrade-based requests
pub fn is_connect_or_upgrade_request(method: &Method, headers: &axum::http::HeaderMap) -> bool {
    if *method == Method::CONNECT {
        return true;
    }

    // Explicit Upgrade header is a clear signal
    if headers.contains_key(UPGRADE) {
        return true;
    }

    // Connection: upgrade (case-insensitive, may contain multiple tokens)
    if let Some(connection) = headers.get(CONNECTION).and_then(|h| h.to_str().ok()) {
        if connection
            .split(',')
            .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        {
            return true;
        }
    }

    false
}

/// Build the complete upstream URL from upstream configuration and request URI
pub fn build_upstream_url(
    upstream: &crate::config::UpstreamEntry,
    request_uri: &Uri,
) -> Result<Url> {
    let base_url = Url::parse(&upstream.target_url)
        .with_context(|| format!("Invalid upstream target URL: {}", upstream.target_url))?;

    // Get the base path (without trailing slash)
    let base_path = base_url.path().trim_end_matches('/');

    // Get request path and query
    let request_path = request_uri.path();
    let request_query = request_uri.query();

    // Remove the request_path prefix from the request path
    // For example, if request_path = "/test" and request is "/test/health-check",
    // the path sent to upstream should be "/health-check"
    let upstream_request_path = if request_path.starts_with(&upstream.request_path) {
        let remaining = &request_path[upstream.request_path.len()..];
        if remaining.is_empty() {
            "/"
        } else if !remaining.starts_with('/') {
            // This shouldn't happen if routing is correct, but handle it gracefully
            remaining
        } else {
            remaining
        }
    } else {
        // Fallback: use the full request path if it doesn't start with request_path
        // This shouldn't happen if routing is correct
        request_path
    };

    // Combine paths: base_path + upstream_request_path
    // Remove leading slash from upstream_request_path to avoid double slashes
    let upstream_path_trimmed = upstream_request_path.trim_start_matches('/');
    let combined_path = if base_path.is_empty() {
        if upstream_request_path == "/" {
            "/".to_string()
        } else {
            format!("/{}", upstream_path_trimmed)
        }
    } else if upstream_request_path == "/" || upstream_path_trimmed.is_empty() {
        format!("{}/", base_path)
    } else {
        format!("{}/{}", base_path, upstream_path_trimmed)
    };

    // Create the final URL
    let mut upstream_url = base_url.clone();
    upstream_url.set_path(&combined_path);
    upstream_url.set_query(request_query);

    Ok(upstream_url)
}

#[derive(Clone)]
pub struct ConnectionLimiter {
    semaphore: Arc<RwLock<Arc<Semaphore>>>,
    limit: Arc<AtomicU32>,
    active: Arc<AtomicU32>,
}

impl ConnectionLimiter {
    pub fn new(limit: u32) -> Self {
        let normalized = limit.max(1);
        Self {
            semaphore: Arc::new(RwLock::new(Arc::new(Semaphore::new(normalized as usize)))),
            limit: Arc::new(AtomicU32::new(normalized)),
            active: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn ensure_limit(&self, limit: u32) {
        let target = limit.max(1);
        loop {
            let current = self.limit.load(Ordering::Relaxed);
            if current == target {
                return;
            }
            if self
                .limit
                .compare_exchange(current, target, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                let mut guard = self
                    .semaphore
                    .write()
                    .expect("connection limiter semaphore lock poisoned");
                *guard = Arc::new(Semaphore::new(target as usize));
                return;
            }
        }
    }

    /// Try to acquire a connection permit immediately.
    /// Returns Ok(TrackedPermit) if a permit is available, Err(()) if the limit is reached.
    /// Optimized: clone Arc immediately to minimize lock hold time
    #[allow(clippy::result_unit_err)] // Using () as error type is intentional for semaphore
    pub fn try_acquire(&self) -> Result<TrackedPermit, ()> {
        // Clone Arc<Semaphore> immediately (cheap - just increments reference count)
        // This minimizes the time we hold the read lock
        let semaphore = {
            let guard = self
                .semaphore
                .read()
                .expect("connection limiter semaphore lock poisoned");
            guard.clone()
        };
        // Lock is released here, before the potentially slow try_acquire_owned call
        match semaphore.try_acquire_owned() {
            Ok(permit) => {
                self.active.fetch_add(1, Ordering::Relaxed);
                Ok(TrackedPermit {
                    permit,
                    active: Arc::clone(&self.active),
                })
            }
            Err(_) => Err(()),
        }
    }

    pub fn active_count(&self) -> u32 {
        self.active.load(Ordering::Relaxed)
    }
}

/// Wrapper around OwnedSemaphorePermit that tracks active connections
pub struct TrackedPermit {
    #[allow(dead_code)]
    permit: OwnedSemaphorePermit,
    active: Arc<AtomicU32>,
}

impl Drop for TrackedPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Start the proxy server with graceful shutdown
/// Requirement: C3 - Support hot-reloading configuration changes including bind_address
pub async fn start_proxy_server(
    config_manager: ConfigManager,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let mut config_receiver = config_manager.subscribe();

    // Create a shutdown signal that can be triggered by both external signal and config changes
    let (main_shutdown_tx, mut main_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_signal_clone = shutdown_signal;
    tokio::spawn(async move {
        shutdown_signal_clone.await;
        let _ = main_shutdown_tx.send(());
    });

    // Start initial server
    let config = config_receiver.borrow().clone();
    let initial_addr: std::net::SocketAddr = config
        .server
        .bind_address
        .parse()
        .with_context(|| format!("Invalid bind address: {}", config.server.bind_address))?;

    // Requirement: O3 - Log server startup at INFO level
    info!("Starting proxy server on {}", initial_addr);

    let (initial_handle, initial_shutdown_tx) =
        start_server_instance(config_manager.clone(), initial_addr)
            .await
            .with_context(|| format!("Failed to start initial server on {}", initial_addr))?;

    let mut current_addr = Some(initial_addr);
    let mut server_handle = Some(initial_handle);
    let mut server_shutdown_tx = Some(initial_shutdown_tx);

    loop {
        tokio::select! {
            _ = &mut main_shutdown_rx => {
                // External shutdown signal received
                if let Some(tx) = server_shutdown_tx.take() {
                    let _ = tx.send(());
                }
                if let Some(handle) = server_handle.take() {
                    let _ = handle.await;
                }
                info!("Proxy server shutdown complete");
                return Ok(());
            }
            _ = config_receiver.changed() => {
                // Configuration changed - check if bind_address changed
                let config = config_receiver.borrow().clone();
                let new_addr: std::net::SocketAddr = match config
                    .server
                    .bind_address
                    .parse()
                {
                    Ok(addr) => addr,
                    Err(err) => {
                        warn!(
                            address = %config.server.bind_address,
                            error = %err,
                            "Invalid bind address in configuration; keeping previous address"
                        );
                        continue;
                    }
                };

                // Check if bind address actually changed
                if current_addr.as_ref().map(|a| a == &new_addr).unwrap_or(false) {
                    // Address hasn't changed, continue monitoring
                    continue;
                }

                // Bind address changed - need to restart server
                // Requirement O7: Log actual values, not wrapped in Some(...)
                if let Some(old_addr) = current_addr {
                    info!(
                        old_address = %old_addr,
                        new_address = %new_addr,
                        "Bind address changed, restarting server"
                    );
                } else {
                    info!(
                        new_address = %new_addr,
                        "Bind address changed, restarting server"
                    );
                }

                // Gracefully shutdown old server
                if let Some(tx) = server_shutdown_tx.take() {
                    let _ = tx.send(());
                }
                if let Some(handle) = server_handle.take() {
                    // Wait for old server to shutdown gracefully
                    // This allows existing connections to complete
                    let _ = handle.await;
                    info!("Old server shutdown complete");
                }

                // Start new server on new address
                match start_server_instance(config_manager.clone(), new_addr).await {
                    Ok((handle, shutdown_tx)) => {
                        current_addr = Some(new_addr);
                        server_handle = Some(handle);
                        server_shutdown_tx = Some(shutdown_tx);
                        info!("Proxy server restarted on {}", new_addr);
                    }
                    Err(err) => {
                        warn!(
                            address = %new_addr,
                            error = %err,
                            "Failed to start server on new address; server is not running"
                        );
                        // Server failed to start - current_addr is None, server_handle is None
                        // This means the server is not running, but we continue monitoring
                        // in case the config is fixed
                    }
                }
            }
        }
    }
}

/// Start a single server instance on the specified address
/// Returns the server handle and shutdown channel
async fn start_server_instance(
    config_manager: ConfigManager,
    addr: std::net::SocketAddr,
) -> Result<(
    tokio::task::JoinHandle<Result<()>>,
    tokio::sync::oneshot::Sender<()>,
)> {
    // Requirement: O4 - Log binding failures at WARNING level
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            warn!(
                address = %addr,
                error = %err,
                "Failed to bind to address"
            );
            return Err(err).with_context(|| format!("Failed to bind to {}", addr));
        }
    };

    let state = ProxyState::new(config_manager.clone());
    let app = create_router(state);

    // Requirement: O3 - Log server startup at INFO level
    info!("Fluxgate proxy server listening on {}", addr);

    // Create shutdown channel for this server instance
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    // Start the server with ConnectInfo support
    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    let server_future = axum::serve(listener, make_service).with_graceful_shutdown(async {
        shutdown_rx.await.ok();
    });

    // Spawn server in a separate task
    let handle = tokio::spawn(async move {
        server_future.await?;
        Ok(())
    });

    Ok((handle, shutdown_tx))
}

/// Requirement: F13, P4 - Stream request bodies without loading into memory
#[cfg_attr(not(test), allow(dead_code))]
pub fn stream_request_body(body: Body) -> reqwest::Body {
    let stream = body.into_data_stream().map_err(io::Error::other);
    reqwest::Body::wrap_stream(stream)
}

/// Requirement: O5, O6, O7, O8 - Log final request completion at TRACE level
/// Helper function to log request completion with all required fields
/// O6: timestamp is automatically provided by tracing framework, human-readable description
/// is "Request processed", and all important parameters are included as structured fields
/// O7: All fields must be logged as actual values, not wrapped in Some(...)
/// O8: Only non-sensitive identifiers are logged (api_key, not the key itself);
/// request/response headers and body content are excluded to prevent information leakage
#[allow(clippy::too_many_arguments)] // All arguments required by O5 and O6
fn log_request_completion(
    client_ip: std::net::IpAddr,
    method: &Method,
    url: &str,
    request_body_length: Option<u64>,
    api_key: Option<&str>,
    target_url: Option<&str>,
    upstream: Option<&str>,
    duration_ms: u128,
    status: StatusCode,
    response_body_length: Option<u64>,
) {
    // Requirement O7: Format optional fields as actual values, not Some(...)
    // Use conditional field inclusion to log only when values are present
    // Requirement O6: Field order: client_ip, method, request_url, request_body_length, api_key, target_url, upstream, duration_ms, status, response_body_length
    match (
        request_body_length,
        api_key,
        target_url,
        upstream,
        response_body_length,
    ) {
        (Some(req_len), Some(key_name), Some(tgt_url), Some(up), Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                api_key = %key_name,
                target_url = %tgt_url,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (Some(req_len), Some(key_name), Some(tgt_url), Some(up), None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                api_key = %key_name,
                target_url = %tgt_url,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (Some(req_len), Some(key_name), Some(tgt_url), None, Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                api_key = %key_name,
                target_url = %tgt_url,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (Some(req_len), Some(key_name), Some(tgt_url), None, None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                api_key = %key_name,
                target_url = %tgt_url,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (Some(req_len), Some(key_name), None, Some(up), Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                api_key = %key_name,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (Some(req_len), Some(key_name), None, Some(up), None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                api_key = %key_name,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (Some(req_len), Some(key_name), None, None, Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                api_key = %key_name,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (Some(req_len), Some(key_name), None, None, None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                api_key = %key_name,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (Some(req_len), None, Some(tgt_url), Some(up), Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                target_url = %tgt_url,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (Some(req_len), None, Some(tgt_url), Some(up), None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                target_url = %tgt_url,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (Some(req_len), None, Some(tgt_url), None, Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                target_url = %tgt_url,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (Some(req_len), None, Some(tgt_url), None, None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                target_url = %tgt_url,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (Some(req_len), None, None, Some(up), Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (Some(req_len), None, None, Some(up), None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (Some(req_len), None, None, None, Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (Some(req_len), None, None, None, None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                request_body_length = %req_len,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (None, Some(key_name), Some(tgt_url), Some(up), Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                api_key = %key_name,
                target_url = %tgt_url,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (None, Some(key_name), Some(tgt_url), Some(up), None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                api_key = %key_name,
                target_url = %tgt_url,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (None, Some(key_name), Some(tgt_url), None, Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                api_key = %key_name,
                target_url = %tgt_url,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (None, Some(key_name), Some(tgt_url), None, None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                api_key = %key_name,
                target_url = %tgt_url,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (None, Some(key_name), None, Some(up), Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                api_key = %key_name,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (None, Some(key_name), None, Some(up), None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                api_key = %key_name,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (None, Some(key_name), None, None, Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                api_key = %key_name,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (None, Some(key_name), None, None, None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                api_key = %key_name,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (None, None, Some(tgt_url), Some(up), Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                target_url = %tgt_url,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (None, None, Some(tgt_url), Some(up), None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                target_url = %tgt_url,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (None, None, Some(tgt_url), None, Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                target_url = %tgt_url,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (None, None, Some(tgt_url), None, None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                target_url = %tgt_url,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (None, None, None, Some(up), Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (None, None, None, Some(up), None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                upstream = %up,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
        (None, None, None, None, Some(resp_len)) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                response_body_length = %resp_len,
                "Request processed"
            );
        }
        (None, None, None, None, None) => {
            trace!(
                client_ip = %client_ip,
                method = %method,
                request_url = %url,
                duration_ms = %duration_ms,
                status = status.as_u16(),
                "Request processed"
            );
        }
    }
}

/// Extract body length from Content-Length header
/// Requirement: O6 - Extract request/response body length for logging
pub fn get_body_length_from_headers(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}
