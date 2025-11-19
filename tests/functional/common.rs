//! Shared utilities for functional integration tests of the Fluxgate proxy.

use std::{
    borrow::Cow,
    collections::VecDeque,
    fs,
    future::Future,
    io::{BufRead, BufReader},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{to_bytes, Body},
    extract::{connect_info::ConnectInfo, Request},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::Response,
    Router,
};
use tempfile::TempDir;
use tokio::{net::TcpListener, runtime::Runtime, sync::oneshot, task::JoinHandle};

#[cfg(unix)]
use nix::{
    sys::signal::{kill, Signal},
    unistd::Pid,
};

/// Allocate an ephemeral port on localhost for tests.
pub fn allocate_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .map(|listener| {
            let port = listener
                .local_addr()
                .expect("determine ephemeral port")
                .port();
            drop(listener);
            port
        })
        .expect("allocate ephemeral port")
}

/// Generate a `SocketAddr` bound to localhost with an ephemeral port.
pub fn allocate_socket_addr() -> SocketAddr {
    let port = allocate_port();
    format!("127.0.0.1:{port}")
        .parse()
        .expect("parse ephemeral socket addr")
}

#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    pub remote_addr: SocketAddr,
}

#[derive(Clone)]
struct MockResponseTemplate {
    status: StatusCode,
    body: Arc<Vec<u8>>,
    headers: Arc<HeaderMap>,
}

struct MockResponder {
    responses: Arc<Mutex<VecDeque<MockResponseTemplate>>>,
    fallback: MockResponseTemplate,
}

pub struct MockServer {
    captured_requests: Arc<Mutex<Vec<CapturedRequest>>>,
    local_addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    pub async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_with_headers(StatusCode::OK, b"OK".to_vec(), HeaderMap::new()).await
    }

    pub async fn start_with(
        status: StatusCode,
        body: Vec<u8>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_with_headers(status, body, HeaderMap::new()).await
    }

    pub async fn start_with_headers(
        status: StatusCode,
        body: Vec<u8>,
        headers: HeaderMap,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_with_sequence(vec![(status, body, headers)]).await
    }

    pub async fn start_with_sequence(
        responses: Vec<(StatusCode, Vec<u8>, HeaderMap)>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_with_sequence_at(None, responses).await
    }

    pub async fn start_with_sequence_at(
        addr: Option<SocketAddr>,
        responses: Vec<(StatusCode, Vec<u8>, HeaderMap)>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        assert!(
            !responses.is_empty(),
            "at least one response template must be provided"
        );

        let captured_requests = Arc::new(Mutex::new(Vec::new()));
        let captured_requests_clone = captured_requests.clone();

        let mut queue = VecDeque::new();
        for (status, body, headers) in responses.into_iter() {
            queue.push_back(MockResponseTemplate {
                status,
                body: Arc::new(body),
                headers: Arc::new(headers),
            });
        }

        let fallback = queue
            .back()
            .cloned()
            .expect("validated non-empty response queue");

        let responder = Arc::new(MockResponder {
            responses: Arc::new(Mutex::new(queue)),
            fallback,
        });

        let app = Router::new().fallback(
            move |ConnectInfo(remote_addr): ConnectInfo<SocketAddr>, req: Request| {
                let captured_requests = captured_requests_clone.clone();
                let responder = responder.clone();
                async move {
                    let (parts, body) = req.into_parts();
                    let body_bytes = to_bytes(body, 1024 * 1024).await.unwrap_or_default();

                    let captured = CapturedRequest {
                        method: parts.method,
                        uri: parts.uri,
                        headers: parts.headers,
                        body: body_bytes.to_vec(),
                        remote_addr,
                    };

                    captured_requests.lock().unwrap().push(captured);

                    let template = {
                        let mut responses = responder.responses.lock().unwrap();
                        responses
                            .pop_front()
                            .unwrap_or_else(|| responder.fallback.clone())
                    };

                    let mut builder = Response::builder().status(template.status);
                    for (key, value) in template.headers.iter() {
                        builder = builder.header(key, value);
                    }
                    builder
                        .body(Body::from(template.body.as_slice().to_vec()))
                        .unwrap()
                }
            },
        );

        let listener = if let Some(addr) = addr {
            TcpListener::bind(addr).await?
        } else {
            TcpListener::bind("127.0.0.1:0").await?
        };
        let local_addr = listener.local_addr()?;

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let make_service = app.into_make_service_with_connect_info::<SocketAddr>();

        let handle = tokio::spawn(async move {
            let result = axum::serve(listener, make_service)
                .with_graceful_shutdown(async {
                    shutdown_rx.await.ok();
                })
                .await;

            if let Err(err) = result {
                eprintln!("Error serving: {:?}", err);
            }
        });

        Ok(Self {
            captured_requests,
            local_addr,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        })
    }

    pub async fn start_on_port(
        port: u16,
        responses: Vec<(StatusCode, Vec<u8>, HeaderMap)>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse provided mock server port");
        Self::start_with_sequence_at(Some(addr), responses).await
    }

    pub fn captured_requests(&self) -> Vec<CapturedRequest> {
        self.captured_requests.lock().unwrap().clone()
    }

    pub fn clear_captured(&self) {
        self.captured_requests.lock().unwrap().clear();
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.local_addr)
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

pub struct ProxyProcess {
    child: Option<Child>,
    config_path: PathBuf,
    _temp_dir: TempDir,
    stdout_buffer: Arc<Mutex<String>>,
    stderr_buffer: Arc<Mutex<String>>,
    stdout_handle: Option<std::thread::JoinHandle<()>>,
    stderr_handle: Option<std::thread::JoinHandle<()>>,
}

impl ProxyProcess {
    pub fn spawn(config_yaml: &str) -> Self {
        Self::spawn_internal(config_yaml, true, "info")
    }

    pub fn spawn_with_log_level(config_yaml: &str, log_level: &str) -> Self {
        Self::spawn_internal(config_yaml, true, log_level)
    }

    pub fn spawn_without_version(config_yaml: &str) -> Self {
        Self::spawn_internal(config_yaml, false, "info")
    }

    fn spawn_internal(config_yaml: &str, normalize_version: bool, log_level: &str) -> Self {
        let temp_dir = TempDir::new().expect("create temp dir");
        let config_path = temp_dir.path().join("fluxgate.yaml");
        let content = if normalize_version {
            Self::ensure_version_line(config_yaml)
        } else {
            Cow::Borrowed(config_yaml)
        };
        fs::write(&config_path, content.as_ref()).expect("write proxy configuration");

        let binary = assert_cmd::cargo::cargo_bin!("fluxgate");
        let mut child = Command::new(binary)
            .current_dir(temp_dir.path())
            .arg("--config")
            .arg(&config_path)
            .env("FLUXGATE_LOG", log_level)
            .env("FLUXGATE_LOG_STYLE", "never")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn fluxgate proxy");

        let stdout = child
            .stdout
            .take()
            .expect("proxy stdout should be piped for capture");
        let stderr = child
            .stderr
            .take()
            .expect("proxy stderr should be piped for capture");

        let stdout_buffer = Arc::new(Mutex::new(String::new()));
        let stderr_buffer = Arc::new(Mutex::new(String::new()));

        let stdout_handle = Self::spawn_output_reader(stdout, Arc::clone(&stdout_buffer));
        let stderr_handle = Self::spawn_output_reader(stderr, Arc::clone(&stderr_buffer));

        Self {
            child: Some(child),
            config_path,
            _temp_dir: temp_dir,
            stdout_buffer,
            stderr_buffer,
            stdout_handle: Some(stdout_handle),
            stderr_handle: Some(stderr_handle),
        }
    }

    fn ensure_version_line(config_yaml: &str) -> Cow<'_, str> {
        let mut lines = config_yaml.lines();
        let mut has_version = false;

        while let Some(line) = lines.next() {
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let trimmed = trimmed.trim_start_matches('\u{feff}');
            if trimmed.starts_with("version:") {
                has_version = true;
            }

            break;
        }

        if has_version {
            return Cow::Borrowed(config_yaml);
        }

        let uses_crlf = config_yaml.contains("\r\n");
        let line_ending = if uses_crlf { "\r\n" } else { "\n" };
        let mut normalized = String::from("version: 1");

        let trimmed = config_yaml.trim_start_matches(|c| c == '\n' || c == '\r');
        if !trimmed.is_empty() {
            normalized.push_str(line_ending);
            normalized.push_str(line_ending);
            normalized.push_str(trimmed);
        }

        Cow::Owned(normalized)
    }

    pub fn wait_for_ready(&mut self, addr: SocketAddr, timeout: Duration) {
        let deadline = Instant::now() + timeout;

        loop {
            if Instant::now() > deadline {
                let logs = self.take_process_output();
                panic!(
                    "proxy failed to listen on {addr} within {:?}\n{}",
                    timeout, logs
                );
            }

            if let Some(child) = self.child.as_mut() {
                if let Some(status) = child.try_wait().expect("poll proxy status") {
                    let logs = self.take_process_output();
                    panic!("proxy exited early with status {status:?}\n{logs}");
                }
            } else {
                panic!("proxy process is not running");
            }

            if TcpStream::connect(addr).is_ok() {
                return;
            }

            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn wait_for_exit(&mut self, timeout: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + timeout;

        while Instant::now() <= deadline {
            let exit_status = match self.child.as_mut() {
                Some(child) => child.try_wait().expect("poll proxy status"),
                None => return None,
            };

            if exit_status.is_some() {
                let mut child = self
                    .child
                    .take()
                    .expect("child handle unexpectedly missing after exit");
                let status = child.wait().expect("wait for proxy exit");
                self.join_output_threads();
                return Some(status);
            }

            thread::sleep(Duration::from_millis(50));
        }

        None
    }

    pub fn shutdown(&mut self) {
        if let Some(mut child) = self.child.take() {
            if child.try_wait().expect("poll proxy status").is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        self.join_output_threads();
    }

    pub fn config_path(&self) -> &Path {
        self.config_path.as_path()
    }

    #[cfg(unix)]
    pub fn pid(&self) -> Option<Pid> {
        self.child
            .as_ref()
            .map(|child| Pid::from_raw(child.id() as i32))
    }

    #[cfg(unix)]
    pub fn send_signal(&self, signal: Signal) -> Result<(), nix::Error> {
        if let Some(pid) = self.pid() {
            kill(pid, signal)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    pub fn send_sigint(&self) -> Result<(), nix::Error> {
        self.send_signal(Signal::SIGINT)
    }

    #[cfg(unix)]
    pub fn send_sigterm(&self) -> Result<(), nix::Error> {
        self.send_signal(Signal::SIGTERM)
    }

    pub fn take_process_output(&mut self) -> String {
        self.logs_snapshot()
    }

    pub fn logs_snapshot(&self) -> String {
        let stdout = self.stdout_buffer.lock().unwrap().clone();
        let stderr = self.stderr_buffer.lock().unwrap().clone();
        format!("stdout:\n{stdout}\nstderr:\n{stderr}")
    }

    pub fn wait_for_logs<F>(&self, timeout: Duration, mut predicate: F) -> String
    where
        F: FnMut(&str) -> bool,
    {
        let deadline = Instant::now() + timeout;

        loop {
            let logs = self.logs_snapshot();
            if predicate(&logs) {
                return logs;
            }

            if Instant::now() >= deadline {
                return logs;
            }

            thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn runtime() -> Runtime {
        Runtime::new().expect("create tokio runtime")
    }

    fn join_output_threads(&mut self) {
        if let Some(handle) = self.stdout_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr_handle.take() {
            let _ = handle.join();
        }
    }

    fn spawn_output_reader<R>(reader: R, buffer: Arc<Mutex<String>>) -> std::thread::JoinHandle<()>
    where
        R: std::io::Read + Send + 'static,
    {
        thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        let mut buf = buffer.lock().unwrap();
                        buf.push_str(&line);
                    }
                    Err(err) => {
                        let mut buf = buffer.lock().unwrap();
                        buf.push_str(&format!("\n<output read error: {err}>\n"));
                        break;
                    }
                }
            }
        })
    }
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Execute the provided async test body on a Tokio runtime.
pub fn run_async_test<F, Fut>(future: F)
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    ProxyProcess::runtime().block_on(future());
}

#[cfg(unix)]
#[allow(dead_code)]
pub fn reload_socket_path_for(config_path: &Path) -> PathBuf {
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

/// YAML configuration field names as constants to avoid duplication.
pub mod yaml_fields {
    pub const VERSION: &str = "version";
    pub const SERVER: &str = "server";
    pub const BIND_ADDRESS: &str = "bind_address";
    pub const MAX_CONNECTIONS: &str = "max_connections";
    pub const UPSTREAMS: &str = "upstreams";
    pub const REQUEST_TIMEOUT_MS: &str = "request_timeout_ms";
    pub const TARGET_URL: &str = "target_url";
    pub const API_KEY: &str = "api_key";
    pub const KEY: &str = "key";
    pub const REQUEST_PATH: &str = "request_path";
    pub const API_KEYS: &str = "api_keys";
    pub const STATIC: &str = "static";
}

/// Configuration for generating test YAML configs.
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub bind_address: String,
    pub max_connections: Option<u32>,
    pub request_timeout_ms: Option<u32>,
    pub upstreams: Vec<UpstreamConfig>,
    pub api_keys: Vec<ApiKeyConfig>,
    pub jwt_keys: Vec<JwtApiKeyConfig>,
}

/// Configuration for a single upstream.
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    pub name: String,
    pub target_url: String,
    pub api_key: String,
    pub request_path: String,
}

/// Configuration for a single API key.
#[derive(Debug, Clone)]
pub struct ApiKeyConfig {
    pub id: String,
    pub key: String,
    pub upstreams: Vec<String>,
}

/// Configuration for a single JWT API key.
#[derive(Debug, Clone)]
pub struct JwtApiKeyConfig {
    pub id: String,
    pub key: String,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            bind_address: "{}".to_string(),
            max_connections: Some(100),
            request_timeout_ms: Some(5000),
            upstreams: vec![UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: "{}".to_string(),
                api_key: "upstream-key".to_string(),
                request_path: "/test".to_string(),
            }],
            api_keys: vec![ApiKeyConfig {
                id: "test-key".to_string(),
                key: "valid-token".to_string(),
                upstreams: vec!["test-upstream".to_string()],
            }],
            jwt_keys: vec![],
        }
    }
}

impl TestConfig {
    /// Create a new test config with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the bind address (use "{}" as placeholder for format!).
    pub fn with_bind_address(mut self, bind_address: impl Into<String>) -> Self {
        self.bind_address = bind_address.into();
        self
    }

    /// Set max_connections.
    pub fn with_max_connections(mut self, max_connections: Option<u32>) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Set request_timeout_ms.
    pub fn with_request_timeout_ms(mut self, request_timeout_ms: Option<u32>) -> Self {
        self.request_timeout_ms = request_timeout_ms;
        self
    }

    /// Add an upstream configuration.
    pub fn add_upstream(mut self, upstream: UpstreamConfig) -> Self {
        self.upstreams.push(upstream);
        self
    }

    /// Add an API key configuration.
    pub fn add_api_key(mut self, api_key: ApiKeyConfig) -> Self {
        self.api_keys.push(api_key);
        self
    }

    /// Clear all upstreams.
    pub fn clear_upstreams(mut self) -> Self {
        self.upstreams.clear();
        self
    }

    /// Clear all API keys.
    pub fn clear_api_keys(mut self) -> Self {
        self.api_keys.clear();
        self
    }

    /// Add a JWT API key configuration.
    pub fn add_jwt_key(mut self, jwt_key: JwtApiKeyConfig) -> Self {
        self.jwt_keys.push(jwt_key);
        self
    }

    /// Clear all JWT keys.
    pub fn clear_jwt_keys(mut self) -> Self {
        self.jwt_keys.clear();
        self
    }

    /// Generate the YAML configuration string.
    pub fn to_yaml(&self) -> String {
        use yaml_fields::*;
        let mut yaml = format!("{}: 1\n", VERSION);

        // Server section
        yaml.push_str(&format!("\n{}:\n", SERVER));
        yaml.push_str(&format!("  {}: \"{}\"\n", BIND_ADDRESS, self.bind_address));
        if let Some(max_conn) = self.max_connections {
            yaml.push_str(&format!("  {}: {}\n", MAX_CONNECTIONS, max_conn));
        }

        // Upstreams section
        if !self.upstreams.is_empty() {
            yaml.push_str(&format!("\n{}:\n", UPSTREAMS));
            if let Some(timeout) = self.request_timeout_ms {
                yaml.push_str(&format!("  {}: {}\n", REQUEST_TIMEOUT_MS, timeout));
            }
            for upstream in &self.upstreams {
                yaml.push_str(&format!("  {}:\n", upstream.name));
                yaml.push_str(&format!(
                    "    {}: \"{}\"\n",
                    TARGET_URL, upstream.target_url
                ));
                yaml.push_str(&format!("    {}: \"{}\"\n", API_KEY, upstream.api_key));
                yaml.push_str(&format!(
                    "    {}: \"{}\"\n",
                    REQUEST_PATH, upstream.request_path
                ));
            }
        }

        // API keys section
        if !self.api_keys.is_empty() || !self.jwt_keys.is_empty() {
            yaml.push_str(&format!("\n{}:\n", API_KEYS));
            // Always include static field (required by deserialization), even if empty
            if !self.api_keys.is_empty() {
                yaml.push_str(&format!("  {}:\n", STATIC));
                for api_key in &self.api_keys {
                    yaml.push_str(&format!("    - id: {}\n", api_key.id));
                    yaml.push_str(&format!("      {}: \"{}\"\n", KEY, api_key.key));
                    if api_key.upstreams.is_empty() {
                        yaml.push_str(&format!("      {}: []\n", UPSTREAMS));
                    } else {
                        yaml.push_str(&format!("      {}:\n", UPSTREAMS));
                        for upstream in &api_key.upstreams {
                            yaml.push_str(&format!("        - {}\n", upstream));
                        }
                    }
                }
            } else {
                // Add empty static field when only JWT keys are present (required by deserialization)
                yaml.push_str(&format!("  {}: []\n", STATIC));
            }
            if !self.jwt_keys.is_empty() {
                yaml.push_str(&format!("  jwt:\n"));
                for jwt_key in &self.jwt_keys {
                    yaml.push_str(&format!("    - id: {}\n", jwt_key.id));
                    yaml.push_str(&format!("      {}: \"{}\"\n", KEY, jwt_key.key));
                }
            }
        }

        yaml
    }
}

/// Helper to create a simple upstream config.
pub fn simple_upstream(
    name: impl Into<String>,
    url: impl Into<String>,
    path: impl Into<String>,
) -> UpstreamConfig {
    UpstreamConfig {
        name: name.into(),
        target_url: url.into(),
        api_key: "upstream-key".to_string(),
        request_path: path.into(),
    }
}

/// Helper to create a simple API key config.
pub fn simple_api_key(
    id: impl Into<String>,
    key: impl Into<String>,
    upstreams: Vec<String>,
) -> ApiKeyConfig {
    ApiKeyConfig {
        id: id.into(),
        key: key.into(),
        upstreams,
    }
}

/// Helper to create a simple JWT API key config.
pub fn simple_jwt_key(id: impl Into<String>, key: impl Into<String>) -> JwtApiKeyConfig {
    JwtApiKeyConfig {
        id: id.into(),
        key: key.into(),
    }
}

/// Create a JWT token for testing.
/// This function creates a valid JWT token with the specified kid, signed with the given key.
/// Optionally includes exp (expiration) and nbf (not before) claims.
pub fn create_jwt_token(
    kid: &str,
    key: &str,
    exp: Option<i64>,
    nbf: Option<i64>,
) -> Result<String, Box<dyn std::error::Error>> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::Map;

    let mut header = Header::default();
    header.alg = Algorithm::HS256;
    header.typ = Some("JWT".to_string());
    header.kid = Some(kid.to_string());

    let mut claims = Map::new();
    if let Some(exp_val) = exp {
        claims.insert(
            "exp".to_string(),
            serde_json::Value::Number(serde_json::Number::from(exp_val)),
        );
    }
    if let Some(nbf_val) = nbf {
        claims.insert(
            "nbf".to_string(),
            serde_json::Value::Number(serde_json::Number::from(nbf_val)),
        );
    }

    let encoding_key = EncodingKey::from_secret(key.as_bytes());
    let token = encode(&header, &claims, &encoding_key)?;
    Ok(token)
}

/// Get current Unix timestamp in seconds.
pub fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
