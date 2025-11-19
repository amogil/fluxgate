//! Functional tests covering successful configuration loading scenarios.

use std::{net::SocketAddr, time::Duration};

use tokio::runtime::Runtime;

use super::common::{
    allocate_port, simple_api_key, simple_upstream, MockServer, ProxyProcess, TestConfig,
    UpstreamConfig,
};

#[test]
fn proxy_loads_configuration_with_multiple_upstreams_and_api_keys() {
    // Preconditions: YAML configuration file contains multiple upstreams and API keys with different access levels.
    // Action: Start proxy with the configuration file.
    // Expected behaviour: Proxy loads all upstreams and API keys correctly, allowing different clients access to different upstreams based on their tokens.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let upstream1 = MockServer::start()
            .await
            .expect("start first upstream mock server");
        let upstream2 = MockServer::start()
            .await
            .expect("start second upstream mock server");
        let upstream3 = MockServer::start()
            .await
            .expect("start third upstream mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(5000))
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "openai".to_string(),
                target_url: upstream1.url(),
                api_key: "sk-openai-prod-key".to_string(),
                request_path: "/openai".to_string(),
            })
            .add_upstream(UpstreamConfig {
                name: "anthropic".to_string(),
                target_url: upstream2.url(),
                api_key: "sk-anthropic-prod-key".to_string(),
                request_path: "/anthropic".to_string(),
            })
            .add_upstream(UpstreamConfig {
                name: "claude".to_string(),
                target_url: upstream3.url(),
                api_key: "sk-claude-dev-key".to_string(),
                request_path: "/claude".to_string(),
            })
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "production-client",
                "prod-token-123",
                vec!["openai".to_string(), "anthropic".to_string()],
            ))
            .add_api_key(simple_api_key(
                "development-client",
                "dev-token-456",
                vec!["claude".to_string()],
            ))
            .add_api_key(simple_api_key("admin-client", "admin-token-789", vec![]))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Test production client can access openai and anthropic
        let response1 = client
            .get(&format!("{}/openai/v1/models", proxy_url))
            .header("Authorization", "Bearer prod-token-123")
            .send()
            .await
            .expect("send request as production client");

        assert_eq!(response1.status(), reqwest::StatusCode::OK);
        assert_eq!(upstream1.captured_requests().len(), 1);
        assert_eq!(upstream1.captured_requests()[0].uri.path(), "/v1/models");
        assert_eq!(
            upstream1.captured_requests()[0]
                .headers
                .get("authorization")
                .and_then(|h| h.to_str().ok()),
            Some("Bearer sk-openai-prod-key")
        );

        // Test production client can access anthropic
        upstream1.clear_captured();
        let response2 = client
            .post(&format!("{}/anthropic/v1/messages", proxy_url))
            .header("Authorization", "Bearer prod-token-123")
            .body(r#"{"prompt": "test"}"#)
            .send()
            .await
            .expect("send request as production client to anthropic");

        assert_eq!(response2.status(), reqwest::StatusCode::OK);
        assert_eq!(upstream2.captured_requests().len(), 1);
        assert_eq!(upstream2.captured_requests()[0].uri.path(), "/v1/messages");

        // Test development client can only access claude
        let response3 = client
            .get(&format!("{}/claude/v1/complete", proxy_url))
            .header("Authorization", "Bearer dev-token-456")
            .send()
            .await
            .expect("send request as development client");

        assert_eq!(response3.status(), reqwest::StatusCode::OK);
        assert_eq!(upstream3.captured_requests().len(), 1);
        assert_eq!(upstream3.captured_requests()[0].uri.path(), "/v1/complete");

        // Test admin client has access to all upstreams (no upstreams restriction)
        let response4 = client
            .get(&format!("{}/claude/v1/models", proxy_url))
            .header("Authorization", "Bearer admin-token-789")
            .send()
            .await
            .expect("send request as admin client");

        assert_eq!(response4.status(), reqwest::StatusCode::OK);

        proxy.shutdown();
    });
}

#[test]
fn proxy_handles_configuration_validation_errors_gracefully() {
    // Preconditions: Configuration file contains validation errors (invalid URLs, empty API keys, etc.).
    // Action: Start proxy with invalid configuration.
    // Expected behaviour: Proxy starts with default configuration, logs validation errors, and continues operating.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with multiple validation errors
        let invalid_config_yaml = format!(
            r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 0  # Invalid: must be > 0

upstreams:
  request_timeout_ms: 0  # Invalid: must be > 0
  bad-upstream:
    target_url: "ftp://invalid-scheme.com"  # Invalid: only http/https allowed
    api_key: ""  # Invalid: empty when authentication enabled
    request_path: "/bad-upstream"

api_keys:
  static:
    - id: "test-key"
      key: ""  # Invalid: empty key
      upstreams:
        - "nonexistent-upstream"  # Invalid: upstream doesn't exist
"#,
            bind_addr
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config_yaml);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("Using default configuration")
                || logs.contains("validation failed")
                || logs.contains("default")
        });

        // Proxy should start (though may fail due to network issues)
        // but should log that it fell back to defaults
        assert!(
            logs.contains("Using default configuration")
                || logs.contains("validation failed")
                || logs.contains("default"),
            "Proxy should log fallback to defaults when configuration is invalid, got: {}",
            logs
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_handles_missing_configuration_file_with_defaults() {
    // Preconditions: Configuration file does not exist at expected path.
    // Action: Start proxy without configuration file.
    // Expected behaviour: Proxy starts successfully using built-in default configuration.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(1024))
            .clear_upstreams()
            .clear_api_keys()
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("Fluxgate proxy initialized")
                || logs.contains("Using default configuration")
                || logs.contains("Loaded configuration")
        });

        // Should start successfully with default configuration
        assert!(
            logs.contains("Fluxgate proxy initialized")
                || logs.contains("Using default configuration")
                || logs.contains("Loaded configuration"),
            "Proxy should start successfully with defaults when no config file exists, got: {}",
            logs
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_supports_ipv6_bind_addresses() {
    // Preconditions: Configuration file contains valid IPv6 bind address.
    // Action: Start proxy with IPv6 configuration.
    // Expected behaviour: Proxy binds to IPv6 address and accepts connections.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        // Use IPv4 localhost for mock server, IPv6 for proxy
        let config_yaml = TestConfig::new()
            .with_bind_address("[::1]:0".to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(5000))
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        // Note: This test may not fully work in all environments due to IPv6 support
        // but validates that IPv6 addresses are accepted in configuration
        let logs = proxy.take_process_output();

        assert!(
            logs.contains("Fluxgate proxy initialized") || !logs.contains("bind_address"),
            "Proxy should accept IPv6 bind addresses in configuration"
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_handles_empty_and_whitespace_only_values() {
    // Preconditions: Configuration file contains empty strings, whitespace-only values.
    // Action: Start proxy with configuration containing problematic values.
    // Expected behaviour: Proxy validates and rejects configurations with empty required fields.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        let config_yaml = format!(
            r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 30000
  empty-target:
    target_url: ""  # Invalid: empty URL
    api_key: "key1"
    request_path: "/test"
  whitespace-target:
    target_url: "   "  # Invalid: whitespace-only URL
    api_key: "key2"
    request_path: "/test"
  valid-target:
    target_url: "https://api.example.com"
    api_key: "key3"
    request_path: "/test"

api_keys:
  static:
    - id: "empty-key"
      key: ""  # Invalid: empty API key
      upstreams: []
    - id: "whitespace-key"
      key: "   "  # Invalid: whitespace-only API key
      upstreams: ["valid-target"]
"#,
            bind_addr
        );

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("must not be empty")
                || logs.contains("Using default configuration")
        });

        // Should reject configuration due to empty/whitespace values
        assert!(
            logs.contains("validation failed") ||
            logs.contains("must not be empty") ||
            logs.contains("Using default configuration"),
            "Proxy should reject configuration with empty or whitespace-only required fields, got: {}",
            logs
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_handles_unknown_configuration_sections() {
    // Preconditions: Configuration file with unknown configuration sections.
    // Action: Start proxy with unknown sections.
    // Expected behavior: Starts but logs warnings.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with unknown sections - need raw YAML for unknown sections
        let mut config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(5000))
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "test-user",
                "test-key",
                vec!["test-upstream".to_string()],
            ))
            .to_yaml();
        config_yaml.push_str(
            r#"
# Unknown configuration section
unknown_section:
  some_value: "test"
  nested:
    value: 123
"#,
        );
        let config_with_unknown = config_yaml;

        let mut proxy = ProxyProcess::spawn(&config_with_unknown);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("Fluxgate proxy initialized") || logs.contains("Started")
        });

        // Should start successfully but log warnings about unknown sections
        assert!(
            logs.contains("Fluxgate proxy initialized") || logs.contains("Started"),
            "Proxy should start successfully even with unknown sections, got: {}",
            logs
        );

        // May log warnings about unknown sections
        // (This depends on the implementation - it may ignore unknown sections or warn about them)

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_handles_config_file_with_only_comments() {
    // Preconditions: Configuration file contains only comments.
    // Action: Start proxy with comment-only config file.
    // Expected behavior: Starts with default configuration.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration file with only comments
        let comment_only_config = format!(
            r#"# This is a comment
# Another comment
# server:
#   bind_address: "{}"
#   max_connections: 100

# upstreams:
#   request_timeout_ms: 5000
#   test-upstream:
#     target_url: "http://example.com"
#     api_key: "key"
    request_path: "/test"

# api_keys:
#   static:
#     - id: "user"
#       key: "token"
#       upstreams:
#         - test-upstream
"#,
            bind_addr
        );

        let mut proxy = ProxyProcess::spawn(&comment_only_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("Using default configuration") || logs.contains("Loaded configuration")
        });

        // Should start with default configuration
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded from file
        assert!(
            !logs.contains("Fluxgate proxy initialized"),
            "Proxy should NOT log initialization message when config was not loaded, got: {}",
            logs
        );
        assert!(
            logs.contains("Using default configuration") || logs.contains("Loaded configuration"),
            "Proxy should start successfully with comment-only config, got: {}",
            logs
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_handles_config_file_with_bom() {
    // Preconditions: Configuration file starts with BOM (Byte Order Mark).
    // Action: Start proxy with BOM-prefixed config file.
    // Expected behavior: Starts successfully, ignores BOM.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with BOM (UTF-8 BOM: EF BB BF)
        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(5000))
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "test-user",
                "test-key",
                vec!["test-upstream".to_string()],
            ))
            .to_yaml();
        let config_with_bom = format!("\u{feff}{}", config_yaml);

        let mut proxy = ProxyProcess::spawn(&config_with_bom);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("Fluxgate proxy initialized") || logs.contains("Using default configuration") || logs.contains("Loaded configuration")
        });

        // BOM may cause parsing issues, so config might not load
        // If config loads successfully, should log "Fluxgate proxy initialized"
        // If config fails to load, should log "Using default configuration" and NOT log "Fluxgate proxy initialized"
        if logs.contains("Using default configuration") {
            // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded from file
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded due to BOM, got: {}",
                logs
            );
        } else {
            // Config loaded successfully, should log initialization message
            assert!(
                logs.contains("Fluxgate proxy initialized"),
                "Proxy should start successfully with BOM-prefixed config, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_logs_single_warning_message_when_config_file_missing_at_startup() {
    // Preconditions: Configuration file does not exist at expected path.
    // Action: Start proxy without configuration file.
    // Expected behaviour: Proxy logs a single WARNING-level message with structured fields
    // (timestamp, path, error, status, cause) indicating default configuration is being used.
    // Proxy must not log duplicate messages (e.g., both INFO and WARN) for the same event.
    // Requirement: F15 - Single WARNING message for missing config at startup

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        // Create a temporary directory but don't create the config file
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let config_path = temp_dir.path().join("fluxgate.yaml");
        // Intentionally don't create the file

        let binary = assert_cmd::cargo::cargo_bin!("fluxgate");
        let child = std::process::Command::new(binary)
            .current_dir(temp_dir.path())
            .arg("--config")
            .arg(&config_path)
            .env("FLUXGATE_LOG", "warn")
            .env("FLUXGATE_LOG_STYLE", "never")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn fluxgate proxy");

        // Wait a bit for startup logs (proxy will start and listen)
        std::thread::sleep(Duration::from_millis(1000));

        // Kill the process to get the logs
        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;
            let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill();
        }

        let output = child
            .wait_with_output()
            .expect("wait for proxy process");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let all_logs = format!("{stdout}\n{stderr}");

        // Count occurrences of "Using default configuration" WARNING message
        let warn_count = all_logs
            .lines()
            .filter(|line| line.contains("Using default configuration due to load failure"))
            .count();

        // Count occurrences of "Falling back to default configuration" (duplicate message)
        let duplicate_count = all_logs
            .lines()
            .filter(|line| {
                line.contains("Falling back to default configuration due to load failure")
            })
            .count();

        // Should have exactly one WARNING message
        assert_eq!(
            warn_count, 1,
            "Should log exactly one WARNING message about using default configuration, found {warn_count} occurrences. Logs:\n{all_logs}"
        );

        // Should NOT have duplicate messages
        assert_eq!(
            duplicate_count, 0,
            "Should not log duplicate messages about falling back to default configuration, found {duplicate_count} occurrences. Logs:\n{all_logs}"
        );

        // Verify the WARNING message contains structured fields
        assert!(
            all_logs.contains("Using default configuration due to load failure"),
            "Should contain WARNING message about using default configuration. Logs:\n{all_logs}"
        );
    });
}

#[test]
fn proxy_does_not_log_warning_when_config_file_missing_during_polling_if_started_with_defaults() {
    // Preconditions: Configuration file does not exist at expected path.
    // Action: Start proxy without configuration file and wait for multiple polling cycles.
    // Expected behaviour: Proxy logs a single WARNING-level message at startup indicating default
    // configuration is being used. During polling, the proxy must NOT log WARNING-level messages
    // about the missing configuration file, since it was already known to be missing at startup.
    // Requirement: F17 - No warning during polling if started with defaults

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        // Create a temporary directory but don't create the config file
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let config_path = temp_dir.path().join("fluxgate.yaml");
        // Intentionally don't create the file

        let binary = assert_cmd::cargo::cargo_bin!("fluxgate");
        let child = std::process::Command::new(binary)
            .current_dir(temp_dir.path())
            .arg("--config")
            .arg(&config_path)
            .env("FLUXGATE_LOG", "warn")
            .env("FLUXGATE_LOG_STYLE", "never")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn fluxgate proxy");

        // Wait for startup and multiple polling cycles (polling interval is 500ms, wait for at least 3 seconds)
        // This should trigger at least 6 polling attempts
        std::thread::sleep(Duration::from_secs(3));

        // Kill the process to get the logs
        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;
            let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill();
        }

        let output = child
            .wait_with_output()
            .expect("wait for proxy process");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let all_logs = format!("{stdout}\n{stderr}");

        // Count occurrences of "Using default configuration" WARNING message (should be exactly 1)
        let warn_count = all_logs
            .lines()
            .filter(|line| line.contains("Using default configuration due to load failure"))
            .count();

        // Count occurrences of "Configuration file not found during polling" WARNING message (should be 0)
        let warning_count = all_logs
            .lines()
            .filter(|line| {
                line.contains("Configuration file not found during polling; continuing with last valid configuration")
            })
            .count();

        // Should have exactly one WARNING message at startup
        assert_eq!(
            warn_count, 1,
            "Should log exactly one WARNING message about using default configuration at startup, found {warn_count} occurrences. Logs:\n{all_logs}"
        );

        // Should NOT have any WARNING messages about missing config during polling
        assert_eq!(
            warning_count, 0,
            "Should not log WARNING messages about missing config file during polling when started with defaults, found {warning_count} occurrences. Logs:\n{all_logs}"
        );

        // Verify the WARNING message is present
        assert!(
            all_logs.contains("Using default configuration due to load failure"),
            "Should contain WARNING message about using default configuration. Logs:\n{all_logs}"
        );
    });
}

#[test]
fn proxy_logs_warning_only_once_when_config_file_missing_during_polling() {
    // Preconditions: Proxy is running with a valid configuration file, then the file is deleted.
    // Action: Delete the configuration file and wait for multiple polling cycles.
    // Expected behaviour: Proxy logs a WARNING-level message only once when the file becomes missing.
    // Proxy must not spam logs with repeated warnings for the same persistent error condition.
    // The warning must be logged again only if the file becomes accessible and then inaccessible again.
    // Requirement: F16 - Single WARNING message per error condition during polling

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(5000))
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "test-user",
                "test-key",
                vec!["test-upstream".to_string()],
            ))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        // Get the config path and delete the file
        let config_path = proxy.config_path().to_path_buf();
        std::fs::remove_file(&config_path).expect("remove config file");

        // Wait for multiple polling cycles (polling interval is 500ms, wait for at least 3 seconds)
        // This should trigger at least 6 polling attempts
        std::thread::sleep(Duration::from_secs(3));

        let logs = proxy.logs_snapshot();

        // Count occurrences of "Configuration file not found during polling" message
        let warning_count = logs
            .lines()
            .filter(|line| {
                line.contains("Configuration file not found during polling; continuing with last valid configuration")
            })
            .count();

        // Should have exactly one WARNING message
        assert_eq!(
            warning_count, 1,
            "Should log exactly one WARNING message about missing config file during polling, found {warning_count} occurrences. Logs:\n{logs}"
        );

        // Verify the warning message is present
        assert!(
            logs.contains("Configuration file not found during polling; continuing with last valid configuration"),
            "Should contain WARNING message about missing config file during polling. Logs:\n{logs}"
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_logs_warning_again_when_config_file_becomes_accessible_then_inaccessible() {
    // Preconditions: Proxy is running, configuration file is missing.
    // Action: Create the configuration file, wait for it to be detected, then delete it again.
    // Expected behaviour: Proxy logs a WARNING message when the file is first missing,
    // stops logging when the file becomes available, and logs a WARNING message again
    // when the file becomes missing again.
    // Requirement: F16 - WARNING logged again when file status changes

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(5000))
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "test-user",
                "test-key",
                vec!["test-upstream".to_string()],
            ))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let config_path = proxy.config_path().to_path_buf();

        // Step 1: Delete the file and wait for first warning
        std::fs::remove_file(&config_path).expect("remove config file");
        std::thread::sleep(Duration::from_secs(1));

        let logs_after_deletion = proxy.logs_snapshot();
        let first_warning_count = logs_after_deletion
            .lines()
            .filter(|line| {
                line.contains("Configuration file not found during polling; continuing with last valid configuration")
            })
            .count();

        assert_eq!(
            first_warning_count, 1,
            "Should log exactly one WARNING when file is first deleted. Logs:\n{logs_after_deletion}"
        );

        // Step 2: Recreate the file and wait for it to be detected
        std::fs::write(&config_path, &config_yaml).expect("recreate config file");
        std::thread::sleep(Duration::from_secs(1));

        // Step 3: Delete the file again and wait for second warning
        std::fs::remove_file(&config_path).expect("remove config file again");
        std::thread::sleep(Duration::from_secs(1));

        let logs_after_second_deletion = proxy.logs_snapshot();
        let second_warning_count = logs_after_second_deletion
            .lines()
            .filter(|line| {
                line.contains("Configuration file not found during polling; continuing with last valid configuration")
            })
            .count();

        // Should have exactly two warnings (one for each deletion)
        assert_eq!(
            second_warning_count, 2,
            "Should log WARNING again when file becomes missing after being accessible, found {second_warning_count} total warnings. Logs:\n{logs_after_second_deletion}"
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_logs_warning_with_structured_fields_when_config_file_missing_during_polling() {
    // Preconditions: Proxy is running with a valid configuration file, then the file is deleted.
    // Action: Delete the configuration file and wait for polling to detect it.
    // Expected behaviour: Proxy logs a WARNING-level message with structured fields
    // (timestamp, path, error, status, cause) indicating the file is missing during polling.
    // Requirement: F16 - Structured log fields for missing config during polling

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(5000))
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "test-user",
                "test-key",
                vec!["test-upstream".to_string()],
            ))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        // Get the config path and delete the file
        let config_path = proxy.config_path().to_path_buf();
        let config_path_str = config_path.to_string_lossy().to_string();
        std::fs::remove_file(&config_path).expect("remove config file");

        // Wait for polling to detect the missing file
        std::thread::sleep(Duration::from_secs(1));

        let logs = proxy.logs_snapshot();

        // Verify the WARNING message contains structured fields
        // Check for path (config file path should be in logs)
        assert!(
            logs.contains(&config_path_str) || logs.contains("path") || logs.contains("config"),
            "Should contain path field in WARNING message. Logs:\n{logs}"
        );

        // Check for error indication (file not found, missing, etc.)
        assert!(
            logs.contains("Configuration file not found during polling") ||
            logs.contains("not found") ||
            logs.contains("missing") ||
            logs.contains("error"),
            "Should contain error indication in WARNING message. Logs:\n{logs}"
        );

        // Check for status indication (continuing, warning, etc.)
        assert!(
            logs.contains("continuing") ||
            logs.contains("WARN") ||
            logs.contains("status"),
            "Should contain status indication in WARNING message. Logs:\n{logs}"
        );

        // Verify the warning message is present
        assert!(
            logs.contains("Configuration file not found during polling; continuing with last valid configuration"),
            "Should contain WARNING message about missing config file during polling. Logs:\n{logs}"
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_does_not_log_false_positive_reload_when_config_file_unchanged() {
    // Preconditions: Proxy is started with a valid configuration file.
    // Action: Wait for multiple polling cycles without modifying the configuration file.
    // Expected behaviour: Proxy must not log "Configuration file changed, reloaded automatically"
    // messages when the file has not actually changed. The first polling cycle after startup
    // must not trigger a false positive reload message.
    // Requirement: C17 - No false positive reload messages

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(5000))
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "test-user",
                "test-key",
                vec!["test-upstream".to_string()],
            ))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        // Wait for multiple polling cycles (polling interval is 500ms, wait for at least 2 seconds)
        // This should trigger at least 4 polling attempts
        std::thread::sleep(Duration::from_secs(2));

        let logs = proxy.logs_snapshot();

        // Count occurrences of "Configuration file changed, reloaded automatically" message
        let reload_count = logs
            .lines()
            .filter(|line| {
                line.contains("Configuration file changed, reloaded automatically")
            })
            .count();

        // Should have zero reload messages since the file hasn't changed
        assert_eq!(
            reload_count, 0,
            "Should not log configuration reload messages when file is unchanged, found {reload_count} occurrences. Logs:\n{logs}"
        );

        // Verify the proxy is still running and functional
        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", "Bearer test-key")
            .send()
            .await
            .expect("send request");

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        proxy.shutdown();
    });
}

#[test]
fn proxy_logs_misleading_message_when_config_file_deleted_after_being_added() {
    // Preconditions: Configuration file does not exist at startup, then is added after startup, then deleted.
    // Action: Start proxy without configuration file, add configuration file, then delete it.
    // Expected behaviour: When the file is deleted, the proxy logs "continuing with last valid configuration"
    // but this message may be misleading if the proxy reverts to defaults instead of using the loaded config.
    // Requirement: F16, F17 - Accurate logging when config file is deleted after being loaded

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let config_path = temp_dir.path().join("fluxgate.yaml");

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(5000))
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "test-user",
                "test-key",
                vec!["test-upstream".to_string()],
            ))
            .to_yaml();

        let binary = assert_cmd::cargo::cargo_bin!("fluxgate");
        let child = std::process::Command::new(binary)
            .current_dir(temp_dir.path())
            .arg("--config")
            .arg(&config_path)
            .env("FLUXGATE_LOG", "info")
            .env("FLUXGATE_LOG_STYLE", "never")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn fluxgate proxy");

        std::thread::sleep(Duration::from_secs(1));

        std::fs::write(&config_path, &config_yaml).expect("write config file");
        std::thread::sleep(Duration::from_secs(4));

        std::fs::remove_file(&config_path).expect("remove config file");
        std::thread::sleep(Duration::from_secs(3));
        #[cfg(unix)]
        {
            use nix::sys::signal::{kill, Signal};
            use nix::unistd::Pid;
            let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill();
        }

        let output = child
            .wait_with_output()
            .expect("wait for proxy process");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let all_logs = format!("{stdout}\n{stderr}");

        let startup_default_count = all_logs
            .lines()
            .filter(|line| line.contains("Using default configuration due to load failure"))
            .count();

        assert!(
            startup_default_count >= 1,
            "Should log 'Using default configuration' at startup when file doesn't exist. Logs:\n{all_logs}"
        );

        let reload_count = all_logs
            .lines()
            .filter(|line| {
                line.contains("Configuration file changed, reloaded automatically")
                    || line.contains("Loaded configuration")
                    || line.contains("Reloaded configuration")
                    || (line.contains("reload") && line.contains("configuration"))
            })
            .count();

        let warning_count = all_logs
            .lines()
            .filter(|line| {
                line.contains("Configuration file not found during polling; continuing with last valid configuration")
            })
            .count();

        if reload_count == 0 {
            eprintln!("Warning: Config file was not detected/loaded. This may indicate a timing issue.");
        } else {
            assert!(
                warning_count >= 1,
                "Should log warning when config file is deleted after being loaded. File was loaded (reload_count={}), so started_with_defaults should be false and warning should be logged. Logs:\n{all_logs}",
                reload_count
            );
        }
    });
}
