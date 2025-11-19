//! Functional tests covering proxy observability features and process startup.

use std::{net::SocketAddr, thread, time::Duration};

use tokio::runtime::Runtime;

use super::common::{
    allocate_port, simple_api_key, simple_upstream, MockServer, ProxyProcess, TestConfig,
};

/// # Requirements: O5, O6
///
/// Tests that API key ids appear in logs for observability.
#[test]
fn proxy_logs_api_key_names_for_observability() {
    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let server1 = MockServer::start().await.expect("start first mock server");
        let server2 = MockServer::start().await.expect("start second mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        let config_yaml = format!(
            r#"
server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  server1:
    target_url: "{}"
    api_key: "key1"
    request_path: "/server1"
  server2:
    target_url: "{}"
    api_key: "key2"
    request_path: "/server2"

api_keys:
  static:
    - id: "production-client"
      key: "prod-token"
      upstreams:
        - server1
    - id: "staging-client"
      key: "staging-token"
      upstreams:
        - server2
"#,
            bind_addr,
            server1.url(),
            server2.url()
        );

        // Requirement: O5 - Enable TRACE logging to see request completion logs
        let mut proxy = ProxyProcess::spawn_with_log_level(&config_yaml, "fluxgate::proxy=trace");
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Make requests with different API keys
        let response1 = client
            .get(&format!("{}/server1/test1", proxy_url))
            .header("Authorization", "Bearer prod-token")
            .send()
            .await
            .expect("send request with production token");

        let response2 = client
            .get(&format!("{}/server2/test2", proxy_url))
            .header("Authorization", "Bearer staging-token")
            .send()
            .await
            .expect("send request with staging token");

        assert_eq!(response1.status(), reqwest::StatusCode::OK);
        assert_eq!(response2.status(), reqwest::StatusCode::OK);

        // Wait a bit for logs to be written
        thread::sleep(Duration::from_millis(200));

        let logs = proxy.take_process_output();

        // Requirement: O5, O7 - Verify final request completion logs contain required fields
        // Verify API key ids appear in final request logs as actual values (not wrapped in Some(...))
        // O7 requires logging actual values, not type constructors like Some(...)
        assert!(
            logs.contains("api_key=\"production-client\"")
                || logs.contains("api_key=production-client"),
            "expected production-client API key id in logs (as actual value per O7), got: {}",
            logs
        );
        assert!(
            logs.contains("api_key=\"staging-client\"") || logs.contains("api_key=staging-client"),
            "expected staging-client API key id in logs (as actual value per O7), got: {}",
            logs
        );
        // Requirement: O5 - Verify final request completion log is present
        assert!(
            logs.contains("Request processed"),
            "expected final request completion log, got: {}",
            logs
        );
        // Requirement: O5 - Verify intermediate logs are NOT present
        assert!(
            !logs.contains("Authentication successful"),
            "intermediate authentication log should not be present, got: {}",
            logs
        );
        assert!(
            !logs.contains("Upstream routing decision"),
            "intermediate routing decision log should not be present, got: {}",
            logs
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_process_starts_http_server() {
    // Preconditions: valid configuration file present and binary available.
    // Action: start the proxy with configuration.
    // Expected behaviour: proxy starts HTTP server and outputs listening message.

    let config_yaml = r#"
server:
  bind_address: "127.0.0.1:0"
  max_connections: 64

upstreams:
  request_timeout_ms: 1000
  default:
    target_url: "https://httpbin.org/"
    api_key: "test-key"
    request_path: "/test"
"#;

    let mut proxy = ProxyProcess::spawn(config_yaml);

    // Give the proxy a moment to start
    thread::sleep(Duration::from_millis(500));

    let logs = proxy.take_process_output();

    // Verify server attempted to start and logged correctly
    assert!(
        logs.contains("Fluxgate proxy initialized"),
        "expected proxy initialization, got: {}",
        logs
    );
    assert!(
        logs.contains("Starting proxy server on"),
        "expected server startup attempt, got: {}",
        logs
    );

    proxy.shutdown();
}

/// # Requirements: O4
///
/// Tests that binding failure is logged at WARNING level.
#[test]
fn proxy_logs_binding_failure_at_warning_level() {
    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Start first proxy on the port
        let config_yaml1 = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(5000))
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "test-key",
                "client-token",
                vec!["test-upstream".to_string()],
            ))
            .to_yaml();

        let mut proxy1 = ProxyProcess::spawn(&config_yaml1);
        proxy1.wait_for_ready(bind_addr, Duration::from_secs(2));

        // Wait a bit to ensure first proxy is fully bound
        thread::sleep(Duration::from_millis(200));

        // Attempt to start second proxy on the same port
        let config_yaml2 = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(5000))
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "test-key",
                "client-token",
                vec!["test-upstream".to_string()],
            ))
            .to_yaml();

        let mut proxy2 = ProxyProcess::spawn(&config_yaml2);

        // Wait for the second proxy to fail
        thread::sleep(Duration::from_millis(500));

        // Check that second proxy exited with error
        let exit_status = proxy2.wait_for_exit(Duration::from_secs(2));
        assert!(
            exit_status.is_some(),
            "second proxy should exit when binding fails"
        );

        // Get logs from second proxy
        let logs = proxy2.take_process_output();

        // Verify binding failure is logged at WARNING level (O4)
        assert!(
            logs.contains("WARN") || logs.contains("WARNING"),
            "expected WARNING level log for binding failure, got: {}",
            logs
        );
        assert!(
            logs.contains("Failed to bind to address"),
            "expected binding failure message in logs, got: {}",
            logs
        );
        // Check that the address appears in the log (either as structured field or in message)
        assert!(
            logs.contains(&format!("address={}", bind_addr))
                || logs.contains(&format!("address=\"{}\"", bind_addr))
                || logs.contains(&bind_addr.to_string()),
            "expected bind address in log message, got: {}",
            logs
        );

        proxy1.shutdown();
    });
}
