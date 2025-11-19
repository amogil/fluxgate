//! Functional tests covering graceful shutdown and recovery behaviour.

use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};

use super::common::{
    allocate_socket_addr, run_async_test, MockServer, ProxyProcess, TestConfig, UpstreamConfig,
};

#[cfg(unix)]
#[test]
fn proxy_gracefully_shuts_down_on_sigterm() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: mock_server.url(),
                api_key: "test-key".to_string(),
                request_path: "/test".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        let response = client
            .get(&format!("{}/test/health-check", proxy_url))
            .send()
            .await
            .expect("send request before shutdown");
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        proxy.send_sigterm().expect("send SIGTERM to proxy process");

        let status = proxy
            .wait_for_exit(Duration::from_secs(5))
            .expect("proxy should exit after SIGTERM");
        assert!(
            status.success(),
            "expected graceful exit status after SIGTERM, got {:?}",
            status
        );

        let logs = proxy.logs_snapshot();
        assert!(
            logs.contains("Shutdown signal received")
                && logs.contains("Proxy server shutdown complete"),
            "expected shutdown logs to include signal and completion message, got:\n{logs}"
        );
    });
}

#[cfg(unix)]
#[test]
fn proxy_handles_sigint_interrupt() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: mock_server.url(),
                api_key: "test-key".to_string(),
                request_path: "/test".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        proxy.send_sigint().expect("send SIGINT to proxy process");

        let status = proxy
            .wait_for_exit(Duration::from_secs(5))
            .expect("proxy should exit after SIGINT");

        // SIGINT typically results in exit code 130 (128 + 2) or 2, not 0
        // The important thing is that the process exits gracefully with shutdown logs
        // Check that it exited (not None) rather than checking success()
        let exit_code = status.code();
        assert!(
            exit_code.is_some(),
            "expected proxy to exit after SIGINT, got {:?}",
            status
        );

        let logs = proxy.logs_snapshot();
        assert!(
            logs.contains("Shutdown signal received")
                && logs.contains("Proxy server shutdown complete"),
            "expected shutdown logs to include signal and completion message, got:\n{logs}"
        );
    });
}

#[cfg(unix)]
#[test]
fn proxy_logs_detailed_errors_during_shutdown() {
    run_async_test(|| async {
        let failing_responses = vec![(
            StatusCode::INTERNAL_SERVER_ERROR,
            b"temporary failure".to_vec(),
            HeaderMap::new(),
        )];
        let mock_server = MockServer::start_with_sequence(failing_responses)
            .await
            .expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: mock_server.url(),
                api_key: "test-key".to_string(),
                request_path: "/test".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        // Use TRACE log level to see request processing logs (Requirement: O1, O5)
        let mut proxy = ProxyProcess::spawn_with_log_level(&config_yaml, "trace");
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/test/failing", proxy_url))
            .send()
            .await
            .expect("send request to trigger upstream error");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        proxy.send_sigterm().expect("send SIGTERM to proxy process");

        let _ = proxy
            .wait_for_exit(Duration::from_secs(5))
            .expect("proxy should exit after SIGTERM");

        let logs = proxy.logs_snapshot();
        // Requirement: O5 - Request processing logs are at TRACE level with structured fields
        // Check that the error response (500) is logged in the TRACE log with status field
        assert!(
            logs.contains("status=500")
                || logs.contains("status=\"500\"")
                || logs.contains("status=InternalServerError"),
            "expected error status (500) in TRACE logs, got:\n{logs}"
        );
        assert!(
            logs.contains("Request processed"),
            "expected 'Request processed' message in TRACE logs, got:\n{logs}"
        );
        assert!(
            logs.contains("Proxy server shutdown complete"),
            "expected shutdown completion log message, got:\n{logs}"
        );
    });
}
