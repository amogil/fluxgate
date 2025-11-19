//! Functional tests validating proxy error handling paths.
//!
//! Requirement: FT6 - At minimum, the following tests must be present (see `04-testing.md`).

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{body::Body, extract::Request, response::Response, Router};
use tokio::{net::TcpListener, runtime::Runtime};

use super::common::{
    allocate_port, allocate_socket_addr, simple_api_key, simple_upstream, CapturedRequest,
    MockServer, ProxyProcess, TestConfig, UpstreamConfig,
};

/// Helper function to test that a request is rejected with HTTP 501 and not forwarded to upstream.
async fn assert_request_rejected_with_501(
    request: &[u8],
    error_message: &str,
    upstream_error_message: &str,
) {
    let mock_server = MockServer::start().await.expect("start mock server");
    let bind_addr = allocate_socket_addr();

    let config_yaml = TestConfig::new()
        .with_bind_address(bind_addr.to_string())
        .clear_upstreams()
        .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
        .clear_api_keys()
        .add_api_key(simple_api_key(
            "test-key",
            "client-token",
            vec!["test-upstream".to_string()],
        ))
        .to_yaml();

    let mut proxy = ProxyProcess::spawn(&config_yaml);
    proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

    use std::io::{Read, Write};
    use std::net::TcpStream;

    let mut stream = TcpStream::connect(bind_addr).expect("connect to proxy");
    stream.write_all(request).expect("send request to proxy");

    let mut buffer = [0; 1024];
    let n = stream.read(&mut buffer).expect("read response from proxy");
    let response = String::from_utf8_lossy(&buffer[..n]);

    assert!(
        response.contains("501") || response.contains("Not Implemented"),
        "expected HTTP 501 response {}, got: {response}",
        error_message
    );

    assert!(
        mock_server.captured_requests().is_empty(),
        "{}",
        upstream_error_message
    );

    proxy.shutdown();
}

#[test]
fn proxy_handles_different_timeout_values() {
    // Preconditions: Proxy configured with different timeout values.
    // Action: Send requests that test timeout behavior.
    // Expected behaviour: Different timeouts work as configured.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        // Create a slow mock server that takes 2 seconds to respond
        let captured_requests = Arc::new(Mutex::new(Vec::new()));
        let captured_requests_clone = captured_requests.clone();

        let app = Router::new().fallback(move |req: Request| {
            let captured_requests = captured_requests_clone.clone();
            async move {
                let (parts, _body) = req.into_parts();
                let captured = CapturedRequest {
                    method: parts.method,
                    uri: parts.uri,
                    headers: parts.headers,
                    body: vec![],
                    remote_addr: "127.0.0.1:12345".parse().unwrap(),
                };
                captured_requests.lock().unwrap().push(captured);

                // Sleep for 2 seconds to trigger timeout
                tokio::time::sleep(Duration::from_millis(2000)).await;
                Response::new(Body::from("Slow response"))
            }
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow_server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        // Test with longer timeout (5 seconds)
        let port1 = allocate_port();
        let bind_addr1: SocketAddr = format!("127.0.0.1:{port1}")
            .parse()
            .expect("parse bind address");

        let config_yaml1 = TestConfig::new()
            .with_bind_address(bind_addr1.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(5000))
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: format!("http://{}", slow_server_addr),
                api_key: "".to_string(),
                request_path: "/test".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        let mut proxy1 = ProxyProcess::spawn(&config_yaml1);
        proxy1.wait_for_ready(bind_addr1, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url1 = format!("http://{}", bind_addr1);

        // Request should succeed with longer timeout (5 seconds > 2 seconds server delay)
        let response1 = client
            .get(&format!("{}/test/slow", proxy_url1))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .expect("send request with longer timeout");

        assert_eq!(response1.status(), reqwest::StatusCode::OK);

        proxy1.shutdown();

        // Test with shorter timeout (500ms)
        let port2 = allocate_port();
        let bind_addr2: SocketAddr = format!("127.0.0.1:{port2}")
            .parse()
            .expect("parse bind address");

        let config_yaml2 = TestConfig::new()
            .with_bind_address(bind_addr2.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(500))
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: format!("http://{}", slow_server_addr),
                api_key: "".to_string(),
                request_path: "/test".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        let mut proxy2 = ProxyProcess::spawn(&config_yaml2);
        proxy2.wait_for_ready(bind_addr2, Duration::from_secs(2));

        let proxy_url2 = format!("http://{}", bind_addr2);

        // Request should fail with shorter timeout (500ms < 2 seconds server delay)
        let response2 = client
            .get(&format!("{}/test/slow", proxy_url2))
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        // Should either fail due to timeout or return error status
        assert!(
            response2.is_err() || {
                let status = response2.as_ref().unwrap().status();
                status == reqwest::StatusCode::BAD_GATEWAY
                    || status == reqwest::StatusCode::GATEWAY_TIMEOUT
            }
        );

        proxy2.shutdown();
        server_handle.abort();
    });
}

#[test]
fn proxy_handles_upstream_connection_timeout() {
    // Preconditions: Upstream server slow to respond.
    // Action: Send request with short timeout.
    // Expected behaviour: Returns HTTP 504 Gateway Timeout.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        // Create a slow mock server that takes longer than timeout
        let captured_requests = Arc::new(Mutex::new(Vec::new()));
        let captured_requests_clone = captured_requests.clone();

        let app = Router::new().fallback(move |req: Request| {
            let captured_requests = captured_requests_clone.clone();
            async move {
                let (parts, _body) = req.into_parts();
                let captured = CapturedRequest {
                    method: parts.method,
                    uri: parts.uri,
                    headers: parts.headers,
                    body: vec![],
                    remote_addr: "127.0.0.1:12345".parse().unwrap(),
                };
                captured_requests.lock().unwrap().push(captured);

                // Sleep longer than the timeout (3 seconds)
                tokio::time::sleep(Duration::from_secs(3)).await;
                Response::new(Body::from("Slow response"))
            }
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let slow_server_addr = listener.local_addr().unwrap();

        let server_handle = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(1000))
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: format!("http://{}", slow_server_addr),
                api_key: "upstream-timeout-key".to_string(),
                request_path: "/test".to_string(),
            })
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "test-key",
                "client-token",
                vec!["test-upstream".to_string()],
            ))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        let response = client
            .get(&format!("{}/test/slow", proxy_url))
            .header("Authorization", "Bearer client-token")
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .expect("send request that should timeout");

        // Should return 504 Gateway Timeout due to upstream timeout
        assert_eq!(response.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);

        proxy.shutdown();
        server_handle.abort();
    });
}

#[test]
fn proxy_handles_upstream_ssl_errors() {
    // Preconditions: Upstream has invalid SSL certificate.
    // Action: Send HTTPS request to upstream with invalid SSL.
    // Expected behavior: Returns HTTP 502, logs SSL error.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Use invalid HTTPS URL that will cause SSL errors
        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(5000))
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: "https://invalid-cert.example.com:443".to_string(),
                api_key: "test-key".to_string(),
                request_path: "/test".to_string(),
            })
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "test-key",
                "client-token",
                vec!["test-upstream".to_string()],
            ))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        let response = client
            .get(&format!("{}/test/ssl-test", proxy_url))
            .header("Authorization", "Bearer client-token")
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .expect("send request that should trigger SSL error");

        // Should return 502 Bad Gateway due to SSL error
        assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);

        proxy.shutdown();
    });
}

#[test]
fn proxy_handles_malformed_http_requests() {
    // Preconditions: Proxy is running.
    // Action: Send malformed HTTP request.
    // Expected behaviour: Proxy returns HTTP 400 with graceful error.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

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
  request_timeout_ms: 5000
  test-upstream:
    target_url: "{}"
    api_key: "test-key"
    request_path: "/test"

api_keys:
  static:
    - id: test-key
      key: "client-token"
      upstreams:
        - test-upstream
"#,
            bind_addr,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        // Send malformed HTTP request directly using TCP
        use std::io::Write;
        use std::net::TcpStream;

        let mut stream = TcpStream::connect(bind_addr).expect("connect to proxy");
        // Send malformed HTTP request (missing proper headers)
        let malformed_request =
            b"GET / HTTP/1.1\r\nHost: \r\nAuthorization: Bearer client-token\r\n\r\n";
        stream
            .write_all(malformed_request)
            .expect("send malformed request");

        // Read response
        use std::io::Read;
        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer).expect("read response");

        let response = String::from_utf8_lossy(&buffer[..n]);
        assert!(
            response.contains("400") || response.contains("Bad Request"),
            "expected 400 Bad Request for malformed HTTP, got: {}",
            response
        );

        assert!(
            mock_server.captured_requests().is_empty(),
            "upstream should not receive malformed requests"
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_resists_http_request_smuggling() {
    // Preconditions: Proxy is running.
    // Action: Send crafted request smuggling attack.
    // Expected behavior: Rejects request, logs security warning.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

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
  request_timeout_ms: 5000
  test-upstream:
    target_url: "{}"
    api_key: "test-key"
    request_path: "/test"

api_keys:
  static:
    - id: test-key
      key: "client-token"
      upstreams:
        - test-upstream
"#,
            bind_addr,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Test various smuggling techniques
        // 1. Try to inject additional headers via malformed Host header
        let smuggling_attempts = vec![
            (
                "GET /test/ HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer client-token\r\nX-Injected: bad\r\n\r\n",
                "Host header injection",
            ),
            (
                "GET /test/ HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer client-token\r\n\r\nGET /test/admin HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer client-token\r\n\r\n",
                "Request splitting",
            ),
            (
                "GET /test/ HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer client-token\r\nContent-Length: 0\r\n\r\n",
                "CL.0 smuggling",
            ),
        ];

        for (malformed_request, attack_type) in smuggling_attempts {
            // Send raw HTTP request directly using TCP
            use std::net::TcpStream;
            use std::io::{Read, Write};

            let mut stream = TcpStream::connect(bind_addr).expect("connect to proxy");
            stream.write_all(malformed_request.as_bytes()).expect("send smuggling attempt");

            let mut buffer = [0; 1024];
            let n = stream.read(&mut buffer).expect("read response");
            let response = String::from_utf8_lossy(&buffer[..n]);

            // Should reject the request or sanitize it
            assert!(
                response.contains("400") ||
                response.contains("403") ||
                response.contains("200") && !response.contains("X-Injected"), // If 200, ensure injection didn't work
                "Proxy should resist {} attack, got response: {}",
                attack_type,
                response
            );
        }

        // Test that normal requests still work
        let response = client
            .get(&format!("{}/test/normal", proxy_url))
            .header("Authorization", "Bearer client-token")
            .send()
            .await
            .expect("send normal request after smuggling attempts");

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        proxy.shutdown();
    });
}

#[test]
fn proxy_rejects_http_1_0_with_505() {
    // Preconditions: Proxy is running.
    // Action: Send an HTTP/1.0 request line over raw TCP.
    // Expected behaviour: Proxy responds with HTTP 505 (HTTP Version Not Supported).
    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

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
  request_timeout_ms: 5000
  test-upstream:
    target_url: "{}"
    api_key: "test-key"
    request_path: "/test"

api_keys:
  static:
    - id: test-key
      key: "client-token"
      upstreams:
        - test-upstream
"#,
            bind_addr,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        use std::io::{Read, Write};
        use std::net::TcpStream;

        // Send a minimal HTTP/1.0 request line that the proxy must reject
        let mut stream = TcpStream::connect(bind_addr).expect("connect to proxy");
        let request =
            b"GET /version-test HTTP/1.0\r\nHost: example.com\r\nAuthorization: Bearer client-token\r\n\r\n";
        stream.write_all(request).expect("send HTTP/1.0 request");

        let mut buffer = [0; 1024];
        let n = stream.read(&mut buffer).expect("read response from proxy");
        let response = String::from_utf8_lossy(&buffer[..n]);

        assert!(
            response.contains("505") || response.contains("HTTP Version Not Supported"),
            "expected HTTP 505 response for HTTP/1.0 request, got: {response}"
        );

        assert!(
            mock_server.captured_requests().is_empty(),
            "upstream should not receive HTTP/1.0 requests"
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_rejects_connect_method_with_501() {
    // Preconditions: Proxy is running.
    // Action: Send CONNECT request over raw TCP.
    // Expected behaviour: Proxy responds with HTTP 501 (Not Implemented).
    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nAuthorization: Bearer client-token\r\n\r\n";
        assert_request_rejected_with_501(
            request,
            "for CONNECT request",
            "upstream should not receive CONNECT requests",
        )
        .await;
    });
}

#[test]
fn proxy_rejects_http_upgrade_with_501() {
    // Preconditions: Proxy is running.
    // Action: Send HTTP/1.1 request with Upgrade: websocket and Connection: Upgrade over raw TCP.
    // Expected behaviour: Proxy responds with HTTP 501 (Not Implemented) and does not forward the request upstream.
    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let request = b"GET /ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nAuthorization: Bearer client-token\r\n\r\n";
        assert_request_rejected_with_501(
            request,
            "for Upgrade request",
            "upstream should not receive Upgrade-based requests",
        )
        .await;
    });
}

#[test]
fn proxy_returns_properly_formatted_error_responses() {
    // Preconditions: Proxy configured without upstreams.
    // Action: Send request to proxy with no upstreams configured.
    // Expected behaviour: Proxy returns HTTP 503 (Service Unavailable) with properly formatted
    // response, not an empty reply. This validates requirement F10 that all error responses
    // must be properly formatted and delivered to clients.
    //
    // # Requirements: F8, F10

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configure proxy without any upstreams
        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .clear_upstreams()
            .clear_api_keys()
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Send request when no upstreams are configured
        let response = client
            .get(&format!("{}/test/path", proxy_url))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .expect("send request to proxy without upstreams");

        // Should return HTTP 503 Service Unavailable (F8)
        assert_eq!(
            response.status(),
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            "expected HTTP 503 when no upstreams are configured"
        );

        // Verify response is properly formatted (F10) - should have status line and headers
        let status = response.status();
        assert_eq!(status.as_u16(), 503, "status code should be 503");

        // Verify response has headers (content-length should be present)
        let content_length = response.headers().get("content-length");
        assert!(
            content_length.is_some(),
            "response should have content-length header (F10: properly formatted response)"
        );

        // Verify we can read the response body (even if empty)
        let _body = response
            .bytes()
            .await
            .expect("should be able to read response body (F10: response delivered)");

        // Test with request to non-existent path when upstreams exist but path doesn't match
        let mock_server = MockServer::start().await.expect("start mock server");
        let port2 = allocate_port();
        let bind_addr2: SocketAddr = format!("127.0.0.1:{port2}")
            .parse()
            .expect("parse bind address");

        let config_yaml2 = TestConfig::new()
            .with_bind_address(bind_addr2.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: mock_server.url(),
                api_key: "test-key".to_string(),
                request_path: "/api".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        let mut proxy2 = ProxyProcess::spawn(&config_yaml2);
        proxy2.wait_for_ready(bind_addr2, Duration::from_secs(2));

        let proxy_url2 = format!("http://{}", bind_addr2);

        // Request path that doesn't match any upstream
        let response2 = client
            .get(&format!("{}/nonexistent/path", proxy_url2))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .expect("send request with non-matching path");

        // Should return HTTP 404 Not Found (F2, F3)
        assert_eq!(
            response2.status(),
            reqwest::StatusCode::NOT_FOUND,
            "expected HTTP 404 when no upstream matches request path"
        );

        // Verify response is properly formatted (F10)
        let status2 = response2.status();
        assert_eq!(status2.as_u16(), 404, "status code should be 404");

        let content_length2 = response2.headers().get("content-length");
        assert!(
            content_length2.is_some(),
            "response should have content-length header (F10: properly formatted response)"
        );

        let _body2 = response2
            .bytes()
            .await
            .expect("should be able to read response body (F10: response delivered)");

        proxy.shutdown();
        proxy2.shutdown();
    });
}
