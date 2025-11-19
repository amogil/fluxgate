//! Functional tests covering request forwarding and proxy behaviours.

use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use reqwest::Url;

use super::common::{
    allocate_port, allocate_socket_addr, run_async_test, MockServer, ProxyProcess, TestConfig,
    UpstreamConfig,
};

#[test]
fn proxy_forwards_requests_transparently() {
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
            .get(&format!("{}/test/api/test?param=value", proxy_url))
            .header("X-Custom-Header", "test-value")
            .header("User-Agent", "test-client")
            .send()
            .await
            .expect("send GET request through proxy");

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let captured = mock_server.captured_requests();
        assert_eq!(captured.len(), 1);

        let req = &captured[0];
        assert_eq!(req.method, reqwest::Method::GET);
        assert_eq!(req.uri.path(), "/api/test");
        assert_eq!(req.uri.query(), Some("param=value"));
        assert_eq!(
            req.headers
                .get("x-custom-header")
                .and_then(|value| value.to_str().ok()),
            Some("test-value")
        );
        assert_eq!(
            req.headers
                .get("user-agent")
                .and_then(|value| value.to_str().ok()),
            Some("test-client")
        );
        assert_eq!(
            req.headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer test-key"),
            "expected proxy to inject upstream API key"
        );

        let post_body = r#"{"test": "data", "number": 42}"#;
        let response = client
            .post(&format!("{}/test/api/submit", proxy_url))
            .header("Content-Type", "application/json")
            .body(post_body)
            .send()
            .await
            .expect("send POST request through proxy");

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let captured = mock_server.captured_requests();
        assert_eq!(captured.len(), 2);

        let req = &captured[1];
        assert_eq!(req.method, reqwest::Method::POST);
        assert_eq!(req.uri.path(), "/api/submit");
        assert_eq!(String::from_utf8_lossy(&req.body), post_body);
        assert_eq!(
            req.headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json")
        );
        assert_eq!(
            req.headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer test-key"),
            "expected proxy to inject authentication header for POST requests"
        );

        let _ = client
            .get(&format!("{}/test/api/final", proxy_url))
            .header("Connection", "keep-alive")
            .header("Proxy-Authenticate", "test")
            .header("Transfer-Encoding", "chunked")
            .send()
            .await
            .expect("send request with hop-by-hop headers");

        let captured = mock_server.captured_requests();
        assert_eq!(captured.len(), 3);

        let req = &captured[2];
        assert!(
            !req.headers.contains_key("connection"),
            "connection header must be stripped"
        );
        assert!(
            !req.headers.contains_key("proxy-authenticate"),
            "proxy-authenticate header must be stripped"
        );
        assert!(
            !req.headers.contains_key("transfer-encoding"),
            "transfer-encoding header must be stripped"
        );
        assert_eq!(
            req.headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer test-key")
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_preserves_request_fields_except_authorization_and_host() {
    run_async_test(|| async {
        let mock_server = MockServer::start()
            .await
            .expect("start mock server for field preservation test");
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: mock_server.url(),
                api_key: "proxy-api-key".to_string(),
                request_path: "/test".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let body = r#"{"payload": "unchanged"}"#;

        let response = client
            .request(
                reqwest::Method::PATCH,
                &format!("{}/test/v1/resource?id=42", proxy_url),
            )
            .header("Content-Type", "application/json")
            .header("X-Client-Trace", "trace-abc")
            .header("X-Request-ID", "req-123")
            .header("Authorization", "Bearer client-token")
            .header("Host", "client-host.example.com")
            .body(body.to_string())
            .send()
            .await
            .expect("send PATCH request through proxy");

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let captured = mock_server.captured_requests();
        assert_eq!(captured.len(), 1, "upstream should receive single request");

        let forwarded = &captured[0];
        assert_eq!(forwarded.method, reqwest::Method::PATCH);
        assert_eq!(forwarded.uri.path(), "/v1/resource");
        assert_eq!(
            forwarded.uri.query(),
            Some("id=42"),
            "query parameters must remain unchanged"
        );
        assert_eq!(
            String::from_utf8_lossy(&forwarded.body),
            body,
            "request body must remain byte-for-byte identical"
        );
        assert_eq!(
            forwarded
                .headers
                .get("x-client-trace")
                .and_then(|value| value.to_str().ok()),
            Some("trace-abc"),
            "custom headers must be preserved"
        );
        assert_eq!(
            forwarded
                .headers
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("req-123"),
            "custom headers must be preserved"
        );
        assert_eq!(
            forwarded
                .headers
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/json"),
            "content-type must remain unchanged"
        );
        assert_eq!(
            forwarded
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok()),
            Some("Bearer proxy-api-key"),
            "proxy must rewrite Authorization header using configured API key"
        );
        // Verify Host header is set from upstream target URL
        let upstream_url = Url::parse(&mock_server.url()).unwrap();
        let expected_host = upstream_url.host_str().unwrap();
        let host_header = forwarded
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .expect("Host header must be present in upstream request");
        if let Some(port) = upstream_url.port() {
            assert_eq!(
                host_header,
                format!("{}:{}", expected_host, port),
                "Host header must be set to upstream target URL with explicit port"
            );
        } else {
            let scheme = upstream_url.scheme();
            let default_port = match scheme {
                "https" => 443,
                "http" => 80,
                _ => 80,
            };
            match upstream_url.port_or_known_default() {
                Some(actual_port) if actual_port != default_port => {
                    assert_eq!(
                        host_header,
                        format!("{}:{}", expected_host, actual_port),
                        "Host header must include non-standard port"
                    );
                }
                _ => {
                    assert_eq!(
                        host_header, expected_host,
                        "Host header must be set to upstream target URL without standard port"
                    );
                }
            }
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_handles_upstream_errors() {
    run_async_test(|| async {
        let mock_server = MockServer::start_with(
            StatusCode::INTERNAL_SERVER_ERROR,
            b"Internal Server Error".to_vec(),
        )
        .await
        .expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: mock_server.url(),
                api_key: "".to_string(),
                request_path: "/test".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/test/error", proxy_url))
            .send()
            .await
            .expect("send request through proxy");

        assert_eq!(
            response.status(),
            reqwest::StatusCode::INTERNAL_SERVER_ERROR
        );

        let captured = mock_server.captured_requests();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].uri.path(), "/error");

        proxy.shutdown();
    });
}

#[test]
fn proxy_handles_invalid_requests() {
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
        let large_body = vec![b'x'; 11 * 1024 * 1024];

        let result = client
            .post(&format!("{}/test/test", proxy_url))
            .body(large_body)
            .send()
            .await;

        let captured = mock_server.captured_requests();
        match result {
            Ok(response) => {
                let status = response.status();
                assert!(
                    status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                        || status == reqwest::StatusCode::PAYLOAD_TOO_LARGE
                        || status == reqwest::StatusCode::BAD_REQUEST
                        || status == reqwest::StatusCode::BAD_GATEWAY
                        || status == reqwest::StatusCode::OK,
                    "unexpected status for oversized request: {status}"
                );
                if status == reqwest::StatusCode::OK {
                    assert!(
                        !captured.is_empty(),
                        "when request succeeds, upstream should receive it"
                    );
                }
            }
            Err(err) => {
                assert!(
                    err.is_request(),
                    "expected request error when sending oversized payload, got {err}"
                );
            }
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_omits_authorization_when_api_key_missing() {
    run_async_test(|| async {
        let mock_server = MockServer::start()
            .await
            .expect("start mock server without API key");
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: mock_server.url(),
                api_key: "".to_string(),
                request_path: "/test".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        let response = client
            .get(&format!("{}/test/no-auth", proxy_url))
            .send()
            .await
            .expect("send request through proxy without API key");

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let captured = mock_server.captured_requests();
        assert_eq!(captured.len(), 1);
        assert!(
            !captured[0].headers.contains_key("authorization"),
            "proxy must not inject Authorization header when API key is absent"
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_returns_bad_gateway_when_upstream_unreachable() {
    run_async_test(|| async {
        let unreachable_port = allocate_port();
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: format!("http://127.0.0.1:{}", unreachable_port),
                api_key: "".to_string(),
                request_path: "/test".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/test/unreachable", proxy_url))
            .send()
            .await
            .expect("send request to unreachable upstream");

        assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);

        proxy.shutdown();
    });
}

#[test]
fn proxy_forwards_upstream_response_headers() {
    run_async_test(|| async {
        let mut headers = HeaderMap::new();
        headers.insert("x-upstream-trace", HeaderValue::from_static("trace-123"));

        let mock_server = MockServer::start_with_headers(StatusCode::OK, b"OK".to_vec(), headers)
            .await
            .expect("start mock server with custom headers");
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
            .get(&format!("{}/test/headers", proxy_url))
            .send()
            .await
            .expect("send request through proxy");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let headers = response.headers();

        assert_eq!(
            headers
                .get("x-upstream-trace")
                .and_then(|value| value.to_str().ok()),
            Some("trace-123"),
            "proxy must forward custom upstream headers"
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_sets_host_header_from_upstream_target_url() {
    // Precondition: Proxy with upstream configured with target URL.
    // Action: Send request through proxy to upstream.
    // Expected behaviour: Host header in upstream request is set to value derived from upstream's target URL.
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

        // Send request with a different Host header to verify it's replaced
        let response = client
            .get(&format!("{}/test/api/test", proxy_url))
            .header("Host", "client-host.example.com")
            .send()
            .await
            .expect("send GET request through proxy");

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let captured = mock_server.captured_requests();
        assert_eq!(captured.len(), 1);

        let req = &captured[0];
        // Extract host and port from mock_server.url() for comparison
        let upstream_url = Url::parse(&mock_server.url()).unwrap();
        let expected_host = upstream_url.host_str().unwrap();
        let expected_port = upstream_url.port();

        let host_header = req
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .expect("Host header must be present in upstream request");

        if let Some(port) = expected_port {
            assert_eq!(
                host_header,
                format!("{}:{}", expected_host, port),
                "Host header must be set to upstream target URL with explicit port"
            );
        } else {
            // Check if it's a non-standard port
            let scheme = upstream_url.scheme();
            let default_port = match scheme {
                "https" => 443,
                "http" => 80,
                _ => 80,
            };
            match upstream_url.port_or_known_default() {
                Some(actual_port) if actual_port != default_port => {
                    assert_eq!(
                        host_header,
                        format!("{}:{}", expected_host, actual_port),
                        "Host header must include non-standard port"
                    );
                }
                _ => {
                    assert_eq!(
                        host_header, expected_host,
                        "Host header must be set to upstream target URL without standard port"
                    );
                }
            }
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_sets_host_header_with_non_standard_port() {
    // Precondition: Proxy with upstream configured with non-standard port.
    // Action: Send request through proxy to upstream with non-standard port.
    // Expected behaviour: Host header includes port number when upstream uses non-standard port.
    run_async_test(|| async {
        let non_standard_port = allocate_port();
        let mock_server = MockServer::start_with_sequence_at(
            Some(format!("127.0.0.1:{}", non_standard_port).parse().unwrap()),
            vec![(StatusCode::OK, b"OK".to_vec(), HeaderMap::new())],
        )
        .await
        .expect("start mock server on non-standard port");

        let bind_addr = allocate_socket_addr();
        let upstream_url = format!("http://127.0.0.1:{}", non_standard_port);

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: upstream_url.clone(),
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
            .get(&format!("{}/test/api/test", proxy_url))
            .send()
            .await
            .expect("send GET request through proxy");

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let captured = mock_server.captured_requests();
        assert_eq!(captured.len(), 1);

        let req = &captured[0];
        let host_header = req
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .expect("Host header must be present in upstream request");

        assert_eq!(
            host_header,
            format!("127.0.0.1:{}", non_standard_port),
            "Host header must include non-standard port number"
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_routes_requests_by_request_path() {
    // Preconditions: Proxy with multiple upstreams with different request_path values.
    // Action: Send request matching request_path.
    // Expected behaviour: Request routed to correct upstream based on path.
    run_async_test(|| async {
        let upstream1 = MockServer::start().await.expect("start upstream1");
        let upstream2 = MockServer::start().await.expect("start upstream2");
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "openai".to_string(),
                target_url: upstream1.url(),
                api_key: "key1".to_string(),
                request_path: "/openai".to_string(),
            })
            .add_upstream(UpstreamConfig {
                name: "anthropic".to_string(),
                target_url: upstream2.url(),
                api_key: "key2".to_string(),
                request_path: "/anthropic".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Send request to /openai path
        let response1 = client
            .get(&format!("{}/openai/v1/models", proxy_url))
            .send()
            .await
            .expect("send request to /openai");
        assert_eq!(response1.status(), StatusCode::OK);

        // Send request to /anthropic path
        let response2 = client
            .get(&format!("{}/anthropic/v1/messages", proxy_url))
            .send()
            .await
            .expect("send request to /anthropic");
        assert_eq!(response2.status(), StatusCode::OK);

        // Verify requests were routed correctly
        let upstream1_requests = upstream1.captured_requests();
        let upstream2_requests = upstream2.captured_requests();

        assert_eq!(
            upstream1_requests.len(),
            1,
            "upstream1 should receive /openai request"
        );
        assert_eq!(
            upstream1_requests[0].uri.path(),
            "/v1/models",
            "upstream1 should receive correct path"
        );

        assert_eq!(
            upstream2_requests.len(),
            1,
            "upstream2 should receive /anthropic request"
        );
        assert_eq!(
            upstream2_requests[0].uri.path(),
            "/v1/messages",
            "upstream2 should receive correct path"
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_selects_longest_matching_request_path() {
    // Preconditions: Proxy with overlapping request_path values.
    // Action: Send request matching multiple paths.
    // Expected behaviour: Request routed to upstream with longest matching path.
    run_async_test(|| async {
        let upstream1 = MockServer::start().await.expect("start upstream1");
        let upstream2 = MockServer::start().await.expect("start upstream2");
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "api".to_string(),
                target_url: upstream1.url(),
                api_key: "key1".to_string(),
                request_path: "/api".to_string(),
            })
            .add_upstream(UpstreamConfig {
                name: "api-v1".to_string(),
                target_url: upstream2.url(),
                api_key: "key2".to_string(),
                request_path: "/api/v1".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Send request to /api/v1/models - should match /api/v1 (longest)
        let response = client
            .get(&format!("{}/api/v1/models", proxy_url))
            .send()
            .await
            .expect("send request to /api/v1/models");
        assert_eq!(response.status(), StatusCode::OK);

        // Verify request was routed to upstream with longest matching path
        let upstream1_requests = upstream1.captured_requests();
        let upstream2_requests = upstream2.captured_requests();

        assert_eq!(
            upstream1_requests.len(),
            0,
            "upstream1 should not receive request (shorter path)"
        );
        assert_eq!(
            upstream2_requests.len(),
            1,
            "upstream2 should receive request (longest matching path)"
        );
        assert_eq!(
            upstream2_requests[0].uri.path(),
            "/models",
            "upstream2 should receive correct path"
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_returns_404_when_no_request_path_matches() {
    // Preconditions: Proxy with upstreams configured.
    // Action: Send request with path not matching any request_path.
    // Expected behaviour: HTTP 404 returned.
    run_async_test(|| async {
        let upstream = MockServer::start().await.expect("start upstream");
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: upstream.url(),
                api_key: "test-key".to_string(),
                request_path: "/api".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Send request to path that doesn't match any request_path
        let response = client
            .get(&format!("{}/unknown/path", proxy_url))
            .send()
            .await
            .expect("send request to unmatched path");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // Verify upstream did not receive the request
        let upstream_requests = upstream.captured_requests();
        assert_eq!(
            upstream_requests.len(),
            0,
            "upstream should not receive unmatched request"
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_handles_trailing_slash_in_request_path_matching() {
    // Preconditions: Proxy with request_path="/api".
    // Action: Send request to /api/.
    // Expected behaviour: Request routed correctly, original path preserved when forwarding.
    run_async_test(|| async {
        let upstream = MockServer::start().await.expect("start upstream");
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "test-upstream".to_string(),
                target_url: upstream.url(),
                api_key: "test-key".to_string(),
                request_path: "/api".to_string(),
            })
            .clear_api_keys()
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Send request to /api/ (with trailing slash)
        let response = client
            .get(&format!("{}/api/", proxy_url))
            .send()
            .await
            .expect("send request to /api/");
        assert_eq!(response.status(), StatusCode::OK);

        // Verify request was routed correctly
        let upstream_requests = upstream.captured_requests();
        assert_eq!(
            upstream_requests.len(),
            1,
            "upstream should receive request"
        );
        // When request_path is /api and request is /api/, upstream receives /
        assert_eq!(
            upstream_requests[0].uri.path(),
            "/",
            "upstream should receive root path"
        );

        // Also test /api/endpoint
        upstream.clear_captured();
        let response2 = client
            .get(&format!("{}/api/endpoint", proxy_url))
            .send()
            .await
            .expect("send request to /api/endpoint");
        assert_eq!(response2.status(), StatusCode::OK);

        let upstream_requests2 = upstream.captured_requests();
        assert_eq!(
            upstream_requests2.len(),
            1,
            "upstream should receive request"
        );
        assert_eq!(
            upstream_requests2[0].uri.path(),
            "/endpoint",
            "upstream should receive correct path"
        );

        proxy.shutdown();
    });
}
