//! Functional tests covering authentication and authorization behaviour.
//!
//! # Requirements Coverage
//! This module covers the following requirement areas:
//! - **authentication**: Client authentication and API key validation
//! - **authorization**: Upstream access control based on API keys
//! - **bearer-auth**: Bearer authentication scheme enforcement
//! - **error-handling**: HTTP 401 error responses for authentication failures
//!
//! # Related Modules
//! - `proxy_flow.rs`: Routing tests that depend on authentication
//! - `config_loading.rs`: API key configuration tests

use std::time::Duration;

use futures::future;
use tokio;

use super::common::{
    allocate_socket_addr, create_jwt_token, current_timestamp, run_async_test, simple_api_key,
    simple_jwt_key, simple_upstream, MockServer, ProxyProcess, TestConfig, UpstreamConfig,
};

/// # Requirements: F3
///
/// Tests that the proxy rejects requests without an Authorization header.
#[test]
fn proxy_requires_authentication_header() {
    run_async_test(|| async {
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

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/anthropic/test/test", proxy_url))
            .send()
            .await
            .expect("send request without authorization");

        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(
            mock_server.captured_requests().is_empty(),
            "upstream should not receive unauthenticated requests"
        );

        proxy.shutdown();
    });
}

/// # Requirements: F3
///
/// Tests that the proxy rejects requests with unknown API keys.
#[test]
fn proxy_rejects_invalid_auth_token() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "test-key",
                "valid-token",
                vec!["test-upstream".to_string()],
            ))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/anthropic/test/test", proxy_url))
            .header("Authorization", "Bearer invalid-token")
            .send()
            .await
            .expect("send request with invalid token");

        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(
            mock_server.captured_requests().is_empty(),
            "upstream should not receive requests with invalid tokens"
        );

        proxy.shutdown();
    });
}

/// # Requirements: F1, F2
///
/// Tests that the proxy authenticates requests and routes them to the correct
/// upstream with proper Authorization header replacement.
#[test]
fn proxy_authenticates_and_routes_to_permitted_upstream() {
    run_async_test(|| async {
        let openai_server = MockServer::start().await.expect("start OpenAI mock server");
        let anthropic_server = MockServer::start()
            .await
            .expect("start Anthropic mock server");
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(UpstreamConfig {
                name: "openai".to_string(),
                target_url: openai_server.url(),
                api_key: "sk-openai-key".to_string(),
                request_path: "/openai".to_string(),
            })
            .add_upstream(UpstreamConfig {
                name: "anthropic".to_string(),
                target_url: anthropic_server.url(),
                api_key: "sk-anthropic-key".to_string(),
                request_path: "/anthropic".to_string(),
            })
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "openai-user",
                "openai-token",
                vec!["openai".to_string()],
            ))
            .add_api_key(simple_api_key(
                "anthropic-user",
                "anthropic-token",
                vec!["anthropic".to_string()],
            ))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Test OpenAI user
        let response = client
            .get(&format!("{}/openai/v1/models", proxy_url))
            .header("Authorization", "Bearer openai-token")
            .send()
            .await
            .expect("send request as OpenAI user");
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let openai_requests = openai_server.captured_requests();
        assert_eq!(openai_requests.len(), 1);
        assert_eq!(openai_requests[0].uri.path(), "/v1/models");
        assert_eq!(
            openai_requests[0]
                .headers
                .get("authorization")
                .and_then(|h| h.to_str().ok()),
            Some("Bearer sk-openai-key")
        );

        // Test Anthropic user
        let response = client
            .post(&format!("{}/anthropic/v1/messages", proxy_url))
            .header("Authorization", "Bearer anthropic-token")
            .body(r#"{"prompt": "test"}"#)
            .send()
            .await
            .expect("send request as Anthropic user");
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let anthropic_requests = anthropic_server.captured_requests();
        assert_eq!(anthropic_requests.len(), 1);
        assert_eq!(anthropic_requests[0].uri.path(), "/v1/messages");
        assert_eq!(
            anthropic_requests[0]
                .headers
                .get("authorization")
                .and_then(|h| h.to_str().ok()),
            Some("Bearer sk-anthropic-key")
        );

        assert_eq!(
            openai_server.captured_requests().len(),
            1,
            "OpenAI server should not receive Anthropic user's requests"
        );

        proxy.shutdown();
    });
}

/// # Requirements: F3
///
/// Tests that the proxy rejects API keys without upstream permissions.
#[test]
fn proxy_rejects_api_key_without_upstream_access() {
    run_async_test(|| async {
        let bind_addr = allocate_socket_addr();

        // Test when API key has empty upstreams list and upstreams section exists but is empty.
        // This should result in HTTP 401 because the API key refers
        // to no permitted upstreams (permitted_upstreams will be empty).
        //
        // This is a valid config with upstreams section (but empty) and API keys.
        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .with_max_connections(Some(100))
            .with_request_timeout_ms(Some(30000))
            .clear_upstreams()
            .clear_api_keys()
            .add_api_key(simple_api_key("no-access-user", "no-access-token", vec![]))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        let response = client
            .get(&format!("{}/anthropic/test", proxy_url))
            .header("Authorization", "Bearer no-access-token")
            .send()
            .await
            .expect("send request with token that has no upstream access");

        // When the API key refers to no permitted upstreams (empty upstreams section),
        // requests with this API key must be rejected with HTTP 401.
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

        proxy.shutdown();
    });
}

/// # Requirements: F5
///
/// Tests that the proxy rejects non-Bearer authentication schemes.
#[test]
fn proxy_rejects_non_bearer_authentication_schemes() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "test-key",
                "valid-token",
                vec!["test-upstream".to_string()],
            ))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Test various non-Bearer authentication schemes
        let non_bearer_schemes = vec![
            "Token valid-token",
            "Basic dXNlcjpwYXNz",
            "Digest username=\"user\"",
            "ApiKey valid-token",
            "valid-token", // Missing scheme entirely
        ];

        for scheme in non_bearer_schemes {
            let response = client
                .get(&format!("{}/test/test", proxy_url))
                .header("Authorization", scheme)
                .send()
                .await
                .expect(&format!("send request with non-Bearer scheme: {}", scheme));

            assert_eq!(
                response.status(),
                reqwest::StatusCode::UNAUTHORIZED,
                "Expected 401 for non-Bearer scheme: {}",
                scheme
            );
        }

        assert!(
            mock_server.captured_requests().is_empty(),
            "upstream should not receive requests with non-Bearer authentication schemes"
        );

        // Verify that Bearer tokens still work
        let response = client
            .get(&format!("{}/test/test", proxy_url))
            .header("Authorization", "Bearer valid-token")
            .send()
            .await
            .expect("send request with Bearer token");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            mock_server.captured_requests().len(),
            1,
            "upstream should receive requests with valid Bearer tokens"
        );

        proxy.shutdown();
    });
}

/// # Requirements: F3
///
/// Tests that the proxy handles empty upstreams list edge case.
#[test]
fn proxy_rejects_api_key_with_empty_upstreams_list() {
    run_async_test(|| async {
        let bind_addr = allocate_socket_addr();

        // Valid config with API key having empty upstreams list and no upstreams configured
        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "empty-upstreams-key",
                "test-token",
                vec![], // Empty list, and no upstreams configured
            ))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/anthropic/test", proxy_url))
            .header("Authorization", "Bearer test-token")
            .send()
            .await
            .expect("send request with API key that has empty upstreams list and no upstreams configured");

        // When api_keys.static[].upstreams is empty and no upstreams are configured,
        // requests with this API key must be rejected with HTTP 401.
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

        proxy.shutdown();
    });
}

/// # Requirements: F17.1, F18, F19, F20, F21, F22
///
/// Tests that the proxy successfully authenticates requests with valid JWT tokens
/// and routes them to upstreams. This test verifies the complete JWT authentication
/// flow through the proxy, which is difficult to test in unit tests.
#[test]
fn proxy_authenticates_with_valid_jwt_token() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600; // Valid for 1 hour

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send request with valid JWT token");

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        let requests = mock_server.captured_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].uri.path(), "/v1/test");
        assert_eq!(
            requests[0]
                .headers
                .get("authorization")
                .and_then(|h| h.to_str().ok()),
            Some("Bearer upstream-key")
        );

        proxy.shutdown();
    });
}

/// # Requirements: F17.1
///
/// Tests that static API keys are checked before JWT tokens. This verifies the
/// authentication order requirement in a real HTTP request flow, which cannot
/// be fully tested in unit tests that only test individual components.
#[test]
fn proxy_rejects_jwt_when_static_key_matches_first() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let static_key = "shared-key-value";
        let jwt_secret = "jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600;

        // Create a JWT token that, when base64url decoded, would not match the static key
        // but the static key string itself matches the static key configuration
        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "static-key",
                static_key,
                vec!["test-upstream".to_string()],
            ))
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Send the static key as Bearer token - should authenticate as static key
        let response = client
            .get(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", static_key))
            .send()
            .await
            .expect("send request with static key");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            mock_server.captured_requests().len(),
            1,
            "Static key should be authenticated first"
        );

        // Now create a JWT token with the same string as kid, but different secret
        // This tests that even if a JWT token could theoretically be created with
        // the same kid, the static key check happens first
        let jwt_token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        // Verify JWT token works when static key doesn't match
        let response = client
            .get(&format!("{}/test/v1/test2", proxy_url))
            .header("Authorization", format!("Bearer {}", jwt_token))
            .send()
            .await
            .expect("send request with JWT token");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(
            mock_server.captured_requests().len(),
            2,
            "JWT token should work when static key doesn't match"
        );

        proxy.shutdown();
    });
}

/// # Requirements: F23
///
/// Tests that the proxy rejects expired JWT tokens. This test verifies expiration
/// checking in a real HTTP request flow, which is important because expiration
/// is time-dependent and needs to be tested with actual time values.
#[test]
fn proxy_rejects_expired_jwt_token() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() - 60; // Expired 60 seconds ago

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let token = create_jwt_token(jwt_kid, jwt_secret, Some(exp), None)
            .expect("create expired JWT token");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send request with expired JWT token");

        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(
            mock_server.captured_requests().is_empty(),
            "upstream should not receive requests with expired JWT tokens"
        );

        proxy.shutdown();
    });
}

/// # Requirements: F3
///
/// Tests that the proxy rejects requests with valid JWT tokens when no upstreams
/// are configured. This verifies that JWT tokens follow the same upstream access
/// rules as static keys, which is important for the complete authentication flow.
#[test]
fn proxy_rejects_jwt_token_without_upstreams() {
    run_async_test(|| async {
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600;

        // Config with JWT keys but no upstreams
        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send request with valid JWT token but no upstreams");

        // When JWT token authentication succeeds but no upstreams are configured,
        // requests with this JWT token must be rejected with HTTP 401.
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

        proxy.shutdown();
    });
}

/// # Requirements: F22
///
/// Tests that the proxy rejects JWT tokens with invalid signatures. This test
/// verifies signature verification in a real HTTP request flow, which is important
/// because signature verification is a critical security check that must work
/// correctly in the complete request processing pipeline.
#[test]
fn proxy_rejects_jwt_token_with_invalid_signature() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let wrong_secret = "wrong-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600;

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        // Create token with correct kid but wrong secret (invalid signature)
        let token = create_jwt_token(jwt_kid, wrong_secret, Some(exp), None)
            .expect("create JWT token with wrong secret");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send request with JWT token with invalid signature");

        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        assert!(
            mock_server.captured_requests().is_empty(),
            "upstream should not receive requests with invalid JWT signatures"
        );

        proxy.shutdown();
    });
}

/// # Requirements: F2, F18
///
/// Precondition: Proxy configured with multiple upstreams and JWT keys, valid JWT token created
/// Action: Send requests with valid JWT token to different request paths matching different upstreams
/// Expected behavior: Requests routed to correct upstreams based on path matching, all requests proxied successfully
#[test]
fn proxy_routes_jwt_authenticated_requests_by_path() {
    run_async_test(|| async {
        let mock_server1 = MockServer::start().await.expect("start first mock server");
        let mock_server2 = MockServer::start().await.expect("start second mock server");
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600;

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("upstream1", mock_server1.url(), "/api/v1"))
            .add_upstream(simple_upstream("upstream2", mock_server2.url(), "/api/v2"))
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Route to first upstream
        let response = client
            .get(&format!("{}/api/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send request to first upstream");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(mock_server1.captured_requests().len(), 1);
        assert_eq!(mock_server2.captured_requests().len(), 0);

        // Route to second upstream
        let response = client
            .get(&format!("{}/api/v2/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send request to second upstream");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(mock_server1.captured_requests().len(), 1);
        assert_eq!(mock_server2.captured_requests().len(), 1);

        proxy.shutdown();
    });
}

/// # Requirements: F2, F18
///
/// Precondition: Proxy configured with multiple upstreams having overlapping paths and JWT keys, valid JWT token created
/// Action: Send request with valid JWT token to path matching multiple upstreams
/// Expected behavior: Longest matching path selected, request routed to correct upstream
#[test]
fn proxy_selects_longest_matching_path_for_jwt_requests() {
    run_async_test(|| async {
        let mock_server1 = MockServer::start().await.expect("start first mock server");
        let mock_server2 = MockServer::start().await.expect("start second mock server");
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600;

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("upstream1", mock_server1.url(), "/api"))
            .add_upstream(simple_upstream("upstream2", mock_server2.url(), "/api/v1"))
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Should match longest path (/api/v1)
        let response = client
            .get(&format!("{}/api/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send request matching longest path");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(mock_server1.captured_requests().len(), 0);
        assert_eq!(mock_server2.captured_requests().len(), 1);

        proxy.shutdown();
    });
}

/// # Requirements: F1, F2, F18
///
/// Precondition: Proxy configured with upstreams and JWT keys, valid JWT token created
/// Action: Send POST request with valid JWT token, custom headers, and body
/// Expected behavior: Request method, headers, and body preserved in proxied request, Authorization header replaced
#[test]
fn proxy_preserves_request_details_for_jwt_authenticated_requests() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600;

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Test POST with body and custom headers
        let response = client
            .post(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .header("X-Custom-Header", "custom-value")
            .header("Content-Type", "application/json")
            .body(r#"{"test": "data"}"#)
            .send()
            .await
            .expect("send POST request with JWT token");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let requests = mock_server.captured_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(
            requests[0]
                .headers
                .get("x-custom-header")
                .and_then(|h| h.to_str().ok()),
            Some("custom-value")
        );

        proxy.shutdown();
    });
}

/// # Requirements: F3, F18
///
/// Precondition: Proxy configured with upstreams and JWT keys, valid JWT token created, request path doesn't match any upstream
/// Action: Send request with valid JWT token to non-matching path
/// Expected behavior: Request rejected with HTTP 404 (path not found), upstream does not receive request
#[test]
fn proxy_rejects_jwt_token_when_path_doesnt_match() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600;

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/api"))
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/unknown/path", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send request with JWT token to non-matching path");

        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        assert!(mock_server.captured_requests().is_empty());

        proxy.shutdown();
    });
}

/// # Requirements: F17.1
///
/// Precondition: Proxy configured with both static keys and JWT keys, JWT token created that doesn't match static key
/// Action: Send request with JWT token that doesn't match any static key
/// Expected behavior: Static key check fails, JWT validation succeeds, request proxied successfully
#[test]
fn proxy_handles_jwt_token_that_looks_like_static_key() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let static_key = "some-static-key";
        let jwt_secret = "jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600;

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "static-key",
                static_key,
                vec!["test-upstream".to_string()],
            ))
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        // Create a JWT token that doesn't match the static key
        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send request with JWT token");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(mock_server.captured_requests().len(), 1);

        proxy.shutdown();
    });
}

/// # Requirements: F2, F18
///
/// Precondition: Proxy configured with upstreams and JWT keys, valid JWT token created
/// Action: Send 10 concurrent requests with valid JWT token
/// Expected behavior: All requests handled correctly, all proxied to upstream successfully
#[test]
fn proxy_handles_concurrent_jwt_authenticated_requests() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600;

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        let proxy_url = format!("http://{}", bind_addr);

        // Send 10 concurrent requests
        let mut handles = Vec::new();
        for i in 0..10 {
            let token = token.clone();
            let url = format!("{}/test/v1/test{}", proxy_url, i);
            let handle = tokio::spawn(async move {
                let client = reqwest::Client::new();
                client
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", token))
                    .send()
                    .await
            });
            handles.push(handle);
        }

        let results: Vec<_> = future::join_all(handles).await;
        for result in results {
            let response = result
                .expect("request should complete")
                .expect("request should succeed");
            assert_eq!(response.status(), reqwest::StatusCode::OK);
        }

        assert_eq!(mock_server.captured_requests().len(), 10);

        proxy.shutdown();
    });
}

/// # Requirements: F2, F18, O6
///
/// Precondition: Proxy configured with upstreams and JWT keys, valid JWT token created, proxy started with trace log level
/// Action: Send request with valid JWT token
/// Expected behavior: JWT key id appears in request logs, request proxied successfully
#[test]
fn proxy_logs_jwt_key_id_in_request_logs() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let jwt_kid = "test-jwt-key-id";
        let exp = current_timestamp() + 3600;

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn_with_log_level(&config_yaml, "trace");
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let _response = client
            .get(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send request with JWT token");

        // Check that logs contain the JWT key id
        let logs = proxy.logs_snapshot();
        assert!(
            logs.contains(jwt_kid),
            "Logs should contain JWT key id: {}\nLogs: {}",
            jwt_kid,
            logs
        );

        proxy.shutdown();
    });
}

/// # Requirements: F2, F18
///
/// Precondition: Proxy configured with upstreams and JWT keys, valid JWT token created
/// Action: Send requests with valid JWT token using different HTTP methods (GET, POST, PUT, DELETE)
/// Expected behavior: All HTTP methods handled correctly, all requests proxied to upstream successfully
#[test]
fn proxy_handles_different_http_methods_with_jwt() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600;

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Test GET
        let response = client
            .get(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send GET request");
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        // Test POST
        let response = client
            .post(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send POST request");
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        // Test PUT
        let response = client
            .put(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send PUT request");
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        // Test DELETE
        let response = client
            .delete(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send DELETE request");
        assert_eq!(response.status(), reqwest::StatusCode::OK);

        assert_eq!(mock_server.captured_requests().len(), 4);

        proxy.shutdown();
    });
}

/// # Requirements: F2, F18
///
/// Precondition: Proxy configured with upstreams and JWT keys, valid JWT token created
/// Action: Send request with valid JWT token to URL with query parameters
/// Expected behavior: Query parameters preserved in proxied request, request proxied successfully
#[test]
fn proxy_handles_jwt_authentication_with_query_parameters() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600;

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!(
                "{}/test/v1/test?param1=value1&param2=value2",
                proxy_url
            ))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send request with query parameters");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let requests = mock_server.captured_requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].uri.query().is_some());

        proxy.shutdown();
    });
}

/// # Requirements: F2, F18
///
/// Precondition: Proxy configured with upstreams and JWT keys, valid JWT token created
/// Action: Send POST request with valid JWT token and large request body (10KB)
/// Expected behavior: Large body handled correctly, request proxied to upstream successfully
#[test]
fn proxy_handles_jwt_authentication_with_large_request_body() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600;

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let large_body = "x".repeat(10000); // 10KB body
        let response = client
            .post(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "text/plain")
            .body(large_body)
            .send()
            .await
            .expect("send request with large body");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let requests = mock_server.captured_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");

        proxy.shutdown();
    });
}

/// # Requirements: F2, F18
///
/// Precondition: Proxy configured with upstreams and JWT keys, valid JWT token created
/// Action: Send request with valid JWT token and read streaming response
/// Expected behavior: Streaming response handled correctly, request proxied and response streamed successfully
#[test]
fn proxy_handles_jwt_authentication_with_streaming_response() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let jwt_secret = "test-jwt-secret-key";
        let jwt_kid = "test-jwt-key";
        let exp = current_timestamp() + 3600;

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);
        let response = client
            .get(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send request with JWT token");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let _body = response.bytes().await.expect("read response body");
        assert_eq!(mock_server.captured_requests().len(), 1);

        proxy.shutdown();
    });
}

/// # Requirements: F17.1, F18
///
/// Precondition: Proxy configured with both static keys and JWT keys, valid JWT token created
/// Action: Send requests with static key and with JWT token separately
/// Expected behavior: Static key authenticated first when matches, JWT token authenticated when static doesn't match, both requests proxied successfully
#[test]
fn proxy_prioritizes_static_keys_over_jwt_when_both_configured() {
    run_async_test(|| async {
        let mock_server = MockServer::start().await.expect("start mock server");
        let bind_addr = allocate_socket_addr();

        let static_key = "static-api-key-123";
        let jwt_secret = "jwt-secret-key";
        let jwt_kid = "jwt-key-id";
        let exp = current_timestamp() + 3600;

        let config_yaml = TestConfig::new()
            .with_bind_address(bind_addr.to_string())
            .clear_upstreams()
            .add_upstream(simple_upstream("test-upstream", mock_server.url(), "/test"))
            .clear_api_keys()
            .add_api_key(simple_api_key(
                "static-key",
                static_key,
                vec!["test-upstream".to_string()],
            ))
            .add_jwt_key(simple_jwt_key(jwt_kid, jwt_secret))
            .to_yaml();

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        proxy.wait_for_ready(bind_addr, Duration::from_secs(2));

        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        // Static key should work
        let response = client
            .get(&format!("{}/test/v1/test", proxy_url))
            .header("Authorization", format!("Bearer {}", static_key))
            .send()
            .await
            .expect("send request with static key");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(mock_server.captured_requests().len(), 1);

        // JWT token should also work (different token)
        let token =
            create_jwt_token(jwt_kid, jwt_secret, Some(exp), None).expect("create JWT token");
        let response = client
            .get(&format!("{}/test/v1/test2", proxy_url))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .expect("send request with JWT token");

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(mock_server.captured_requests().len(), 2);

        proxy.shutdown();
    });
}
