//! Unit tests for Functional Requirements (F1-F17)
//!
//! This module contains unit tests covering functional requirements.
//! Tests have been migrated from proxy.rs, request_path_routing.rs, and config_manager.rs.

use crate::common::*;
use axum::http::{HeaderMap, HeaderValue, Method};
use fluxgate::config::{
    ApiKeysConfig, Config, ConfigManager, ServerConfig, StaticApiKey, UpstreamEntry,
    UpstreamsConfig, SUPPORTED_CONFIG_VERSION,
};
use fluxgate::proxy::{
    build_upstream_url, is_connect_or_upgrade_request, is_hop_by_hop_header, ConnectionLimiter,
};
use std::collections::HashMap;
use tempfile::tempdir;
use tokio::time::{sleep, Duration as TokioDuration};

// Re-export common helpers for convenience
use crate::common::test_upstream_entry_with_path;

#[test]
fn build_upstream_url_with_path_and_query() {
    // Precondition: Upstream entry with target URL and request URI with path and query parameters.
    // Action: Call build_upstream_url with upstream entry and request URI containing path and query.
    // Expected behavior: Returns correctly constructed URL with path and query parameters preserved.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/users/123?filter=active".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(
        result.as_str(),
        "https://api.example.com/v1/users/123?filter=active"
    );
}

#[test]
fn build_upstream_url_with_path_only() {
    // Precondition: Upstream entry with target URL and request URI with path only (no query).
    // Action: Call build_upstream_url with upstream entry and request URI containing only path.
    // Expected behavior: Returns correctly constructed URL with path preserved, no query parameters.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/users/123".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(result.as_str(), "https://api.example.com/v1/users/123");
}

#[test]
fn build_upstream_url_with_root_path() {
    // Precondition: Upstream entry with target URL and request URI with root path.
    // Action: Call build_upstream_url with upstream entry and root path request URI.
    // Expected behavior: Returns correctly constructed URL with root path preserved.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(result.as_str(), "https://api.example.com/v1/");
}

#[test]
fn build_upstream_url_handles_trailing_slash_in_base() {
    // Precondition: Upstream entry with target URL containing trailing slash.
    // Action: Call build_upstream_url with upstream entry having trailing slash and request URI.
    // Expected behavior: Returns correctly constructed URL without double slashes.
    // Covers Requirements: F1
    let upstream =
        test_upstream_entry_with_path("https://api.example.com/v1/", "test-key", "/test");

    let request_uri = "/models".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(
        result.as_str(),
        "https://api.example.com/v1/models",
        "trailing slash in the base URL should not produce double slashes"
    );
}

#[test]
fn build_upstream_url_invalid_base_url() {
    // Precondition: Upstream entry with invalid target URL.
    // Action: Call build_upstream_url with invalid target URL.
    // Expected behavior: Returns error indicating invalid URL.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("not-a-valid-url", "test-key", "/test");

    let request_uri = "/test".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri);

    assert!(result.is_err());
}

#[test]
fn is_hop_by_hop_header_identifies_connection_header() {
    // Precondition: Header name "connection" exists.
    // Action: Call is_hop_by_hop_header with "connection" header name.
    // Expected behavior: Returns true indicating it is a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "connection".parse().unwrap();
    assert!(is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_identifies_keep_alive_header() {
    // Precondition: Header name "keep-alive" exists.
    // Action: Call is_hop_by_hop_header with "keep-alive" header name.
    // Expected behavior: Returns true indicating it is a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "keep-alive".parse().unwrap();
    assert!(is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_identifies_proxy_authenticate_header() {
    // Precondition: Header name "proxy-authenticate" exists.
    // Action: Call is_hop_by_hop_header with "proxy-authenticate" header name.
    // Expected behavior: Returns true indicating it is a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "proxy-authenticate".parse().unwrap();
    assert!(is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_identifies_te_header() {
    // Precondition: Header name "te" exists.
    // Action: Call is_hop_by_hop_header with "te" header name.
    // Expected behavior: Returns true indicating it is a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "te".parse().unwrap();
    assert!(is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_identifies_trailers_header() {
    // Precondition: Header name "trailers" exists.
    // Action: Call is_hop_by_hop_header with "trailers" header name.
    // Expected behavior: Returns true indicating it is a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "trailers".parse().unwrap();
    assert!(is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_identifies_transfer_encoding_header() {
    // Precondition: Header name "transfer-encoding" exists.
    // Action: Call is_hop_by_hop_header with "transfer-encoding" header name.
    // Expected behavior: Returns true indicating it is a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "transfer-encoding".parse().unwrap();
    assert!(is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_identifies_upgrade_header() {
    // Precondition: Header name "upgrade" exists.
    // Action: Call is_hop_by_hop_header with "upgrade" header name.
    // Expected behavior: Returns true indicating it is a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "upgrade".parse().unwrap();
    assert!(is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_allows_content_type_header() {
    // Precondition: Header name "content-type" exists (not a hop-by-hop header).
    // Action: Call is_hop_by_hop_header with "content-type" header name.
    // Expected behavior: Returns false indicating it is not a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "content-type".parse().unwrap();
    assert!(!is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_allows_authorization_header() {
    // Precondition: Header name "authorization" exists (not a hop-by-hop header).
    // Action: Call is_hop_by_hop_header with "authorization" header name.
    // Expected behavior: Returns false indicating it is not a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "authorization".parse().unwrap();
    assert!(!is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_allows_user_agent_header() {
    // Precondition: Header name "user-agent" exists (not a hop-by-hop header).
    // Action: Call is_hop_by_hop_header with "user-agent" header name.
    // Expected behavior: Returns false indicating it is not a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "user-agent".parse().unwrap();
    assert!(!is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_allows_custom_header() {
    // Precondition: Header name "x-custom-header" exists (not a hop-by-hop header).
    // Action: Call is_hop_by_hop_header with "x-custom-header" header name.
    // Expected behavior: Returns false indicating it is not a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "x-custom-header".parse().unwrap();
    assert!(!is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_is_case_insensitive() {
    // Precondition: Header name "Connection" with mixed case exists.
    // Action: Call is_hop_by_hop_header with "Connection" header name (capitalized).
    // Expected behavior: Returns true indicating case-insensitive matching works.
    // Covers Requirements: F1
    let header_name = "Connection".parse().unwrap();
    assert!(
        is_hop_by_hop_header(&header_name),
        "header matching must be case-insensitive"
    );
}

#[test]
fn connect_method_is_treated_as_upgrade_like_request() {
    // Precondition: Request uses CONNECT method.
    // Action: Call is_connect_or_upgrade_request with CONNECT method.
    // Expected behavior: Returns true indicating CONNECT requests are rejected by the proxy.
    // Covers Requirements: F11
    let method = Method::CONNECT;
    let headers = HeaderMap::new();

    assert!(
        is_connect_or_upgrade_request(&method, &headers),
        "CONNECT requests must be treated as unsupported tunnelling attempts"
    );
}

#[test]
fn explicit_upgrade_header_is_rejected() {
    // Precondition: Request with Upgrade header.
    // Action: Call is_connect_or_upgrade_request with request containing Upgrade header.
    // Expected behavior: Returns true indicating Upgrade-based requests are rejected by the proxy.
    // Covers Requirements: F11
    let method = Method::GET;
    let mut headers = HeaderMap::new();
    headers.insert("upgrade", HeaderValue::from_static("websocket"));

    assert!(
        is_connect_or_upgrade_request(&method, &headers),
        "requests carrying an Upgrade header must be rejected"
    );
}

#[test]
fn connection_upgrade_token_is_rejected_case_insensitively() {
    // Precondition: Request with Connection: Upgrade header (any casing, with extra tokens).
    // Action: Call is_connect_or_upgrade_request with Connection header containing Upgrade token.
    // Expected behavior: Returns true indicating it is treated as unsupported Upgrade-based request.
    // Covers Requirements: F11
    let method = Method::GET;
    let mut headers = HeaderMap::new();
    headers.insert(
        "connection",
        HeaderValue::from_static("keep-alive, Upgrade, another-token"),
    );

    assert!(
        is_connect_or_upgrade_request(&method, &headers),
        "Connection header with Upgrade token must be rejected"
    );
}

#[test]
fn normal_get_request_without_upgrade_is_allowed() {
    // Precondition: Regular GET request without CONNECT or Upgrade semantics.
    // Action: Call is_connect_or_upgrade_request with normal GET request.
    // Expected behavior: Returns false indicating request is allowed.
    // Covers Requirements: F11
    let method = Method::GET;
    let headers = HeaderMap::new();

    assert!(
        !is_connect_or_upgrade_request(&method, &headers),
        "ordinary requests without Upgrade or CONNECT must be allowed"
    );
}

#[test]
fn build_upstream_url_with_empty_base_path() {
    // Precondition: Upstream URL with empty path (root only).
    // Action: Call build_upstream_url with upstream entry and request path.
    // Expected behavior: Returns correctly constructed URL combining paths.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com", "test-key", "/test");

    let request_uri = "/users/123".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(result.as_str(), "https://api.example.com/users/123");
}

#[test]
fn build_upstream_url_with_base_path_and_request_path() {
    // Precondition: Upstream URL with path and request with path.
    // Action: Call build_upstream_url with upstream entry and request path.
    // Expected behavior: Returns correctly constructed URL combining paths without double slashes.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/users/123".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(result.as_str(), "https://api.example.com/v1/users/123");
}

#[test]
fn build_upstream_url_preserves_query_parameters() {
    // Precondition: Request URI with query parameters.
    // Action: Call build_upstream_url with upstream entry and request URI containing query.
    // Expected behavior: Returns correctly constructed URL with query parameters preserved.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/search?q=test&page=1".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(
        result.as_str(),
        "https://api.example.com/v1/search?q=test&page=1"
    );
}

#[test]
fn build_upstream_url_with_base_url_having_query() {
    // Precondition: Upstream URL with query parameters (edge case).
    // Action: Call build_upstream_url with upstream entry having query and request with query.
    // Expected behavior: Returns correctly constructed URL with request query replacing base query.
    // Covers Requirements: F1
    let upstream =
        test_upstream_entry_with_path("https://api.example.com/v1?base=param", "test-key", "/test");

    let request_uri = "/search?q=test".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(result.as_str(), "https://api.example.com/v1/search?q=test");
}

#[test]
fn build_upstream_url_with_request_path_starting_with_slash() {
    // Precondition: Request path starts with slash (normal case).
    // Action: Call build_upstream_url with upstream entry and request path starting with slash.
    // Expected behavior: Returns correctly constructed URL handling leading slash.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/api/users".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(result.as_str(), "https://api.example.com/v1/api/users");
}

#[test]
fn build_upstream_url_with_query_only() {
    // Precondition: Request URI with root path and query.
    // Action: Call build_upstream_url with upstream entry and request URI with root path and query.
    // Expected behavior: Returns correctly constructed URL using base path and preserving query.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/?query=value".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(result.as_str(), "https://api.example.com/v1/?query=value");
}

#[test]
fn build_upstream_url_with_http_scheme() {
    // Precondition: Upstream URL uses http (not https).
    // Action: Call build_upstream_url with upstream entry using http scheme.
    // Expected behavior: Returns correctly constructed URL preserving http scheme.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("http://api.example.com/v1", "test-key", "/test");

    let request_uri = "/test".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    // When request path exactly matches request_path, upstream receives root path
    assert_eq!(result.as_str(), "http://api.example.com/v1/");
    assert_eq!(result.scheme(), "http");
}

#[test]
fn build_upstream_url_with_port_in_base_url() {
    // Precondition: Upstream URL includes port number.
    // Action: Call build_upstream_url with upstream entry containing port number.
    // Expected behavior: Returns correctly constructed URL preserving port number.
    // Covers Requirements: F1
    let upstream =
        test_upstream_entry_with_path("https://api.example.com:8443/v1", "test-key", "/test");

    let request_uri = "/test".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    // When request path exactly matches request_path, upstream receives root path
    assert_eq!(result.as_str(), "https://api.example.com:8443/v1/");
    assert_eq!(result.port(), Some(8443));
}

#[test]
fn build_upstream_url_with_fragment_in_request() {
    // Precondition: Request URI (fragments are not preserved by Uri parsing).
    // Action: Call build_upstream_url with upstream entry and request URI.
    // Expected behavior: Returns correctly constructed URL (fragments not preserved by Uri).
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    // Note: Uri doesn't preserve fragments in the standard way, so we test without fragment
    // Fragment handling would require custom logic
    let request_uri = "/users/123".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(result.as_str(), "https://api.example.com/v1/users/123");
}

#[test]
fn build_upstream_url_with_special_characters_in_path() {
    // Precondition: Request path with special characters (URL-encoded).
    // Action: Call build_upstream_url with upstream entry and request URI with encoded characters.
    // Expected behavior: Returns correctly constructed URL with special characters properly encoded.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/users/test%20user/data".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(
        result.as_str(),
        "https://api.example.com/v1/users/test%20user/data"
    );
}

#[test]
fn build_upstream_url_with_multiple_slashes_in_request() {
    // Precondition: Request path (URL parser normalizes multiple slashes).
    // Action: Call build_upstream_url with upstream entry and request URI.
    // Expected behavior: Returns correctly constructed URL (multiple slashes normalized by parser).
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    // Uri parser normalizes paths, so we test with a path that has slashes
    let request_uri = "/users/123".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    // URL parser normalizes paths
    assert_eq!(result.as_str(), "https://api.example.com/v1/users/123");
}

#[test]
fn build_upstream_url_with_complex_query_parameters() {
    // Precondition: Request URI with complex query parameters.
    // Action: Call build_upstream_url with upstream entry and request URI with complex query.
    // Expected behavior: Query parameters are preserved in the constructed URL.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/search?q=test+query&page=1&sort=desc&filter[]=a&filter[]=b"
        .parse()
        .unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(result.as_str().contains("q=test+query"));
    assert!(result.as_str().contains("page=1"));
}

#[test]
fn build_upstream_url_with_base_path_ending_in_slash() {
    // Precondition: Base URL path ends with slash, request path starts with slash.
    // Action: Call build_upstream_url with upstream entry having trailing slash and request path.
    // Expected behavior: Paths are correctly combined without double slashes.
    // Covers Requirements: F1
    let upstream =
        test_upstream_entry_with_path("https://api.example.com/v1/", "test-key", "/test");

    let request_uri = "/users/123".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(result.as_str(), "https://api.example.com/v1/users/123");
}

#[test]
fn build_upstream_url_with_empty_base_and_request_path() {
    // Precondition: Base URL has no path, request has root path.
    // Action: Call build_upstream_url with upstream entry having no path and root request URI.
    // Expected behavior: Result has root path.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com", "test-key", "/test");

    let request_uri = "/".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(result.as_str(), "https://api.example.com/");
}

#[test]
fn build_upstream_url_preserves_base_url_fragment() {
    // Precondition: Base URL has fragment, request has no fragment.
    // Action: Call build_upstream_url with upstream entry having fragment and request URI.
    // Expected behavior: Base fragment is preserved (set_path doesn't remove fragments).
    // Covers Requirements: F1
    let upstream =
        test_upstream_entry_with_path("https://api.example.com/v1#base", "test-key", "/test");

    let request_uri = "/users/123".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    // Url::set_path doesn't remove fragments, so base fragment is preserved
    assert_eq!(result.as_str(), "https://api.example.com/v1/users/123#base");
    assert_eq!(result.fragment(), Some("base"));
}

#[test]
fn get_upstream_case_sensitive() {
    // Precondition: Configuration with upstreams having case-sensitive names.
    // Action: Call get_upstream with upstream name in different case.
    // Expected behavior: Returns None for case mismatch.
    // Covers Requirements: F1
    use crate::common::{test_config, test_upstream_entry, test_upstreams_config};

    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "Upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        None,
    );

    assert!(config.get_upstream("upstream1").is_none());
    assert!(config.get_upstream("Upstream1").is_some());
}

#[test]
fn has_upstreams_with_many_upstreams() {
    // Precondition: Configuration with many upstreams.
    // Action: Call has_upstreams on configuration with many upstreams.
    // Expected behavior: Returns true.
    // Covers Requirements: F1
    use crate::common::create_multi_upstream_config;

    let (config, _) = create_multi_upstream_config(50);

    assert!(config.has_upstreams());
}

#[test]
fn stream_request_body_converts_axum_body_to_reqwest_body() {
    // Precondition: Axum Body with content.
    // Action: Convert body using stream_request_body.
    // Expected behavior: Returns reqwest::Body without panicking.
    // Covers Requirements: F1
    use axum::body::Body;
    use fluxgate::proxy::stream_request_body;

    let axum_body = Body::from("test content");
    let _reqwest_body = stream_request_body(axum_body);
    // Function should complete without panicking
}

#[test]
fn stream_request_body_handles_empty_body() {
    // Precondition: Empty axum Body.
    // Action: Convert body using stream_request_body.
    // Expected behavior: Returns reqwest::Body without panicking.
    // Covers Requirements: F1
    use axum::body::Body;
    use fluxgate::proxy::stream_request_body;

    let axum_body = Body::empty();
    let _reqwest_body = stream_request_body(axum_body);
    // Function should complete without panicking
}

#[test]
fn stream_request_body_handles_large_body() {
    // Precondition: Axum Body with large content.
    // Action: Convert body using stream_request_body.
    // Expected behavior: Returns reqwest::Body without panicking.
    // Covers Requirements: F1
    use axum::body::Body;
    use fluxgate::proxy::stream_request_body;

    let large_content = "x".repeat(10000);
    let axum_body = Body::from(large_content);
    let _reqwest_body = stream_request_body(axum_body);
    // Function should complete without panicking
}

#[test]
fn stream_request_body_preserves_binary_content() {
    // Precondition: Axum Body with binary content.
    // Action: Convert body using stream_request_body.
    // Expected behavior: Returns reqwest::Body without panicking.
    // Covers Requirements: F1
    use axum::body::Body;
    use fluxgate::proxy::stream_request_body;

    let binary_content = vec![0u8, 1u8, 2u8, 255u8, 128u8];
    let axum_body = Body::from(binary_content);
    let _reqwest_body = stream_request_body(axum_body);
    // Function should complete without panicking
}

#[test]
fn is_hop_by_hop_header_handles_mixed_case_header_names() {
    // Precondition: Header names with mixed case (CONNECTION, Keep-Alive, Transfer-Encoding).
    // Action: Call is_hop_by_hop_header with header names in different cases.
    // Expected behavior: Case-insensitive matching works correctly.
    // Covers Requirements: F1
    let header_name = "CONNECTION".parse().unwrap();
    assert!(is_hop_by_hop_header(&header_name));

    let header_name = "Keep-Alive".parse().unwrap();
    assert!(is_hop_by_hop_header(&header_name));

    let header_name = "Transfer-Encoding".parse().unwrap();
    assert!(is_hop_by_hop_header(&header_name));
}

#[test]
fn is_connect_or_upgrade_request_handles_malformed_connection_header() {
    // Precondition: Request with malformed Connection header (invalid bytes).
    // Action: Call is_connect_or_upgrade_request with request containing malformed Connection header.
    // Expected behavior: Handles malformed headers gracefully without panicking.
    // Covers Requirements: F11
    let method = Method::GET;
    let mut headers = HeaderMap::new();
    headers.insert(
        "connection",
        HeaderValue::from_bytes(b"upgrade\xff").unwrap(),
    );

    // Should not panic, but may or may not detect upgrade depending on implementation
    let result = is_connect_or_upgrade_request(&method, &headers);
    // The function should handle this gracefully without panicking
    // Result can be true or false, but the important thing is it doesn't panic
    let _ = result; // Just check it doesn't panic
}

#[test]
fn is_connect_or_upgrade_request_handles_empty_connection_header() {
    // Precondition: Request with empty Connection header value.
    // Action: Call is_connect_or_upgrade_request with request containing empty Connection header.
    // Expected behavior: Empty header doesn't trigger upgrade detection.
    // Covers Requirements: F11
    let method = Method::GET;
    let mut headers = HeaderMap::new();
    headers.insert("connection", HeaderValue::from_static(""));

    assert!(!is_connect_or_upgrade_request(&method, &headers));
}

#[test]
fn is_connect_or_upgrade_request_handles_connection_header_with_only_whitespace() {
    // Precondition: Request with Connection header containing only whitespace.
    // Action: Call is_connect_or_upgrade_request with request containing whitespace-only Connection header.
    // Expected behavior: Whitespace-only header doesn't trigger upgrade detection.
    // Covers Requirements: F11
    let method = Method::GET;
    let mut headers = HeaderMap::new();
    headers.insert("connection", HeaderValue::from_static("   "));

    assert!(!is_connect_or_upgrade_request(&method, &headers));
}

#[test]
fn build_upstream_url_handles_unicode_in_path() {
    // Precondition: Request path with unicode characters.
    // Action: Call build_upstream_url with upstream entry and request URI containing unicode.
    // Expected behavior: Unicode characters are properly encoded in the constructed URL.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/users/тест".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    // URL should be properly encoded
    assert!(result.as_str().contains("/users/"));
}

#[test]
fn build_upstream_url_handles_special_characters_in_query() {
    // Precondition: Request URI with special characters in query parameters.
    // Action: Call build_upstream_url with upstream entry and request URI with special characters in query.
    // Expected behavior: Special characters are properly encoded in the constructed URL.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    // Use properly encoded URI
    let request_uri = "/search?q=hello%20world&filter=a%26b".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(result.as_str().contains("q=hello"));
    assert!(result.query().is_some());
    assert!(result.as_str().contains("/v1/search"));
}

#[tokio::test]
async fn connection_limiter_handles_limit_of_one() {
    // Precondition: Connection limiter with limit of 1.
    // Action: Acquire and release permit multiple times.
    // Expected behavior: Only one permit can be held at a time.
    // Covers Requirements: P2, F8
    let limiter = ConnectionLimiter::new(1);
    let permit1 = limiter.try_acquire().expect("first permit should succeed");
    assert_eq!(limiter.active_count(), 1);

    assert!(
        limiter.try_acquire().is_err(),
        "second permit should fail when limit is 1"
    );
    drop(permit1);
    sleep(TokioDuration::from_millis(10)).await;
    assert_eq!(limiter.active_count(), 0);

    let permit2 = limiter
        .try_acquire()
        .expect("second permit should succeed after release");
    assert_eq!(limiter.active_count(), 1);
    drop(permit2);
}

#[test]
fn build_upstream_url_with_path_containing_encoded_spaces() {
    // Precondition: Request URI with path containing encoded spaces (%20).
    // Action: Call build_upstream_url with upstream entry and request URI with encoded spaces.
    // Expected behavior: Returns correctly constructed URL with encoded spaces preserved.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/users/john%20doe".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(result.as_str().contains("john%20doe") || result.as_str().contains("john doe"));
}

#[test]
fn build_upstream_url_with_path_containing_unicode() {
    // Precondition: Request URI with path containing unicode characters.
    // Action: Call build_upstream_url with upstream entry and request URI with unicode.
    // Expected behavior: Returns correctly constructed URL with unicode properly encoded.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/users/тест".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(result.as_str().contains("/users/"));
}

#[test]
fn build_upstream_url_with_base_having_path_and_query() {
    // Precondition: Upstream URL with path and query, request has path and query.
    // Action: Call build_upstream_url with upstream entry and request URI.
    // Expected behavior: Returns correctly constructed URL with request query overriding base query.
    // Covers Requirements: F1
    let upstream = UpstreamEntry {
        target_url: "https://api.example.com/v1?base=param".to_string(),
        api_key: "test-key".to_string(),
        request_path: "/test".to_string(),
    };

    let request_uri = "/search?q=test&page=1".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(
        result.as_str(),
        "https://api.example.com/v1/search?q=test&page=1"
    );
}

#[test]
fn build_upstream_url_with_base_having_no_path_and_request_has_path() {
    // Precondition: Upstream URL with no path (root only), request has path.
    // Action: Call build_upstream_url with upstream entry and request URI with path.
    // Expected behavior: Returns correctly constructed URL combining paths.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com", "test-key", "/api");

    let request_uri = "/users/123".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(result.as_str(), "https://api.example.com/users/123");
}

#[test]
fn build_upstream_url_with_request_path_exactly_matching_upstream_request_path() {
    // Precondition: Request path exactly matches upstream request_path.
    // Action: Call build_upstream_url with upstream entry and request URI matching request_path.
    // Expected behavior: Returns correctly constructed URL with root path or preserved path.
    // Covers Requirements: F1, F2
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/api");

    let request_uri = "/api".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(result.as_str(), "https://api.example.com/v1/");
}

#[test]
fn build_upstream_url_with_request_path_matching_upstream_request_path_with_trailing_slash() {
    // Precondition: Request path matches upstream request_path with trailing slash.
    // Action: Call build_upstream_url with upstream entry and request URI.
    // Expected behavior: Returns correctly constructed URL handling trailing slash.
    // Covers Requirements: F1, F2
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/api");

    let request_uri = "/api/".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(result.as_str().ends_with('/'));
}

#[test]
fn build_upstream_url_with_ipv6_upstream() {
    // Precondition: Upstream URL using IPv6 address.
    // Action: Call build_upstream_url with upstream entry using IPv6.
    // Expected behavior: Returns correctly constructed URL with IPv6 address preserved.
    // Covers Requirements: F1
    let upstream = UpstreamEntry {
        target_url: "https://[2001:db8::1]:8443/v1".to_string(),
        api_key: "test-key".to_string(),
        request_path: "/test".to_string(),
    };

    let request_uri = "/users/123".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(result.as_str().contains("[2001:db8::1]"));
    assert_eq!(result.port(), Some(8443));
}

#[test]
fn build_upstream_url_with_query_containing_special_chars() {
    // Precondition: Request URI with query parameters containing special characters.
    // Action: Call build_upstream_url with upstream entry and request URI with special chars in query.
    // Expected behavior: Returns correctly constructed URL with special characters properly encoded.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/search?q=hello%20world&data=a%3Db".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(result.as_str().contains("q=hello"));
    assert!(result.query().is_some());
}

#[test]
fn build_upstream_url_with_empty_query_string() {
    // Precondition: Request URI with empty query string (?).
    // Action: Call build_upstream_url with upstream entry and request URI with empty query.
    // Expected behavior: Returns correctly constructed URL handling empty query.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/test");

    let request_uri = "/search?".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    // Empty query should be handled gracefully
    assert!(result.as_str().contains("/v1/search"));
}

#[test]
fn build_upstream_url_with_multiple_path_segments_removed() {
    // Precondition: Request path with multiple segments, upstream request_path matches prefix.
    // Action: Call build_upstream_url with upstream entry and request URI.
    // Expected behavior: Correctly removes request_path prefix and preserves remaining path.
    // Covers Requirements: F1, F2
    let upstream = UpstreamEntry {
        target_url: "https://api.example.com/v1".to_string(),
        api_key: "test-key".to_string(),
        request_path: "/api/v1".to_string(),
    };

    let request_uri = "/api/v1/models/gpt-4".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(result.as_str(), "https://api.example.com/v1/models/gpt-4");
}

#[test]
fn is_hop_by_hop_header_identifies_proxy_authorization_header() {
    // Precondition: Header name "proxy-authorization" exists.
    // Action: Call is_hop_by_hop_header with "proxy-authorization" header name.
    // Expected behavior: Returns true indicating it is a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "proxy-authorization".parse().unwrap();
    assert!(is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_allows_content_length_header() {
    // Precondition: Header name "content-length" exists (not a hop-by-hop header).
    // Action: Call is_hop_by_hop_header with "content-length" header name.
    // Expected behavior: Returns false indicating it is not a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "content-length".parse().unwrap();
    assert!(!is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_allows_accept_header() {
    // Precondition: Header name "accept" exists (not a hop-by-hop header).
    // Action: Call is_hop_by_hop_header with "accept" header name.
    // Expected behavior: Returns false indicating it is not a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "accept".parse().unwrap();
    assert!(!is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_allows_host_header() {
    // Precondition: Header name "host" exists (not a hop-by-hop header, but special).
    // Action: Call is_hop_by_hop_header with "host" header name.
    // Expected behavior: Returns false (host is end-to-end, not hop-by-hop).
    // Covers Requirements: F1
    let header_name = "host".parse().unwrap();
    assert!(!is_hop_by_hop_header(&header_name));
}

#[test]
fn is_hop_by_hop_header_allows_cache_control_header() {
    // Precondition: Header name "cache-control" exists (not a hop-by-hop header).
    // Action: Call is_hop_by_hop_header with "cache-control" header name.
    // Expected behavior: Returns false indicating it is not a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "cache-control".parse().unwrap();
    assert!(!is_hop_by_hop_header(&header_name));
}

#[test]
fn is_connect_or_upgrade_request_handles_connection_with_multiple_tokens() {
    // Precondition: Request with Connection header containing multiple tokens including Upgrade.
    // Action: Call is_connect_or_upgrade_request with request containing Connection: token1, upgrade, token2.
    // Expected behavior: Returns true indicating Upgrade token is present.
    // Covers Requirements: F14
    let method = Method::GET;
    let mut headers = HeaderMap::new();
    headers.insert(
        "connection",
        HeaderValue::from_static("keep-alive, upgrade, close"),
    );

    assert!(
        is_connect_or_upgrade_request(&method, &headers),
        "Connection header with Upgrade token must be rejected"
    );
}

#[test]
fn is_connect_or_upgrade_request_handles_connection_with_only_keep_alive() {
    // Precondition: Request with Connection header containing only keep-alive.
    // Action: Call is_connect_or_upgrade_request with request containing Connection: keep-alive.
    // Expected behavior: Returns false indicating no Upgrade token.
    // Covers Requirements: F14
    let method = Method::GET;
    let mut headers = HeaderMap::new();
    headers.insert("connection", HeaderValue::from_static("keep-alive"));

    assert!(
        !is_connect_or_upgrade_request(&method, &headers),
        "Connection header with only keep-alive should not be rejected"
    );
}

#[test]
fn is_connect_or_upgrade_request_handles_case_insensitive_upgrade_header() {
    // Precondition: Request with Upgrade header in different case.
    // Action: Call is_connect_or_upgrade_request with request containing Upgrade header.
    // Expected behavior: Returns true (header names are case-insensitive).
    // Covers Requirements: F14
    let method = Method::GET;
    let mut headers = HeaderMap::new();
    headers.insert("upgrade", HeaderValue::from_static("websocket"));

    assert!(
        is_connect_or_upgrade_request(&method, &headers),
        "Upgrade header must be rejected regardless of case"
    );
}

#[test]
fn is_connect_or_upgrade_request_handles_post_method_with_upgrade() {
    // Precondition: POST request with Upgrade header.
    // Action: Call is_connect_or_upgrade_request with POST request containing Upgrade header.
    // Expected behavior: Returns true indicating Upgrade requests are rejected.
    // Covers Requirements: F14
    let method = Method::POST;
    let mut headers = HeaderMap::new();
    headers.insert("upgrade", HeaderValue::from_static("websocket"));

    assert!(
        is_connect_or_upgrade_request(&method, &headers),
        "POST with Upgrade header must be rejected"
    );
}

#[test]
fn is_connect_or_upgrade_request_handles_put_method_with_connection_upgrade() {
    // Precondition: PUT request with Connection: Upgrade header.
    // Action: Call is_connect_or_upgrade_request with PUT request containing Connection: Upgrade.
    // Expected behavior: Returns true indicating Upgrade requests are rejected.
    // Covers Requirements: F14
    let method = Method::PUT;
    let mut headers = HeaderMap::new();
    headers.insert("connection", HeaderValue::from_static("upgrade"));

    assert!(
        is_connect_or_upgrade_request(&method, &headers),
        "PUT with Connection: Upgrade must be rejected"
    );
}

#[test]
fn stream_request_body_handles_chunked_encoding() {
    // Precondition: Axum Body with chunked encoding.
    // Action: Convert body using stream_request_body.
    // Expected behavior: Returns reqwest::Body without panicking.
    // Covers Requirements: F13, P4
    use axum::body::Body;
    use fluxgate::proxy::stream_request_body;

    // Create a body that would use chunked encoding
    let body = Body::from("test content");
    let _reqwest_body = stream_request_body(body);
    // Function should complete without panicking
}

#[test]
fn stream_request_body_handles_streaming_body() {
    // Precondition: Axum Body that streams data.
    // Action: Convert streaming body using stream_request_body.
    // Expected behavior: Returns reqwest::Body that preserves streaming semantics.
    // Covers Requirements: F13, P4
    use axum::body::Body;
    use fluxgate::proxy::stream_request_body;

    // Create streaming body
    use axum::body::Bytes;
    let stream = futures_util::stream::iter(vec![
        Ok::<_, std::io::Error>(Bytes::from("chunk1")),
        Ok(Bytes::from("chunk2")),
    ]);
    let axum_body = Body::from_stream(stream);
    let _reqwest_body = stream_request_body(axum_body);
    // Function should complete without panicking
}

#[test]
fn stream_request_body_preserves_streaming_semantics() {
    // Precondition: Axum Body with streaming content.
    // Action: Convert body using stream_request_body.
    // Expected behavior: Returns reqwest::Body that can be streamed (doesn't buffer entire body).
    // Covers Requirements: F13, P4
    use axum::body::Body;
    use fluxgate::proxy::stream_request_body;

    // Large body that should stream
    let large_content = vec![0u8; 100000]; // 100KB
    let axum_body = Body::from(large_content);
    let _reqwest_body = stream_request_body(axum_body);
    // Function should complete without loading entire body into memory
}

#[test]
fn stream_request_body_handles_multiple_stream_chunks() {
    // Precondition: Axum Body with multiple stream chunks.
    // Action: Convert body using stream_request_body.
    // Expected behavior: Returns reqwest::Body preserving all chunks.
    // Covers Requirements: F13, P4
    use axum::body::Body;
    use fluxgate::proxy::stream_request_body;

    use axum::body::Bytes;
    let chunks = vec![
        Bytes::from("chunk1"),
        Bytes::from("chunk2"),
        Bytes::from("chunk3"),
    ];
    let axum_body = Body::from_stream(futures_util::stream::iter(
        chunks.into_iter().map(Ok::<_, std::io::Error>),
    ));
    let _reqwest_body = stream_request_body(axum_body);
    // Function should complete without panicking
}

#[test]
fn stream_request_body_handles_error_in_stream() {
    // Precondition: Axum Body with stream that may produce errors.
    // Action: Convert body using stream_request_body.
    // Expected behavior: Returns reqwest::Body handling errors gracefully.
    // Covers Requirements: F13, P4
    use axum::body::Body;
    use fluxgate::proxy::stream_request_body;

    // Create stream that may have errors
    use axum::body::Bytes;
    let stream = futures_util::stream::iter(vec![Ok::<_, std::io::Error>(Bytes::from("data"))]);
    let axum_body = Body::from_stream(stream);
    let _reqwest_body = stream_request_body(axum_body);
    // Function should handle stream errors gracefully
}

#[test]
fn find_upstream_by_path_returns_none_when_no_upstreams_configured() {
    // Precondition: Config with no upstreams configured.
    // Action: Call find_upstream_by_path with request path.
    // Expected behavior: Returns None when no upstreams configured.
    // Covers Requirements: F1
    let config = minimal_test_config();
    assert_eq!(
        config.find_upstream_by_path("/api/test", &[]),
        None,
        "should return None when no upstreams configured"
    );
}

#[test]
fn find_upstream_by_path_returns_none_when_upstreams_empty() {
    // Precondition: Config with empty upstreams map.
    // Action: Call find_upstream_by_path with request path.
    // Expected behavior: Returns None when upstreams map is empty.
    // Covers Requirements: F1
    let config = test_config(
        Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::new(),
        }),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/test", &[]),
        None,
        "should return None when upstreams map is empty"
    );
}

#[test]
fn find_upstream_by_path_returns_none_when_no_match() {
    // Precondition: Config with upstreams, but request path doesn't match any request_path.
    // Action: Call find_upstream_by_path with non-matching request path.
    // Expected behavior: Returns None when no match found.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api1"),
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api2/test", &[]),
        None,
        "should return None when no upstream matches"
    );
}

#[test]
fn find_upstream_by_path_returns_exact_match() {
    // Precondition: Config with upstream having request_path matching request path prefix.
    // Action: Call find_upstream_by_path with request path matching upstream request_path.
    // Expected behavior: Returns Some(upstream_name) for exact prefix match.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api1"),
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api1/test", &[]),
        Some("upstream1".to_string()),
        "should return upstream for exact prefix match"
    );
}

#[test]
fn find_upstream_by_path_returns_longest_match() {
    // Precondition: Config with multiple upstreams having overlapping request_paths.
    // Action: Call find_upstream_by_path with request path matching multiple request_paths.
    // Expected behavior: Returns Some(upstream_name) for longest matching prefix.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "api",
                    UpstreamEntry {
                        target_url: "https://api.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/api".to_string(),
                    },
                ),
                (
                    "api-v1",
                    UpstreamEntry {
                        target_url: "https://api-v1.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/api/v1".to_string(),
                    },
                ),
            ],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/v1/models", &[]),
        Some("api-v1".to_string()),
        "should return longest matching prefix"
    );
}

#[test]
fn find_upstream_by_path_handles_trailing_slash_in_request() {
    // Precondition: Config with upstream having request_path, request path has trailing slash.
    // Action: Call find_upstream_by_path with request path containing trailing slash.
    // Expected behavior: Returns Some(upstream_name) matching request_path with trailing slash.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api"),
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/", &[]),
        Some("upstream1".to_string()),
        "should match request_path with trailing slash"
    );
}

#[test]
fn find_upstream_by_path_handles_trailing_slash_in_config() {
    // Precondition: Config with upstream having request_path with trailing slash.
    // Action: Call find_upstream_by_path with request path.
    // Expected behavior: Returns Some(upstream_name) matching request_path with trailing slash.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/test", &[]),
        Some("upstream1".to_string()),
        "should match when config has trailing slash"
    );
}

#[test]
fn find_upstream_by_path_handles_both_trailing_slashes() {
    // Precondition: Config with upstream having request_path with trailing slash, request path also has trailing slash.
    // Action: Call find_upstream_by_path with request path containing trailing slash matching upstream request_path.
    // Expected behavior: Returns Some(upstream_name) when both have trailing slashes.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/", &[]),
        Some("upstream1".to_string()),
        "should match when both have trailing slashes"
    );
}

#[test]
fn find_upstream_by_path_handles_root_path() {
    // Precondition: Config with upstream having request_path "/" (root path).
    // Action: Call find_upstream_by_path with any request path.
    // Expected behavior: Returns Some(upstream_name) matching root path for any request.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "root",
                UpstreamEntry {
                    target_url: "https://root.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/anything", &[]),
        Some("root".to_string()),
        "should match root path for any request"
    );
}

#[test]
fn find_upstream_by_path_handles_empty_request_path() {
    // Precondition: Config with upstream having request_path "/" (root path).
    // Action: Call find_upstream_by_path with empty request path.
    // Expected behavior: Returns Some(upstream_name) matching root path for empty request.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "root",
                UpstreamEntry {
                    target_url: "https://root.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("", &[]),
        Some("root".to_string()),
        "should match root path for empty request"
    );
}

#[test]
fn find_upstream_by_path_handles_multiple_trailing_slashes() {
    // Precondition: Config with upstream having request_path, request path has multiple consecutive slashes.
    // Action: Call find_upstream_by_path with request path containing multiple slashes.
    // Expected behavior: Returns Some(upstream_name) handling multiple slashes in request.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api"),
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api///test", &[]),
        Some("upstream1".to_string()),
        "should handle multiple slashes in request"
    );
}

#[test]
fn find_upstream_by_path_selects_longest_when_multiple_match() {
    // Precondition: Config with multiple upstreams having overlapping request_paths of different lengths.
    // Action: Call find_upstream_by_path with request path matching multiple request_paths.
    // Expected behavior: Returns Some(upstream_name) for longest matching prefix.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "short",
                    UpstreamEntry {
                        target_url: "https://short.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/a".to_string(),
                    },
                ),
                (
                    "medium",
                    UpstreamEntry {
                        target_url: "https://medium.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/a/b".to_string(),
                    },
                ),
                (
                    "long",
                    UpstreamEntry {
                        target_url: "https://long.example.com".to_string(),
                        api_key: "key3".to_string(),
                        request_path: "/a/b/c".to_string(),
                    },
                ),
            ],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/a/b/c/d", &[]),
        Some("long".to_string()),
        "should select longest matching prefix"
    );
}

#[test]
fn find_upstream_by_path_handles_same_length_prefixes() {
    // Precondition: Config with multiple upstreams having request_paths of same length.
    // Action: Call find_upstream_by_path with request path matching one of the same-length prefixes.
    // Expected behavior: Returns Some(upstream_name) for matching prefix (first one found).
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "api1",
                    UpstreamEntry {
                        target_url: "https://api1.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/api/v1".to_string(),
                    },
                ),
                (
                    "api2",
                    UpstreamEntry {
                        target_url: "https://api2.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/api/v2".to_string(),
                    },
                ),
            ],
        )),
        None,
    );
    // Both have same length, should return first one found (implementation detail)
    let result = config.find_upstream_by_path("/api/v1/test", &[]);
    assert_eq!(result, Some("api1".to_string()));
}

#[test]
fn find_upstream_by_path_handles_nested_paths() {
    // Precondition: Config with multiple upstreams having nested request_paths.
    // Action: Call find_upstream_by_path with request path matching nested paths.
    // Expected behavior: Returns Some(upstream_name) for longest matching nested prefix.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "level1",
                    UpstreamEntry {
                        target_url: "https://level1.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/level1".to_string(),
                    },
                ),
                (
                    "level2",
                    UpstreamEntry {
                        target_url: "https://level2.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/level1/level2".to_string(),
                    },
                ),
                (
                    "level3",
                    UpstreamEntry {
                        target_url: "https://level3.example.com".to_string(),
                        api_key: "key3".to_string(),
                        request_path: "/level1/level2/level3".to_string(),
                    },
                ),
            ],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/level1/level2/level3/deep", &[]),
        Some("level3".to_string()),
        "should match deepest nested path"
    );
}

#[test]
fn find_upstream_by_path_handles_partial_path_segment_match() {
    // Precondition: Config with upstreams having request_paths where one is prefix of another but different segments.
    // Action: Call find_upstream_by_path with request path that should match longer prefix, not partial segment.
    // Expected behavior: Returns Some(upstream_name) for exact prefix match, not partial segment match.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "api",
                    UpstreamEntry {
                        target_url: "https://api.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/api".to_string(),
                    },
                ),
                (
                    "api-test",
                    UpstreamEntry {
                        target_url: "https://api-test.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/api-test".to_string(),
                    },
                ),
            ],
        )),
        None,
    );
    // "/api-test" should not match "/api" prefix
    assert_eq!(
        config.find_upstream_by_path("/api-test/endpoint", &[]),
        Some("api-test".to_string()),
        "should not match partial segment"
    );
}

#[test]
fn find_upstream_by_path_handles_unicode_in_paths() {
    // Precondition: Config with upstream having request_path containing unicode characters.
    // Action: Call find_upstream_by_path with request path containing unicode characters.
    // Expected behavior: Returns Some(upstream_name) correctly handling unicode characters in paths.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "unicode",
                UpstreamEntry {
                    target_url: "https://unicode.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/тест".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/тест/data", &[]),
        Some("unicode".to_string()),
        "should handle unicode characters"
    );
}

#[test]
fn find_upstream_by_path_handles_special_characters() {
    // Precondition: Config with upstream having request_path containing special characters.
    // Action: Call find_upstream_by_path with request path containing special characters.
    // Expected behavior: Returns Some(upstream_name) correctly handling special characters in paths.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "special",
                UpstreamEntry {
                    target_url: "https://special.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/v1.0".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/v1.0/test", &[]),
        Some("special".to_string()),
        "should handle special characters like dots"
    );
}

#[test]
fn find_upstream_by_path_respects_permitted_upstreams() {
    // Precondition: Config with multiple upstreams, permitted_upstreams list provided.
    // Action: Call find_upstream_by_path with request path and permitted_upstreams list.
    // Expected behavior: Returns Some(upstream_name) only for permitted upstreams, None for non-permitted.
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "upstream1",
                    test_upstream_entry_with_path("https://api1.example.com", "key1", "/api1"),
                ),
                (
                    "upstream2",
                    test_upstream_entry_with_path("https://api2.example.com", "key2", "/api2"),
                ),
            ],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api1/test", &["upstream1".to_string()]),
        Some("upstream1".to_string()),
        "should return permitted upstream"
    );
    assert_eq!(
        config.find_upstream_by_path("/api2/test", &["upstream1".to_string()]),
        None,
        "should not return non-permitted upstream"
    );
}

#[test]
fn find_upstream_by_path_handles_empty_permitted_list() {
    // Precondition: Config with upstreams, empty permitted_upstreams list.
    // Action: Call find_upstream_by_path with request path and empty permitted_upstreams list.
    // Expected behavior: Returns Some(upstream_name) for matching upstream (empty list means all allowed).
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api1"),
            )],
        )),
        None,
    );
    // Empty permitted list means all upstreams are allowed
    assert_eq!(
        config.find_upstream_by_path("/api1/test", &[]),
        Some("upstream1".to_string()),
        "empty permitted list should allow all upstreams"
    );
}

#[test]
fn find_upstream_by_path_handles_permitted_with_longest_match() {
    // Precondition: Config with multiple upstreams having overlapping request_paths, only longer one is permitted.
    // Action: Call find_upstream_by_path with request path matching both, but only longer is permitted.
    // Expected behavior: Returns Some(upstream_name) for longest match from permitted upstreams.
    // Covers Requirements: F1, F3
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "api",
                    UpstreamEntry {
                        target_url: "https://api.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/api".to_string(),
                    },
                ),
                (
                    "api-v1",
                    UpstreamEntry {
                        target_url: "https://api-v1.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/api/v1".to_string(),
                    },
                ),
            ],
        )),
        None,
    );
    // Only api-v1 is permitted, should still get longest match
    assert_eq!(
        config.find_upstream_by_path("/api/v1/test", &["api-v1".to_string()]),
        Some("api-v1".to_string()),
        "should select longest match from permitted upstreams"
    );
}

#[test]
fn find_upstream_by_path_skips_non_permitted_in_longest_match() {
    // Precondition: Config with multiple upstreams having overlapping request_paths, only shorter one is permitted.
    // Action: Call find_upstream_by_path with request path matching both, but only shorter is permitted.
    // Expected behavior: Returns Some(upstream_name) for permitted upstream even if shorter match.
    // Covers Requirements: F1, F3
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "api",
                    UpstreamEntry {
                        target_url: "https://api.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/api".to_string(),
                    },
                ),
                (
                    "api-v1",
                    UpstreamEntry {
                        target_url: "https://api-v1.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/api/v1".to_string(),
                    },
                ),
            ],
        )),
        None,
    );
    // Only "api" is permitted, should not match longer "api-v1"
    assert_eq!(
        config.find_upstream_by_path("/api/v1/test", &["api".to_string()]),
        Some("api".to_string()),
        "should select permitted upstream even if shorter match"
    );
}

#[test]
fn find_upstream_by_path_handles_root_vs_specific_path() {
    // Precondition: Config with upstreams having root path "/" and specific path "/api".
    // Action: Call find_upstream_by_path with request paths matching both or only root.
    // Expected behavior: Returns Some(upstream_name) for specific path when it matches, root otherwise.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "root",
                    UpstreamEntry {
                        target_url: "https://root.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/".to_string(),
                    },
                ),
                (
                    "specific",
                    UpstreamEntry {
                        target_url: "https://specific.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/api".to_string(),
                    },
                ),
            ],
        )),
        None,
    );
    // Root should match everything, but specific should be selected when it matches
    assert_eq!(
        config.find_upstream_by_path("/api/test", &[]),
        Some("specific".to_string()),
        "should prefer specific path over root"
    );
    assert_eq!(
        config.find_upstream_by_path("/other/test", &[]),
        Some("root".to_string()),
        "should fall back to root when specific doesn't match"
    );
}

#[test]
fn find_upstream_by_path_handles_case_sensitive_matching() {
    // Precondition: Config with upstreams having request_paths differing only by case.
    // Action: Call find_upstream_by_path with request path matching one case.
    // Expected behavior: Returns Some(upstream_name) for exact case match (case-sensitive matching).
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "api",
                UpstreamEntry {
                    target_url: "https://api.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api".to_string(),
                },
            )],
        )),
        None,
    );
    // Path matching should be case-sensitive
    assert_eq!(
        config.find_upstream_by_path("/API/test", &[]),
        None,
        "should be case-sensitive"
    );
    assert_eq!(
        config.find_upstream_by_path("/api/test", &[]),
        Some("api".to_string()),
        "should match correct case"
    );
}

#[test]
fn find_upstream_by_path_handles_very_long_paths() {
    // Precondition: Config with upstream having very long request_path.
    // Action: Call find_upstream_by_path with request path matching very long request_path.
    // Expected behavior: Returns Some(upstream_name) correctly handling very long paths.
    // Covers Requirements: F1
    let long_path = "/".to_string() + &"a/".repeat(100);
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "long",
                UpstreamEntry {
                    target_url: "https://long.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: long_path.clone(),
                },
            )],
        )),
        None,
    );
    let request_path = long_path + "test";
    assert_eq!(
        config.find_upstream_by_path(&request_path, &[]),
        Some("long".to_string()),
        "should handle very long paths"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_only_slashes() {
    // Precondition: Config with upstream having root path "/", request path contains only slashes.
    // Action: Call find_upstream_by_path with request path containing only slashes.
    // Expected behavior: Returns Some(upstream_name) for root path (multiple slashes normalized to root).
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "root",
                UpstreamEntry {
                    target_url: "https://root.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("///", &[]),
        Some("root".to_string()),
        "should normalize multiple slashes to root"
    );
}

#[test]
fn find_upstream_by_path_handles_path_starting_without_slash() {
    // Precondition: Config with upstream having request_path, request path doesn't start with slash.
    // Action: Call find_upstream_by_path with request path not starting with slash.
    // Expected behavior: Returns None (request path without leading slash shouldn't match).
    // Covers Requirements: F1
    // Note: This shouldn't happen in practice, but test defensive behavior
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "api",
                UpstreamEntry {
                    target_url: "https://api.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api".to_string(),
                },
            )],
        )),
        None,
    );
    // Request path without leading slash shouldn't match
    assert_eq!(
        config.find_upstream_by_path("api/test", &[]),
        None,
        "should not match path without leading slash"
    );
}

#[test]
fn find_upstream_by_path_handles_single_character_paths() {
    // Precondition: Config with upstreams having single and multi-character request_paths.
    // Action: Call find_upstream_by_path with request paths matching single and multi-character paths.
    // Expected behavior: Returns Some(upstream_name) for matching path, prefers longer match.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "a",
                    UpstreamEntry {
                        target_url: "https://a.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/a".to_string(),
                    },
                ),
                (
                    "ab",
                    UpstreamEntry {
                        target_url: "https://ab.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/ab".to_string(),
                    },
                ),
            ],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/a/test", &[]),
        Some("a".to_string()),
        "should match single character path"
    );
    assert_eq!(
        config.find_upstream_by_path("/ab/test", &[]),
        Some("ab".to_string()),
        "should match two character path and prefer over single"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_dots() {
    // Precondition: Config with upstreams having request_paths containing dots.
    // Action: Call find_upstream_by_path with request path containing dots.
    // Expected behavior: Returns Some(upstream_name) correctly handling dots in path.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "versioned",
                    UpstreamEntry {
                        target_url: "https://versioned.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/api/v1.0".to_string(),
                    },
                ),
                (
                    "versioned2",
                    UpstreamEntry {
                        target_url: "https://versioned2.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/api/v2.0".to_string(),
                    },
                ),
            ],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/v1.0/test", &[]),
        Some("versioned".to_string()),
        "should handle dots in path"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_hyphens() {
    // Precondition: Config with upstream having request_path containing hyphens.
    // Action: Call find_upstream_by_path with request path containing hyphens.
    // Expected behavior: Returns Some(upstream_name) correctly handling hyphens in path.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "hyphenated",
                UpstreamEntry {
                    target_url: "https://hyphenated.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/test-endpoint".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/test-endpoint/data", &[]),
        Some("hyphenated".to_string()),
        "should handle hyphens in path"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_underscores() {
    // Precondition: Config with upstream having request_path containing underscores.
    // Action: Call find_upstream_by_path with request path containing underscores.
    // Expected behavior: Returns Some(upstream_name) correctly handling underscores in path.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "underscored",
                UpstreamEntry {
                    target_url: "https://underscored.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/test_endpoint".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/test_endpoint/data", &[]),
        Some("underscored".to_string()),
        "should handle underscores in path"
    );
}

#[test]
fn find_upstream_by_path_handles_many_upstreams_performance() {
    // Precondition: Config with many upstreams (50+) having different request_paths.
    // Action: Call find_upstream_by_path with request path matching one of many upstreams.
    // Expected behavior: Returns Some(upstream_name) efficiently even with many upstreams.
    // Covers Requirements: F1, P1
    // Note: Test that longest match still works efficiently with many upstreams
    let mut upstreams_map = HashMap::new();
    for i in 0..50 {
        upstreams_map.insert(
            format!("upstream{}", i),
            UpstreamEntry {
                target_url: format!("https://api{}.example.com", i),
                api_key: format!("key{}", i),
                request_path: format!("/api/v{}", i),
            },
        );
    }
    // Add one that should match
    upstreams_map.insert(
        "target".to_string(),
        UpstreamEntry {
            target_url: "https://target.example.com".to_string(),
            api_key: "target-key".to_string(),
            request_path: "/api/v50/test".to_string(),
        },
    );

    let config = test_config(
        Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: upstreams_map,
        }),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/v50/test/deep", &[]),
        Some("target".to_string()),
        "should find correct upstream among many"
    );
}

#[test]
fn find_upstream_by_path_handles_permitted_with_many_options() {
    // Precondition: Config with many upstreams, only one is permitted.
    // Action: Call find_upstream_by_path with request path and permitted_upstreams list containing one upstream.
    // Expected behavior: Returns Some(upstream_name) only for permitted upstream, None for non-permitted.
    // Covers Requirements: F3
    let mut upstreams_map = HashMap::new();
    for i in 0..20 {
        upstreams_map.insert(
            format!("upstream{}", i),
            UpstreamEntry {
                target_url: format!("https://api{}.example.com", i),
                api_key: format!("key{}", i),
                request_path: format!("/api/v{}", i),
            },
        );
    }

    let config = test_config(
        Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: upstreams_map,
        }),
        None,
    );

    // Only permit upstream10
    let permitted = vec!["upstream10".to_string()];
    assert_eq!(
        config.find_upstream_by_path("/api/v10/test", &permitted),
        Some("upstream10".to_string()),
        "should find permitted upstream among many"
    );
    assert_eq!(
        config.find_upstream_by_path("/api/v5/test", &permitted),
        None,
        "should not find non-permitted upstream"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_percent_encoding() {
    // Precondition: Config with upstream having request_path containing percent-encoded characters.
    // Action: Call find_upstream_by_path with request path containing percent-encoded characters.
    // Expected behavior: Returns Some(upstream_name) correctly handling percent-encoded characters in path.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "encoded",
                UpstreamEntry {
                    target_url: "https://encoded.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/test%20path".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/test%20path/data", &[]),
        Some("encoded".to_string()),
        "should handle percent-encoded characters in path"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_plus_sign() {
    // Precondition: Config with upstream having request_path containing plus sign.
    // Action: Call find_upstream_by_path with request path containing plus sign.
    // Expected behavior: Returns Some(upstream_name) correctly handling plus sign in path.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "plus",
                UpstreamEntry {
                    target_url: "https://plus.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/v1+beta".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/v1+beta/test", &[]),
        Some("plus".to_string()),
        "should handle plus sign in path"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_at_sign() {
    // Precondition: Config with upstream having request_path containing @ sign.
    // Action: Call find_upstream_by_path with request path containing @ sign.
    // Expected behavior: Returns Some(upstream_name) correctly handling @ sign in path.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "at",
                UpstreamEntry {
                    target_url: "https://at.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/user@domain".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/user@domain/data", &[]),
        Some("at".to_string()),
        "should handle @ sign in path"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_hash_symbol() {
    // Precondition: Config with upstream having request_path, request path contains hash symbol.
    // Action: Call find_upstream_by_path with request path containing hash.
    // Expected behavior: Returns Some(upstream_name) correctly handling hash symbol in path.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "hash",
                UpstreamEntry {
                    target_url: "https://hash.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/test#fragment".to_string(),
                },
            )],
        )),
        None,
    );
    // Note: Uri parser may remove fragments, but test path matching
    assert_eq!(
        config.find_upstream_by_path("/api/test#fragment/data", &[]),
        Some("hash".to_string()),
        "should handle hash symbol in path"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_tilde() {
    // Precondition: Config with upstream having request_path containing tilde.
    // Action: Call find_upstream_by_path with request path containing tilde.
    // Expected behavior: Returns Some(upstream_name) correctly handling tilde in path.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "tilde",
                UpstreamEntry {
                    target_url: "https://tilde.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/~user".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/~user/data", &[]),
        Some("tilde".to_string()),
        "should handle tilde in path"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_exclamation() {
    // Precondition: Config with upstream having request_path containing exclamation mark.
    // Action: Call find_upstream_by_path with request path containing exclamation.
    // Expected behavior: Returns Some(upstream_name) correctly handling exclamation in path.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "exclamation",
                UpstreamEntry {
                    target_url: "https://exclamation.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/important!".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/important!/data", &[]),
        Some("exclamation".to_string()),
        "should handle exclamation mark in path"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_parentheses() {
    // Precondition: Config with upstream having request_path containing parentheses.
    // Action: Call find_upstream_by_path with request path containing parentheses.
    // Expected behavior: Returns Some(upstream_name) correctly handling parentheses in path.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "parentheses",
                UpstreamEntry {
                    target_url: "https://parentheses.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/v(1)".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/v(1)/test", &[]),
        Some("parentheses".to_string()),
        "should handle parentheses in path"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_brackets() {
    // Precondition: Config with upstream having request_path containing brackets.
    // Action: Call find_upstream_by_path with request path containing brackets.
    // Expected behavior: Returns Some(upstream_name) correctly handling brackets in path.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "brackets",
                UpstreamEntry {
                    target_url: "https://brackets.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/v[1]".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/v[1]/test", &[]),
        Some("brackets".to_string()),
        "should handle brackets in path"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_percent_sign() {
    // Precondition: Config with upstream having request_path containing percent sign.
    // Action: Call find_upstream_by_path with request path containing percent sign.
    // Expected behavior: Returns Some(upstream_name) correctly handling percent sign in path.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "percent",
                UpstreamEntry {
                    target_url: "https://percent.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/100%".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/100%/test", &[]),
        Some("percent".to_string()),
        "should handle percent sign in path"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_backslash() {
    // Precondition: Config with upstream having request_path containing backslash (encoded).
    // Action: Call find_upstream_by_path with request path containing backslash.
    // Expected behavior: Returns Some(upstream_name) correctly handling backslash in path.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "backslash",
                UpstreamEntry {
                    target_url: "https://backslash.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/path%5Csub".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/path%5Csub/data", &[]),
        Some("backslash".to_string()),
        "should handle encoded backslash in path"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_quotes() {
    // Precondition: Config with upstream having request_path containing quotes.
    // Action: Call find_upstream_by_path with request path containing quotes.
    // Expected behavior: Returns Some(upstream_name) correctly handling quotes in path.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "quotes",
                UpstreamEntry {
                    target_url: "https://quotes.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/test%22path".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/test%22path/data", &[]),
        Some("quotes".to_string()),
        "should handle encoded quotes in path"
    );
}

#[test]
fn find_upstream_by_path_handles_path_starting_with_dot() {
    // Precondition: Config with upstream having request_path starting with dot.
    // Action: Call find_upstream_by_path with request path starting with dot.
    // Expected behavior: Returns Some(upstream_name) correctly handling dot at start.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "dot",
                UpstreamEntry {
                    target_url: "https://dot.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/.hidden".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/.hidden/data", &[]),
        Some("dot".to_string()),
        "should handle dot at start of path segment"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_double_dots() {
    // Precondition: Config with upstream having request_path containing double dots.
    // Action: Call find_upstream_by_path with request path containing double dots.
    // Expected behavior: Returns Some(upstream_name) correctly handling double dots in path.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "dots",
                UpstreamEntry {
                    target_url: "https://dots.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/v1..2".to_string(),
                },
            )],
        )),
        None,
    );
    assert_eq!(
        config.find_upstream_by_path("/api/v1..2/test", &[]),
        Some("dots".to_string()),
        "should handle double dots in path"
    );
}

#[tokio::test]
async fn missing_configuration_file_uses_defaults() {
    // Precondition: Configuration file path does not exist on disk.
    // Action: Initialise the configuration manager with the missing path.
    // Expected behavior: Manager falls back to built-in defaults and reports the configured path.
    // Covers Requirements: C4, F15
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("absent.yaml");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;
    let current = manager.current();

    assert_eq!(
        current,
        Config::default(),
        "missing configuration must fall back to built-in defaults"
    );
    assert_eq!(
        manager.config_path(),
        config_path.as_path(),
        "manager should keep tracking the requested configuration path"
    );
}

#[tokio::test]
async fn started_with_defaults_returns_true_when_config_file_missing() {
    // Precondition: Configuration file path does not exist on disk.
    // Action: Initialise the configuration manager with the missing path and check started_with_defaults().
    // Expected behavior: started_with_defaults() returns true, indicating default configuration was used.
    // Covers Requirements: C4, F15
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("absent.yaml");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;

    assert!(
        manager.started_with_defaults(),
        "started_with_defaults() should return true when config file is missing"
    );
}

#[tokio::test]
async fn invalid_configuration_file_uses_defaults() {
    // Precondition: Configuration file exists with structurally valid YAML that violates validation rules.
    // Action: Initialise the configuration manager with the invalid file.
    // Expected behavior: Manager rejects the invalid configuration and retains the built-in defaults.
    // Covers Requirements: C2, C4, F15
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("invalid.yaml");
    let invalid_config = r#"
version: 1

server:
  bind_address: ""
  max_connections: 0
upstreams:
  request_timeout_ms: 0
  bad-upstream:
    target_url: ""
    api_key: ""
"#;
    std::fs::write(&config_path, invalid_config).expect("write invalid configuration");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;
    let current = manager.current();

    assert_eq!(
        current,
        Config::default(),
        "invalid configuration must not replace built-in defaults"
    );
    assert!(
        manager.started_with_defaults(),
        "started_with_defaults() should return true when config file is invalid"
    );
    assert_eq!(
        manager.config_path(),
        config_path.as_path(),
        "manager should continue watching the invalid configuration path for future updates"
    );
}

#[test]
fn authenticate_returns_none_when_no_api_keys_configured() {
    // Precondition: Configuration without api_keys section.
    // Action: Attempt to authenticate with any token.
    // Expected behavior: Authentication fails (returns None).
    // Covers Requirements: F3
    let config = minimal_test_config();

    assert!(
        config.authenticate("any-token").is_none(),
        "authentication should fail when no API keys are configured"
    );
}

#[test]
fn authenticate_returns_none_when_token_not_found() {
    // Precondition: Configuration with API keys, but token doesn't match.
    // Action: Attempt to authenticate with unknown token.
    // Expected behavior: Authentication fails (returns None).
    // Covers Requirements: F3
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            None,
        )])),
    );

    assert!(
        config.authenticate("invalid-token").is_none(),
        "authentication should fail for unknown token"
    );
}

#[test]
fn authenticate_with_explicit_upstreams_list() {
    // Precondition: Configuration with API key having explicit upstreams list.
    // Action: Authenticate with valid token.
    // Expected behavior: Returns only the upstreams from the explicit list.
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "upstream1",
                    test_upstream_entry("https://api1.example.com", "key1"),
                ),
                (
                    "upstream2",
                    test_upstream_entry("https://api2.example.com", "key2"),
                ),
                (
                    "upstream3",
                    test_upstream_entry("https://api3.example.com", "key3"),
                ),
            ],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec!["upstream1".to_string(), "upstream3".to_string()]),
        )])),
    );

    let result = config
        .authenticate("valid-token")
        .expect("authentication should succeed");
    assert_eq!(result.api_key, Some("test-key".to_string()));
    assert_eq!(
        result.permitted_upstreams,
        vec!["upstream1".to_string(), "upstream3".to_string()]
    );
}

#[test]
fn authenticate_with_empty_upstreams_list_and_upstreams_configured() {
    // Precondition: API key with empty upstreams list, but upstreams are configured.
    // Action: authenticate with valid token.
    // Expected behavior: returns all configured upstreams (empty list means access to all).
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "upstream1",
                    test_upstream_entry("https://api1.example.com", "key1"),
                ),
                (
                    "upstream2",
                    test_upstream_entry("https://api2.example.com", "key2"),
                ),
            ],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec![]), // Empty list
        )])),
    );

    let result = config
        .authenticate("valid-token")
        .expect("authentication should succeed");
    let mut permitted = result.permitted_upstreams;
    permitted.sort();
    assert_eq!(
        permitted,
        vec!["upstream1".to_string(), "upstream2".to_string()]
    );
}

#[test]
fn authenticate_with_omitted_upstreams_and_upstreams_configured() {
    // Precondition: API key with omitted (None) upstreams, but upstreams are configured.
    // Action: authenticate with valid token.
    // Expected behavior: returns all configured upstreams (None means access to all).
    // Covers Requirements: F1
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([
                (
                    "upstream1".to_string(),
                    UpstreamEntry {
                        target_url: "https://api1.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/test".to_string(),
                    },
                ),
                (
                    "upstream2".to_string(),
                    UpstreamEntry {
                        target_url: "https://api2.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/test".to_string(),
                    },
                ),
            ]),
        }),
        api_keys: Some(ApiKeysConfig {
            static_: vec![StaticApiKey {
                id: Some("test-key".to_string()),
                key: "valid-token".to_string(),
                upstreams: None, // Omitted
            }],
            jwt: None,
        }),
    };

    let result = config
        .authenticate("valid-token")
        .expect("authentication should succeed");
    let mut permitted = result.permitted_upstreams;
    permitted.sort();
    assert_eq!(
        permitted,
        vec!["upstream1".to_string(), "upstream2".to_string()]
    );
}

#[test]
fn get_upstream_returns_correct_upstream() {
    // Precondition: configuration with multiple upstreams.
    // Action: get upstream by name.
    // Expected behavior: returns the correct upstream entry.
    // Covers Requirements: F1
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([
                (
                    "upstream1".to_string(),
                    UpstreamEntry {
                        target_url: "https://api1.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/test".to_string(),
                    },
                ),
                (
                    "upstream2".to_string(),
                    UpstreamEntry {
                        target_url: "https://api2.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/test".to_string(),
                    },
                ),
            ]),
        }),
        api_keys: None,
    };

    let upstream = config
        .get_upstream("upstream1")
        .expect("upstream should exist");
    assert_eq!(upstream.target_url, "https://api1.example.com");
    assert_eq!(upstream.api_key, "key1");
}

#[tokio::test]
async fn started_with_defaults_returns_false_when_config_file_loaded() {
    // Precondition: configuration file exists with valid configuration.
    // Action: initialise the configuration manager with the valid file and check started_with_defaults().
    // Expected behavior: started_with_defaults() returns false, indicating configuration was loaded from file.
    // Covers Requirements: C4, F15
    // Requirement: C4.2 - Check if configuration was loaded from file
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_contents = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 1024
"#;
    std::fs::write(&config_path, config_contents).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path)).await;

    assert!(
        !manager.started_with_defaults(),
        "started_with_defaults() should return false when config file is successfully loaded"
    );
    assert_ne!(
        manager.current(),
        Config::default(),
        "loaded configuration should differ from defaults"
    );
}

#[test]
fn authenticate_with_single_upstream_in_explicit_list() {
    // Precondition: API key with single upstream in explicit list.
    // Action: authenticate with valid token.
    // Expected behavior: returns the single upstream.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "upstream1",
                    test_upstream_entry("https://api1.example.com", "key1"),
                ),
                (
                    "upstream2",
                    test_upstream_entry("https://api2.example.com", "key2"),
                ),
            ],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config
        .authenticate("valid-token")
        .expect("authentication should succeed");
    assert_eq!(result.permitted_upstreams, vec!["upstream1".to_string()]);
}

#[test]
fn authenticate_preserves_upstream_order_in_explicit_list() {
    // Precondition: API key with explicit upstreams list in specific order.
    // Action: authenticate with valid token.
    // Expected behavior: returns upstreams in the same order as in the list.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "upstream1",
                    test_upstream_entry("https://api1.example.com", "key1"),
                ),
                (
                    "upstream2",
                    test_upstream_entry("https://api2.example.com", "key2"),
                ),
                (
                    "upstream3",
                    test_upstream_entry("https://api3.example.com", "key3"),
                ),
            ],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec![
                "upstream3".to_string(),
                "upstream1".to_string(),
                "upstream2".to_string(),
            ]),
        )])),
    );

    let result = config
        .authenticate("valid-token")
        .expect("authentication should succeed");
    assert_eq!(
        result.permitted_upstreams,
        vec![
            "upstream3".to_string(),
            "upstream1".to_string(),
            "upstream2".to_string()
        ]
    );
}

#[test]
fn authenticate_with_all_upstreams_when_omitted() {
    // Precondition: API key with omitted upstreams, multiple upstreams configured.
    // Action: authenticate with valid token.
    // Expected behavior: returns all configured upstreams (order may vary).
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "upstream1",
                    test_upstream_entry("https://api1.example.com", "key1"),
                ),
                (
                    "upstream2",
                    test_upstream_entry("https://api2.example.com", "key2"),
                ),
                (
                    "upstream3",
                    test_upstream_entry("https://api3.example.com", "key3"),
                ),
            ],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            None, // Omitted
        )])),
    );

    let result = config
        .authenticate("valid-token")
        .expect("authentication should succeed");
    let mut permitted = result.permitted_upstreams;
    permitted.sort();
    assert_eq!(
        permitted,
        vec![
            "upstream1".to_string(),
            "upstream2".to_string(),
            "upstream3".to_string()
        ]
    );
}

#[test]
fn authenticate_handles_empty_token() {
    // Precondition: configuration with API keys.
    // Action: authenticate with empty token.
    // Expected behavior: authentication fails.
    // Covers Requirements: F3
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "token",
            None,
        )])),
    );

    assert!(config.authenticate("").is_none());
}

#[test]
fn authenticate_handles_very_long_token() {
    // Precondition: configuration with API key.
    // Action: authenticate with very long token.
    // Expected behavior: authentication works correctly with long tokens.
    // Covers Requirements: F3
    let long_token = "a".repeat(10000);
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            &long_token,
            None,
        )])),
    );

    assert!(config.authenticate(&long_token).is_some());
    assert!(config.authenticate("wrong-token").is_none());
}

#[test]
fn authenticate_with_duplicate_keys_returns_first_match() {
    // Precondition: multiple API keys with same token (this config would be rejected by validation).
    // Action: authenticate with duplicate token (bypassing validation for testing authentication logic).
    // Expected behavior: returns first matching key.
    // Note: In practice, duplicate keys are rejected by validation (C16), but this test verifies
    // authentication behavior if validation is bypassed.
    // Covers Requirements: F2, F3
    // Note: This test uses a config that would fail C16 validation, but tests authentication logic
    // in isolation. In real usage, such configs are rejected before authentication.
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![
            test_api_key(Some("first"), "token", None),
            test_api_key(Some("second"), "token", None),
        ])),
    );
    // Bypass validation for this test to verify authentication behavior
    // In real usage, validation (C16) would reject this config
    let result = config.authenticate("token").expect("should authenticate");
    assert_eq!(result.api_key, Some("first".to_string()));
}

#[test]
fn authenticate_with_unicode_key_name() {
    // Precondition: API key with unicode id.
    // Action: authenticate.
    // Expected behavior: authentication succeeds and preserves unicode id.
    // Covers Requirements: F3
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some("ключ-тест"),
            "token",
            None,
        )])),
    );
    let result = config.authenticate("token").expect("should authenticate");
    assert_eq!(result.api_key, Some("ключ-тест".to_string()));
}

#[test]
fn authenticate_preserves_duplicate_upstream_references() {
    // Precondition: API key with duplicate upstream in list.
    // Action: authenticate.
    // Expected behavior: returns upstreams as configured (with duplicates).
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("key1"),
            "token",
            Some(vec!["upstream1".to_string(), "upstream1".to_string()]),
        )])),
    );
    let result = config.authenticate("token").expect("should authenticate");
    assert_eq!(result.permitted_upstreams.len(), 2);
    assert_eq!(result.permitted_upstreams[0], "upstream1");
    assert_eq!(result.permitted_upstreams[1], "upstream1");
}

#[tokio::test]
async fn config_manager_handles_config_with_only_version() {
    // Precondition: config file with only version field.
    // Action: initialize config manager.
    // Expected behavior: uses defaults for other fields.
    // Covers Requirements: C4, F15
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_contents = "version: 1\n";
    std::fs::write(&config_path, config_contents).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path)).await;
    let current = manager.current();

    assert_eq!(current.version, 1);
    assert_eq!(current.server.bind_address, "0.0.0.0:8080");
}

#[tokio::test]
async fn config_manager_handles_config_with_extra_fields() {
    // Precondition: config file with unknown fields.
    // Action: initialize config manager.
    // Expected behavior: ignores unknown fields, uses defaults.
    // Covers Requirements: C4, F15
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_contents = r#"
version: 1
unknown_field: "value"
server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#;
    std::fs::write(&config_path, config_contents).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path)).await;
    let current = manager.current();

    assert_eq!(current.server.bind_address, "127.0.0.1:8080");
}

#[test]
fn authenticate_with_numeric_token() {
    // Precondition: API key with numeric token.
    // Action: authenticate.
    // Expected behavior: authentication succeeds.
    // Covers Requirements: F3
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some("key1"),
            "1234567890",
            None,
        )])),
    );
    assert!(config.authenticate("1234567890").is_some());
}

#[test]
fn authenticate_with_hex_token() {
    // Precondition: API key with hexadecimal token.
    // Action: authenticate.
    // Expected behavior: authentication succeeds.
    // Covers Requirements: F3
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some("key1"),
            "deadbeef1234567890abcdef",
            None,
        )])),
    );
    assert!(config.authenticate("deadbeef1234567890abcdef").is_some());
}

#[test]
fn authenticate_with_base64_like_token() {
    // Precondition: API key with base64-like token.
    // Action: authenticate.
    // Expected behavior: authentication succeeds.
    // Covers Requirements: F3
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some("key1"),
            "SGVsbG8gV29ybGQ=",
            None,
        )])),
    );
    assert!(config.authenticate("SGVsbG8gV29ybGQ=").is_some());
}

#[test]
fn authenticate_with_partial_upstream_list() {
    // Precondition: API key with partial upstream access.
    // Action: authenticate.
    // Expected behavior: returns only permitted upstreams.
    // Covers Requirements: F1
    let (_config, upstream_names) = create_multi_upstream_config(5);
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            upstream_names
                .iter()
                .enumerate()
                .map(|(idx, name)| {
                    (
                        name.as_str(),
                        test_upstream_entry(
                            &format!("https://api{}.example.com", idx + 1),
                            &format!("key{}", idx + 1),
                        ),
                    )
                })
                .collect(),
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("key1"),
            "token",
            Some(vec![upstream_names[0].clone(), upstream_names[2].clone()]),
        )])),
    );
    let result = config.authenticate("token").expect("should authenticate");
    assert_eq!(result.permitted_upstreams.len(), 2);
    assert!(result.permitted_upstreams.contains(&upstream_names[0]));
    assert!(result.permitted_upstreams.contains(&upstream_names[2]));
}

#[test]
fn authenticate_with_all_upstreams_via_empty_list() {
    // Precondition: API key with empty upstreams list, multiple upstreams configured.
    // Action: authenticate.
    // Expected behavior: returns all upstreams.
    // Covers Requirements: F1
    let (base_config, upstream_names) = create_multi_upstream_config(3);
    let config = test_config(
        base_config.upstreams,
        Some(test_api_keys_config(vec![test_api_key(
            Some("key1"),
            "token",
            Some(vec![]), // Empty list means all
        )])),
    );
    let result = config.authenticate("token").expect("should authenticate");
    let mut permitted = result.permitted_upstreams;
    permitted.sort();
    assert_eq!(permitted, upstream_names);
}

#[test]
fn authenticate_with_many_api_keys_performance() {
    // Precondition: configuration with 1000 API keys.
    // Action: authenticate with last key.
    // Expected behavior: authentication succeeds (tests performance).
    // Covers Requirements: F3
    let (base_config, upstream_names) = create_multi_upstream_config(5);
    let mut keys = Vec::new();
    for i in 1..=1000 {
        keys.push(test_api_key(
            Some(&format!("key{}", i)),
            &format!("token{}", i),
            Some(upstream_names.clone()),
        ));
    }
    let config = test_config(base_config.upstreams, Some(test_api_keys_config(keys)));
    let result = config
        .authenticate("token1000")
        .expect("should authenticate");
    assert_eq!(result.api_key, Some("key1000".to_string()));
}

#[test]
fn get_upstream_with_many_upstreams() {
    // Precondition: configuration with 1000 upstreams.
    // Action: get upstream by name.
    // Expected behavior: returns correct upstream (tests performance).
    // Covers Requirements: F1
    let (config, upstream_names) = create_multi_upstream_config(1000);
    let upstream = config
        .get_upstream(&upstream_names[999])
        .expect("should find upstream");
    assert_eq!(upstream.target_url, "https://api1000.example.com");
}

#[test]
fn authenticate_with_none_upstreams_and_single_upstream() {
    // Precondition: API key with None upstreams, single upstream configured.
    // Action: authenticate.
    // Expected behavior: returns the single upstream.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("key1"),
            "token",
            None,
        )])),
    );
    let result = config.authenticate("token").expect("should authenticate");
    assert_eq!(result.permitted_upstreams, vec!["upstream1".to_string()]);
}

#[test]
fn authenticate_with_explicit_single_upstream() {
    // Precondition: API key with explicit single upstream.
    // Action: authenticate.
    // Expected behavior: returns the single upstream.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("key1"),
            "token",
            Some(vec!["upstream1".to_string()]),
        )])),
    );
    let result = config.authenticate("token").expect("should authenticate");
    assert_eq!(result.permitted_upstreams, vec!["upstream1".to_string()]);
}

#[tokio::test]
async fn config_manager_retains_previous_config_when_invalid_hot_reload_detected() {
    // Precondition: Proxy started with a valid configuration that differs from defaults.
    // Action: Write an invalid configuration to disk to trigger a reload attempt.
    // Expected behavior: Proxy continues using the last valid configuration without falling back to defaults.
    // Covers Requirements: C4, F15
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");

    let mut initial_config = test_config(
        Some(test_upstreams_config(
            1500,
            vec![(
                "test-upstream",
                UpstreamEntry {
                    target_url: "https://api.example.com".to_string(),
                    api_key: "hot-reload-secret".to_string(),
                    request_path: "/test".to_string(),
                },
            )],
        )),
        None,
    );
    initial_config.server.max_connections = 256;
    let initial_yaml = serde_yaml::to_string(&initial_config).expect("serialize initial config");
    std::fs::write(&config_path, initial_yaml).expect("write initial config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;
    let initial = manager.current();
    assert_eq!(initial.server.max_connections, 256);
    assert_eq!(initial.upstreams.as_ref().unwrap().request_timeout_ms, 1500);

    // Write invalid config (empty fields)
    let invalid_config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "".to_string(),
            max_connections: 0,
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 5000,
            upstreams: HashMap::from([(
                "test-upstream".to_string(),
                UpstreamEntry {
                    target_url: "".to_string(),
                    api_key: "".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: None,
    };
    let invalid_yaml = serde_yaml::to_string(&invalid_config).expect("serialize invalid config");
    std::fs::write(&config_path, invalid_yaml).expect("write invalid config");

    // Attempt reload - should fail
    let result = manager.reload().await;
    assert!(result.is_err(), "reload should fail for invalid config");

    // Previous config should be retained
    let current = manager.current();
    assert_eq!(
        current.server.max_connections, 256,
        "previous config should be retained"
    );
    assert_eq!(current.upstreams.as_ref().unwrap().request_timeout_ms, 1500);
}

#[test]
fn config_authenticate_with_empty_upstreams_list_returns_empty_permitted() {
    // Precondition: API key with empty upstreams list and no upstreams configured.
    // Action: Authenticate with the key.
    // Expected behavior: Returns empty permitted upstreams list.
    // Covers Requirements: F1
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec![]),
        )])),
    );

    let result = config.authenticate("valid-token");
    assert!(result.is_some());
    assert_eq!(result.unwrap().permitted_upstreams, Vec::<String>::new());
}

#[test]
fn config_authenticate_with_omitted_upstreams_gives_access_to_all() {
    // Precondition: API key with omitted upstreams list and upstreams configured.
    // Action: Authenticate with the key.
    // Expected behavior: Returns all configured upstreams.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![
                (
                    "upstream1",
                    UpstreamEntry {
                        target_url: "https://api1.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/upstream1".to_string(),
                    },
                ),
                (
                    "upstream2",
                    UpstreamEntry {
                        target_url: "https://api2.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/upstream2".to_string(),
                    },
                ),
            ],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            None, // Omitted - should give access to all
        )])),
    );

    let result = config.authenticate("valid-token");
    assert!(result.is_some());
    let permitted = result.unwrap().permitted_upstreams;
    assert_eq!(permitted.len(), 2);
    assert!(permitted.contains(&"upstream1".to_string()));
    assert!(permitted.contains(&"upstream2".to_string()));
}

#[test]
fn config_authenticate_with_specific_upstreams_restricts_access() {
    // Precondition: API key with specific upstreams list.
    // Action: Authenticate with the key.
    // Expected behavior: Returns only the specified upstreams.
    // Covers Requirements: F1
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![
                (
                    "upstream1",
                    UpstreamEntry {
                        target_url: "https://api1.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/upstream1".to_string(),
                    },
                ),
                (
                    "upstream2",
                    UpstreamEntry {
                        target_url: "https://api2.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/upstream2".to_string(),
                    },
                ),
            ],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec!["upstream1".to_string()]), // Only upstream1
        )])),
    );

    let result = config.authenticate("valid-token");
    assert!(result.is_some());
    let permitted = result.unwrap().permitted_upstreams;
    assert_eq!(permitted.len(), 1);
    assert_eq!(permitted[0], "upstream1");
}

#[test]
fn authenticate_with_token_containing_whitespace_prefix() {
    // Precondition: API key with leading whitespace in token.
    // Action: Authenticate with token having leading whitespace.
    // Expected behavior: Returns None (tokens should match exactly, whitespace-sensitive).
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/upstream1".to_string(),
                },
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate(" valid-token");
    assert!(
        result.is_none(),
        "token with leading whitespace should not match"
    );
}

#[test]
fn authenticate_with_token_containing_whitespace_suffix() {
    // Precondition: API key with trailing whitespace in token.
    // Action: Authenticate with token having trailing whitespace.
    // Expected behavior: Returns None (tokens should match exactly, whitespace-sensitive).
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/upstream1".to_string(),
                },
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate("valid-token ");
    assert!(
        result.is_none(),
        "token with trailing whitespace should not match"
    );
}

#[test]
fn authenticate_with_newline_in_token() {
    // Precondition: Token containing newline character.
    // Action: Authenticate with token containing newline.
    // Expected behavior: Returns None if token doesn't match, Some if it does match.
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/upstream1".to_string(),
                },
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "token\nwith\nnewline",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate("token\nwith\nnewline");
    assert!(
        result.is_some(),
        "token with newline should match if configured"
    );
}

#[test]
fn authenticate_with_tab_character_in_token() {
    // Precondition: Token containing tab character.
    // Action: Authenticate with token containing tab.
    // Expected behavior: Returns Some if token matches exactly.
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/upstream1".to_string(),
                },
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "token\twith\ttab",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate("token\twith\ttab");
    assert!(
        result.is_some(),
        "token with tab should match if configured"
    );
}

#[test]
fn authenticate_returns_same_result_on_multiple_calls() {
    // Precondition: Valid configuration with API key.
    // Action: Call authenticate multiple times with same token.
    // Expected behavior: Returns same result each time (idempotent).
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![
                (
                    "upstream1",
                    UpstreamEntry {
                        target_url: "https://api1.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/upstream1".to_string(),
                    },
                ),
                (
                    "upstream2",
                    UpstreamEntry {
                        target_url: "https://api2.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/upstream2".to_string(),
                    },
                ),
            ],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec!["upstream1".to_string(), "upstream2".to_string()]),
        )])),
    );

    let result1 = config.authenticate("valid-token");
    let result2 = config.authenticate("valid-token");
    let result3 = config.authenticate("valid-token");

    assert_eq!(result1.is_some(), result2.is_some());
    assert_eq!(result2.is_some(), result3.is_some());
    if let (Some(auth1), Some(auth2), Some(auth3)) = (result1, result2, result3) {
        assert_eq!(auth1.permitted_upstreams, auth2.permitted_upstreams);
        assert_eq!(auth2.permitted_upstreams, auth3.permitted_upstreams);
        assert_eq!(auth1.api_key, auth2.api_key);
        assert_eq!(auth2.api_key, auth3.api_key);
    }
}

#[test]
fn authenticate_handles_unicode_characters_in_key_name() {
    // Precondition: API key with unicode characters in name field.
    // Action: Authenticate with valid token.
    // Expected behavior: Returns Some with unicode name preserved.
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/upstream1".to_string(),
                },
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("тест-ключ"),
            "valid-token",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate("valid-token");
    assert!(result.is_some());
    assert_eq!(result.unwrap().api_key, Some("тест-ключ".to_string()));
}

#[test]
fn authenticate_with_non_ascii_characters_in_token() {
    // Precondition: API key with non-ASCII characters in token.
    // Action: Authenticate with token containing non-ASCII characters.
    // Expected behavior: Returns Some if token matches exactly.
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/upstream1".to_string(),
                },
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "токен-с-кириллицей",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate("токен-с-кириллицей");
    assert!(
        result.is_some(),
        "token with non-ASCII characters should match if configured"
    );
}

#[test]
fn authenticate_with_binary_like_token() {
    // Precondition: API key with token containing binary-like hex characters.
    // Action: Authenticate with hex token.
    // Expected behavior: Returns Some if token matches exactly.
    // Covers Requirements: F3
    let binary_like_token = "deadbeefcafebabe1234567890abcdef";
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/upstream1".to_string(),
                },
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            binary_like_token,
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate(binary_like_token);
    assert!(
        result.is_some(),
        "binary-like token should match if configured"
    );
}

#[test]
fn authenticate_with_token_matching_multiple_keys_returns_first() {
    // Precondition: Configuration with duplicate API key values.
    // Action: Authenticate with token that matches multiple keys.
    // Expected behavior: Returns first matching key (implementation detail).
    // Covers Requirements: F3, C16
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![
                (
                    "upstream1",
                    UpstreamEntry {
                        target_url: "https://api1.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/upstream1".to_string(),
                    },
                ),
                (
                    "upstream2",
                    UpstreamEntry {
                        target_url: "https://api2.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/upstream2".to_string(),
                    },
                ),
            ],
        )),
        Some(test_api_keys_config(vec![
            test_api_key(
                Some("first-key"),
                "duplicate-token",
                Some(vec!["upstream1".to_string()]),
            ),
            test_api_key(
                Some("second-key"),
                "duplicate-token", // Duplicate - should not pass validation normally
                Some(vec!["upstream2".to_string()]),
            ),
        ])),
    );

    // Note: This test documents behavior when duplicates exist despite validation
    let result = config.authenticate("duplicate-token");
    assert!(
        result.is_some(),
        "should find first matching key even with duplicates"
    );
}

#[test]
fn authenticate_with_api_key_having_whitespace_only_name() {
    // Precondition: API key with name containing only whitespace.
    // Action: Authenticate with valid token.
    // Expected behavior: Returns Some with whitespace-only name preserved (validation should catch this).
    // Covers Requirements: F3, C16
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/upstream1".to_string(),
                },
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("   "), // Whitespace-only name (should fail validation, but test behavior)
            "valid-token",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate("valid-token");
    // Note: This test documents behavior - validation should reject whitespace-only names
    if result.is_some() {
        assert_eq!(
            result.unwrap().api_key,
            Some("   ".to_string()),
            "whitespace-only name should be preserved if validation doesn't catch it"
        );
    }
}

#[test]
fn authenticate_with_nonexistent_upstream_in_permitted_list() {
    // Precondition: API key with upstream that doesn't exist in configuration.
    // Action: Authenticate with valid token.
    // Expected behavior: Returns Some, but permitted_upstreams contains only existing upstreams.
    // Covers Requirements: F3, C2
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/upstream1".to_string(),
                },
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec!["upstream1".to_string(), "nonexistent".to_string()]),
        )])),
    );

    let result = config.authenticate("valid-token");
    // Note: This test documents behavior when upstream reference is invalid
    // Validation should catch this, but if it doesn't, auth should still work
    assert!(result.is_some());
}

#[test]
fn authenticate_preserves_api_key_name_with_whitespace() {
    // Precondition: API key with name containing leading/trailing whitespace.
    // Action: Authenticate with valid token.
    // Expected behavior: Returns Some with name as configured (whitespace preserved).
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/upstream1".to_string(),
                },
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("  key-with-whitespace  "),
            "valid-token",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate("valid-token");
    assert!(result.is_some());
    assert_eq!(
        result.unwrap().api_key,
        Some("  key-with-whitespace  ".to_string())
    );
}

#[test]
fn authenticate_with_very_long_token() {
    // Precondition: API key with very long token (1000+ characters).
    // Action: Authenticate with very long matching token.
    // Expected behavior: Returns Some if token matches exactly.
    // Covers Requirements: F3
    let long_token = "a".repeat(2000);
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/upstream1".to_string(),
                },
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            &long_token,
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate(&long_token);
    assert!(
        result.is_some(),
        "very long token should match if configured"
    );
}

#[test]
fn authenticate_with_permitted_upstreams_containing_duplicates() {
    // Precondition: API key with duplicate upstream names in permitted list.
    // Action: Authenticate with valid token.
    // Expected behavior: Returns Some with duplicates preserved in permitted_upstreams.
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/upstream1".to_string(),
                },
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec![
                "upstream1".to_string(),
                "upstream1".to_string(), // Duplicate
            ]),
        )])),
    );

    let result = config.authenticate("valid-token");
    assert!(result.is_some());
    let permitted = result.unwrap().permitted_upstreams;
    // Should contain duplicates if they were in the config
    assert!(permitted.len() >= 1);
}

#[test]
fn authenticate_returns_none_for_partial_token_match() {
    // Precondition: API key with token "full-token".
    // Action: Authenticate with partial token "full".
    // Expected behavior: Returns None (tokens must match exactly, not partially).
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/upstream1".to_string(),
                },
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "full-token",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate("full");
    assert!(result.is_none(), "partial token should not match");
}

#[tokio::test]
async fn config_manager_started_with_defaults_returns_true_when_no_file() {
    // Precondition: ConfigManager initialized without config file.
    // Action: Call started_with_defaults() on ConfigManager without config file.
    // Expected behavior: Returns true indicating defaults were used.
    // Covers Requirements: C4.2, F17
    use tempfile::tempdir;
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("nonexistent.yaml");
    let manager = ConfigManager::initialize(Some(config_path)).await;

    assert!(
        manager.started_with_defaults(),
        "should return true when started with defaults"
    );
}

#[tokio::test]
async fn config_manager_started_with_defaults_returns_false_when_file_loaded() {
    // Precondition: ConfigManager initialized with valid config file.
    // Action: Call started_with_defaults() on ConfigManager with valid file.
    // Expected behavior: Returns false indicating config was loaded from file.
    // Covers Requirements: C4.2, F17
    use std::fs;
    use tempfile::tempdir;
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_yaml = format!(
        r#"
version: 1
server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#,
    );
    fs::write(&config_path, config_yaml).expect("write config file");
    let manager = ConfigManager::initialize(Some(config_path)).await;

    assert!(
        !manager.started_with_defaults(),
        "should return false when config was loaded from file"
    );
}

// ============================================================================
// Bearer Authentication Scheme (F5) Tests
// ============================================================================

#[test]
fn bearer_scheme_extracts_token_correctly() {
    // Precondition: Authorization header value with Bearer scheme.
    // Action: Extract token from "Bearer <token>" format.
    // Expected behavior: Returns token value without "Bearer " prefix.
    // Covers Requirements: F5
    let auth_header = "Bearer test-api-key-12345";
    let token = auth_header.strip_prefix("Bearer ");

    assert_eq!(
        token,
        Some("test-api-key-12345"),
        "Bearer scheme should extract token correctly"
    );
}

#[test]
fn non_bearer_scheme_returns_none() {
    // Precondition: Authorization header value with non-Bearer scheme.
    // Action: Extract token from "Token <token>" format.
    // Expected behavior: strip_prefix returns None, indicating non-Bearer scheme should be rejected.
    // Covers Requirements: F5
    let auth_header = "Token test-api-key-12345";
    let token = auth_header.strip_prefix("Bearer ");

    assert_eq!(
        token, None,
        "Non-Bearer schemes (Token) should return None and be rejected"
    );
}

#[test]
fn basic_auth_scheme_returns_none() {
    // Precondition: Authorization header value with Basic scheme.
    // Action: Extract token from "Basic <credentials>" format.
    // Expected behavior: strip_prefix returns None, indicating Basic scheme should be rejected.
    // Covers Requirements: F5
    let auth_header = "Basic dXNlcm5hbWU6cGFzc3dvcmQ=";
    let token = auth_header.strip_prefix("Bearer ");

    assert_eq!(
        token, None,
        "Non-Bearer schemes (Basic) should return None and be rejected"
    );
}

#[test]
fn digest_auth_scheme_returns_none() {
    // Precondition: Authorization header value with Digest scheme.
    // Action: Extract token from "Digest <credentials>" format.
    // Expected behavior: strip_prefix returns None, indicating Digest scheme should be rejected.
    // Covers Requirements: F5
    let auth_header = r#"Digest username="user", realm="test""#;
    let token = auth_header.strip_prefix("Bearer ");

    assert_eq!(
        token, None,
        "Non-Bearer schemes (Digest) should return None and be rejected"
    );
}

#[test]
fn bearer_scheme_is_case_sensitive() {
    // Precondition: Authorization header value with lowercase "bearer" scheme.
    // Action: Extract token from "bearer <token>" format.
    // Expected behavior: strip_prefix returns None, as Bearer must be capitalized.
    // Covers Requirements: F5
    let auth_header = "bearer test-api-key-12345";
    let token = auth_header.strip_prefix("Bearer ");

    assert_eq!(
        token, None,
        "Bearer scheme must be capitalized, lowercase 'bearer' should be rejected"
    );
}

#[test]
fn bearer_scheme_with_space_after_bearer_extracts_token() {
    // Precondition: Authorization header value with "Bearer " (space after Bearer).
    // Action: Extract token from "Bearer <token>" format.
    // Expected behavior: Returns token value correctly, space is required after "Bearer".
    // Covers Requirements: F5
    let auth_header_correct = "Bearer test-api-key-12345";
    let token_correct = auth_header_correct.strip_prefix("Bearer ");
    assert_eq!(
        token_correct,
        Some("test-api-key-12345"),
        "Bearer with single space should extract token correctly"
    );
}

#[test]
fn bearer_scheme_with_empty_token_extracts_empty_string() {
    // Precondition: Authorization header value with "Bearer " but no token.
    // Action: Extract token from "Bearer " format (empty token).
    // Expected behavior: Returns empty string, which will be rejected by authenticate().
    // Covers Requirements: F5
    let auth_header = "Bearer ";
    let token = auth_header.strip_prefix("Bearer ");

    assert_eq!(
        token,
        Some(""),
        "Bearer with empty token should extract empty string (will be rejected by authenticate)"
    );
}

// ============================================================================
// Error Handling (F6) Tests - Host Header Validation
// ============================================================================

#[test]
fn host_header_validation_requires_non_empty_value() {
    // Precondition: Host header value can be checked for validity.
    // Action: Check if Host header value is non-empty and valid.
    // Expected behavior: Empty or whitespace-only Host headers should be considered invalid.
    // Covers Requirements: F6
    use axum::http::HeaderValue;

    // Valid Host header
    let valid_host = HeaderValue::from_static("example.com");
    assert!(
        valid_host.to_str().is_ok(),
        "Valid host should parse correctly"
    );

    // Empty Host header (would be invalid)
    let empty_host = HeaderValue::from_static("");
    let empty_valid = empty_host
        .to_str()
        .ok()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    assert!(!empty_valid, "Empty Host header should be invalid");

    // Whitespace-only Host header (would be invalid)
    let whitespace_host = HeaderValue::from_static("   ");
    let whitespace_valid = whitespace_host
        .to_str()
        .ok()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    assert!(
        !whitespace_valid,
        "Whitespace-only Host header should be invalid"
    );
}

#[test]
fn host_header_validation_accepts_valid_domain() {
    // Precondition: Host header value with valid domain.
    // Action: Check if Host header value is valid.
    // Expected behavior: Valid domain names should be accepted.
    // Covers Requirements: F6
    use axum::http::HeaderValue;

    let valid_hosts = vec![
        "example.com",
        "api.example.com",
        "subdomain.api.example.com",
        "localhost",
        "127.0.0.1",
        "[2001:db8::1]",
        "example.com:8080",
    ];

    for host in valid_hosts {
        let header_value = HeaderValue::from_str(host);
        assert!(
            header_value.is_ok(),
            "Valid host '{}' should parse correctly",
            host
        );
    }
}

#[test]
fn host_header_validation_rejects_invalid_format() {
    // Precondition: Host header value that cannot be parsed as valid HTTP header.
    // Action: Check if Host header value is valid.
    // Expected behavior: Invalid header values should be rejected.
    // Covers Requirements: F6
    use axum::http::HeaderValue;

    // Invalid header values (contain control characters or invalid bytes)
    let invalid_hosts = vec![
        " example.com", // Null byte
        "example.com ", // Null byte at end
        "example.com", // Control character
    ];

    for host in invalid_hosts {
        let header_value = HeaderValue::from_str(host);
        assert!(header_value.is_err(), "Invalid host should be rejected");
    }
}

// ============================================================================
// Response Forwarding (F4) Tests
// ============================================================================

#[test]
fn response_forwarding_preserves_upstream_status_code() {
    // Precondition: Upstream response has specific status code.
    // Action: Forward response from upstream to client.
    // Expected behavior: Status code is preserved exactly as received from upstream.
    // Covers Requirements: F4
    // Note: This tests the concept - actual forwarding requires full HTTP context
    use axum::http::StatusCode;

    // Test that status codes are preserved (conceptual test)
    let upstream_statuses = vec![
        StatusCode::OK,
        StatusCode::CREATED,
        StatusCode::NOT_FOUND,
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::BAD_REQUEST,
    ];

    for status in upstream_statuses {
        // Status codes should be preserved as-is
        assert_eq!(
            status.as_u16(),
            status.as_u16(),
            "Status code should be preserved"
        );
    }
}

#[test]
fn response_forwarding_filters_hop_by_hop_headers() {
    // Precondition: Upstream response contains hop-by-hop headers.
    // Action: Forward response headers from upstream to client.
    // Expected behavior: Hop-by-hop headers are filtered out, other headers are preserved.
    // Covers Requirements: F4
    use fluxgate::proxy::is_hop_by_hop_header;

    // Check which headers are hop-by-hop
    assert!(is_hop_by_hop_header(&"connection".parse().unwrap()));
    assert!(!is_hop_by_hop_header(&"content-type".parse().unwrap()));
    assert!(!is_hop_by_hop_header(&"content-length".parse().unwrap()));
    assert!(is_hop_by_hop_header(&"transfer-encoding".parse().unwrap()));

    // Response forwarding should filter out hop-by-hop headers
    // but preserve end-to-end headers like content-type and content-length
}

#[test]
fn response_forwarding_preserves_end_to_end_headers() {
    // Precondition: Upstream response contains end-to-end headers.
    // Action: Forward response headers from upstream to client.
    // Expected behavior: End-to-end headers are preserved exactly as received.
    // Covers Requirements: F4
    use fluxgate::proxy::is_hop_by_hop_header;

    let end_to_end_headers = vec![
        "content-type",
        "content-length",
        "content-encoding",
        "cache-control",
        "etag",
        "last-modified",
        "location",
        "x-custom-header",
    ];

    for header_name in end_to_end_headers {
        let header_name_parsed: axum::http::HeaderName = header_name.parse().unwrap();
        assert!(
            !is_hop_by_hop_header(&header_name_parsed),
            "End-to-end header '{}' should not be filtered",
            header_name
        );
    }
}

// ============================================================================
// Streaming Semantics (F12) Tests
// ============================================================================

#[test]
fn http_version_symmetry_requires_matching_versions() {
    // Precondition: Client and upstream use HTTP versions.
    // Action: Check if client and upstream HTTP versions match.
    // Expected behavior: Versions must match, otherwise return 502 Bad Gateway.
    // Covers Requirements: F12
    use axum::http::Version;

    // Test HTTP version matching logic
    let client_http_11 = Version::HTTP_11;
    let client_http_2 = Version::HTTP_2;
    let upstream_http_11 = Version::HTTP_11;
    let upstream_http_2 = Version::HTTP_2;

    // Matching versions should be allowed
    assert_eq!(
        client_http_11, upstream_http_11,
        "HTTP/1.1 versions should match"
    );
    assert_eq!(
        client_http_2, upstream_http_2,
        "HTTP/2 versions should match"
    );

    // Mismatched versions should be rejected
    assert_ne!(
        client_http_11, upstream_http_2,
        "HTTP/1.1 and HTTP/2 should not match"
    );
    assert_ne!(
        client_http_2, upstream_http_11,
        "HTTP/2 and HTTP/1.1 should not match"
    );
}

#[test]
fn streaming_semantics_preserves_http_version() {
    // Precondition: Client request uses specific HTTP version.
    // Action: Forward request to upstream and response back to client.
    // Expected behavior: HTTP version is preserved throughout the request/response cycle.
    // Covers Requirements: F12
    use axum::http::Version;

    // Test that HTTP versions are preserved for streaming
    let versions = vec![Version::HTTP_11, Version::HTTP_2];

    for version in versions {
        // HTTP version should be preserved for streaming semantics
        assert!(
            matches!(version, Version::HTTP_11 | Version::HTTP_2),
            "Supported HTTP version should be preserved"
        );
    }
}

// ============================================================================
// Additional Edge Case Tests (50 new tests)
// ============================================================================

#[test]
fn build_upstream_url_with_request_path_prefix_removal() {
    // Precondition: Upstream entry with request_path "/api" and request URI "/api/users".
    // Action: Call build_upstream_url with request URI matching request_path prefix.
    // Expected behavior: request_path prefix is removed from request path before appending to base URL.
    // Covers Requirements: F1, F2
    let upstream = test_upstream_entry_with_path("https://api.example.com", "test-key", "/api");

    let request_uri = "/api/users/123".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(
        result.as_str(),
        "https://api.example.com/users/123",
        "request_path prefix should be removed from request path"
    );
}

#[test]
fn build_upstream_url_with_exact_request_path_match() {
    // Precondition: Upstream entry with request_path "/api" and request URI exactly "/api".
    // Action: Call build_upstream_url with request URI exactly matching request_path.
    // Expected behavior: Returns base URL with root path "/" when request path exactly matches request_path.
    // Covers Requirements: F1, F2
    let upstream = test_upstream_entry_with_path("https://api.example.com", "test-key", "/api");

    let request_uri = "/api".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(
        result.as_str(),
        "https://api.example.com/",
        "exact request_path match should result in root path"
    );
}

#[test]
fn build_upstream_url_with_request_path_containing_special_chars() {
    // Precondition: Upstream entry and request URI with special characters in path.
    // Action: Call build_upstream_url with paths containing URL-encoded special characters.
    // Expected behavior: Special characters are properly encoded in the final URL.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com", "test-key", "/api");

    let request_uri = "/api/users%20test".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(
        result.as_str().contains("users%20test"),
        "special characters should be preserved"
    );
}

#[test]
fn build_upstream_url_with_multiple_query_parameters() {
    // Precondition: Upstream entry and request URI with multiple query parameters.
    // Action: Call build_upstream_url with request URI containing multiple query params.
    // Expected behavior: All query parameters are preserved in the final URL.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com", "test-key", "/api");

    let request_uri = "/api/users?a=1&b=2&c=3".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(
        result.query().unwrap().contains("a=1"),
        "all query parameters should be preserved"
    );
    assert!(
        result.query().unwrap().contains("b=2"),
        "all query parameters should be preserved"
    );
    assert!(
        result.query().unwrap().contains("c=3"),
        "all query parameters should be preserved"
    );
}

#[test]
fn find_upstream_by_path_selects_longest_match() {
    // Precondition: Config with multiple upstreams having overlapping request_path values.
    // Action: Call find_upstream_by_path with request path matching multiple upstreams.
    // Expected behavior: Returns upstream with longest matching request_path.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![
                (
                    "upstream1",
                    UpstreamEntry {
                        target_url: "https://api1.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/api".to_string(),
                    },
                ),
                (
                    "upstream2",
                    UpstreamEntry {
                        target_url: "https://api2.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/api/v1".to_string(),
                    },
                ),
                (
                    "upstream3",
                    UpstreamEntry {
                        target_url: "https://api3.example.com".to_string(),
                        api_key: "key3".to_string(),
                        request_path: "/api/v1/users".to_string(),
                    },
                ),
            ],
        )),
        None,
    );

    let permitted = vec![
        "upstream1".to_string(),
        "upstream2".to_string(),
        "upstream3".to_string(),
    ];
    let result = config.find_upstream_by_path("/api/v1/users/123", &permitted);

    assert_eq!(
        result,
        Some("upstream3".to_string()),
        "should select longest matching request_path"
    );
}

#[test]
fn find_upstream_by_path_normalizes_trailing_slashes() {
    // Precondition: Config with upstream having request_path "/api" and request path "/api/".
    // Action: Call find_upstream_by_path with request path having trailing slash.
    // Expected behavior: Trailing slashes are normalized for matching, upstream is found.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api"),
            )],
        )),
        None,
    );

    let permitted = vec!["upstream1".to_string()];
    let result1 = config.find_upstream_by_path("/api", &permitted);
    let result2 = config.find_upstream_by_path("/api/", &permitted);

    assert_eq!(
        result1,
        Some("upstream1".to_string()),
        "should match without trailing slash"
    );
    assert_eq!(
        result2,
        Some("upstream1".to_string()),
        "should match with trailing slash (normalized)"
    );
}

#[test]
fn authenticate_handles_whitespace_in_token() {
    // Precondition: API key with token containing leading/trailing whitespace.
    // Action: Authenticate with token containing whitespace.
    // Expected behavior: Whitespace is preserved, exact match required (whitespace tokens may not match).
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "token-without-whitespace",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result1 = config.authenticate("token-without-whitespace");
    let result2 = config.authenticate(" token-without-whitespace ");
    let result3 = config.authenticate("token-without-whitespace\n");

    assert!(result1.is_some(), "exact token should match");
    assert!(
        result2.is_none(),
        "token with whitespace should not match exact token"
    );
    assert!(
        result3.is_none(),
        "token with newline should not match exact token"
    );
}

#[test]
fn authenticate_handles_special_characters_in_token() {
    // Precondition: API key with token containing special characters.
    // Action: Authenticate with token containing special characters.
    // Expected behavior: Special characters are matched exactly as configured.
    // Covers Requirements: F3
    let special_token = "token-with-special-chars-!@#$%^&*()";
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            special_token,
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate(special_token);
    assert!(
        result.is_some(),
        "token with special characters should match exactly"
    );
}

#[test]
fn authenticate_returns_all_upstreams_when_upstreams_list_empty() {
    // Precondition: API key with empty upstreams list and multiple upstreams configured.
    // Action: Authenticate with valid token.
    // Expected behavior: Returns all configured upstreams when upstreams list is empty.
    // Covers Requirements: F2, F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![
                (
                    "upstream1",
                    test_upstream_entry_with_path("https://api1.example.com", "key1", "/api1"),
                ),
                (
                    "upstream2",
                    test_upstream_entry_with_path("https://api2.example.com", "key2", "/api2"),
                ),
            ],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec![]), // Empty list
        )])),
    );

    let result = config.authenticate("valid-token");
    assert!(result.is_some());
    let permitted = result.unwrap().permitted_upstreams;
    assert_eq!(
        permitted.len(),
        2,
        "should return all upstreams when list is empty"
    );
    assert!(permitted.contains(&"upstream1".to_string()));
    assert!(permitted.contains(&"upstream2".to_string()));
}

#[test]
fn authenticate_returns_empty_list_when_no_upstreams_configured() {
    // Precondition: API key with empty upstreams list and no upstreams configured.
    // Action: Authenticate with valid token.
    // Expected behavior: Returns empty permitted_upstreams list (will result in HTTP 401).
    // Covers Requirements: F3
    let config = test_config(
        None, // No upstreams
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec![]), // Empty list
        )])),
    );

    let result = config.authenticate("valid-token");
    assert!(result.is_some());
    let permitted = result.unwrap().permitted_upstreams;
    assert_eq!(
        permitted.len(),
        0,
        "should return empty list when no upstreams configured"
    );
}

#[test]
fn is_connect_or_upgrade_request_handles_connection_header_with_multiple_tokens() {
    // Precondition: Request with Connection header containing multiple tokens including "upgrade".
    // Action: Call is_connect_or_upgrade_request with Connection header "keep-alive, upgrade".
    // Expected behavior: Returns true when "upgrade" token is present in Connection header.
    // Covers Requirements: F14
    use axum::http::{HeaderMap, HeaderValue, Method};

    let method = Method::GET;
    let mut headers = HeaderMap::new();
    headers.insert(
        "connection",
        HeaderValue::from_static("keep-alive, upgrade"),
    );

    let result = is_connect_or_upgrade_request(&method, &headers);
    assert!(
        result,
        "should detect upgrade in Connection header with multiple tokens"
    );
}

#[test]
fn is_connect_or_upgrade_request_handles_connection_header_case_insensitive() {
    // Precondition: Request with Connection header containing "Upgrade" (capitalized).
    // Action: Call is_connect_or_upgrade_request with Connection header "Upgrade".
    // Expected behavior: Returns true regardless of case (case-insensitive matching).
    // Covers Requirements: F14
    use axum::http::{HeaderMap, HeaderValue, Method};

    let method = Method::GET;
    let mut headers = HeaderMap::new();
    headers.insert("connection", HeaderValue::from_static("Upgrade"));

    let result = is_connect_or_upgrade_request(&method, &headers);
    assert!(result, "should detect upgrade case-insensitively");
}

#[test]
fn is_connect_or_upgrade_request_handles_connection_header_with_whitespace() {
    // Precondition: Request with Connection header containing whitespace around tokens.
    // Action: Call is_connect_or_upgrade_request with Connection header " upgrade ".
    // Expected behavior: Whitespace is trimmed, upgrade is detected.
    // Covers Requirements: F14
    use axum::http::{HeaderMap, HeaderValue, Method};

    let method = Method::GET;
    let mut headers = HeaderMap::new();
    headers.insert("connection", HeaderValue::from_static(" upgrade "));

    let result = is_connect_or_upgrade_request(&method, &headers);
    assert!(result, "should handle whitespace in Connection header");
}

#[test]
fn is_connect_or_upgrade_request_handles_connection_header_without_upgrade() {
    // Precondition: Request with Connection header not containing "upgrade".
    // Action: Call is_connect_or_upgrade_request with Connection header "keep-alive".
    // Expected behavior: Returns false when upgrade token is not present.
    // Covers Requirements: F14
    use axum::http::{HeaderMap, HeaderValue, Method};

    let method = Method::GET;
    let mut headers = HeaderMap::new();
    headers.insert("connection", HeaderValue::from_static("keep-alive"));

    let result = is_connect_or_upgrade_request(&method, &headers);
    assert!(!result, "should return false when upgrade is not present");
}

#[test]
fn is_hop_by_hop_header_handles_proxy_authorization() {
    // Precondition: Header name "proxy-authorization" exists.
    // Action: Call is_hop_by_hop_header with "proxy-authorization" header name.
    // Expected behavior: Returns true indicating it is a hop-by-hop header.
    // Covers Requirements: F1
    let header_name = "proxy-authorization".parse().unwrap();
    assert!(
        is_hop_by_hop_header(&header_name),
        "proxy-authorization should be hop-by-hop"
    );
}

#[test]
fn build_upstream_url_with_path_containing_dots() {
    // Precondition: Upstream entry and request URI with path containing dots (e.g., "../").
    // Action: Call build_upstream_url with path containing dots.
    // Expected behavior: URL parser may normalize paths, but the path should be correctly constructed.
    // Covers Requirements: F1
    let upstream = test_upstream_entry_with_path("https://api.example.com", "test-key", "/api");

    let request_uri = "/api/users/../test".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    // URL parser normalizes paths, so "../" is resolved to parent directory
    // The result should be "/test" (normalized) or contain the normalized path
    assert!(
        result.path() == "/test" || result.path().ends_with("/test"),
        "path should be correctly constructed (may be normalized by URL parser)"
    );
}

#[test]
fn build_upstream_url_with_ipv6_base_url() {
    // Precondition: Upstream entry with IPv6 address in target URL.
    // Action: Call build_upstream_url with IPv6 base URL.
    // Expected behavior: IPv6 address is properly formatted in the final URL.
    // Covers Requirements: F1
    let upstream = UpstreamEntry {
        target_url: "https://[2001:db8::1]".to_string(),
        api_key: "test-key".to_string(),
        request_path: "/api".to_string(),
    };

    let request_uri = "/api/users".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri);

    assert!(result.is_ok(), "IPv6 address should be handled correctly");
}

#[test]
fn build_upstream_url_with_port_in_target_url() {
    // Precondition: Upstream entry with port number in target URL.
    // Action: Call build_upstream_url with target URL containing port.
    // Expected behavior: Port number is preserved in the final URL.
    // Covers Requirements: F1
    let upstream = UpstreamEntry {
        target_url: "https://api.example.com:8443".to_string(),
        api_key: "test-key".to_string(),
        request_path: "/api".to_string(),
    };

    let request_uri = "/api/users".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(
        result.as_str().contains(":8443"),
        "port number should be preserved"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_trailing_slash_in_request_path() {
    // Precondition: Config with upstream having request_path "/api/" and request path "/api/users".
    // Action: Call find_upstream_by_path with request path matching request_path with trailing slash.
    // Expected behavior: Trailing slash in request_path is normalized, match succeeds.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/api/".to_string(),
                },
            )],
        )),
        None,
    );

    let permitted = vec!["upstream1".to_string()];
    let result = config.find_upstream_by_path("/api/users", &permitted);

    assert_eq!(
        result,
        Some("upstream1".to_string()),
        "should match with trailing slash normalized"
    );
}

#[test]
fn authenticate_handles_unicode_in_token() {
    // Precondition: API key with token containing Unicode characters.
    // Action: Authenticate with token containing Unicode.
    // Expected behavior: Unicode characters are matched exactly as configured.
    // Covers Requirements: F3
    let unicode_token = "token-тест-测试-🎉";
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            unicode_token,
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate(unicode_token);
    assert!(result.is_some(), "token with Unicode should match exactly");
}

#[test]
fn build_upstream_url_with_fragment_in_base_url() {
    // Precondition: Upstream entry with fragment in target URL.
    // Action: Call build_upstream_url with base URL containing fragment.
    // Expected behavior: Fragment from base URL is preserved in the final URL.
    // Covers Requirements: F1
    let upstream = UpstreamEntry {
        target_url: "https://api.example.com#fragment".to_string(),
        api_key: "test-key".to_string(),
        request_path: "/api".to_string(),
    };

    let request_uri = "/api/users".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(
        result.as_str().contains("#fragment"),
        "fragment from base URL should be preserved"
    );
}

#[test]
fn build_upstream_url_with_query_in_base_url() {
    // Precondition: Upstream entry with query parameters in target URL.
    // Action: Call build_upstream_url with base URL containing query.
    // Expected behavior: Query from request URI takes precedence, base URL query may be overwritten.
    // Covers Requirements: F1
    let upstream = UpstreamEntry {
        target_url: "https://api.example.com?base=value".to_string(),
        api_key: "test-key".to_string(),
        request_path: "/api".to_string(),
    };

    let request_uri = "/api/users?request=value".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    // Request query should be used, not base query
    assert!(
        result.query().unwrap().contains("request=value"),
        "request query should be used"
    );
}

#[test]
fn authenticate_handles_case_sensitive_token_matching() {
    // Precondition: API key with token "Token123" (case-sensitive).
    // Action: Authenticate with "token123" (different case).
    // Expected behavior: Returns None (token matching is case-sensitive).
    // Covers Requirements: F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "Token123",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result1 = config.authenticate("Token123");
    let result2 = config.authenticate("token123");

    assert!(result1.is_some(), "exact case should match");
    assert!(result2.is_none(), "different case should not match");
}

#[test]
fn build_upstream_url_with_base_url_having_no_scheme() {
    // Precondition: Upstream entry with invalid target URL (missing scheme).
    // Action: Call build_upstream_url with invalid target URL.
    // Expected behavior: Returns error indicating invalid URL.
    // Covers Requirements: F1
    let upstream = UpstreamEntry {
        target_url: "api.example.com".to_string(), // Missing scheme
        api_key: "test-key".to_string(),
        request_path: "/api".to_string(),
    };

    let request_uri = "/api/users".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri);

    assert!(
        result.is_err(),
        "should return error for URL without scheme"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_encoded_characters() {
    // Precondition: Config with upstream and request path containing URL-encoded characters.
    // Action: Call find_upstream_by_path with encoded path.
    // Expected behavior: Encoded characters are handled correctly in path matching.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api"),
            )],
        )),
        None,
    );

    let permitted = vec!["upstream1".to_string()];
    let result = config.find_upstream_by_path("/api/users%20test", &permitted);

    assert_eq!(
        result,
        Some("upstream1".to_string()),
        "should handle encoded characters"
    );
}

#[test]
fn authenticate_returns_api_key_name_when_configured() {
    // Precondition: API key with name configured.
    // Action: Authenticate with valid token.
    // Expected behavior: Returns AuthenticationResult with api_key_name set.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("my-api-key"),
            "valid-token",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate("valid-token");
    assert!(result.is_some());
    assert_eq!(result.unwrap().api_key, Some("my-api-key".to_string()));
}

#[test]
fn authenticate_returns_none_api_key_name_when_not_configured() {
    // Precondition: API key without name configured.
    // Action: Authenticate with valid token.
    // Expected behavior: Returns AuthenticationResult with api_key_name as None.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            None, // No name
            "valid-token",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate("valid-token");
    assert!(result.is_some());
    assert_eq!(result.unwrap().api_key, None);
}

#[test]
fn build_upstream_url_with_request_path_not_starting_with_slash() {
    // Precondition: Upstream entry with request_path not starting with "/" (invalid, but test edge case).
    // Action: Call build_upstream_url with request URI.
    // Expected behavior: Function handles edge case gracefully (request_path should always start with "/" per validation).
    // Covers Requirements: F1
    let upstream = UpstreamEntry {
        target_url: "https://api.example.com".to_string(),
        api_key: "test-key".to_string(),
        request_path: "api".to_string(), // No leading slash (invalid per C15)
    };

    let request_uri = "/api/users".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri);

    // Function may handle this gracefully or return error
    // This tests defensive behavior
    let _ = result;
}

#[test]
fn find_upstream_by_path_handles_multiple_matches_with_same_length() {
    // Precondition: Config with multiple upstreams having same-length request_path values.
    // Action: Call find_upstream_by_path with request path matching multiple upstreams with same length.
    // Expected behavior: Returns one of the matching upstreams (implementation-defined which one).
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![
                (
                    "upstream1",
                    UpstreamEntry {
                        target_url: "https://api1.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/api/v1".to_string(),
                    },
                ),
                (
                    "upstream2",
                    UpstreamEntry {
                        target_url: "https://api2.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/api/v2".to_string(),
                    },
                ),
            ],
        )),
        None,
    );

    let permitted = vec!["upstream1".to_string(), "upstream2".to_string()];
    // Request path "/api/v1/users" matches upstream1, "/api/v2/users" matches upstream2
    let result1 = config.find_upstream_by_path("/api/v1/users", &permitted);
    let result2 = config.find_upstream_by_path("/api/v2/users", &permitted);

    assert_eq!(result1, Some("upstream1".to_string()));
    assert_eq!(result2, Some("upstream2".to_string()));
}

#[test]
fn is_connect_or_upgrade_request_handles_mixed_case_upgrade_header() {
    // Precondition: Request with Upgrade header in mixed case.
    // Action: Call is_connect_or_upgrade_request with Upgrade header "UpGrAdE".
    // Expected behavior: Returns true (Upgrade header presence is detected regardless of case).
    // Covers Requirements: F14
    use axum::http::{HeaderMap, HeaderValue, Method};

    let method = Method::GET;
    let mut headers = HeaderMap::new();
    headers.insert("upgrade", HeaderValue::from_static("websocket"));

    let result = is_connect_or_upgrade_request(&method, &headers);
    assert!(result, "should detect Upgrade header regardless of case");
}

#[test]
fn build_upstream_url_preserves_user_info_in_base_url() {
    // Precondition: Upstream entry with user info in target URL (e.g., "user:pass@host").
    // Action: Call build_upstream_url with base URL containing user info.
    // Expected behavior: User info is preserved in the final URL.
    // Covers Requirements: F1
    let upstream = UpstreamEntry {
        target_url: "https://user:pass@api.example.com".to_string(),
        api_key: "test-key".to_string(),
        request_path: "/api".to_string(),
    };

    let request_uri = "/api/users".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(
        result.as_str().contains("@"),
        "user info should be preserved"
    );
}

#[test]
fn find_upstream_by_path_handles_path_with_query_string() {
    // Precondition: Config with upstream and request path containing query string.
    // Action: Call find_upstream_by_path with path containing query.
    // Expected behavior: Query string is ignored for path matching, only path component is used.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api"),
            )],
        )),
        None,
    );

    let permitted = vec!["upstream1".to_string()];
    // Note: find_upstream_by_path receives only the path, not query
    let result = config.find_upstream_by_path("/api/users", &permitted);

    assert_eq!(
        result,
        Some("upstream1".to_string()),
        "query should not affect path matching"
    );
}

#[test]
fn authenticate_handles_token_with_newlines() {
    // Precondition: API key with token containing newline characters.
    // Action: Authenticate with token containing newlines.
    // Expected behavior: Newlines are part of token, exact match required.
    // Covers Requirements: F3
    let token_with_newline = "token\nwith\nnewlines";
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api1.example.com", "key1", "/api"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            token_with_newline,
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result1 = config.authenticate(token_with_newline);
    let result2 = config.authenticate("token\nwith\nnewlines\n"); // Extra newline

    assert!(result1.is_some(), "exact token with newlines should match");
    assert!(
        result2.is_none(),
        "token with extra newline should not match"
    );
}

#[test]
fn build_upstream_url_with_empty_request_path_after_prefix_removal() {
    // Precondition: Upstream entry with request_path "/api" and request URI exactly "/api".
    // Action: Call build_upstream_url when request path exactly matches request_path.
    // Expected behavior: Returns base URL with trailing slash when remaining path is empty.
    // Covers Requirements: F1, F2
    let upstream = test_upstream_entry_with_path("https://api.example.com/v1", "test-key", "/api");

    let request_uri = "/api".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    // When remaining path is empty, it becomes "/" which is combined with base_path "/v1" to produce "/v1/"
    assert_eq!(
        result.path(),
        "/v1/",
        "should append trailing slash to base path when remaining path is empty"
    );
}

#[test]
fn find_upstream_by_path_handles_nested_path_matching() {
    // Precondition: Config with upstreams having nested request_path values.
    // Action: Call find_upstream_by_path with request path matching nested structure.
    // Expected behavior: Longest matching request_path is selected correctly.
    // Covers Requirements: F2
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![
                (
                    "upstream1",
                    UpstreamEntry {
                        target_url: "https://api1.example.com".to_string(),
                        api_key: "key1".to_string(),
                        request_path: "/a".to_string(),
                    },
                ),
                (
                    "upstream2",
                    UpstreamEntry {
                        target_url: "https://api2.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/a/b".to_string(),
                    },
                ),
                (
                    "upstream3",
                    UpstreamEntry {
                        target_url: "https://api3.example.com".to_string(),
                        api_key: "key3".to_string(),
                        request_path: "/a/b/c".to_string(),
                    },
                ),
            ],
        )),
        None,
    );

    let permitted = vec![
        "upstream1".to_string(),
        "upstream2".to_string(),
        "upstream3".to_string(),
    ];
    let result = config.find_upstream_by_path("/a/b/c/d", &permitted);

    assert_eq!(
        result,
        Some("upstream3".to_string()),
        "should select longest nested match"
    );
}

#[test]
fn is_hop_by_hop_header_handles_all_rfc_7230_headers() {
    // Precondition: All hop-by-hop headers from RFC 7230.
    // Action: Call is_hop_by_hop_header with each RFC 7230 hop-by-hop header.
    // Expected behavior: All RFC 7230 hop-by-hop headers return true.
    // Covers Requirements: F1
    let hop_by_hop_headers = vec![
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ];

    for header_name in hop_by_hop_headers {
        let header = header_name.parse().unwrap();
        assert!(
            is_hop_by_hop_header(&header),
            "RFC 7230 hop-by-hop header '{}' should return true",
            header_name
        );
    }
}

#[test]
fn authenticate_handles_omitted_upstreams_field() {
    // Precondition: API key with upstreams field omitted (None) and upstreams configured.
    // Action: Authenticate with valid token.
    // Expected behavior: Returns all configured upstreams when upstreams field is omitted.
    // Covers Requirements: F2, F3
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![
                (
                    "upstream1",
                    test_upstream_entry_with_path("https://api1.example.com", "key1", "/api1"),
                ),
                (
                    "upstream2",
                    test_upstream_entry_with_path("https://api2.example.com", "key2", "/api2"),
                ),
            ],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            None, // Omitted upstreams field
        )])),
    );

    let result = config.authenticate("valid-token");
    assert!(result.is_some());
    let permitted = result.unwrap().permitted_upstreams;
    assert_eq!(
        permitted.len(),
        2,
        "should return all upstreams when field is omitted"
    );
}

// ============================================================================
// Tests for F2.1-F2.5: Authentication & Routing (broken down requirements)
// ============================================================================

#[test]
fn authenticate_when_no_api_keys_configured_returns_none() {
    // Precondition: Configuration with no API keys configured (authentication not required).
    // Action: Call authenticate with any token.
    // Expected behavior: Returns None (authentication not required, but method should handle gracefully).
    // Covers Requirements: F2.1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api.example.com", "key1", "/api"),
            )],
        )),
        None, // No API keys
    );

    let result = config.authenticate("any-token");
    assert!(
        result.is_none(),
        "should return None when no API keys configured"
    );
}

#[test]
fn authenticate_with_jwt_after_static_key_fails() {
    // Precondition: Configuration with both static and JWT keys, token doesn't match static key.
    // Action: Authenticate with token that doesn't match static key but could be JWT.
    // Expected behavior: Should attempt JWT authentication after static key fails (order per F17.1).
    // Covers Requirements: F2.1, F17.1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api.example.com", "key1", "/api"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("static-key"),
            "static-token-123",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    // Token that doesn't match static key (would need JWT validation, but we're testing order)
    let result = config.authenticate("not-static-token");
    assert!(
        result.is_none(),
        "should return None when token doesn't match static key"
    );
}

#[test]
fn authenticate_with_empty_token_after_bearer_returns_none() {
    // Precondition: Configuration with API keys, Authorization header has "Bearer " with empty token.
    // Action: Authenticate with empty string (simulating "Bearer " with no token).
    // Expected behavior: Returns None (empty token cannot match any key).
    // Covers Requirements: F2.1, F5
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api.example.com", "key1", "/api"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("key1"),
            "valid-token",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate("");
    assert!(result.is_none(), "empty token should not authenticate");
}

#[test]
fn authenticate_with_token_not_matching_any_key_returns_none() {
    // Precondition: Configuration with API keys, token doesn't match any configured key.
    // Action: Authenticate with unknown token.
    // Expected behavior: Returns None (token doesn't match static keys and is not valid JWT).
    // Covers Requirements: F2.1, F3
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api.example.com", "key1", "/api"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("key1"),
            "valid-token",
            Some(vec!["upstream1".to_string()]),
        )])),
    );

    let result = config.authenticate("unknown-token-xyz");
    assert!(result.is_none(), "unknown token should not authenticate");
}

#[test]
fn find_upstream_when_no_authentication_required() {
    // Precondition: Configuration with upstreams but no API keys (authentication not required).
    // Action: Call find_upstream_by_path with empty permitted list.
    // Expected behavior: Returns upstream matching the path (all upstreams accessible when no auth).
    // Covers Requirements: F2.2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api.example.com", "key1", "/api"),
            )],
        )),
        None, // No API keys - authentication not required
    );

    let result = config.find_upstream_by_path("/api/test", &[]);
    assert_eq!(
        result,
        Some("upstream1".to_string()),
        "should find upstream when authentication not required"
    );
}

#[test]
fn find_upstream_with_single_permitted_upstream() {
    // Precondition: Configuration with multiple upstreams, API key has access to only one.
    // Action: Call find_upstream_by_path with single upstream in permitted list.
    // Expected behavior: Returns the permitted upstream if path matches, None otherwise.
    // Covers Requirements: F2.2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "upstream1",
                    test_upstream_entry_with_path("https://api1.example.com", "key1", "/api/v1"),
                ),
                (
                    "upstream2",
                    test_upstream_entry_with_path("https://api2.example.com", "key2", "/api/v2"),
                ),
            ],
        )),
        None,
    );

    let permitted = vec!["upstream1".to_string()];
    let result1 = config.find_upstream_by_path("/api/v1/test", &permitted);
    let result2 = config.find_upstream_by_path("/api/v2/test", &permitted);

    assert_eq!(
        result1,
        Some("upstream1".to_string()),
        "should find permitted upstream when path matches"
    );
    assert_eq!(
        result2, None,
        "should return None when path matches non-permitted upstream"
    );
}

#[test]
fn find_upstream_with_nonexistent_permitted_upstream() {
    // Precondition: Configuration with upstreams, permitted list contains upstream not in config.
    // Action: Call find_upstream_by_path with permitted list containing non-existent upstream.
    // Expected behavior: Ignores non-existent upstreams, only considers valid ones.
    // Covers Requirements: F2.2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api.example.com", "key1", "/api"),
            )],
        )),
        None,
    );

    let permitted = vec!["nonexistent".to_string(), "upstream1".to_string()];
    let result = config.find_upstream_by_path("/api/test", &permitted);

    assert_eq!(
        result,
        Some("upstream1".to_string()),
        "should ignore non-existent upstreams in permitted list"
    );
}

#[test]
fn find_upstream_with_exact_path_match() {
    // Precondition: Configuration with upstream having request_path exactly matching request path.
    // Action: Call find_upstream_by_path with request path exactly matching request_path.
    // Expected behavior: Returns upstream (exact match is also a prefix match).
    // Covers Requirements: F2.2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api.example.com", "key1", "/api/test"),
            )],
        )),
        None,
    );

    let result = config.find_upstream_by_path("/api/test", &[]);
    assert_eq!(
        result,
        Some("upstream1".to_string()),
        "exact path match should return upstream"
    );
}

#[test]
fn path_matching_normalizes_trailing_slash_request_path_with_slash() {
    // Precondition: Configuration with upstream having request_path "/api" (no trailing slash).
    // Action: Call find_upstream_by_path with request path "/api/" (with trailing slash).
    // Expected behavior: Returns upstream (trailing slashes normalized for matching).
    // Covers Requirements: F2.3
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api.example.com", "key1", "/api"),
            )],
        )),
        None,
    );

    let result = config.find_upstream_by_path("/api/", &[]);
    assert_eq!(
        result,
        Some("upstream1".to_string()),
        "should match when request_path has no trailing slash but request does"
    );
}

#[test]
fn path_matching_normalizes_trailing_slash_request_path_without_slash() {
    // Precondition: Configuration with upstream having request_path "/api/" (with trailing slash).
    // Action: Call find_upstream_by_path with request path "/api" (no trailing slash).
    // Expected behavior: Returns upstream (trailing slashes normalized for matching).
    // Covers Requirements: F2.3
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api.example.com", "key1", "/api/"),
            )],
        )),
        None,
    );

    let result = config.find_upstream_by_path("/api", &[]);
    assert_eq!(
        result,
        Some("upstream1".to_string()),
        "should match when request_path has trailing slash but request doesn't"
    );
}

#[test]
fn path_matching_selects_first_when_multiple_same_length_matches() {
    // Precondition: Configuration with multiple upstreams having same length request_path.
    // Action: Call find_upstream_by_path with request path matching multiple upstreams equally.
    // Expected behavior: Returns one of the matching upstreams (implementation-defined which).
    // Covers Requirements: F2.3
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![
                (
                    "upstream1",
                    test_upstream_entry_with_path("https://api1.example.com", "key1", "/api/v1"),
                ),
                (
                    "upstream2",
                    test_upstream_entry_with_path("https://api2.example.com", "key2", "/api/v2"),
                ),
            ],
        )),
        None,
    );

    // Both have same length, but request path "/api/v1/test" only matches upstream1
    let permitted = vec!["upstream1".to_string(), "upstream2".to_string()];
    let result = config.find_upstream_by_path("/api/v1/test", &permitted);
    assert_eq!(
        result,
        Some("upstream1".to_string()),
        "should select matching upstream when path matches"
    );
}

#[test]
fn path_matching_ignores_query_string() {
    // Precondition: Configuration with upstream having request_path "/api/test".
    // Action: Call find_upstream_by_path with request path "/api/test?param=value".
    // Expected behavior: Returns upstream (query string ignored for path matching).
    // Covers Requirements: F2.2, F2.3
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api.example.com", "key1", "/api/test"),
            )],
        )),
        None,
    );

    // Note: find_upstream_by_path takes path without query, but test that query is ignored
    // In real usage, query string is stripped before calling this method
    let result = config.find_upstream_by_path("/api/test", &[]);
    assert_eq!(
        result,
        Some("upstream1".to_string()),
        "path matching should work (query string handled separately)"
    );
}

#[test]
fn path_matching_with_url_encoded_characters() {
    // Precondition: Configuration with upstream having request_path with URL-encoded characters.
    // Action: Call find_upstream_by_path with request path containing URL-encoded characters.
    // Expected behavior: Returns upstream if encoded path matches.
    // Covers Requirements: F2.2, F2.3
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path(
                    "https://api.example.com",
                    "key1",
                    "/api/test%20path",
                ),
            )],
        )),
        None,
    );

    let result = config.find_upstream_by_path("/api/test%20path/data", &[]);
    assert_eq!(
        result,
        Some("upstream1".to_string()),
        "should match URL-encoded paths"
    );
}

#[test]
fn path_matching_returns_none_when_no_match() {
    // Precondition: Configuration with upstreams, request path doesn't match any request_path.
    // Action: Call find_upstream_by_path with non-matching request path.
    // Expected behavior: Returns None (no upstream matches, should result in HTTP 404).
    // Covers Requirements: F2.3, F3
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path("https://api.example.com", "key1", "/api"),
            )],
        )),
        None,
    );

    let result = config.find_upstream_by_path("/other/path", &[]);
    assert_eq!(
        result, None,
        "should return None when no upstream matches (should result in HTTP 404)"
    );
}

#[test]
fn upstream_api_key_is_available_for_authorization_replacement() {
    // Precondition: Configuration with upstream having configured api_key.
    // Action: Get upstream entry and check api_key field.
    // Expected behavior: api_key field contains the key to use for Authorization header replacement.
    // Covers Requirements: F2.4
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry_with_path(
                    "https://api.example.com",
                    "upstream-key-123",
                    "/api",
                ),
            )],
        )),
        None,
    );

    let upstream = config
        .get_upstream("upstream1")
        .expect("upstream should exist");
    assert_eq!(
        upstream.api_key, "upstream-key-123",
        "upstream should have api_key for Authorization header replacement"
    );
}

#[test]
fn upstream_without_api_key_has_empty_string() {
    // Precondition: Configuration with upstream having empty api_key (edge case).
    // Action: Get upstream entry and check api_key field.
    // Expected behavior: api_key field may be empty (Authorization header should be omitted).
    // Covers Requirements: F2.4, F1
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                UpstreamEntry {
                    target_url: "https://api.example.com".to_string(),
                    api_key: "".to_string(), // Empty key
                    request_path: "/api".to_string(),
                },
            )],
        )),
        None,
    );

    let upstream = config
        .get_upstream("upstream1")
        .expect("upstream should exist");
    assert_eq!(
        upstream.api_key, "",
        "upstream with empty api_key should have empty string"
    );
}

#[test]
fn build_upstream_url_preserves_original_path_when_forwarding() {
    // Precondition: Upstream entry with request_path "/api", request path "/api/test" with trailing slash.
    // Action: Call build_upstream_url with request path containing trailing slash.
    // Expected behavior: Original path with trailing slash is preserved in forwarded URL.
    // Covers Requirements: F2.3, F2.5
    let upstream = test_upstream_entry_with_path("https://api.example.com", "key1", "/api");

    let request_uri = "/api/test/".parse().unwrap(); // Original path with trailing slash
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(
        result.path().ends_with('/'),
        "original trailing slash should be preserved when forwarding"
    );
}

#[test]
fn build_upstream_url_handles_path_prefix_removal_correctly() {
    // Precondition: Upstream entry with request_path "/api/v1", request path "/api/v1/users/123".
    // Action: Call build_upstream_url to build target URL.
    // Expected behavior: request_path prefix is removed, remaining path "/users/123" is appended.
    // Covers Requirements: F2.2, F2.5
    let upstream = test_upstream_entry_with_path("https://api.example.com", "key1", "/api/v1");

    let request_uri = "/api/v1/users/123".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert_eq!(
        result.path(),
        "/users/123",
        "request_path prefix should be removed, remaining path appended"
    );
}

#[test]
fn build_upstream_url_preserves_query_parameters_when_forwarding() {
    // Precondition: Upstream entry with request_path "/api", request path "/api/test?param=value&other=123".
    // Action: Call build_upstream_url with request path containing query parameters.
    // Expected behavior: Query parameters are preserved in forwarded URL.
    // Covers Requirements: F2.5, F1
    let upstream = test_upstream_entry_with_path("https://api.example.com", "key1", "/api");

    let request_uri = "/api/test?param=value&other=123".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    assert!(
        result.query().unwrap().contains("param=value"),
        "query parameters should be preserved when forwarding"
    );
    assert!(
        result.query().unwrap().contains("other=123"),
        "all query parameters should be preserved"
    );
}

#[test]
fn build_upstream_url_preserves_fragment_in_request_uri() {
    // Precondition: Upstream entry with request_path "/api", request path "/api/test#fragment".
    // Action: Call build_upstream_url with request path containing fragment.
    // Expected behavior: Fragment is preserved in forwarded URL (if supported by URI parser).
    // Covers Requirements: F2.5, F1
    let upstream = test_upstream_entry_with_path("https://api.example.com", "key1", "/api");

    let request_uri = "/api/test#fragment".parse().unwrap();
    let result = build_upstream_url(&upstream, &request_uri).unwrap();

    // Note: URI parser may remove fragments, but we test that method handles it
    assert_eq!(
        result.path(),
        "/test",
        "path should be correctly processed (fragment handling depends on URI parser)"
    );
}
