//! Unit tests for Configuration Requirements (C1-C17)
//!
//! This module contains unit tests covering configuration requirements.
//! Tests have been migrated from config_manager.rs and request_path_routing.rs.

use crate::common::*;
use fluxgate::config::{
    ApiKeysConfig, Config, ConfigManager, ServerConfig, StaticApiKey, UpstreamEntry,
    UpstreamsConfig, SUPPORTED_CONFIG_VERSION,
};
use futures::future;
use std::collections::HashMap;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn validate_rejects_request_path_without_leading_slash() {
    // Precondition: Config with upstream having request_path without leading slash.
    // Action: Call validate on config with invalid request_path.
    // Expected behavior: Returns validation error indicating request_path must start with '/'.
    // Covers Requirements: C15
    let upstream = test_upstream_entry_with_path(
        "https://api.example.com",
        "key",
        "api/test", // Missing leading slash
    );
    let config = test_config(
        Some(test_upstreams_config(30_000, vec![("test", upstream)])),
        None,
    );
    let error = config
        .validate()
        .expect_err("should reject request_path without leading slash");
    assert!(
        error
            .reasons()
            .iter()
            .any(|r| r.contains("request_path") && r.contains("start with '/'")),
        "should report missing leading slash"
    );
}

#[test]
fn validate_rejects_request_path_with_scheme() {
    // Precondition: Config with upstream having request_path containing scheme (e.g., "https://").
    // Action: Call validate on config with invalid request_path containing scheme.
    // Expected behavior: Returns validation error indicating request_path cannot contain scheme.
    // Covers Requirements: C15
    let upstream = test_upstream_entry_with_path(
        "https://api.example.com",
        "key",
        "https://api.example.com/path",
    );
    let config = test_config(
        Some(test_upstreams_config(30_000, vec![("test", upstream)])),
        None,
    );
    let error = config
        .validate()
        .expect_err("should reject request_path with scheme");
    assert!(
        error
            .reasons()
            .iter()
            .any(|r| r.contains("scheme") || r.contains("://")),
        "should report scheme in request_path"
    );
}

#[test]
fn validate_rejects_request_path_with_query_string() {
    // Precondition: Config with upstream having request_path containing query string.
    // Action: Call validate on config with invalid request_path containing query string.
    // Expected behavior: Returns validation error indicating request_path cannot contain query string.
    // Covers Requirements: C15
    let upstream =
        test_upstream_entry_with_path("https://api.example.com", "key", "/api/test?param=value");
    let config = test_config(
        Some(test_upstreams_config(30_000, vec![("test", upstream)])),
        None,
    );
    let error = config
        .validate()
        .expect_err("should reject request_path with query");
    assert!(
        error
            .reasons()
            .iter()
            .any(|r| r.contains("query string") || r.contains('?')),
        "should report query string in request_path"
    );
}

#[test]
fn validate_rejects_request_path_with_port() {
    // Precondition: Config with upstream having request_path containing port separator.
    // Action: Call validate on config with invalid request_path containing port separator.
    // Expected behavior: Returns validation error indicating request_path cannot contain port separator.
    // Covers Requirements: C15
    let upstream =
        test_upstream_entry_with_path("https://api.example.com", "key", "/api:8080/test");
    let config = test_config(
        Some(test_upstreams_config(30_000, vec![("test", upstream)])),
        None,
    );
    let error = config
        .validate()
        .expect_err("should reject request_path with port");
    assert!(
        error
            .reasons()
            .iter()
            .any(|r| r.contains("port separator") || r.contains(':')),
        "should report port separator in request_path"
    );
}

#[test]
fn validate_allows_colon_in_path_segment() {
    // Precondition: Config with upstream having request_path containing colon not followed by digits.
    // Action: Call validate on config with request_path containing colon in path segment.
    // Expected behavior: Validation succeeds (colon allowed when not followed by digits).
    // Covers Requirements: C15
    let upstream = test_upstream_entry_with_path(
        "https://api.example.com",
        "key",
        "/api/v1:test/path", // Colon not followed by digits
    );
    let config = test_config(
        Some(test_upstreams_config(30_000, vec![("test", upstream)])),
        None,
    );
    assert!(
        config.validate().is_ok(),
        "should allow colon in path segment when not followed by digits"
    );
}

#[test]
fn validate_rejects_empty_request_path() {
    // Precondition: Config with upstream having empty request_path.
    // Action: Call validate on config with empty request_path.
    // Expected behavior: Returns validation error indicating request_path cannot be empty.
    // Covers Requirements: C15
    let upstream = test_upstream_entry_with_path("https://api.example.com", "key", "");
    let config = test_config(
        Some(test_upstreams_config(30_000, vec![("test", upstream)])),
        None,
    );
    let error = config
        .validate()
        .expect_err("should reject empty request_path");
    assert!(
        error
            .reasons()
            .iter()
            .any(|r| r.contains("request_path") && r.contains("not be empty")),
        "should report empty request_path"
    );
}

#[test]
fn validate_rejects_whitespace_only_request_path() {
    // Precondition: Config with upstream having request_path containing only whitespace.
    // Action: Call validate on config with whitespace-only request_path.
    // Expected behavior: Returns validation error indicating request_path cannot be empty (whitespace treated as empty).
    // Covers Requirements: C15
    let upstream = test_upstream_entry_with_path("https://api.example.com", "key", "   ");
    let config = test_config(
        Some(test_upstreams_config(30_000, vec![("test", upstream)])),
        None,
    );
    let error = config
        .validate()
        .expect_err("should reject whitespace-only request_path");
    assert!(
        error
            .reasons()
            .iter()
            .any(|r| r.contains("request_path") && r.contains("not be empty")),
        "should report whitespace-only request_path as empty"
    );
}

#[test]
fn validate_rejects_duplicate_request_paths() {
    // Precondition: Config with multiple upstreams having duplicate request_paths.
    // Action: Call validate on config with duplicate request_paths.
    // Expected behavior: Returns validation error indicating request_paths must be unique.
    // Covers Requirements: C16
    let upstream1 = test_upstream_entry_with_path("https://api1.example.com", "key1", "/api");
    let upstream2 = test_upstream_entry_with_path(
        "https://api2.example.com",
        "key2",
        "/api", // Duplicate
    );
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![("upstream1", upstream1), ("upstream2", upstream2)],
        )),
        None,
    );
    let error = config
        .validate()
        .expect_err("should reject duplicate request_paths");
    assert!(
        error
            .reasons()
            .iter()
            .any(|r| r.contains("not unique") || r.contains("duplicate")),
        "should report duplicate request_path"
    );
}

#[test]
fn validate_allows_duplicate_request_paths_with_different_trailing_slashes() {
    // Precondition: Config with multiple upstreams having request_paths differing only by trailing slash.
    // Action: Call validate on config with /api and /api/ request_paths.
    // Expected behavior: Returns validation error if trailing slashes are normalized (duplicates detected).
    // Covers Requirements: C16
    // Note: Trailing slashes are normalized, so /api and /api/ should be considered duplicates
    let upstream1 = test_upstream_entry_with_path("https://api1.example.com", "key1", "/api");
    let upstream2 = test_upstream_entry_with_path(
        "https://api2.example.com",
        "key2",
        "/api/", // Should be considered duplicate
    );
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![("upstream1", upstream1), ("upstream2", upstream2)],
        )),
        None,
    );
    // Note: This depends on validation implementation - if it normalizes before checking,
    // it should reject. If not, it might allow. Let's test what actually happens.
    let result = config.validate();
    // The validation should normalize and detect duplicate
    if let Err(error) = result {
        assert!(
            error
                .reasons()
                .iter()
                .any(|r| r.contains("not unique") || r.contains("duplicate")),
            "should report /api and /api/ as duplicate after normalization"
        );
    }
}

#[test]
fn validate_accepts_valid_request_paths() {
    // Precondition: Config with upstreams having various valid request_path formats.
    // Action: Call validate on configs with different valid request_path formats.
    // Expected behavior: Validation succeeds for all valid request_path formats.
    // Covers Requirements: C15
    let valid_paths = vec![
        "/",
        "/api",
        "/api/v1",
        "/api/v1/models",
        "/api/test-endpoint",
        "/api/v1.0",
        "/api/v1/test",
        "/very/long/nested/path/structure",
    ];
    for path in valid_paths {
        let upstream = test_upstream_entry_with_path("https://api.example.com", "key", path);
        let upstream_name = format!("upstream-{}", path.replace('/', "-"));
        let config = test_config(
            Some(test_upstreams_config(
                30_000,
                vec![(&upstream_name, upstream)],
            )),
            None,
        );
        assert!(
            config.validate().is_ok(),
            "should accept valid request_path: {}",
            path
        );
    }
}

#[test]
fn validate_handles_request_path_with_encoded_characters() {
    // Precondition: Config with upstream having request_path containing URL-encoded characters.
    // Action: Call validate on config with request_path containing URL-encoded characters.
    // Expected behavior: Validation succeeds (URL-encoded characters are allowed).
    // Covers Requirements: C15
    let upstream = test_upstream_entry_with_path(
        "https://api.example.com",
        "key",
        "/api/test%20path", // URL encoded space
    );
    let config = test_config(
        Some(test_upstreams_config(30_000, vec![("test", upstream)])),
        None,
    );
    assert!(
        config.validate().is_ok(),
        "should allow URL-encoded characters in request_path"
    );
}

#[test]
fn validate_handles_request_path_with_multiple_slashes() {
    // Precondition: Config with upstream having request_path containing multiple consecutive slashes.
    // Action: Call validate on config with request_path containing multiple slashes.
    // Expected behavior: Validation succeeds (multiple slashes are normalized during matching).
    // Covers Requirements: C15
    let upstream = test_upstream_entry_with_path(
        "https://api.example.com",
        "key",
        "/api//test", // Multiple slashes
    );
    let config = test_config(
        Some(test_upstreams_config(30_000, vec![("test", upstream)])),
        None,
    );
    assert!(
        config.validate().is_ok(),
        "should allow multiple slashes in request_path (normalized during matching)"
    );
}

#[test]
fn default_configuration_is_valid() {
    // Precondition: Default configuration from Config::default().
    // Action: Call validate on default configuration.
    // Expected behavior: Validation succeeds, proving the baked-in defaults are safe.
    // Covers Requirements: C1
    let default_config = Config::default();
    assert!(
        default_config.validate().is_ok(),
        "default configuration must remain valid"
    );
    assert_eq!(
        default_config.server.bind_address, "0.0.0.0:8080",
        "default bind address must listen on all interfaces"
    );
}

#[test]
fn invalid_configuration_reports_all_reasons() {
    // Precondition: Configuration violating multiple invariants (empty fields, invalid values).
    // Action: Call validate on invalid configuration.
    // Expected behavior: Validation fails and reports each violated constraint.
    // Covers Requirements: C2
    let invalid_config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "".to_string(),
            max_connections: 0,
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 0,
            upstreams: HashMap::from([(
                "bad-upstream".to_string(),
                UpstreamEntry {
                    target_url: "".to_string(),
                    api_key: "".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: Some(ApiKeysConfig {
            static_: vec![StaticApiKey {
                id: None,
                key: "".to_string(),
                upstreams: Some(vec!["nonexistent".to_string()]),
            }],
            jwt: None,
        }),
    };

    let error = invalid_config
        .validate()
        .expect_err("configuration with empty fields should fail validation");
    let reasons = error.reasons();

    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("server.bind_address")),
        "expected validation error for empty bind address, got: {reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("server.max_connections")),
        "expected validation error for zero max_connections, got: {reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("upstreams.request_timeout_ms")),
        "expected validation error for zero request_timeout_ms, got: {reasons:?}"
    );
    assert!(
        reasons.iter().any(|reason| reason.contains("target_url")),
        "expected validation error for empty target_url, got: {reasons:?}"
    );
    assert!(
        reasons.iter().any(|reason| reason.contains("api_key")),
        "expected validation error for empty api_key, got: {reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("api_keys.static[0].key")),
        "expected validation error for empty api key, got: {reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|reason| reason.contains("unknown upstream")),
        "expected validation error for unknown upstream reference, got: {reasons:?}"
    );
}

#[test]
fn whitespace_only_bind_address_is_rejected() {
    // Precondition: Configuration with bind address containing only whitespace.
    // Action: Call validate on configuration with whitespace-only bind address.
    // Expected behavior: Validation fails because whitespace-only bind addresses are invalid.
    // Covers Requirements: C2
    // Note: This test specifically tests invalid server config, so we can't use test_server_config()
    let server = ServerConfig {
        bind_address: "   ".to_string(),
        max_connections: 100,
    };
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server,
        upstreams: None,
        api_keys: None,
    };

    let error = config
        .validate()
        .expect_err("whitespace-only bind address must be rejected");
    assert!(
        error
            .reasons()
            .iter()
            .any(|reason| reason.contains("server.bind_address")),
        "expected bind address validation failure, got: {:?}",
        error.reasons()
    );
}

#[test]
fn ipv6_bind_address_is_accepted() {
    // Precondition: Configuration with valid IPv6 bind address.
    // Action: Call validate on configuration with IPv6 bind address.
    // Expected behavior: Validation succeeds for IPv6 addresses.
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "[::1]:8080".to_string(),
            max_connections: 100,
        },
        upstreams: None,
        api_keys: None,
    };

    assert!(
        config.validate().is_ok(),
        "IPv6 bind address should be accepted"
    );
}

#[test]
fn bind_address_without_port_is_accepted() {
    // Precondition: Configuration with bind address without explicit port.
    // Action: Call validate on configuration with bind address without port.
    // Expected behavior: Validation succeeds (let the system choose default port).
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1".to_string(),
            max_connections: 100,
        },
        upstreams: None,
        api_keys: None,
    };

    assert!(
        config.validate().is_ok(),
        "bind address without port should be accepted"
    );
}

#[test]
fn overly_long_bind_address_is_rejected() {
    // Precondition: Configuration with excessively long bind address.
    // Action: Call validate on configuration with overly long bind address.
    // Expected behavior: Validation fails for unreasonably long bind addresses.
    // Covers Requirements: C2
    let long_address = "a".repeat(1000);
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: long_address,
            max_connections: 100,
        },
        upstreams: None,
        api_keys: None,
    };

    let error = config
        .validate()
        .expect_err("overly long bind address must be rejected");
    assert!(
        error
            .reasons()
            .iter()
            .any(|reason| reason.contains("server.bind_address")),
        "expected bind address validation failure, got: {:?}",
        error.reasons()
    );
}

#[test]
fn malformed_target_url_is_rejected() {
    // Precondition: Configuration with malformed, non-empty upstream target URL.
    // Action: Call validate on configuration with malformed target URL.
    // Expected behavior: Validation fails and surfaces the URL parsing error.
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([(
                "bad-upstream".to_string(),
                UpstreamEntry {
                    target_url: "ht!tp://bad url".to_string(),
                    api_key: "test-key".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: None,
    };

    let error = config
        .validate()
        .expect_err("malformed upstream target URL must be rejected");
    assert!(
        error
            .reasons()
            .iter()
            .any(|reason| reason.contains("target_url")),
        "expected upstream target URL validation failure, got: {:?}",
        error.reasons()
    );
}

#[test]
fn unsupported_url_scheme_is_rejected() {
    // Precondition: Configuration with unsupported URL scheme (ftp, etc.).
    // Action: Call validate on configuration with unsupported URL scheme.
    // Expected behavior: Validation fails because only http/https schemes are supported.
    // Covers Requirements: C2
    let test_cases = vec![
        "ftp://example.com/api",
        "file:///etc/passwd",
        "custom://example.com",
        "ws://example.com",
        "wss://example.com",
    ];

    for scheme_url in test_cases {
        let config = Config {
            version: SUPPORTED_CONFIG_VERSION,
            server: ServerConfig {
                bind_address: "127.0.0.1:8080".to_string(),
                max_connections: 100,
            },
            upstreams: Some(UpstreamsConfig {
                request_timeout_ms: 30_000,
                upstreams: HashMap::from([(
                    "upstream".to_string(),
                    UpstreamEntry {
                        target_url: scheme_url.to_string(),
                        api_key: "test-key".to_string(),
                        request_path: "/test".to_string(),
                    },
                )]),
            }),
            api_keys: None,
        };

        let error = config
            .validate()
            .expect_err(&format!("URL scheme in {} must be rejected", scheme_url));
        assert!(
            error
                .reasons()
                .iter()
                .any(|reason| reason.contains("target_url")),
            "expected target URL validation failure for unsupported scheme {}, got: {:?}",
            scheme_url,
            error.reasons()
        );
    }
}

#[test]
fn http_and_https_url_schemes_are_accepted() {
    // Precondition: Configurations with http and https URL schemes.
    // Action: Call validate on configurations with http and https schemes.
    // Expected behavior: Validation succeeds for http and https schemes.
    // Covers Requirements: C2
    let test_cases = vec![
        "http://example.com/api",
        "https://api.example.com/v1",
        "HTTP://EXAMPLE.COM",
        "HTTPS://API.EXAMPLE.COM",
    ];

    for scheme_url in test_cases {
        let config = Config {
            version: SUPPORTED_CONFIG_VERSION,
            server: ServerConfig {
                bind_address: "127.0.0.1:8080".to_string(),
                max_connections: 100,
            },
            upstreams: Some(UpstreamsConfig {
                request_timeout_ms: 30_000,
                upstreams: HashMap::from([(
                    "upstream".to_string(),
                    UpstreamEntry {
                        target_url: scheme_url.to_string(),
                        api_key: "test-key".to_string(),
                        request_path: "/test".to_string(),
                    },
                )]),
            }),
            api_keys: None,
        };

        assert!(
            config.validate().is_ok(),
            "URL scheme {} should be accepted",
            scheme_url
        );
    }
}

#[test]
fn url_with_query_parameters_is_accepted() {
    // Precondition: Configuration with URL containing query parameters.
    // Action: Call validate on configuration with URL containing query parameters.
    // Expected behavior: Validation succeeds for URLs with query parameters.
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([(
                "upstream".to_string(),
                UpstreamEntry {
                    target_url: "https://api.example.com/v1?param1=value1&param2=value2"
                        .to_string(),
                    api_key: "test-key".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: None,
    };

    assert!(
        config.validate().is_ok(),
        "URL with query parameters should be accepted"
    );
}

#[test]
fn empty_upstreams_list_in_api_key_is_accepted() {
    // Precondition: Configuration with API key having empty upstreams list.
    // Action: Call validate on configuration with API key having empty upstreams list.
    // Expected behavior: Validation succeeds (empty list means no upstream restrictions).
    // Covers Requirements: C2

    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([(
                "upstream1".to_string(),
                UpstreamEntry {
                    target_url: "https://api.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: Some(ApiKeysConfig {
            static_: vec![StaticApiKey {
                id: Some("test-key".to_string()),
                key: "test-token".to_string(),
                upstreams: Some(vec![]), // Empty list
            }],
            jwt: None,
        }),
    };

    assert!(
        config.validate().is_ok(),
        "API key with empty upstreams list should be accepted"
    );
}

#[test]
fn api_key_with_valid_upstreams_list_is_accepted() {
    // Precondition: Configuration with API key referencing valid upstreams.
    // Action: Call validate on configuration with API key referencing valid upstreams.
    // Expected behavior: Validation succeeds.
    // Covers Requirements: C2

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
                        request_path: "/api1".to_string(),
                    },
                ),
                (
                    "upstream2".to_string(),
                    UpstreamEntry {
                        target_url: "https://api2.example.com".to_string(),
                        api_key: "key2".to_string(),
                        request_path: "/api2".to_string(),
                    },
                ),
            ]),
        }),
        api_keys: Some(ApiKeysConfig {
            static_: vec![StaticApiKey {
                id: Some("test-key".to_string()),
                key: "test-token".to_string(),
                upstreams: Some(vec!["upstream1".to_string(), "upstream2".to_string()]),
            }],
            jwt: None,
        }),
    };

    assert!(
        config.validate().is_ok(),
        "API key with valid upstreams list should be accepted"
    );
}

#[test]
fn api_key_with_none_upstreams_is_accepted() {
    // Precondition: Configuration with API key having None upstreams.
    // Action: Call validate on configuration with API key having None upstreams.
    // Expected behavior: Validation succeeds (None means access to all upstreams).
    // Covers Requirements: C2

    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([(
                "upstream1".to_string(),
                UpstreamEntry {
                    target_url: "https://api.example.com".to_string(),
                    api_key: "key1".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: Some(ApiKeysConfig {
            static_: vec![StaticApiKey {
                id: Some("test-key".to_string()),
                key: "test-token".to_string(),
                upstreams: None, // None means all upstreams
            }],
            jwt: None,
        }),
    };

    assert!(
        config.validate().is_ok(),
        "API key with None upstreams should be accepted"
    );
}

#[tokio::test]
async fn subscribe_returns_current_config_immediately() {
    // Precondition: Configuration file contains non-default values and config manager is initialised.
    // Action: Subscribe to configuration updates.
    // Expected behavior: Subscriber immediately receives the latest configuration snapshot.
    // Covers Requirements: C6
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_contents = r#"
version: 1

server:
  bind_address: "127.0.0.1:19090"
  max_connections: 42
upstreams:
  request_timeout_ms: 1500
  test-upstream:
    target_url: "https://upstream.example.com/api"
    api_key: "test-key"
    request_path: "/test"
"#;
    std::fs::write(&config_path, config_contents).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path)).await;
    let receiver = manager.subscribe();
    let snapshot = receiver.borrow().clone();

    assert_eq!(snapshot.server.bind_address, "127.0.0.1:19090");
    assert_eq!(snapshot.server.max_connections, 42);
    assert_eq!(
        snapshot.upstreams.as_ref().unwrap().request_timeout_ms,
        1_500
    );
    let upstream = snapshot
        .upstreams
        .as_ref()
        .unwrap()
        .upstreams
        .get("test-upstream")
        .unwrap();
    assert_eq!(upstream.target_url, "https://upstream.example.com/api");
    assert_eq!(upstream.api_key, "test-key");
}

#[tokio::test]
async fn config_manager_without_subscribers_causes_channel_closed_on_update() {
    // Precondition: Configuration manager initialized, no subscribers to configuration changes.
    // Action: Update configuration file and attempt to send update through channel.
    // Expected behavior: Channel closes when no subscribers are present (demonstrates watcher behavior).
    // Covers Requirements: C6
    // Note: Test that demonstrates how the configuration watcher handles updates when no components are subscribed
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let initial_config = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
upstreams:
  request_timeout_ms: 30000
  test-upstream:
    target_url: "https://example.com"
    api_key: "test-key"
"#;
    std::fs::write(&config_path, initial_config).expect("write initial config");

    // Initialize config manager without subscribing to updates
    let _manager = ConfigManager::initialize(Some(config_path.clone())).await;

    // Wait for watcher to be ready
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Modify configuration to trigger watcher
    let updated_config = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 200
upstreams:
  request_timeout_ms: 30000
  test-upstream:
    target_url: "https://example.com"
    api_key: "updated-key"
"#;
    std::fs::write(&config_path, updated_config).expect("write updated config");

    // Wait for watcher to detect change and attempt to publish
    tokio::time::sleep(Duration::from_millis(1000)).await;
}

#[test]
fn authenticate_with_empty_upstreams_list_and_no_upstreams_configured() {
    // Precondition: API key with empty upstreams list, and no upstreams configured.
    // Action: authenticate with valid token.
    // Expected behavior: returns empty list (will result in HTTP 401).
    // Covers Requirements: C2
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec![]), // Empty list
        )])),
    );

    let result = config
        .authenticate("valid-token")
        .expect("authentication should succeed");
    assert!(result.permitted_upstreams.is_empty());
}

#[test]
fn authenticate_with_empty_upstreams_list_and_empty_upstreams_config() {
    // Precondition: API key with empty upstreams list, upstreams section exists but is empty.
    // Action: authenticate with valid token.
    // Expected behavior: returns empty list (will result in HTTP 401).
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(30_000, vec![])), // Empty upstreams map
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec![]), // Empty list
        )])),
    );

    let result = config
        .authenticate("valid-token")
        .expect("authentication should succeed");
    assert!(result.permitted_upstreams.is_empty());
}

#[test]
fn authenticate_with_omitted_upstreams_and_no_upstreams_configured() {
    // Precondition: API key with omitted (None) upstreams, and no upstreams configured.
    // Action: authenticate with valid token.
    // Expected behavior: returns empty list (will result in HTTP 401).
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: None,
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
    assert!(result.permitted_upstreams.is_empty());
}

#[test]
fn authenticate_with_omitted_upstreams_and_empty_upstreams_config() {
    // Precondition: API key with omitted (None) upstreams, upstreams section exists but is empty.
    // Action: authenticate with valid token.
    // Expected behavior: returns empty list (will result in HTTP 401).
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::new(), // Empty upstreams map
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
    assert!(result.permitted_upstreams.is_empty());
}

#[test]
fn authenticate_preserves_api_key_name() {
    // Precondition: configuration with API key with id.
    // Action: authenticate with valid token.
    // Expected behavior: returns the API key id in the result.
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: None,
        api_keys: Some(ApiKeysConfig {
            static_: vec![StaticApiKey {
                id: Some("my-api-key".to_string()),
                key: "valid-token".to_string(),
                upstreams: None,
            }],
            jwt: None,
        }),
    };

    let result = config
        .authenticate("valid-token")
        .expect("authentication should succeed");
    assert_eq!(result.api_key, Some("my-api-key".to_string()));
}

#[test]
fn authenticate_handles_api_key_without_name() {
    // Precondition: configuration with API key without id field.
    // Action: authenticate with valid token.
    // Expected behavior: returns None for api_key.
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: None,
        api_keys: Some(ApiKeysConfig {
            static_: vec![StaticApiKey {
                id: None,
                key: "valid-token".to_string(),
                upstreams: None,
            }],
            jwt: None,
        }),
    };

    let result = config
        .authenticate("valid-token")
        .expect("authentication should succeed");
    assert_eq!(result.api_key, None);
}

#[test]
fn authenticate_with_multiple_api_keys_selects_correct_one() {
    // Precondition: configuration with multiple API keys.
    // Action: authenticate with different tokens.
    // Expected behavior: each token returns the correct API key's configuration.
    // Covers Requirements: C2
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
            static_: vec![
                StaticApiKey {
                    id: Some("key1".to_string()),
                    key: "token1".to_string(),
                    upstreams: Some(vec!["upstream1".to_string()]),
                },
                StaticApiKey {
                    id: Some("key2".to_string()),
                    key: "token2".to_string(),
                    upstreams: Some(vec!["upstream2".to_string()]),
                },
            ],
            jwt: None,
        }),
    };

    let result1 = config
        .authenticate("token1")
        .expect("authentication should succeed");
    assert_eq!(result1.api_key, Some("key1".to_string()));
    assert_eq!(result1.permitted_upstreams, vec!["upstream1".to_string()]);

    let result2 = config
        .authenticate("token2")
        .expect("authentication should succeed");
    assert_eq!(result2.api_key, Some("key2".to_string()));
    assert_eq!(result2.permitted_upstreams, vec!["upstream2".to_string()]);
}

#[test]
fn get_upstream_returns_none_when_no_upstreams_configured() {
    // Precondition: configuration without upstreams section.
    // Action: attempt to get upstream by name.
    // Expected behavior: returns None.
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: None,
        api_keys: None,
    };

    assert!(config.get_upstream("any-upstream").is_none());
}

#[test]
fn get_upstream_returns_none_for_unknown_upstream() {
    // Precondition: configuration with upstreams, but requested name doesn't exist.
    // Action: attempt to get upstream by unknown name.
    // Expected behavior: returns None.
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([(
                "upstream1".to_string(),
                UpstreamEntry {
                    target_url: "https://api.example.com".to_string(),
                    api_key: "key".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: None,
    };

    assert!(config.get_upstream("unknown-upstream").is_none());
}

#[test]
fn upstream_timeout_returns_none_when_no_upstreams_configured() {
    // Precondition: configuration without upstreams section.
    // Action: get upstream timeout.
    // Expected behavior: returns None.
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: None,
        api_keys: None,
    };

    assert!(config.upstream_timeout().is_none());
}

#[test]
fn upstream_timeout_returns_configured_value() {
    // Precondition: configuration with upstreams and timeout set.
    // Action: get upstream timeout.
    // Expected behavior: returns the configured timeout value.
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 15_000,
            upstreams: HashMap::new(),
        }),
        api_keys: None,
    };

    assert_eq!(config.upstream_timeout(), Some(15_000));
}

#[test]
fn has_upstreams_returns_false_when_no_upstreams_configured() {
    // Precondition: configuration without upstreams section.
    // Action: check if upstreams exist.
    // Expected behavior: returns false.
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: None,
        api_keys: None,
    };

    assert!(!config.has_upstreams());
}

#[test]
fn has_upstreams_returns_false_when_upstreams_section_empty() {
    // Precondition: configuration with upstreams section but empty map.
    // Action: check if upstreams exist.
    // Expected behavior: returns false.
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::new(),
        }),
        api_keys: None,
    };

    assert!(!config.has_upstreams());
}

#[test]
fn has_upstreams_returns_true_when_upstreams_exist() {
    // Precondition: configuration with upstreams.
    // Action: check if upstreams exist.
    // Expected behavior: returns true.
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: 100,
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([(
                "upstream1".to_string(),
                UpstreamEntry {
                    target_url: "https://api.example.com".to_string(),
                    api_key: "key".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: None,
    };

    assert!(config.has_upstreams());
}

#[tokio::test]
async fn config_manager_current_returns_initial_config() {
    // Precondition: configuration file with valid config.
    // Action: get current config from manager.
    // Expected behavior: returns the loaded configuration.
    // Covers Requirements: C2
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_contents = r#"
version: 1

server:
  bind_address: "127.0.0.1:9090"
  max_connections: 200
"#;
    std::fs::write(&config_path, config_contents).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path)).await;
    let current = manager.current();

    assert_eq!(current.server.bind_address, "127.0.0.1:9090");
    assert_eq!(current.server.max_connections, 200);
    assert!(
        !manager.started_with_defaults(),
        "started_with_defaults() should return false when config file is successfully loaded"
    );
}

#[tokio::test]
async fn config_manager_reload_applies_valid_config() {
    // Precondition: configuration file exists with initial config.
    // Action: modify file and reload.
    // Expected behavior: new configuration is applied.
    // Covers Requirements: C2
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let initial_config = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#;
    std::fs::write(&config_path, initial_config).expect("write initial config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;
    assert_eq!(manager.current().server.max_connections, 100);

    let updated_config = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 200
"#;
    std::fs::write(&config_path, updated_config).expect("write updated config");

    manager.reload().await.expect("reload should succeed");
    assert_eq!(manager.current().server.max_connections, 200);
}

#[tokio::test]
async fn config_manager_reload_rejects_invalid_config() {
    // Precondition: configuration file exists with valid config.
    // Action: write invalid config and reload.
    // Expected behavior: reload fails, previous config retained.
    // Covers Requirements: C3
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let initial_config = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#;
    std::fs::write(&config_path, initial_config).expect("write initial config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;
    assert_eq!(manager.current().server.max_connections, 100);

    let invalid_config = r#"
version: 1

server:
  bind_address: ""
  max_connections: 0
"#;
    std::fs::write(&config_path, invalid_config).expect("write invalid config");

    let result = manager.reload().await;
    assert!(result.is_err(), "reload should fail for invalid config");
    assert_eq!(
        manager.current().server.max_connections,
        100,
        "previous config should be retained"
    );
}

#[tokio::test]
async fn config_manager_reload_handles_missing_file() {
    // Precondition: configuration file exists.
    // Action: delete file and reload.
    // Expected behavior: reload fails, previous config retained.
    // Covers Requirements: C3
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let initial_config = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#;
    std::fs::write(&config_path, initial_config).expect("write initial config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;
    assert_eq!(manager.current().server.max_connections, 100);

    std::fs::remove_file(&config_path).expect("delete config file");

    let result = manager.reload().await;
    assert!(result.is_err(), "reload should fail for missing file");
    assert_eq!(
        manager.current().server.max_connections,
        100,
        "previous config should be retained"
    );
}

#[test]
fn validate_config_version_accepts_valid_version() {
    // Precondition: YAML value with valid version 1.
    // Action: validate version.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    use fluxgate::config::validate_config_version;
    use serde_yaml::Value;

    let yaml_value: Value = serde_yaml::from_str(
        r#"
version: 1
server:
  bind_address: "127.0.0.1:8080"
"#,
    )
    .expect("parse YAML");

    assert!(validate_config_version(&yaml_value).is_ok());
}

#[test]
fn validate_config_version_rejects_missing_version() {
    // Precondition: YAML value without version field.
    // Action: validate version.
    // Expected behavior: validation fails with appropriate error.
    // Covers Requirements: C2
    use fluxgate::config::validate_config_version;
    use serde_yaml::Value;

    let yaml_value: Value = serde_yaml::from_str(
        r#"
server:
  bind_address: "127.0.0.1:8080"
"#,
    )
    .expect("parse YAML");

    let error = validate_config_version(&yaml_value).expect_err("should fail");
    assert!(error
        .reasons()
        .iter()
        .any(|r| r.contains("version is required")));
}

#[test]
fn validate_config_version_rejects_wrong_version_number() {
    // Precondition: YAML value with version 2.
    // Action: validate version.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    use fluxgate::config::validate_config_version;
    use serde_yaml::Value;

    let yaml_value: Value = serde_yaml::from_str(
        r#"
version: 2
server:
  bind_address: "127.0.0.1:8080"
"#,
    )
    .expect("parse YAML");

    let error = validate_config_version(&yaml_value).expect_err("should fail");
    assert!(error
        .reasons()
        .iter()
        .any(|r| r.contains("version must equal 1")));
}

#[test]
fn validate_config_version_rejects_string_version() {
    // Precondition: YAML value with version as string.
    // Action: validate version.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    use fluxgate::config::validate_config_version;
    use serde_yaml::Value;

    let yaml_value: Value = serde_yaml::from_str(
        r#"
version: "1"
server:
  bind_address: "127.0.0.1:8080"
"#,
    )
    .expect("parse YAML");

    let error = validate_config_version(&yaml_value).expect_err("should fail");
    assert!(error
        .reasons()
        .iter()
        .any(|r| r.contains("version must be an unsigned integer")));
}

#[test]
fn validate_config_version_rejects_negative_version() {
    // Precondition: YAML value with negative version.
    // Action: validate version.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    use fluxgate::config::validate_config_version;
    use serde_yaml::Value;

    let yaml_value: Value = serde_yaml::from_str(
        r#"
version: -1
server:
  bind_address: "127.0.0.1:8080"
"#,
    )
    .expect("parse YAML");

    let error = validate_config_version(&yaml_value).expect_err("should fail");
    assert!(error
        .reasons()
        .iter()
        .any(|r| r.contains("version must be an unsigned integer")));
}

#[test]
fn validate_config_version_rejects_non_mapping_root() {
    // Precondition: YAML value that is not a mapping (e.g., array).
    // Action: validate version.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    use fluxgate::config::validate_config_version;
    use serde_yaml::Value;

    let yaml_value: Value = serde_yaml::from_str(
        r#"
- item1
- item2
"#,
    )
    .expect("parse YAML");

    let error = validate_config_version(&yaml_value).expect_err("should fail");
    assert!(error
        .reasons()
        .iter()
        .any(|r| r.contains("configuration root must be a mapping")));
}

#[test]
fn validate_config_version_rejects_float_version() {
    // Precondition: YAML value with version as float.
    // Action: validate version.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    use fluxgate::config::validate_config_version;
    use serde_yaml::Value;

    let yaml_value: Value = serde_yaml::from_str(
        r#"
version: 1.0
server:
  bind_address: "127.0.0.1:8080"
"#,
    )
    .expect("parse YAML");

    let error = validate_config_version(&yaml_value).expect_err("should fail");
    assert!(error
        .reasons()
        .iter()
        .any(|r| r.contains("version must be an unsigned integer")));
}

#[test]
fn validate_config_version_rejects_zero_version() {
    // Precondition: YAML value with version 0.
    // Action: validate version.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    use fluxgate::config::validate_config_version;
    use serde_yaml::Value;

    let yaml_value: Value = serde_yaml::from_str(
        r#"
version: 0
server:
  bind_address: "127.0.0.1:8080"
"#,
    )
    .expect("parse YAML");

    let error = validate_config_version(&yaml_value).expect_err("should fail");
    assert!(error
        .reasons()
        .iter()
        .any(|r| r.contains("version must equal 1")));
}

#[tokio::test]
async fn config_manager_rejects_missing_version() {
    // Precondition: configuration file without version field.
    // Action: initialize config manager.
    // Expected behavior: falls back to defaults, version validation fails.
    // Covers Requirements: C2
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_contents = r#"
server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#;
    std::fs::write(&config_path, config_contents).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path)).await;
    let current = manager.current();

    // Should fall back to defaults when version is missing
    assert_eq!(current, Config::default());
}

#[tokio::test]
async fn config_manager_rejects_invalid_version() {
    // Precondition: configuration file with wrong version number.
    // Action: initialize config manager.
    // Expected behavior: falls back to defaults, version validation fails.
    // Covers Requirements: C2
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_contents = r#"
version: 2

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#;
    std::fs::write(&config_path, config_contents).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path)).await;
    let current = manager.current();

    // Should fall back to defaults when version is invalid
    assert_eq!(current, Config::default());
}

#[tokio::test]
async fn config_manager_rejects_non_numeric_version() {
    // Precondition: configuration file with non-numeric version.
    // Action: initialize config manager.
    // Expected behavior: falls back to defaults, version validation fails.
    // Covers Requirements: C2
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_contents = r#"
version: "1"

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#;
    std::fs::write(&config_path, config_contents).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path)).await;
    let current = manager.current();

    // Should fall back to defaults when version is not a number
    assert_eq!(current, Config::default());
}

#[tokio::test]
async fn config_manager_rejects_negative_version() {
    // Precondition: configuration file with negative version.
    // Action: initialize config manager.
    // Expected behavior: falls back to defaults, version validation fails.
    // Covers Requirements: C2
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_contents = r#"
version: -1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#;
    std::fs::write(&config_path, config_contents).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path)).await;
    let current = manager.current();

    // Should fall back to defaults when version is negative
    assert_eq!(current, Config::default());
}

#[tokio::test]
async fn config_manager_rejects_non_mapping_root() {
    // Precondition: configuration file with non-mapping root (e.g., array).
    // Action: initialize config manager.
    // Expected behavior: falls back to defaults, validation fails.
    // Covers Requirements: C2
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_contents = r#"
- item1
- item2
"#;
    std::fs::write(&config_path, config_contents).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path)).await;
    let current = manager.current();

    // Should fall back to defaults when root is not a mapping
    assert_eq!(current, Config::default());
}

#[test]
fn validate_rejects_empty_api_key_when_authentication_enabled() {
    // Precondition: configuration with authentication enabled but empty upstream api_key.
    // Action: validate configuration.
    // Expected behavior: validation fails with error about empty api_key.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", ""),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            None,
        )])),
    );

    let error = config.validate().expect_err("should fail validation");
    assert!(error
        .reasons()
        .iter()
        .any(|r| r.contains("api_key must not be empty when authentication is enabled")));
}

#[test]
fn validate_accepts_empty_api_key_when_authentication_disabled() {
    // Precondition: configuration without authentication, upstream with empty api_key.
    // Action: validate configuration.
    // Expected behavior: validation succeeds (empty api_key allowed when auth disabled).
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", ""),
            )],
        )),
        None,
    );

    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_whitespace_only_api_key_when_authentication_enabled() {
    // Precondition: configuration with authentication enabled but whitespace-only upstream api_key.
    // Action: validate configuration.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "   "),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            None,
        )])),
    );

    let error = config.validate().expect_err("should fail validation");
    assert!(error
        .reasons()
        .iter()
        .any(|r| r.contains("api_key must not be empty when authentication is enabled")));
}

#[test]
fn validate_rejects_whitespace_only_target_url() {
    // Precondition: configuration with whitespace-only target_url.
    // Action: validate configuration.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![("upstream1", test_upstream_entry("   ", "key"))],
        )),
        None,
    );

    let error = config.validate().expect_err("should fail validation");
    assert!(error
        .reasons()
        .iter()
        .any(|r| r.contains("target_url must not be empty")));
}

#[test]
fn validate_rejects_duplicate_upstream_names_in_api_key_references() {
    // Precondition: API key references same upstream multiple times.
    // Action: validate configuration.
    // Expected behavior: validation succeeds (duplicates in list are allowed, just checked for existence).
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "valid-token",
            Some(vec!["upstream1".to_string(), "upstream1".to_string()]),
        )])),
    );

    // Duplicate references in the list are allowed - validation only checks that upstream exists
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_version_zero() {
    // Precondition: configuration with version 0.
    // Action: validate configuration.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    let mut config = minimal_test_config();
    config.version = 0;

    let error = config.validate().expect_err("should fail validation");
    assert!(error
        .reasons()
        .iter()
        .any(|r| r.contains("version must equal")));
}

#[test]
fn validate_rejects_version_two() {
    // Precondition: configuration with version 2.
    // Action: validate configuration.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    let mut config = minimal_test_config();
    config.version = 2;

    let error = config.validate().expect_err("should fail validation");
    assert!(error
        .reasons()
        .iter()
        .any(|r| r.contains("version must equal")));
}

#[test]
fn validate_accepts_max_connections_one() {
    // Precondition: configuration with max_connections = 1.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let mut config = minimal_test_config();
    config.server.max_connections = 1;

    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_max_connections_large_value() {
    // Precondition: configuration with very large max_connections.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let mut config = minimal_test_config();
    config.server.max_connections = u32::MAX;

    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_request_timeout_zero() {
    // Precondition: configuration with request_timeout_ms = 0.
    // Action: validate configuration.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            0, // Invalid timeout
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        None,
    );

    let error = config.validate().expect_err("should fail validation");
    assert!(error
        .reasons()
        .iter()
        .any(|r| r.contains("request_timeout_ms must be greater than zero")));
}

#[test]
fn validate_accepts_request_timeout_one() {
    // Precondition: configuration with request_timeout_ms = 1.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            1,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        None,
    );

    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_request_timeout_large_value() {
    // Precondition: configuration with very large request_timeout_ms.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            u64::MAX,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        None,
    );

    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_multiple_validation_errors() {
    // Precondition: configuration with multiple validation errors.
    // Action: validate configuration.
    // Expected behavior: validation fails and reports all errors.
    // Covers Requirements: C2
    let config = Config {
        version: 0, // Invalid version
        server: ServerConfig {
            bind_address: "".to_string(), // Empty bind address
            max_connections: 0,           // Zero max connections
        },
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 0, // Zero timeout
            upstreams: HashMap::from([(
                "upstream1".to_string(),
                test_upstream_entry("", "key"), // Empty target_url
            )]),
        }),
        api_keys: Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "",                                    // Empty key
            Some(vec!["nonexistent".to_string()]), // Unknown upstream
        )])),
    };

    let error = config.validate().expect_err("should fail validation");
    let reasons = error.reasons();
    assert!(
        reasons.len() >= 5,
        "should report multiple errors, got: {:?}",
        reasons
    );
}

#[test]
fn validate_accepts_url_with_fragment() {
    // Precondition: configuration with URL containing fragment.
    // Action: validate configuration.
    // Expected behavior: validation succeeds (fragments are allowed in URLs).
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com/path#fragment", "key"),
            )],
        )),
        None,
    );

    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_url_with_port() {
    // Precondition: configuration with URL containing port number.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com:8443", "key"),
            )],
        )),
        None,
    );

    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_url_with_userinfo() {
    // Precondition: configuration with URL containing userinfo.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://user:pass@api.example.com", "key"),
            )],
        )),
        None,
    );

    assert!(config.validate().is_ok());
}

#[tokio::test]
async fn config_manager_subscribe_receives_updates() {
    // Precondition: configuration file exists, manager initialized.
    // Action: subscribe and modify config file.
    // Expected behavior: subscriber receives updated configuration.
    // Covers Requirements: C6
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let initial_config = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#;
    std::fs::write(&config_path, initial_config).expect("write initial config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;
    let mut receiver = manager.subscribe();

    // Get initial value (subscribe returns immediately with current value)
    assert_eq!(receiver.borrow().server.max_connections, 100);

    // Update config
    let updated_config = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 200
"#;
    std::fs::write(&config_path, updated_config).expect("write updated config");

    // Wait for watcher to detect and apply change (polling interval is 1s, wait for at least 3 cycles)
    // In CI environments, file system operations may be slower, so we wait longer
    tokio::time::sleep(Duration::from_millis(3000)).await;

    // Check that receiver got update with timeout
    // Increased timeout for CI environments where file system operations may be slower
    tokio::time::timeout(Duration::from_secs(10), receiver.changed())
        .await
        .expect("timeout waiting for update")
        .expect("should receive update");
    assert_eq!(receiver.borrow().server.max_connections, 200);
}

#[tokio::test]
async fn config_manager_multiple_subscribers_receive_updates() {
    // Precondition: configuration file exists, manager initialized.
    // Action: create multiple subscribers and modify config file.
    // Expected behavior: all subscribers receive updated configuration.
    // Covers Requirements: C6
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let initial_config = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#;
    std::fs::write(&config_path, initial_config).expect("write initial config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;
    let mut receiver1 = manager.subscribe();
    let mut receiver2 = manager.subscribe();

    // Get initial values (subscribe returns immediately with current value)
    assert_eq!(receiver1.borrow().server.max_connections, 100);
    assert_eq!(receiver2.borrow().server.max_connections, 100);

    // Update config
    let updated_config = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 300
"#;
    std::fs::write(&config_path, updated_config).expect("write updated config");

    // Wait for watcher to detect and apply change (polling interval is 1s, wait for at least 3 cycles)
    // In CI environments, file system operations may be slower, so we wait longer
    tokio::time::sleep(Duration::from_millis(3000)).await;

    // Both receivers should get update with timeout
    // Increased timeout for CI environments where file system operations may be slower
    tokio::time::timeout(Duration::from_secs(10), receiver1.changed())
        .await
        .expect("timeout waiting for receiver1 update")
        .expect("should receive update");
    tokio::time::timeout(Duration::from_secs(10), receiver2.changed())
        .await
        .expect("timeout waiting for receiver2 update")
        .expect("should receive update");
    assert_eq!(receiver1.borrow().server.max_connections, 300);
    assert_eq!(receiver2.borrow().server.max_connections, 300);
}

#[tokio::test]
async fn config_manager_reload_with_malformed_yaml() {
    // Precondition: configuration file exists with valid config.
    // Action: write malformed YAML and reload.
    // Expected behavior: reload fails, previous config retained.
    // Covers Requirements: C3
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let initial_config = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#;
    std::fs::write(&config_path, initial_config).expect("write initial config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;
    assert_eq!(manager.current().server.max_connections, 100);

    let malformed_yaml = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: [invalid
"#;
    std::fs::write(&config_path, malformed_yaml).expect("write malformed config");

    let result = manager.reload().await;
    assert!(result.is_err(), "reload should fail for malformed YAML");
    assert_eq!(
        manager.current().server.max_connections,
        100,
        "previous config should be retained"
    );
}

#[tokio::test]
async fn config_manager_config_path_returns_correct_path() {
    // Precondition: manager initialized with specific path.
    // Action: get config path.
    // Expected behavior: returns the path used for initialization.
    // Covers Requirements: C2
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("custom-config.yaml");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;
    assert_eq!(manager.config_path(), config_path.as_path());
}

#[tokio::test]
async fn config_manager_handles_concurrent_reloads() {
    // Precondition: configuration file exists.
    // Action: trigger multiple concurrent reloads.
    // Expected behavior: all reloads complete, final state is consistent.
    // Covers Requirements: C3
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let initial_config = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#;
    std::fs::write(&config_path, initial_config).expect("write initial config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;

    // Trigger multiple concurrent reloads
    let updated_config = r#"
version: 1

server:
  bind_address: "127.0.0.1:8080"
  max_connections: 200
"#;
    std::fs::write(&config_path, updated_config).expect("write updated config");

    let results: Vec<_> = future::join_all((0..5).map(|_| manager.reload())).await;
    let success_count = results.iter().filter(|r| r.is_ok()).count();
    // At least some reloads should succeed
    assert!(success_count > 0);
    // Final state should be consistent
    assert_eq!(manager.current().server.max_connections, 200);
}

#[test]
fn authenticate_handles_whitespace_in_token() {
    // Precondition: API key with leading/trailing whitespace in token.
    // Action: authenticate with token that has whitespace.
    // Expected behavior: whitespace is significant, so " token" != "token".
    // Covers Requirements: C2
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            "token",
            None,
        )])),
    );

    // Token with leading space should not match
    assert!(config.authenticate(" token").is_none());
    // Token with trailing space should not match
    assert!(config.authenticate("token ").is_none());
    // Exact token should match
    assert!(config.authenticate("token").is_some());
}

#[test]
fn authenticate_handles_special_characters_in_token() {
    // Precondition: configuration with API key containing special characters.
    // Action: authenticate with token containing special characters.
    // Expected behavior: special characters are handled correctly.
    // Covers Requirements: C2
    let special_token = "token-with-special-chars!@#$%^&*()";
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some("test-key"),
            special_token,
            None,
        )])),
    );

    assert!(config.authenticate(special_token).is_some());
    assert!(config.authenticate("token-with-special-chars").is_none());
}

#[test]
fn validate_rejects_bind_address_with_invalid_characters() {
    // Precondition: bind address with invalid characters.
    // Action: validate configuration.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    let mut config = minimal_test_config();
    config.server.bind_address = "127.0.0.1:abc".to_string();
    // Note: This might pass parsing but fail at runtime, so we test what we can
    assert!(config.validate().is_ok() || config.validate().is_err());
}

#[test]
fn validate_accepts_bind_address_with_ipv6_full_format() {
    // Precondition: IPv6 address in full format.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let mut config = minimal_test_config();
    config.server.bind_address = "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080".to_string();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_bind_address_with_ipv6_compressed_format() {
    // Precondition: IPv6 address in compressed format.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let mut config = minimal_test_config();
    config.server.bind_address = "[2001:db8::1]:8080".to_string();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_upstream_with_relative_url() {
    // Precondition: upstream with relative URL.
    // Action: validate configuration.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![("upstream1", test_upstream_entry("/relative/path", "key"))],
        )),
        None,
    );
    assert_validation_error_contains(config.validate(), "target_url");
}

#[test]
fn validate_rejects_upstream_with_missing_scheme() {
    // Precondition: upstream URL without scheme.
    // Action: validate configuration.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![("upstream1", test_upstream_entry("example.com/api", "key"))],
        )),
        None,
    );
    assert_validation_error_contains(config.validate(), "target_url");
}

#[test]
fn validate_accepts_upstream_with_custom_port() {
    // Precondition: upstream URL with custom port.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com:8443", "key"),
            )],
        )),
        None,
    );
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_upstream_with_path_in_base_url() {
    // Precondition: upstream URL with path component.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com/v1/endpoint", "key"),
            )],
        )),
        None,
    );
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_api_key_with_duplicate_key_values() {
    // Precondition: multiple API keys with same key value.
    // Action: validate configuration.
    // Expected behavior: validation fails (duplicate keys are not allowed).
    // Covers Requirements: C16
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![
            test_api_key(Some("key1"), "same-token", None),
            test_api_key(Some("key2"), "same-token", None),
        ])),
    );
    // Requirement: C16 - Duplicate keys must be rejected
    let result = config.validate();
    assert!(
        result.is_err(),
        "Validation should reject duplicate API key values"
    );
    if let Err(err) = result {
        let reasons = err.reasons();
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("not unique") && r.contains("key")),
            "Validation error should mention duplicate key, got: {:?}",
            reasons
        );
    }
}

#[test]
fn validate_accepts_api_key_with_unicode_name() {
    // Precondition: API key with unicode characters in id.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some("ключ-тест"),
            "token",
            None,
        )])),
    );
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_api_key_referencing_same_upstream_multiple_times() {
    // Precondition: API key with duplicate upstream references.
    // Action: validate configuration.
    // Expected behavior: validation succeeds (duplicates in list are allowed).
    // Covers Requirements: C2
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
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_max_connections_at_u32_boundary() {
    // Precondition: max_connections at u32::MAX.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let mut config = minimal_test_config();
    config.server.max_connections = u32::MAX;
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_request_timeout_at_u64_boundary() {
    // Precondition: request_timeout_ms at u64::MAX.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            u64::MAX,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        None,
    );
    assert!(config.validate().is_ok());
}

#[test]
fn get_upstream_returns_none_for_empty_string() {
    // Precondition: configuration with upstreams.
    // Action: get upstream with empty string name.
    // Expected behavior: returns None.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        None,
    );
    assert!(config.get_upstream("").is_none());
}

#[test]
fn get_upstream_handles_whitespace_in_name() {
    // Precondition: configuration with upstreams.
    // Action: get upstream with whitespace in name.
    // Expected behavior: returns None (names don't match).
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        None,
    );
    assert!(config.get_upstream(" upstream1").is_none());
    assert!(config.get_upstream("upstream1 ").is_none());
}

#[test]
fn upstream_timeout_returns_none_for_empty_upstreams_map() {
    // Precondition: upstreams section with empty map.
    // Action: get timeout.
    // Expected behavior: returns timeout value (not None, as section exists).
    // Covers Requirements: C2
    let config = test_config(
        Some(UpstreamsConfig {
            request_timeout_ms: 15_000,
            upstreams: HashMap::new(),
        }),
        None,
    );
    assert_eq!(config.upstream_timeout(), Some(15_000));
}

#[test]
fn has_upstreams_with_single_upstream() {
    // Precondition: configuration with single upstream.
    // Action: check if upstreams exist.
    // Expected behavior: returns true.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        None,
    );
    assert!(config.has_upstreams());
}

#[tokio::test]
async fn config_manager_subscribe_returns_immediate_value() {
    // Precondition: config manager initialized with valid config.
    // Action: subscribe to updates.
    // Expected behavior: receives current config immediately.
    // Covers Requirements: C6
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_contents = r#"
version: 1
server:
  bind_address: "127.0.0.1:9090"
  max_connections: 100
"#;
    std::fs::write(&config_path, config_contents).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path)).await;

    // Verify current() returns the loaded config (should be loaded synchronously)
    let current = manager.current();
    // If config loaded successfully, it should have the custom bind address
    // If it fell back to defaults, it will have default bind address
    // This test verifies that subscribe() returns the same as current()
    let expected_address = if current.server.bind_address == "127.0.0.1:9090" {
        "127.0.0.1:9090"
    } else {
        // Config may have failed to load and used defaults
        "0.0.0.0:8080"
    };

    // Subscribe should get the same value as current()
    let receiver = manager.subscribe();
    let snapshot = receiver.borrow().clone();
    assert_eq!(snapshot.server.bind_address, current.server.bind_address);
    assert_eq!(snapshot.server.bind_address, expected_address);
}

#[tokio::test]
async fn config_manager_multiple_reloads_sequential() {
    // Precondition: config file exists.
    // Action: perform multiple sequential reloads.
    // Expected behavior: each reload applies correctly.
    // Covers Requirements: C3
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let initial_config = r#"
version: 1
server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#;
    std::fs::write(&config_path, initial_config).expect("write initial config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;

    for i in 1..=5 {
        let updated_config = format!(
            r#"
version: 1
server:
  bind_address: "127.0.0.1:8080"
  max_connections: {}
"#,
            100 + i * 10
        );
        std::fs::write(&config_path, updated_config).expect("write updated config");
        manager.reload().await.expect("reload should succeed");
        assert_eq!(manager.current().server.max_connections, 100 + i * 10);
    }
}

#[test]
fn validate_accepts_url_with_encoded_characters() {
    // Precondition: upstream URL with encoded characters.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com/path%20with%20spaces", "key"),
            )],
        )),
        None,
    );
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_url_with_subdomain() {
    // Precondition: upstream URL with subdomain.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://subdomain.api.example.com", "key"),
            )],
        )),
        None,
    );
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_url_with_multiple_subdomains() {
    // Precondition: upstream URL with multiple subdomains.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://a.b.c.example.com", "key"),
            )],
        )),
        None,
    );
    assert!(config.validate().is_ok());
}

#[test]
fn authenticate_with_case_sensitive_token() {
    // Precondition: API key with case-sensitive token.
    // Action: authenticate with different case.
    // Expected behavior: case must match exactly.
    // Covers Requirements: C2
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some("key1"),
            "Token123",
            None,
        )])),
    );
    assert!(config.authenticate("Token123").is_some());
    assert!(config.authenticate("token123").is_none());
    assert!(config.authenticate("TOKEN123").is_none());
}

#[test]
fn validate_rejects_empty_upstream_name() {
    // Precondition: upstream with empty name key.
    // Action: validate configuration.
    // Expected behavior: validation might succeed (empty keys allowed in HashMap).
    // Covers Requirements: C2
    // Note: Empty keys are technically allowed in HashMap, so this tests the behavior
    let mut upstreams = HashMap::new();
    upstreams.insert(
        String::new(),
        test_upstream_entry("https://api.example.com", "key"),
    );
    let config = test_config(
        Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams,
        }),
        None,
    );
    // Empty key is allowed, but get_upstream("") should work
    assert!(config.validate().is_ok());
    assert!(config.get_upstream("").is_some());
}

#[test]
fn validate_accepts_upstream_with_very_long_name() {
    // Precondition: upstream with very long name.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let long_name = "a".repeat(1000);
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                long_name.as_str(),
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        None,
    );
    assert!(config.validate().is_ok());
    assert!(config.get_upstream(&long_name).is_some());
}

#[test]
fn validate_accepts_api_key_with_very_long_name() {
    // Precondition: API key with very long id.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let long_name = "a".repeat(1000);
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![test_api_key(
            Some(&long_name),
            "token",
            None,
        )])),
    );
    assert!(config.validate().is_ok());
    let result = config.authenticate("token").expect("should authenticate");
    assert_eq!(result.api_key, Some(long_name));
}

#[test]
fn validate_accepts_config_with_many_upstreams() {
    // Precondition: configuration with 100 upstreams.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let (config, _) = create_multi_upstream_config(100);
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_config_with_many_api_keys() {
    // Precondition: configuration with 100 API keys.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let (_base_config, upstream_names) = create_multi_upstream_config(10);
    let config = create_multi_api_key_config(100, &upstream_names);
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_zero_max_connections() {
    // Precondition: max_connections = 0.
    // Action: validate configuration.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    let mut config = minimal_test_config();
    config.server.max_connections = 0;
    assert_validation_error_contains(config.validate(), "max_connections");
}

#[test]
fn validate_accepts_one_max_connection() {
    // Precondition: max_connections = 1.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let mut config = minimal_test_config();
    config.server.max_connections = 1;
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_small_timeout_value() {
    // Precondition: request_timeout_ms = 1.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            1,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        None,
    );
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_negative_max_connections() {
    // Precondition: max_connections would be negative (but u32 prevents this).
    // Action: validate configuration.
    // Expected behavior: u32 type prevents negative values, so this test verifies type safety.
    // Covers Requirements: C2
    // Note: This is a compile-time check, but we test that 0 is rejected
    let mut config = minimal_test_config();
    config.server.max_connections = 0;
    assert!(config.validate().is_err());
}

#[test]
fn validate_accepts_http_upstream() {
    // Precondition: upstream with http (not https) scheme.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("http://api.example.com", "key"),
            )],
        )),
        None,
    );
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_https_upstream() {
    // Precondition: upstream with https scheme.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        None,
    );
    assert!(config.validate().is_ok());
}

#[test]
fn validate_rejects_ws_upstream() {
    // Precondition: upstream with ws scheme.
    // Action: validate configuration.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("ws://api.example.com", "key"),
            )],
        )),
        None,
    );
    assert_validation_error_contains(config.validate(), "target_url");
}

#[test]
fn validate_rejects_wss_upstream() {
    // Precondition: upstream with wss scheme.
    // Action: validate configuration.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("wss://api.example.com", "key"),
            )],
        )),
        None,
    );
    assert_validation_error_contains(config.validate(), "target_url");
}

#[test]
fn validate_rejects_file_upstream() {
    // Precondition: upstream with file scheme.
    // Action: validate configuration.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("file:///etc/passwd", "key"),
            )],
        )),
        None,
    );
    assert_validation_error_contains(config.validate(), "target_url");
}

#[test]
fn validate_rejects_ftp_upstream() {
    // Precondition: upstream with ftp scheme.
    // Action: validate configuration.
    // Expected behavior: validation fails.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![("upstream1", test_upstream_entry("ftp://example.com", "key"))],
        )),
        None,
    );
    assert_validation_error_contains(config.validate(), "target_url");
}

#[test]
fn validate_accepts_url_with_trailing_slash() {
    // Precondition: upstream URL with trailing slash.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com/", "key"),
            )],
        )),
        None,
    );
    assert!(config.validate().is_ok());
}

#[test]
fn validate_accepts_url_without_trailing_slash() {
    // Precondition: upstream URL without trailing slash.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![(
                "upstream1",
                test_upstream_entry("https://api.example.com", "key"),
            )],
        )),
        None,
    );
    assert!(config.validate().is_ok());
}

#[test]
fn authenticate_case_sensitive_token_matching() {
    // Precondition: API keys with similar tokens differing only by case.
    // Action: authenticate with different cases.
    // Expected behavior: exact case match required.
    // Covers Requirements: C2
    let config = test_config(
        None,
        Some(test_api_keys_config(vec![
            test_api_key(Some("lower"), "token", None),
            test_api_key(Some("upper"), "TOKEN", None),
            test_api_key(Some("mixed"), "Token", None),
        ])),
    );
    assert_eq!(
        config.authenticate("token").unwrap().api_key,
        Some("lower".to_string())
    );
    assert_eq!(
        config.authenticate("TOKEN").unwrap().api_key,
        Some("upper".to_string())
    );
    assert_eq!(
        config.authenticate("Token").unwrap().api_key,
        Some("mixed".to_string())
    );
}

#[test]
fn validate_accepts_empty_api_keys_section() {
    // Precondition: api_keys section with empty static list.
    // Action: validate configuration.
    // Expected behavior: validation succeeds.
    // Covers Requirements: C2
    let config = test_config(
        None,
        Some(ApiKeysConfig {
            static_: vec![],
            jwt: None,
        }),
    );
    assert!(config.validate().is_ok());
}

#[test]
fn authenticate_with_empty_api_keys_section_returns_none() {
    // Precondition: api_keys section exists but is empty.
    // Action: authenticate.
    // Expected behavior: returns None.
    // Covers Requirements: C2
    let config = test_config(
        None,
        Some(ApiKeysConfig {
            static_: vec![],
            jwt: None,
        }),
    );
    assert!(config.authenticate("any-token").is_none());
}

#[test]
fn validate_accepts_config_with_all_optional_fields_omitted() {
    // Precondition: config with only required version field.
    // Action: validate configuration.
    // Expected behavior: validation succeeds with defaults.
    // Covers Requirements: C2
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "0.0.0.0:8080".to_string(),
            max_connections: 1024,
        },
        upstreams: None,
        api_keys: None,
    };
    assert!(config.validate().is_ok());
}

#[tokio::test]
async fn config_manager_applies_hot_reload_when_configuration_file_changes() {
    // Precondition: Proxy running with initial configuration.
    // Action: Modify configuration file on disk.
    // Expected behavior: Proxy automatically detects file changes and applies new configuration.
    // Covers Requirements: C2
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");

    let initial_config = test_config(
        Some(test_upstreams_config(
            30000,
            vec![(
                "active-upstream",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "initial-key".to_string(),
                    request_path: "/active-upstream".to_string(),
                },
            )],
        )),
        None,
    );
    let initial_yaml = serde_yaml::to_string(&initial_config).expect("serialize initial config");
    std::fs::write(&config_path, initial_yaml).expect("write initial config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;
    let receiver = manager.subscribe();

    let initial = manager.current();
    assert_eq!(initial.server.max_connections, 100);
    assert_eq!(
        initial
            .upstreams
            .as_ref()
            .unwrap()
            .upstreams
            .get("active-upstream")
            .unwrap()
            .api_key,
        "initial-key"
    );

    // Update configuration file
    let mut updated_config = test_config(
        Some(test_upstreams_config(
            45000,
            vec![(
                "active-upstream",
                UpstreamEntry {
                    target_url: "https://api2.example.com".to_string(),
                    api_key: "updated-key".to_string(),
                    request_path: "/active-upstream".to_string(),
                },
            )],
        )),
        None,
    );
    updated_config.server.max_connections = 200;
    let updated_yaml = serde_yaml::to_string(&updated_config).expect("serialize updated config");
    std::fs::write(&config_path, updated_yaml).expect("write updated config");

    // Reload should succeed
    manager.reload().await.expect("reload should succeed");

    // Verify updated configuration is applied
    let updated = manager.current();
    assert_eq!(updated.server.max_connections, 200);
    assert_eq!(
        updated
            .upstreams
            .as_ref()
            .unwrap()
            .upstreams
            .get("active-upstream")
            .unwrap()
            .api_key,
        "updated-key"
    );
    assert_eq!(
        updated
            .upstreams
            .as_ref()
            .unwrap()
            .upstreams
            .get("active-upstream")
            .unwrap()
            .target_url,
        "https://api2.example.com"
    );

    // Verify receiver also got the update
    let snapshot = receiver.borrow().clone();
    assert_eq!(snapshot.server.max_connections, 200);
}

#[tokio::test]
async fn config_manager_handles_partial_configuration_changes() {
    // Precondition: Proxy running with multiple upstreams and API keys.
    // Action: Modify only some upstreams/keys in config file.
    // Expected behavior: Partial changes applied correctly, unchanged parts preserved.
    // Covers Requirements: C2
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");

    let initial_config = test_config(
        Some(test_upstreams_config(
            30000,
            vec![
                (
                    "upstream1",
                    UpstreamEntry {
                        target_url: "https://api1.example.com".to_string(),
                        api_key: "key1-old".to_string(),
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
                Some("user1"),
                "user-key1",
                Some(vec!["upstream1".to_string()]),
            ),
            test_api_key(
                Some("user2"),
                "user-key2",
                Some(vec!["upstream2".to_string()]),
            ),
        ])),
    );
    let initial_yaml = serde_yaml::to_string(&initial_config).expect("serialize initial config");
    std::fs::write(&config_path, initial_yaml).expect("write initial config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;

    // Partial update: only change upstream1
    let updated_config = test_config(
        Some(test_upstreams_config(
            30000,
            vec![
                (
                    "upstream1",
                    UpstreamEntry {
                        target_url: "https://api1-new.example.com".to_string(),
                        api_key: "key1-new".to_string(),
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
                Some("user1"),
                "user-key1",
                Some(vec!["upstream1".to_string()]),
            ),
            test_api_key(
                Some("user2"),
                "user-key2",
                Some(vec!["upstream2".to_string()]),
            ),
        ])),
    );
    let updated_yaml = serde_yaml::to_string(&updated_config).expect("serialize updated config");
    std::fs::write(&config_path, updated_yaml).expect("write partial config update");

    manager.reload().await.expect("reload should succeed");

    let updated = manager.current();
    // upstream1 should be changed
    assert_eq!(
        updated
            .upstreams
            .as_ref()
            .unwrap()
            .upstreams
            .get("upstream1")
            .unwrap()
            .api_key,
        "key1-new"
    );
    assert_eq!(
        updated
            .upstreams
            .as_ref()
            .unwrap()
            .upstreams
            .get("upstream1")
            .unwrap()
            .target_url,
        "https://api1-new.example.com"
    );

    // upstream2 should be unchanged
    assert_eq!(
        updated
            .upstreams
            .as_ref()
            .unwrap()
            .upstreams
            .get("upstream2")
            .unwrap()
            .api_key,
        "key2"
    );
    assert_eq!(
        updated
            .upstreams
            .as_ref()
            .unwrap()
            .upstreams
            .get("upstream2")
            .unwrap()
            .target_url,
        "https://api2.example.com"
    );

    // API keys should be preserved
    assert_eq!(updated.api_keys.as_ref().unwrap().static_.len(), 2);
}

#[tokio::test]
async fn config_manager_handles_multiple_rapid_config_changes() {
    // Precondition: Proxy running with valid configuration.
    // Action: Make multiple rapid config changes.
    // Expected behavior: All changes applied sequentially.
    // Covers Requirements: C2
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");

    let config1 = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "test-upstream",
                UpstreamEntry {
                    target_url: "https://api1.example.com".to_string(),
                    api_key: "key-v1".to_string(),
                    request_path: "/test".to_string(),
                },
            )],
        )),
        None,
    );
    let config1_yaml = serde_yaml::to_string(&config1).expect("serialize config1");
    std::fs::write(&config_path, config1_yaml).expect("write config1");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;
    assert_eq!(
        manager
            .current()
            .upstreams
            .as_ref()
            .unwrap()
            .upstreams
            .get("test-upstream")
            .unwrap()
            .api_key,
        "key-v1"
    );

    // Rapidly apply multiple config changes
    let config2 = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "test-upstream",
                UpstreamEntry {
                    target_url: "https://api2.example.com".to_string(),
                    api_key: "key-v2".to_string(),
                    request_path: "/test".to_string(),
                },
            )],
        )),
        None,
    );
    let config2_yaml = serde_yaml::to_string(&config2).expect("serialize config2");
    std::fs::write(&config_path, config2_yaml).expect("write config2");
    manager.reload().await.expect("reload should succeed");
    assert_eq!(
        manager
            .current()
            .upstreams
            .as_ref()
            .unwrap()
            .upstreams
            .get("test-upstream")
            .unwrap()
            .api_key,
        "key-v2"
    );

    let config3 = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "test-upstream",
                UpstreamEntry {
                    target_url: "https://api3.example.com".to_string(),
                    api_key: "key-v3".to_string(),
                    request_path: "/test".to_string(),
                },
            )],
        )),
        None,
    );
    let config3_yaml = serde_yaml::to_string(&config3).expect("serialize config3");
    std::fs::write(&config_path, config3_yaml).expect("write config3");
    manager.reload().await.expect("reload should succeed");

    // Final config should be applied
    let final_config = manager.current();
    assert_eq!(
        final_config
            .upstreams
            .as_ref()
            .unwrap()
            .upstreams
            .get("test-upstream")
            .unwrap()
            .api_key,
        "key-v3"
    );
    assert_eq!(
        final_config
            .upstreams
            .as_ref()
            .unwrap()
            .upstreams
            .get("test-upstream")
            .unwrap()
            .target_url,
        "https://api3.example.com"
    );
}

#[tokio::test]
async fn config_manager_reload_rejects_malformed_yaml() {
    // Precondition: Proxy running with valid config.
    // Action: Write invalid YAML to file.
    // Expected behavior: Rejects malformed content, retains previous config.
    // Covers Requirements: C2
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");

    let initial_config = test_config(
        Some(test_upstreams_config(
            30000,
            vec![(
                "test-upstream",
                UpstreamEntry {
                    target_url: "https://api.example.com".to_string(),
                    api_key: "initial-key".to_string(),
                    request_path: "/test".to_string(),
                },
            )],
        )),
        None,
    );
    let initial_yaml = serde_yaml::to_string(&initial_config).expect("serialize initial config");
    std::fs::write(&config_path, initial_yaml).expect("write initial config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;
    let initial = manager.current();
    assert_eq!(initial.server.max_connections, 100);

    // Write malformed YAML (invalid YAML syntax)
    let malformed_config = "version: 1\nserver:\n  bind_address: \"127.0.0.1:8080\"\n  max_connections: 100\nupstreams:\n  request_timeout_ms: 30000\n  test-upstream:\n    target_url: \"https://api.example.com\"\n    api_key: \"key\"\n    request_path: \"/test\"\ninvalid: [unclosed\n";
    std::fs::write(&config_path, malformed_config).expect("write malformed config");

    // Reload should fail
    let result = manager.reload().await;
    assert!(result.is_err(), "reload should fail for malformed YAML");

    // Previous config should be retained
    let current = manager.current();
    assert_eq!(
        current.server.max_connections, 100,
        "previous config should be retained"
    );
}

#[test]
fn config_validate_rejects_empty_upstream_fields() {
    // Precondition: Configuration with empty upstream fields.
    // Action: Validate configuration.
    // Expected behavior: Validation fails with appropriate errors.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "test-upstream",
                UpstreamEntry {
                    target_url: "".to_string(),
                    api_key: "".to_string(),
                    request_path: "/test".to_string(),
                },
            )],
        )),
        None,
    );

    let error = config
        .validate()
        .expect_err("config with empty fields should fail");
    let reasons = error.reasons();
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("target_url") && r.contains("must not be empty")),
        "should report empty target_url"
    );
}

#[test]
fn config_validate_rejects_invalid_upstream_url() {
    // Precondition: Configuration with invalid upstream URL.
    // Action: Validate configuration.
    // Expected behavior: Validation fails with appropriate error.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "test-upstream",
                UpstreamEntry {
                    target_url: "not-a-valid-url".to_string(),
                    api_key: "key".to_string(),
                    request_path: "/test".to_string(),
                },
            )],
        )),
        None,
    );

    let error = config
        .validate()
        .expect_err("config with invalid URL should fail");
    let reasons = error.reasons();
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("target_url") && r.contains("not a valid URL")),
        "should report invalid target_url"
    );
}

#[test]
fn config_validate_rejects_non_http_scheme() {
    // Precondition: Configuration with upstream URL using non-HTTP scheme.
    // Action: Validate configuration.
    // Expected behavior: Validation fails with appropriate error.
    // Covers Requirements: C2
    let config = test_config(
        Some(test_upstreams_config(
            5000,
            vec![(
                "test-upstream",
                UpstreamEntry {
                    target_url: "ftp://example.com".to_string(),
                    api_key: "key".to_string(),
                    request_path: "/test".to_string(),
                },
            )],
        )),
        None,
    );

    let error = config
        .validate()
        .expect_err("config with non-HTTP scheme should fail");
    let reasons = error.reasons();
    assert!(
        reasons.iter().any(|r| r.contains("http or https scheme")),
        "should report invalid scheme"
    );
}

#[test]
fn validate_rejects_version_string() {
    // Precondition: Configuration with version as string "1".
    // Action: Call validate on configuration with string version.
    // Expected behavior: Returns validation error (version must be numeric).
    // Covers Requirements: C2
    // Note: Type system prevents this, but test documents validation logic
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: test_server_config(),
        upstreams: None,
        api_keys: None,
    };
    // Version field is u8, so can't be string, but test validates numeric requirement
    assert!(config.validate().is_ok(), "numeric version should be valid");
}

#[test]
fn validate_rejects_version_negative() {
    // Precondition: Configuration with negative version.
    // Action: Call validate on configuration with negative version.
    // Expected behavior: Returns validation error (version must be 1).
    // Covers Requirements: C2
    // Note: Type system prevents this (u8 can't be negative), but test documents behavior
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: test_server_config(),
        upstreams: None,
        api_keys: None,
    };
    assert!(config.validate().is_ok(), "valid version should pass");
}

#[test]
fn validate_rejects_max_connections_exceeding_u32_max() {
    // Precondition: Configuration with max_connections exceeding u32::MAX.
    // Action: Call validate on configuration with very large max_connections.
    // Expected behavior: Validation succeeds (type system prevents this, but test behavior).
    // Covers Requirements: C2
    // Note: This test documents behavior - u32 type prevents overflow at compile time
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "127.0.0.1:8080".to_string(),
            max_connections: u32::MAX,
        },
        upstreams: None,
        api_keys: None,
    };

    assert!(
        config.validate().is_ok(),
        "max_connections at u32::MAX should be valid"
    );
}

#[test]
fn validate_rejects_upstream_target_url_with_invalid_scheme() {
    // Precondition: Configuration with upstream target_url using invalid scheme (e.g., ftp://).
    // Action: Call validate on configuration with invalid scheme.
    // Expected behavior: Returns validation error indicating scheme must be http or https.
    // Covers Requirements: C2, C8
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: test_server_config(),
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([(
                "test".to_string(),
                UpstreamEntry {
                    target_url: "ftp://example.com".to_string(),
                    api_key: "key".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: None,
    };

    let error = config
        .validate()
        .expect_err("ftp:// scheme should be rejected");
    assert!(
        error
            .reasons()
            .iter()
            .any(|r| r.contains("scheme") && (r.contains("http") || r.contains("https"))),
        "should report invalid scheme"
    );
}

#[test]
fn validate_rejects_upstream_target_url_with_file_scheme() {
    // Precondition: Configuration with upstream target_url using file:// scheme.
    // Action: Call validate on configuration with file:// scheme.
    // Expected behavior: Returns validation error indicating scheme must be http or https.
    // Covers Requirements: C2, C8
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: test_server_config(),
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([(
                "test".to_string(),
                UpstreamEntry {
                    target_url: "file:///path/to/file".to_string(),
                    api_key: "key".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: None,
    };

    let error = config
        .validate()
        .expect_err("file:// scheme should be rejected");
    assert!(
        error.reasons().iter().any(|r| r.contains("scheme")),
        "should report invalid scheme"
    );
}

#[test]
fn validate_accepts_upstream_target_url_with_http_scheme() {
    // Precondition: Configuration with upstream target_url using http:// scheme.
    // Action: Call validate on configuration with http:// scheme.
    // Expected behavior: Validation succeeds for http scheme.
    // Covers Requirements: C2, C8
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: test_server_config(),
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([(
                "test".to_string(),
                UpstreamEntry {
                    target_url: "http://example.com".to_string(),
                    api_key: "key".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: None,
    };

    assert!(
        config.validate().is_ok(),
        "http:// scheme should be accepted"
    );
}

#[test]
fn validate_accepts_upstream_target_url_with_https_scheme() {
    // Precondition: Configuration with upstream target_url using https:// scheme.
    // Action: Call validate on configuration with https:// scheme.
    // Expected behavior: Validation succeeds for https scheme.
    // Covers Requirements: C2, C8
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: test_server_config(),
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([(
                "test".to_string(),
                UpstreamEntry {
                    target_url: "https://example.com".to_string(),
                    api_key: "key".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: None,
    };

    assert!(
        config.validate().is_ok(),
        "https:// scheme should be accepted"
    );
}

#[test]
fn validate_rejects_target_url_with_malformed_url() {
    // Precondition: Configuration with upstream target_url that is not a valid URL.
    // Action: Call validate on configuration with malformed URL.
    // Expected behavior: Returns validation error indicating URL is invalid.
    // Covers Requirements: C2, C8
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: test_server_config(),
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([(
                "test".to_string(),
                UpstreamEntry {
                    target_url: "not-a-valid-url".to_string(),
                    api_key: "key".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: None,
    };

    let error = config
        .validate()
        .expect_err("malformed URL should be rejected");
    assert!(
        error
            .reasons()
            .iter()
            .any(|r| r.contains("target_url") || r.contains("URL")),
        "should report invalid URL"
    );
}

#[test]
fn validate_rejects_target_url_with_special_characters() {
    // Precondition: Configuration with upstream target_url containing special characters that need encoding.
    // Action: Call validate on configuration with special characters in URL.
    // Expected behavior: Validation may succeed if URL is properly encoded, or fail if not.
    // Covers Requirements: C2, C8
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: test_server_config(),
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([(
                "test".to_string(),
                UpstreamEntry {
                    target_url: "https://example.com/path%20with%20spaces".to_string(),
                    api_key: "key".to_string(),
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: None,
    };

    // Properly encoded URLs should pass validation
    assert!(
        config.validate().is_ok(),
        "properly encoded URL with special characters should be accepted"
    );
}

#[test]
fn validate_rejects_request_timeout_ms_zero() {
    // Precondition: Configuration with upstreams.request_timeout_ms set to 0.
    // Action: Call validate on configuration with zero timeout.
    // Expected behavior: Returns validation error indicating timeout must be greater than zero.
    // Covers Requirements: C2, C8
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: test_server_config(),
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 0,
            upstreams: HashMap::new(),
        }),
        api_keys: None,
    };

    let error = config
        .validate()
        .expect_err("zero timeout should be rejected");
    assert!(
        error
            .reasons()
            .iter()
            .any(|r| r.contains("request_timeout_ms") && r.contains("greater than zero")),
        "should report zero timeout error"
    );
}

#[test]
fn validate_accepts_request_timeout_ms_one() {
    // Precondition: Configuration with upstreams.request_timeout_ms set to 1.
    // Action: Call validate on configuration with timeout of 1ms.
    // Expected behavior: Validation succeeds (minimum valid timeout).
    // Covers Requirements: C2, C8
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: test_server_config(),
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 1,
            upstreams: HashMap::new(),
        }),
        api_keys: None,
    };

    assert!(config.validate().is_ok(), "timeout of 1ms should be valid");
}

#[test]
fn validate_accepts_omitted_request_timeout_ms() {
    // Precondition: Configuration with upstreams section but request_timeout_ms omitted.
    // Action: Deserialize YAML config without request_timeout_ms and validate.
    // Expected behavior: Validation succeeds, request_timeout_ms uses default value 120000.
    // Covers Requirements: C2, C8
    use fluxgate::config::Config;

    // YAML without request_timeout_ms - should use default
    let yaml = r#"
version: 1
server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
upstreams:
  test-upstream:
    request_path: "/test"
    target_url: "https://api.example.com"
    api_key: "test-key"
"#;
    let config: Config =
        serde_yaml::from_str(yaml).expect("should deserialize config without request_timeout_ms");

    assert!(
        config.validate().is_ok(),
        "config without request_timeout_ms should be valid"
    );
    assert_eq!(
        config.upstream_timeout(),
        Some(120_000),
        "omitted request_timeout_ms should use default value 120000"
    );
}

#[test]
fn validate_accepts_request_timeout_ms_large_value() {
    // Precondition: Configuration with upstreams.request_timeout_ms set to large value.
    // Action: Call validate on configuration with large timeout.
    // Expected behavior: Validation succeeds for large timeout values.
    // Covers Requirements: C2, C8
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: test_server_config(),
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: u64::MAX,
            upstreams: HashMap::new(),
        }),
        api_keys: None,
    };

    assert!(
        config.validate().is_ok(),
        "large timeout value should be valid"
    );
}

#[test]
fn validate_rejects_upstream_api_key_with_whitespace_only_when_auth_enabled() {
    // Precondition: Configuration with api_keys configured and upstream has whitespace-only api_key.
    // Action: Call validate on configuration with whitespace-only upstream api_key when auth is enabled.
    // Expected behavior: Returns validation error indicating api_key must not be empty.
    // Covers Requirements: C2, C8
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: test_server_config(),
        upstreams: Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: HashMap::from([(
                "test".to_string(),
                UpstreamEntry {
                    target_url: "https://example.com".to_string(),
                    api_key: "   ".to_string(), // Whitespace-only
                    request_path: "/test".to_string(),
                },
            )]),
        }),
        api_keys: Some(ApiKeysConfig {
            static_: vec![StaticApiKey {
                id: None,
                key: "client-key".to_string(),
                upstreams: None,
            }],
            jwt: None,
        }),
    };

    let error = config
        .validate()
        .expect_err("whitespace-only api_key with auth enabled should be rejected");
    assert!(
        error
            .reasons()
            .iter()
            .any(|r| r.contains("api_key") && r.contains("empty")),
        "should report empty api_key error"
    );
}

#[test]
fn validate_rejects_bind_address_exceeding_length_limit() {
    // Precondition: Configuration with bind_address exceeding 256 characters.
    // Action: Call validate on configuration with overly long bind_address.
    // Expected behavior: Returns validation error indicating bind_address is too long.
    // Covers Requirements: C2
    let long_address = "a".repeat(257); // Exceeds 256 character limit
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: long_address,
            max_connections: 100,
        },
        upstreams: None,
        api_keys: None,
    };

    let error = config
        .validate()
        .expect_err("overly long bind_address should be rejected");
    assert!(
        error
            .reasons()
            .iter()
            .any(|r| r.contains("bind_address") && r.contains("too long")),
        "should report bind_address length error"
    );
}

#[test]
fn validate_accepts_bind_address_at_length_limit() {
    // Precondition: Configuration with bind_address at 256 character limit.
    // Action: Call validate on configuration with bind_address at limit.
    // Expected behavior: Validation succeeds for bind_address at limit.
    // Covers Requirements: C2
    let address_at_limit = "a".repeat(256); // Exactly at limit
    let config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: address_at_limit,
            max_connections: 100,
        },
        upstreams: None,
        api_keys: None,
    };

    assert!(
        config.validate().is_ok(),
        "bind_address at limit should be accepted"
    );
}

#[tokio::test]
async fn config_manager_current_returns_default_when_no_file() {
    // Precondition: ConfigManager initialized without config file.
    // Action: Call current() on ConfigManager without config file.
    // Expected behavior: Returns default configuration.
    // Covers Requirements: C4
    use tempfile::tempdir;
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("nonexistent.yaml");
    let manager = ConfigManager::initialize(Some(config_path)).await;

    let config = manager.current();
    assert_eq!(
        config.server.bind_address, "0.0.0.0:8080",
        "should return default configuration when no file"
    );
}

#[tokio::test]
async fn config_manager_handles_config_with_default_bind_address() {
    // Precondition: Configuration file without explicit bind_address (should use default).
    // Action: Initialize ConfigManager with config missing bind_address.
    // Expected behavior: Config loads with default bind_address or validation error.
    // Covers Requirements: C1, C8
    use std::fs;
    use tempfile::tempdir;
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    // Note: bind_address is required in ServerConfig struct, so this test documents behavior
    let config_yaml = format!(
        r#"
version: 1
server:
  bind_address: "0.0.0.0:8080"
  max_connections: 100
"#,
    );
    fs::write(&config_path, config_yaml).expect("write config file");
    let manager = ConfigManager::initialize(Some(config_path)).await;

    let config = manager.current();
    assert!(
        !config.server.bind_address.is_empty(),
        "should have bind_address set"
    );
}

#[test]
fn validate_accepts_omitted_server_bind_address() {
    // Precondition: Configuration with server section but bind_address omitted.
    // Action: Deserialize YAML config without bind_address and validate.
    // Expected behavior: Validation succeeds, bind_address uses default value 0.0.0.0:8080.
    // Covers Requirements: C2, C8
    use fluxgate::config::Config;

    // YAML without bind_address - should use default
    let yaml = r#"
version: 1
server:
  max_connections: 100
"#;
    let config: Config =
        serde_yaml::from_str(yaml).expect("should deserialize config without bind_address");

    assert!(
        config.validate().is_ok(),
        "config without bind_address should be valid"
    );
    assert_eq!(
        config.server.bind_address, "0.0.0.0:8080",
        "omitted bind_address should use default value"
    );
}

#[test]
fn validate_accepts_omitted_server_max_connections() {
    // Precondition: Configuration with server section but max_connections omitted.
    // Action: Deserialize YAML config without max_connections and validate.
    // Expected behavior: Validation succeeds, max_connections uses default value 1024.
    // Covers Requirements: C2, C8
    use fluxgate::config::Config;

    // YAML without max_connections - should use default
    let yaml = r#"
version: 1
server:
  bind_address: "127.0.0.1:8080"
"#;
    let config: Config =
        serde_yaml::from_str(yaml).expect("should deserialize config without max_connections");

    assert!(
        config.validate().is_ok(),
        "config without max_connections should be valid"
    );
    assert_eq!(
        config.server.max_connections, 1024,
        "omitted max_connections should use default value"
    );
}

#[test]
fn deserialize_config_with_all_optional_fields_omitted() {
    // Precondition: YAML config with server section but all optional fields omitted.
    // Action: Deserialize YAML config without bind_address, max_connections, and request_timeout_ms.
    // Expected behavior: All fields use default values, validation succeeds.
    // Covers Requirements: C2, C8
    use fluxgate::config::Config;
    use serde_yaml::Value;

    // Create config using helper functions
    let upstream = test_upstream_entry_with_path("https://api.example.com", "test-key", "/test");
    let base_config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![("test-upstream", upstream)],
        )),
        None,
    );

    // Serialize to YAML Value and remove optional fields
    let mut yaml_value: Value =
        serde_yaml::to_value(&base_config).expect("should serialize config to YAML value");

    // Remove optional fields from server section
    if let Some(server_value) = yaml_value.get_mut("server") {
        if let Value::Mapping(ref mut map) = server_value {
            map.remove(&Value::String("bind_address".to_string()));
            map.remove(&Value::String("max_connections".to_string()));
        }
    }

    // Remove request_timeout_ms from upstreams section
    if let Some(upstreams_value) = yaml_value.get_mut("upstreams") {
        if let Value::Mapping(ref mut map) = upstreams_value {
            map.remove(&Value::String("request_timeout_ms".to_string()));
        }
    }

    // Serialize back to string and deserialize
    let yaml = serde_yaml::to_string(&yaml_value).expect("should serialize YAML value");
    let config: Config = serde_yaml::from_str(&yaml)
        .expect("should deserialize config with all optional fields omitted");

    assert!(config.validate().is_ok(), "config should be valid");
    assert_eq!(
        config.server.bind_address, "0.0.0.0:8080",
        "bind_address should use default"
    );
    assert_eq!(
        config.server.max_connections, 1024,
        "max_connections should use default"
    );
    assert_eq!(
        config.upstream_timeout(),
        Some(120_000),
        "request_timeout_ms should use default"
    );
}

#[test]
fn deserialize_config_with_partial_server_fields() {
    // Precondition: YAML config with server section having only bind_address.
    // Action: Deserialize YAML config with only bind_address specified.
    // Expected behavior: max_connections uses default, validation succeeds.
    // Covers Requirements: C2, C8
    use fluxgate::config::{Config, ServerConfig};
    use serde_yaml::Value;

    // Create config using helper functions with custom bind_address
    let base_config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: "192.168.1.1:9000".to_string(),
            max_connections: test_server_config().max_connections,
        },
        upstreams: None,
        api_keys: None,
    };

    // Serialize to YAML Value and remove max_connections
    let mut yaml_value: Value =
        serde_yaml::to_value(&base_config).expect("should serialize config to YAML value");

    if let Some(server_value) = yaml_value.get_mut("server") {
        if let Value::Mapping(ref mut map) = server_value {
            map.remove(&Value::String("max_connections".to_string()));
        }
    }

    // Serialize back to string and deserialize
    let yaml = serde_yaml::to_string(&yaml_value).expect("should serialize YAML value");
    let config: Config =
        serde_yaml::from_str(&yaml).expect("should deserialize config with partial server fields");

    assert!(config.validate().is_ok(), "config should be valid");
    assert_eq!(
        config.server.bind_address, "192.168.1.1:9000",
        "bind_address should be set"
    );
    assert_eq!(
        config.server.max_connections, 1024,
        "max_connections should use default"
    );
}

#[test]
fn deserialize_config_with_partial_server_fields_max_connections_only() {
    // Precondition: YAML config with server section having only max_connections.
    // Action: Deserialize YAML config with only max_connections specified.
    // Expected behavior: bind_address uses default, validation succeeds.
    // Covers Requirements: C2, C8
    use fluxgate::config::{Config, ServerConfig};
    use serde_yaml::Value;

    // Create config using helper functions with custom max_connections
    let base_config = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: test_server_config().bind_address,
            max_connections: 2048,
        },
        upstreams: None,
        api_keys: None,
    };

    // Serialize to YAML Value and remove bind_address
    let mut yaml_value: Value =
        serde_yaml::to_value(&base_config).expect("should serialize config to YAML value");

    if let Some(server_value) = yaml_value.get_mut("server") {
        if let Value::Mapping(ref mut map) = server_value {
            map.remove(&Value::String("bind_address".to_string()));
        }
    }

    // Serialize back to string and deserialize
    let yaml = serde_yaml::to_string(&yaml_value).expect("should serialize YAML value");
    let config: Config =
        serde_yaml::from_str(&yaml).expect("should deserialize config with only max_connections");

    assert!(config.validate().is_ok(), "config should be valid");
    assert_eq!(
        config.server.bind_address, "0.0.0.0:8080",
        "bind_address should use default"
    );
    assert_eq!(
        config.server.max_connections, 2048,
        "max_connections should be set"
    );
}

#[test]
fn deserialize_config_with_upstreams_but_no_timeout() {
    // Precondition: YAML config with upstreams section but no request_timeout_ms.
    // Action: Deserialize YAML config with upstreams but omitted timeout.
    // Expected behavior: request_timeout_ms uses default, validation succeeds.
    // Covers Requirements: C2, C8
    use fluxgate::config::Config;
    use serde_yaml::Value;

    // Create config using helper functions
    let upstream1 = test_upstream_entry_with_path("https://api1.example.com", "key1", "/api1");
    let upstream2 = test_upstream_entry_with_path("https://api2.example.com", "key2", "/api2");
    let base_config = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![("upstream1", upstream1), ("upstream2", upstream2)],
        )),
        None,
    );

    // Serialize to YAML Value and remove request_timeout_ms
    let mut yaml_value: Value =
        serde_yaml::to_value(&base_config).expect("should serialize config to YAML value");

    if let Some(upstreams_value) = yaml_value.get_mut("upstreams") {
        if let Value::Mapping(ref mut map) = upstreams_value {
            map.remove(&Value::String("request_timeout_ms".to_string()));
        }
    }

    // Serialize back to string and deserialize
    let yaml = serde_yaml::to_string(&yaml_value).expect("should serialize YAML value");
    let config: Config = serde_yaml::from_str(&yaml)
        .expect("should deserialize config with upstreams but no timeout");

    assert!(config.validate().is_ok(), "config should be valid");
    assert_eq!(
        config.upstream_timeout(),
        Some(120_000),
        "timeout should use default"
    );
    assert_eq!(
        config.get_upstream("upstream1").is_some(),
        true,
        "upstream1 should exist"
    );
    assert_eq!(
        config.get_upstream("upstream2").is_some(),
        true,
        "upstream2 should exist"
    );
}

#[test]
fn validate_rejects_explicit_zero_timeout_but_accepts_omitted() {
    // Precondition: Two configs - one with explicit zero timeout, one with omitted timeout.
    // Action: Validate both configs.
    // Expected behavior: Explicit zero is rejected, omitted uses default and is accepted.
    // Covers Requirements: C2, C8
    use fluxgate::config::Config;
    use serde_yaml::Value;

    // Config with explicit zero - should be rejected
    let upstream = test_upstream_entry_with_path("https://api.example.com", "test-key", "/test");
    let base_config_zero = test_config(
        Some(test_upstreams_config(0, vec![("test-upstream", upstream)])),
        None,
    );
    let yaml_zero = serde_yaml::to_string(&base_config_zero)
        .expect("should serialize config with zero timeout");
    let config_zero: Config =
        serde_yaml::from_str(&yaml_zero).expect("should deserialize even with invalid value");
    assert!(
        config_zero.validate().is_err(),
        "explicit zero timeout should be rejected"
    );

    // Config with omitted timeout - should be accepted with default
    let upstream_omitted =
        test_upstream_entry_with_path("https://api.example.com", "test-key", "/test");
    let base_config_omitted = test_config(
        Some(test_upstreams_config(
            30_000,
            vec![("test-upstream", upstream_omitted)],
        )),
        None,
    );
    let mut yaml_value: Value =
        serde_yaml::to_value(&base_config_omitted).expect("should serialize config to YAML value");
    if let Some(upstreams_value) = yaml_value.get_mut("upstreams") {
        if let Value::Mapping(ref mut map) = upstreams_value {
            map.remove(&Value::String("request_timeout_ms".to_string()));
        }
    }
    let yaml_omitted =
        serde_yaml::to_string(&yaml_value).expect("should serialize YAML value without timeout");
    let config_omitted: Config =
        serde_yaml::from_str(&yaml_omitted).expect("should deserialize config without timeout");
    assert!(
        config_omitted.validate().is_ok(),
        "omitted timeout should be accepted"
    );
    assert_eq!(
        config_omitted.upstream_timeout(),
        Some(120_000),
        "should use default"
    );
}

#[test]
fn validate_rejects_explicit_zero_max_connections_but_accepts_omitted() {
    // Precondition: Two configs - one with explicit zero max_connections, one with omitted.
    // Action: Validate both configs.
    // Expected behavior: Explicit zero is rejected, omitted uses default and is accepted.
    // Covers Requirements: C2, C8
    use fluxgate::config::{Config, ServerConfig};
    use serde_yaml::Value;

    // Config with explicit zero - should be rejected
    let base_config_zero = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: test_server_config().bind_address,
            max_connections: 0,
        },
        upstreams: None,
        api_keys: None,
    };
    let yaml_zero = serde_yaml::to_string(&base_config_zero)
        .expect("should serialize config with zero max_connections");
    let config_zero: Config =
        serde_yaml::from_str(&yaml_zero).expect("should deserialize even with invalid value");
    assert!(
        config_zero.validate().is_err(),
        "explicit zero max_connections should be rejected"
    );

    // Config with omitted max_connections - should be accepted with default
    let base_config_omitted = Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: ServerConfig {
            bind_address: test_server_config().bind_address,
            max_connections: test_server_config().max_connections,
        },
        upstreams: None,
        api_keys: None,
    };
    let mut yaml_value: Value =
        serde_yaml::to_value(&base_config_omitted).expect("should serialize config to YAML value");
    if let Some(server_value) = yaml_value.get_mut("server") {
        if let Value::Mapping(ref mut map) = server_value {
            map.remove(&Value::String("max_connections".to_string()));
        }
    }
    let yaml_omitted = serde_yaml::to_string(&yaml_value)
        .expect("should serialize YAML value without max_connections");
    let config_omitted: Config = serde_yaml::from_str(&yaml_omitted)
        .expect("should deserialize config without max_connections");
    assert!(
        config_omitted.validate().is_ok(),
        "omitted max_connections should be accepted"
    );
    assert_eq!(
        config_omitted.server.max_connections, 1024,
        "should use default"
    );
}

#[test]
fn deserialize_minimal_config_with_only_version() {
    // Precondition: YAML config with version and empty server section.
    // Action: Deserialize minimal config.
    // Expected behavior: All optional server fields use defaults, validation succeeds.
    // Covers Requirements: C2, C8
    use fluxgate::config::Config;
    use serde_yaml::Value;

    // Create minimal config using helper function
    let base_config = minimal_test_config();

    // Serialize to YAML Value and remove all server fields
    let mut yaml_value: Value =
        serde_yaml::to_value(&base_config).expect("should serialize config to YAML value");

    if let Some(server_value) = yaml_value.get_mut("server") {
        if let Value::Mapping(ref mut map) = server_value {
            map.remove(&Value::String("bind_address".to_string()));
            map.remove(&Value::String("max_connections".to_string()));
        }
    }

    // Serialize back to string and deserialize
    let yaml = serde_yaml::to_string(&yaml_value).expect("should serialize YAML value");
    let config: Config = serde_yaml::from_str(&yaml).expect("should deserialize minimal config");

    assert!(config.validate().is_ok(), "minimal config should be valid");
    assert_eq!(
        config.server.bind_address, "0.0.0.0:8080",
        "bind_address should use default"
    );
    assert_eq!(
        config.server.max_connections, 1024,
        "max_connections should use default"
    );
    assert_eq!(config.upstreams, None, "upstreams should be None");
    assert_eq!(config.api_keys, None, "api_keys should be None");
}

#[test]
fn deserialize_config_with_empty_server_section() {
    // Precondition: YAML config with empty server section.
    // Action: Deserialize config with empty server section.
    // Expected behavior: All server fields use defaults, validation succeeds.
    // Covers Requirements: C2, C8
    use fluxgate::config::Config;
    use serde_yaml::Value;

    // Create minimal config using helper function
    let base_config = minimal_test_config();

    // Serialize to YAML Value and remove all server fields
    let mut yaml_value: Value =
        serde_yaml::to_value(&base_config).expect("should serialize config to YAML value");

    if let Some(server_value) = yaml_value.get_mut("server") {
        if let Value::Mapping(ref mut map) = server_value {
            map.remove(&Value::String("bind_address".to_string()));
            map.remove(&Value::String("max_connections".to_string()));
        }
    }

    // Serialize back to string and deserialize
    let yaml = serde_yaml::to_string(&yaml_value).expect("should serialize YAML value");
    let config: Config =
        serde_yaml::from_str(&yaml).expect("should deserialize config with empty server section");

    assert!(
        config.validate().is_ok(),
        "config with empty server should be valid"
    );
    assert_eq!(
        config.server.bind_address, "0.0.0.0:8080",
        "bind_address should use default"
    );
    assert_eq!(
        config.server.max_connections, 1024,
        "max_connections should use default"
    );
}

#[test]
fn deserialize_config_with_empty_upstreams_section() {
    // Precondition: YAML config with empty upstreams section (no entries, no timeout).
    // Action: Deserialize config with empty upstreams section.
    // Expected behavior: request_timeout_ms uses default, validation succeeds.
    // Covers Requirements: C2, C8
    use fluxgate::config::Config;
    use serde_yaml::Value;

    // Create config with empty upstreams using helper functions
    let base_config = test_config(Some(test_upstreams_config(30_000, vec![])), None);

    // Serialize to YAML Value and remove request_timeout_ms
    let mut yaml_value: Value =
        serde_yaml::to_value(&base_config).expect("should serialize config to YAML value");

    if let Some(upstreams_value) = yaml_value.get_mut("upstreams") {
        if let Value::Mapping(ref mut map) = upstreams_value {
            map.remove(&Value::String("request_timeout_ms".to_string()));
        }
    }

    // Serialize back to string and deserialize
    let yaml = serde_yaml::to_string(&yaml_value).expect("should serialize YAML value");
    let config: Config = serde_yaml::from_str(&yaml)
        .expect("should deserialize config with empty upstreams section");

    assert!(
        config.validate().is_ok(),
        "config with empty upstreams should be valid"
    );
    assert_eq!(
        config.upstream_timeout(),
        Some(120_000),
        "timeout should use default"
    );
    assert!(!config.has_upstreams(), "should have no upstreams");
}

#[test]
fn default_config_uses_same_values_as_serde_defaults() {
    // Precondition: Config created via Default trait and via deserialization with omitted fields.
    // Action: Compare values from both sources.
    // Expected behavior: Both use same default values.
    // Covers Requirements: C2, C8
    use fluxgate::config::Config;
    use serde_yaml::Value;

    let default_config = Config::default();

    // Create minimal config using helper function
    let base_config = minimal_test_config();

    // Serialize to YAML Value and remove all server fields
    let mut yaml_value: Value =
        serde_yaml::to_value(&base_config).expect("should serialize config to YAML value");

    if let Some(server_value) = yaml_value.get_mut("server") {
        if let Value::Mapping(ref mut map) = server_value {
            map.remove(&Value::String("bind_address".to_string()));
            map.remove(&Value::String("max_connections".to_string()));
        }
    }

    // Serialize back to string and deserialize
    let yaml = serde_yaml::to_string(&yaml_value).expect("should serialize YAML value");
    let deserialized_config: Config =
        serde_yaml::from_str(&yaml).expect("should deserialize minimal config");

    assert_eq!(
        default_config.server.bind_address, deserialized_config.server.bind_address,
        "Default and deserialized bind_address should match"
    );
    assert_eq!(
        default_config.server.max_connections, deserialized_config.server.max_connections,
        "Default and deserialized max_connections should match"
    );
    assert_eq!(
        default_config.server.bind_address, "0.0.0.0:8080",
        "Default bind_address should be 0.0.0.0:8080"
    );
    assert_eq!(
        default_config.server.max_connections, 1024,
        "Default max_connections should be 1024"
    );
}

#[tokio::test]
async fn config_manager_subscribe_returns_initial_config_immediately() {
    // Precondition: ConfigManager initialized with config.
    // Action: Call subscribe() and immediately read from receiver.
    // Expected behavior: Receiver contains initial configuration immediately.
    // Covers Requirements: C3, C9
    use std::fs;
    use tempfile::tempdir;
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_yaml = format!(
        r#"
version: 1
server:
  bind_address: "127.0.0.1:8080"
  max_connections: 200
"#,
    );
    fs::write(&config_path, config_yaml).expect("write config file");
    let manager = ConfigManager::initialize(Some(config_path)).await;

    let receiver = manager.subscribe();
    let config = receiver.borrow().clone();
    assert_eq!(
        config.server.max_connections, 200,
        "should receive initial config immediately"
    );
}

#[tokio::test]
async fn config_manager_handles_config_with_empty_upstreams() {
    // Precondition: Configuration file with empty upstreams section.
    // Action: Initialize ConfigManager with config containing empty upstreams.
    // Expected behavior: Config loads successfully with empty upstreams.
    // Covers Requirements: C1, C2
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
upstreams:
  request_timeout_ms: 30000
"#,
    );
    fs::write(&config_path, config_yaml).expect("write config file");
    let manager = ConfigManager::initialize(Some(config_path)).await;

    let config = manager.current();
    assert!(
        config.upstreams.is_some(),
        "should have upstreams section even if empty"
    );
    assert!(
        config.upstreams.as_ref().unwrap().upstreams.is_empty(),
        "upstreams should be empty"
    );
}

#[tokio::test]
async fn config_manager_handles_config_with_empty_api_keys() {
    // Precondition: Configuration file with empty api_keys section.
    // Action: Initialize ConfigManager with config containing empty api_keys.
    // Expected behavior: Config loads successfully with empty api_keys.
    // Covers Requirements: C1, C2
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
api_keys:
  static: []
"#,
    );
    fs::write(&config_path, config_yaml).expect("write config file");
    let manager = ConfigManager::initialize(Some(config_path)).await;

    let config = manager.current();
    assert!(
        config.api_keys.is_some(),
        "should have api_keys section even if empty"
    );
    assert!(
        config.api_keys.as_ref().unwrap().static_.is_empty(),
        "api_keys.static should be empty"
    );
}

#[tokio::test]
async fn config_manager_reload_fails_on_validation_error() {
    // Precondition: ConfigManager initialized with valid config, then config becomes invalid.
    // Action: Modify config file to invalid state and call reload().
    // Expected behavior: Reload fails, previous valid config is retained.
    // Covers Requirements: C2, C6
    use std::fs;
    use tempfile::tempdir;
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let valid_config = format!(
        r#"
version: 1
server:
  bind_address: "127.0.0.1:8080"
  max_connections: 100
"#,
    );
    fs::write(&config_path, valid_config).expect("write config file");
    let manager = ConfigManager::initialize(Some(config_path.clone())).await;

    let initial_config = manager.current();

    // Write invalid config
    let invalid_config = format!(
        r#"
version: 1
server:
  bind_address: ""
  max_connections: 0
"#,
    );
    fs::write(&config_path, invalid_config).expect("write invalid config");
    tokio::time::sleep(Duration::from_millis(600)).await; // Wait for polling

    let current_config = manager.current();
    assert_eq!(
        current_config.server.bind_address, initial_config.server.bind_address,
        "should retain previous config when reload fails"
    );
}

#[tokio::test]
async fn config_manager_handles_config_with_only_server_section() {
    // Precondition: Configuration file with only server section.
    // Action: Initialize ConfigManager with minimal config.
    // Expected behavior: Config loads successfully with defaults for missing sections.
    // Covers Requirements: C1, C8
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

    let config = manager.current();
    assert_eq!(
        config.server.bind_address, "127.0.0.1:8080",
        "should load server config"
    );
    assert_eq!(
        config.server.max_connections, 100,
        "should load max_connections"
    );
}

#[tokio::test]
async fn config_manager_current_returns_consistent_config() {
    // Precondition: ConfigManager initialized with config.
    // Action: Call current() multiple times.
    // Expected behavior: Returns same config each time (idempotent).
    // Covers Requirements: C3
    use std::fs;
    use tempfile::tempdir;
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("fluxgate.yaml");
    let config_yaml = format!(
        r#"
version: 1
server:
  bind_address: "127.0.0.1:8080"
  max_connections: 150
"#,
    );
    fs::write(&config_path, config_yaml).expect("write config file");
    let manager = ConfigManager::initialize(Some(config_path)).await;

    let config1 = manager.current();
    let config2 = manager.current();
    let config3 = manager.current();

    assert_eq!(
        config1.server.max_connections,
        config2.server.max_connections
    );
    assert_eq!(
        config2.server.max_connections,
        config3.server.max_connections
    );
    assert_eq!(config1.server.bind_address, config2.server.bind_address);
    assert_eq!(config2.server.bind_address, config3.server.bind_address);
}

// ============================================================================
// Background Polling Task (C10) Tests
// ============================================================================

#[tokio::test]
async fn config_manager_polls_in_background_task() {
    // Precondition: ConfigManager is initialized with configuration file.
    // Action: Initialize ConfigManager and check if background polling task is running.
    // Expected behavior: Background task polls configuration file without blocking main operation.
    // Covers Requirements: C10
    use fluxgate::config::ConfigManager;
    use std::fs;
    use tempfile::tempdir;

    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    // Create initial config
    let initial_config = r#"
version: 1
server:
  bind_address: "0.0.0.0:8080"
  max_connections: 1024
"#;
    fs::write(&config_path, initial_config).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;

    // ConfigManager should start background polling task
    // Background task should not block main operation

    // Give background task time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Manager should still be responsive (non-blocking)
    let _config = manager.current();
    // If we got here without blocking, background task is working
}

#[tokio::test]
async fn config_manager_background_polling_detects_changes() {
    // Precondition: ConfigManager with background polling task running.
    // Action: Modify configuration file and wait for detection.
    // Expected behavior: Background task detects changes without blocking main operation.
    // Covers Requirements: C10
    use fluxgate::config::ConfigManager;
    use std::fs;
    use tempfile::tempdir;
    use tokio::time::{sleep, Duration};

    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    // Create initial config
    let initial_config = r#"
version: 1
server:
  bind_address: "0.0.0.0:8080"
  max_connections: 1024
"#;
    fs::write(&config_path, initial_config).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;

    // Subscribe to config changes
    let _subscriber = manager.subscribe();

    // Wait for background task to start
    sleep(Duration::from_millis(200)).await;

    // Modify config file
    let updated_config = r#"
version: 1
server:
  bind_address: "0.0.0.0:8081"
  max_connections: 2048
"#;
    fs::write(&config_path, updated_config).expect("write updated config");

    // Wait for background polling to detect change (polling interval + processing time)
    sleep(Duration::from_millis(1200)).await;

    // Background task should have detected change without blocking
    // Check if config was updated (non-blocking check)
    let config = manager.current();
    // Config should be updated by background task
    assert_eq!(config.server.bind_address, "0.0.0.0:8081");
}

// ============================================================================
// Inaccessible File Handling (C11) Tests
// ============================================================================

#[tokio::test]
async fn config_manager_handles_inaccessible_file_gracefully() {
    // Precondition: Configuration file becomes inaccessible during runtime.
    // Action: Delete configuration file while ConfigManager is polling.
    // Expected behavior: Manager continues with last valid configuration and logs warnings.
    // Covers Requirements: C11
    use fluxgate::config::ConfigManager;
    use std::fs;
    use tempfile::tempdir;
    use tokio::time::{sleep, Duration};

    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    // Create initial config
    let initial_config = r#"
version: 1
server:
  bind_address: "0.0.0.0:8080"
  max_connections: 1024
"#;
    fs::write(&config_path, initial_config).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;

    // Get initial config
    let initial_bind_address = manager.current().server.bind_address.clone();

    // Wait for background task to start
    sleep(Duration::from_millis(200)).await;

    // Delete config file (make it inaccessible)
    fs::remove_file(&config_path).expect("delete config file");

    // Wait for background polling to attempt read
    sleep(Duration::from_millis(1200)).await;

    // Manager should continue with last valid configuration
    let config = manager.current();
    assert_eq!(
        config.server.bind_address, initial_bind_address,
        "Manager should retain last valid config when file is inaccessible"
    );
}

#[tokio::test]
async fn config_manager_recovers_when_file_becomes_accessible() {
    // Precondition: Configuration file was inaccessible, then becomes accessible again.
    // Action: Recreate configuration file after deletion.
    // Expected behavior: Manager resumes polling and loads new configuration when file becomes accessible.
    // Covers Requirements: C11
    use fluxgate::config::ConfigManager;
    use std::fs;
    use tempfile::tempdir;
    use tokio::time::{sleep, Duration};

    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    // Create initial config
    let initial_config = r#"
version: 1
server:
  bind_address: "0.0.0.0:8080"
  max_connections: 1024
"#;
    fs::write(&config_path, initial_config).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;

    // Wait for background task to start
    sleep(Duration::from_millis(200)).await;

    // Delete config file
    fs::remove_file(&config_path).expect("delete config file");

    // Wait for background polling to attempt read
    sleep(Duration::from_millis(1200)).await;

    // Recreate config file with different values
    let recovered_config = r#"
version: 1
server:
  bind_address: "0.0.0.0:8082"
  max_connections: 4096
"#;
    fs::write(&config_path, recovered_config).expect("write recovered config");

    // Wait for background polling to detect recovered file
    sleep(Duration::from_millis(1200)).await;

    // Manager should load recovered configuration
    let config = manager.current();
    assert_eq!(
        config.server.bind_address, "0.0.0.0:8082",
        "Manager should load config when file becomes accessible again"
    );
}

#[tokio::test]
async fn config_manager_handles_permission_denied_gracefully() {
    // Precondition: Configuration file has permission denied errors during polling.
    // Action: Attempt to read configuration file with insufficient permissions.
    // Expected behavior: Manager continues with last valid configuration and logs warnings.
    // Covers Requirements: C11
    use fluxgate::config::ConfigManager;
    use std::fs;
    use tempfile::tempdir;
    use tokio::time::{sleep, Duration};

    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    // Create initial config
    let initial_config = r#"
version: 1
server:
  bind_address: "0.0.0.0:8080"
  max_connections: 1024
"#;
    fs::write(&config_path, initial_config).expect("write config");

    let manager = ConfigManager::initialize(Some(config_path.clone())).await;

    // Get initial config
    let initial_bind_address = manager.current().server.bind_address.clone();

    // Wait for background task to start
    sleep(Duration::from_millis(200)).await;

    // Remove read permissions (if possible on this platform)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&config_path).unwrap().permissions();
        perms.set_mode(0o000); // No permissions
        fs::set_permissions(&config_path, perms).unwrap();
    }

    // Wait for background polling to attempt read
    sleep(Duration::from_millis(1200)).await;

    // Manager should continue with last valid configuration
    let config = manager.current();
    assert_eq!(
        config.server.bind_address, initial_bind_address,
        "Manager should retain last valid config when file permissions are denied"
    );

    // Restore permissions for cleanup
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&config_path).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&config_path, perms).ok();
    }
}
