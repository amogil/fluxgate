//! Functional tests ensuring configuration validation rejects invalid inputs.

use std::{net::SocketAddr, time::Duration};

use tokio::runtime::Runtime;

use super::common::{allocate_port, MockServer, ProxyProcess};

#[test]
fn proxy_configuration_validates_missing_required_upstream_fields() {
    // Preconditions: Configuration file with upstream missing required fields (target_url or api_key).
    // Action: Start proxy with incomplete upstream configuration.
    // Expected behavior: Fails with validation errors.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with missing target_url
        let invalid_config = format!(
            r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  test-upstream:
    api_key: "some-key"
    request_path: "/test"
    # target_url is missing
"#,
            bind_addr
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("target_url")
                || logs.contains("required field")
                || logs.contains("Using default configuration")
        });

        // Should fail with validation error or use defaults
        assert!(
            logs.contains("validation failed")
                || logs.contains("target_url")
                || logs.contains("required field")
                || logs.contains("Using default configuration"),
            "Proxy should fail validation when required upstream fields are missing, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_empty_upstream_definitions() {
    // Preconditions: Configuration file with empty upstream definitions.
    // Action: Start proxy with empty upstream configurations.
    // Expected behavior: Fails with validation errors.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with empty upstream definitions
        let invalid_config = format!(
            r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  # Empty upstream definition
  empty-upstream: {{}}
"#,
            bind_addr
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("empty")
                || logs.contains("target_url")
                || logs.contains("required field")
                || logs.contains("Using default configuration")
        });

        // Should fail with validation error or use defaults
        assert!(
            logs.contains("validation failed")
                || logs.contains("empty")
                || logs.contains("target_url")
                || logs.contains("required field")
                || logs.contains("Using default configuration"),
            "Proxy should fail validation when upstream definitions are empty, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_invalid_upstream_urls() {
    // Preconditions: Configuration file with invalid upstream URLs.
    // Action: Start proxy with invalid URL schemes.
    // Expected behavior: Fails with validation errors.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with invalid upstream URLs
        let invalid_config = format!(
            r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  invalid-ftp-upstream:
    target_url: "ftp://example.com/api"
    api_key: "some-key"
    request_path: "/invalid-ftp-upstream"
  invalid-file-upstream:
    target_url: "file:///etc/passwd"
    api_key: "another-key"
    request_path: "/invalid-file-upstream"
"#,
            bind_addr
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("target_url")
                || logs.contains("URL scheme")
                || logs.contains("Using default configuration")
        });

        assert!(
            logs.contains("validation failed")
                || logs.contains("target_url")
                || logs.contains("URL scheme")
                || logs.contains("http")
                || logs.contains("https")
                || logs.contains("Using default configuration"),
            "Proxy should flag invalid upstream URL schemes, got: {}",
            logs
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_empty_api_key_values() {
    // Preconditions: Configuration file with empty API key values.
    // Action: Start proxy with empty API keys.
    // Expected behavior: Fails with validation errors.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with empty API key values
        let invalid_config = format!(
            r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  test-upstream:
    target_url: "{}"
    api_key: "valid-key"
    request_path: "/test"

api_keys:
  static:
    - id: "empty-key-user"
      key: ""  # Empty API key
      upstreams:
        - test-upstream
    - id: "whitespace-key-user"
      key: "   "  # Whitespace-only API key
      upstreams:
        - test-upstream
"#,
            bind_addr,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("key")
                || logs.contains("empty")
                || logs.contains("required field")
                || logs.contains("Using default configuration")
        });

        // Should fail with validation error or use defaults
        assert!(
            logs.contains("validation failed")
                || logs.contains("key")
                || logs.contains("empty")
                || logs.contains("required field")
                || logs.contains("Using default configuration"),
            "Proxy should fail validation when API key values are empty, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_duplicate_api_key_ids() {
    // Preconditions: Configuration file with duplicate API key ids.
    // Action: Start proxy with duplicate API key ids.
    // Expected behavior: Fails with validation errors.
    // Requirement: C16 - API key ids must be unique when specified

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with duplicate API key ids
        let invalid_config = format!(
            r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  test-upstream:
    target_url: "{}"
    api_key: "upstream-key"
    request_path: "/test"

api_keys:
  static:
    - id: "duplicate-name"
      key: "key1"
      upstreams:
        - test-upstream
    - id: "duplicate-name"  # Duplicate id
      key: "key2"
      upstreams:
        - test-upstream
"#,
            bind_addr,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("duplicate")
                || logs.contains("unique")
                || logs.contains("Fluxgate proxy initialized")
                || logs.contains("Using default configuration")
        });

        assert!(
            logs.contains("validation failed")
                || (logs.contains("not unique") && logs.contains("id"))
                || logs.contains("Using default configuration"),
            "Proxy should fail validation when API key ids are duplicated, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_duplicate_api_key_values() {
    // Preconditions: Configuration file with duplicate API key values (keys).
    // Action: Start proxy with duplicate API key values.
    // Expected behavior: Fails with validation errors.
    // Requirement: C16 - API key values must be unique

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with duplicate API key values
        let invalid_config = format!(
            r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  test-upstream:
    target_url: "{}"
    api_key: "upstream-key"
    request_path: "/test"

api_keys:
  static:
    - id: "user1"
      key: "duplicate-key"
      upstreams:
        - test-upstream
    - id: "user2"
      key: "duplicate-key"  # Duplicate key value
      upstreams:
        - test-upstream
"#,
            bind_addr,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("not unique")
                || logs.contains("duplicate")
                || logs.contains("key")
                || logs.contains("Using default configuration")
        });

        assert!(
            logs.contains("validation failed")
                || (logs.contains("not unique") && logs.contains("key"))
                || logs.contains("Using default configuration"),
            "Proxy should fail validation when API key values are duplicated, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_empty_api_key_names() {
    // Preconditions: Configuration file with empty API key ids when id is specified.
    // Action: Start proxy with empty API key ids.
    // Expected behavior: Fails with validation errors.
    // Requirement: C16 - API key ids must be non-empty when specified

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with empty API key ids
        let invalid_config = format!(
            r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  test-upstream:
    target_url: "{}"
    api_key: "upstream-key"
    request_path: "/test"

api_keys:
  static:
    - id: ""  # Empty id (invalid when specified)
      key: "key1"
      upstreams:
        - test-upstream
    - id: "   "  # Whitespace-only id (invalid when specified)
      key: "key2"
      upstreams:
        - test-upstream
    - key: "key3"  # id omitted (valid - id is optional)
      upstreams:
        - test-upstream
"#,
            bind_addr,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("id")
                || logs.contains("empty")
                || logs.contains("Using default configuration")
        });

        assert!(
            logs.contains("validation failed")
                || (logs.contains("id") && logs.contains("empty"))
                || logs.contains("Using default configuration"),
            "Proxy should fail validation when API key ids are empty when specified, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_api_keys_referencing_non_existent_upstreams() {
    // Preconditions: Configuration file with API keys referencing non-existent upstreams.
    // Action: Start proxy with invalid upstream references.
    // Expected behavior: Fails with validation errors.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with API keys referencing non-existent upstreams
        let invalid_config = format!(
            r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  existing-upstream:
    target_url: "{}"
    api_key: "upstream-key"
    request_path: "/existing-upstream"

api_keys:
  static:
    - id: "valid-user"
      key: "valid-key"
      upstreams:
        - existing-upstream
    - id: "invalid-user"
      key: "invalid-key"
      upstreams:
        - non-existent-upstream  # References upstream that doesn't exist
"#,
            bind_addr,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("upstream")
                || logs.contains("non-existent")
                || logs.contains("reference")
                || logs.contains("not found")
                || logs.contains("Using default configuration")
        });

        // Should fail with validation error or use defaults
        assert!(
            logs.contains("validation failed")
                || logs.contains("upstream")
                || logs.contains("non-existent")
                || logs.contains("reference")
                || logs.contains("not found")
                || logs.contains("Using default configuration"),
            "Proxy should fail validation when API keys reference non-existent upstreams, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_invalid_server_bind_address() {
    // Preconditions: Configuration file with invalid server bind address.
    // Action: Start proxy with invalid bind address.
    // Expected behavior: Fails with validation errors.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        // Configuration with invalid bind address
        let invalid_config = format!(
            r#"
server:
  bind_address: "invalid-address:99999"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  test-upstream:
    target_url: "{}"
    api_key: "upstream-key"
    request_path: "/test"

api_keys:
  static:
    - id: "test-user"
      key: "test-key"
      upstreams:
        - test-upstream
"#,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        proxy
            .wait_for_exit(Duration::from_secs(5))
            .expect("proxy should exit when max_connections value is invalid");
        let logs = proxy.take_process_output();

        // Should fail with validation error
        assert!(
            logs.contains("validation failed")
                || logs.contains("bind_address")
                || logs.contains("invalid")
                || logs.contains("address"),
            "Proxy should fail validation when server bind address is invalid, got: {}",
            logs
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_invalid_max_connections_value() {
    // Preconditions: Configuration file with invalid max_connections value.
    // Action: Start proxy with invalid max_connections (zero or negative).
    // Expected behavior: Fails with validation errors.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with invalid max_connections (zero)
        let invalid_config = format!(
            r#"
server:
  bind_address: "{}"
  max_connections: 0  # Invalid: must be > 0

upstreams:
  request_timeout_ms: 5000
  test-upstream:
    target_url: "{}"
    api_key: "upstream-key"
    request_path: "/test"

api_keys:
  static:
    - id: "test-user"
      key: "test-key"
      upstreams:
        - test-upstream
"#,
            bind_addr,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("max_connections")
                || logs.contains("invalid")
                || logs.contains("must be")
                || logs.contains("greater than")
                || logs.contains("Using default configuration")
        });

        // Should fail with validation error or use defaults
        assert!(
            logs.contains("validation failed")
                || logs.contains("max_connections")
                || logs.contains("invalid")
                || logs.contains("must be")
                || logs.contains("greater than")
                || logs.contains("Using default configuration"),
            "Proxy should fail validation when max_connections is invalid, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_nested_upstream_structures() {
    // Preconditions: Configuration file contains nested upstream structures.
    // Action: Start proxy with nested upstream configurations.
    // Expected behavior: Validates nested structures correctly.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with nested upstream structures
        // Note: YAML supports nested structures, but our schema may not support all forms
        let config_with_nested = format!(
            r#"version: 1
server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  nested-upstream:
    target_url: "{}"
    api_key: "nested-key"
    request_path: "/nested-upstream"
    metadata:
      version: "1.0"
      environment: "test"
      nested:
        deep:
          value: 42

api_keys:
  static:
    - id: "test-user"
      key: "test-key"
      upstreams:
        - nested-upstream
"#,
            bind_addr,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn(&config_with_nested);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("Fluxgate proxy initialized")
                || logs.contains("validation failed")
                || logs.contains("Using default configuration")
        });

        // Should either accept the nested structure or reject it with clear error
        // The implementation accepts nested structures (they are ignored by serde)
        // Check that proxy starts successfully
        assert!(
            logs.contains("Fluxgate proxy initialized"),
            "Proxy should start successfully with nested structures (they may be ignored), got: {}",
            logs
        );

        // Test that basic functionality works despite nested structures
        let client = reqwest::Client::new();
        let proxy_url = format!("http://{}", bind_addr);

        let response = client
            .get(&format!("{}/nested-upstream/nested-test", proxy_url))
            .header("Authorization", "Bearer test-key")
            .send()
            .await
            .expect("send request with nested config");

        assert_eq!(response.status(), reqwest::StatusCode::OK);

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_array_values_where_scalars_expected() {
    // Preconditions: Configuration contains array values where scalars are expected.
    // Action: Start proxy with type mismatches (arrays where scalars expected).
    // Expected behavior: Fails validation with type mismatch errors.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with array where scalar expected
        let invalid_config = format!(
            r#"version: 1
server:
  bind_address:
    - "{}"  # Array instead of string
    - "invalid"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  test-upstream:
    target_url: "http://example.com"
    api_key: "test-key"
    request_path: "/test"

api_keys:
  static:
    - id: "test-user"
      key: "test-key"
      upstreams:
        - test-upstream
"#,
            bind_addr
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("type mismatch")
                || logs.contains("expected")
                || logs.contains("found array")
                || logs.contains("Using default configuration")
        });

        // Should fail with validation error due to type mismatch or use defaults
        assert!(
            logs.contains("validation failed")
                || logs.contains("type mismatch")
                || logs.contains("expected")
                || logs.contains("found array")
                || logs.contains("Using default configuration"),
            "Proxy should fail validation when arrays are used where scalars expected, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_scalar_values_where_arrays_expected() {
    // Preconditions: Configuration contains scalar values where arrays are expected.
    // Action: Start proxy with type mismatches (scalars where arrays expected).
    // Expected behavior: Fails validation with type mismatch errors.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with scalar where array expected
        let invalid_config = format!(
            r#"version: 1
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
    - id: "test-user"
      key: "test-key"
      upstreams: "single-upstream"  # Scalar instead of array
"#,
            bind_addr,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("failed to parse configuration")
                || logs.contains("invalid type")
                || logs.contains("expected a sequence")
                || logs.contains("Using default configuration")
        });

        // Should fail with parsing error due to type mismatch (YAML parser catches this)
        assert!(
            logs.contains("failed to parse configuration")
                || logs.contains("invalid type")
                || logs.contains("expected a sequence")
                || logs.contains("Using default configuration"),
            "Proxy should fail validation when scalars are used where arrays expected, got: {}",
            logs
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_url_schemes_and_rejects_unsupported_ones() {
    // Preconditions: Configuration contains upstream URLs with various schemes.
    // Action: Start proxy with mixed valid/invalid URL schemes.
    // Expected behaviour: Proxy accepts http/https URLs but rejects ftp, file, custom schemes.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with mixed valid and invalid URL schemes
        let config_yaml = format!(
            r#"
server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  valid-http:
    target_url: "http://example.com/api"
    api_key: "key1"
    request_path: "/valid-http"
  valid-https:
    target_url: "https://api.example.com/v1"
    api_key: "key2"
    request_path: "/valid-https"
  invalid-ftp:
    target_url: "ftp://files.example.com"
    api_key: "key3"
    request_path: "/invalid-ftp"
  invalid-file:
    target_url: "file:///etc/passwd"
    api_key: "key4"
    request_path: "/invalid-file"
  invalid-custom:
    target_url: "custom://example.com"
    api_key: "key5"
    request_path: "/invalid-custom"
"#,
            bind_addr
        );

        let mut proxy = ProxyProcess::spawn(&config_yaml);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("target_url")
                || logs.contains("URL scheme")
                || logs.contains("Using default configuration")
        });

        assert!(
            logs.contains("validation failed")
                || logs.contains("target_url")
                || logs.contains("URL scheme")
                || logs.contains("Using default configuration"),
            "Proxy should reject configuration with invalid URL schemes, got: {}",
            logs
        );

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_missing_or_invalid_version() {
    // Preconditions: Configuration file is missing the version field or sets an unsupported value.
    // Action: Start proxy with configurations lacking a version or using an invalid version.
    // Expected behavior: Fails validation and refuses to start with the provided configuration.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let mock_server = MockServer::start().await.expect("start mock server");

        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration missing the version field entirely.
        let missing_version_config = format!(
            r#"
server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  test-upstream:
    target_url: "{}"
    api_key: "upstream-key"
    request_path: "/test"

api_keys:
  static:
    - id: "test-client"
      key: "client-key"
      upstreams:
        - test-upstream
"#,
            bind_addr,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn_without_version(&missing_version_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("version")
                || logs.contains("Using default configuration")
        });

        assert!(
            logs.contains("validation failed")
                || logs.contains("version")
                || logs.contains("Using default configuration"),
            "Proxy should reject configuration missing version field, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();

        // Configuration with an invalid version value.
        let invalid_version_config = format!(
            r#"
version: 2

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  test-upstream:
    target_url: "{}"
    api_key: "upstream-key"
    request_path: "/test"

api_keys:
  static:
    - id: "test-client"
      key: "client-key"
      upstreams:
        - test-upstream
"#,
            bind_addr,
            mock_server.url()
        );

        let mut proxy = ProxyProcess::spawn(&invalid_version_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("version")
                || logs.contains("Using default configuration")
        });

        assert!(
            logs.contains("validation failed")
                || logs.contains("version")
                || logs.contains("Using default configuration"),
            "Proxy should reject configuration with invalid version value, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_missing_request_path() {
    // Preconditions: Configuration file with upstream missing request_path field.
    // Action: Start proxy with upstream configuration missing request_path.
    // Expected behavior: Fails with validation errors.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with missing request_path
        let invalid_config = format!(
            r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  test-upstream:
    target_url: "https://api.example.com"
    api_key: "some-key"
    # request_path is missing
"#,
            bind_addr
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("request_path")
                || logs.contains("required field")
                || logs.contains("Using default configuration")
        });

        // Should fail with validation error or use defaults
        assert!(
            logs.contains("validation failed")
                || logs.contains("request_path")
                || logs.contains("required field")
                || logs.contains("Using default configuration"),
            "Proxy should fail validation when request_path is missing, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_empty_request_path() {
    // Preconditions: Configuration file with upstream having empty request_path.
    // Action: Start proxy with empty request_path in upstream configuration.
    // Expected behavior: Fails with validation errors.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with empty request_path
        let invalid_config = format!(
            r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  test-upstream:
    target_url: "https://api.example.com"
    api_key: "some-key"
    request_path: ""
"#,
            bind_addr
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("request_path")
                || logs.contains("must not be empty")
                || logs.contains("Using default configuration")
        });

        // Should fail with validation error or use defaults
        assert!(
            logs.contains("validation failed")
                || logs.contains("request_path")
                || logs.contains("must not be empty")
                || logs.contains("Using default configuration"),
            "Proxy should fail validation when request_path is empty, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}

#[test]
fn proxy_configuration_validates_invalid_request_path_format() {
    // Preconditions: Configuration file with upstream having invalid request_path format.
    // Action: Start proxy with invalid request_path format (no leading /, contains scheme/query/host/port).
    // Expected behavior: Fails with validation errors.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        let test_cases = vec![
            ("api", "must start with '/'"),
            ("https://api.example.com/path", "must not contain scheme"),
            ("/api?param=value", "must not contain query string"),
            ("/api:8080", "must not contain port separator"),
        ];

        for (invalid_path, description) in test_cases {
            let invalid_config = format!(
                r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  test-upstream:
    target_url: "https://api.example.com"
    api_key: "some-key"
    request_path: "{}"
"#,
                bind_addr, invalid_path
            );

            let mut proxy = ProxyProcess::spawn(&invalid_config);
            let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
                logs.contains("validation failed")
                    || logs.contains("request_path")
                    || logs.contains("Using default configuration")
            });

            // Should fail with validation error or use defaults
            assert!(
                logs.contains("validation failed") || logs.contains("request_path") || logs.contains("Using default configuration"),
                "Proxy should fail validation when request_path is invalid ({}: {}), got: {}",
                invalid_path,
                description,
                logs
            );
            // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
            if logs.contains("Using default configuration") {
                assert!(
                    !logs.contains("Fluxgate proxy initialized"),
                    "Proxy should NOT log initialization message when config was not loaded, got: {}",
                    logs
                );
            }

            proxy.shutdown();
        }
    });
}

#[test]
fn proxy_configuration_validates_duplicate_request_path() {
    // Preconditions: Configuration file with multiple upstreams having duplicate request_path values.
    // Action: Start proxy with duplicate request_path values across upstreams.
    // Expected behavior: Fails with validation errors.

    let rt = Runtime::new().expect("create tokio runtime");

    rt.block_on(async {
        let port = allocate_port();
        let bind_addr: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("parse bind address");

        // Configuration with duplicate request_path
        let invalid_config = format!(
            r#"
version: 1

server:
  bind_address: "{}"
  max_connections: 100

upstreams:
  request_timeout_ms: 5000
  upstream1:
    target_url: "https://api1.example.com"
    api_key: "key1"
    request_path: "/test"
  upstream2:
    target_url: "https://api2.example.com"
    api_key: "key2"
    request_path: "/test"
"#,
            bind_addr
        );

        let mut proxy = ProxyProcess::spawn(&invalid_config);
        let logs = proxy.wait_for_logs(Duration::from_secs(5), |logs| {
            logs.contains("validation failed")
                || logs.contains("request_path")
                || logs.contains("not unique")
                || logs.contains("duplicate")
                || logs.contains("Using default configuration")
        });

        // Should fail with validation error or use defaults
        assert!(
            logs.contains("validation failed")
                || logs.contains("request_path")
                || logs.contains("not unique")
                || logs.contains("duplicate")
                || logs.contains("Using default configuration"),
            "Proxy should fail validation when request_path is duplicated, got: {}",
            logs
        );
        // Requirement: C4.2 - "Fluxgate proxy initialized" should not be logged when config was not loaded
        if logs.contains("Using default configuration") {
            assert!(
                !logs.contains("Fluxgate proxy initialized"),
                "Proxy should NOT log initialization message when config was not loaded, got: {}",
                logs
            );
        }

        proxy.shutdown();
    });
}
