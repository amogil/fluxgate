//! Common test utilities and helpers for unit tests.

use fluxgate::config::{
    ApiKeysConfig, Config, JwtApiKey, ServerConfig, StaticApiKey, UpstreamEntry, UpstreamsConfig,
    SUPPORTED_CONFIG_VERSION,
};

/// YAML configuration field names as constants to avoid duplication.
/// These match the constants in functional/common.rs for consistency.
pub mod yaml_fields {
    pub const VERSION: &str = "version";
    pub const SERVER: &str = "server";
    pub const BIND_ADDRESS: &str = "bind_address";
    pub const MAX_CONNECTIONS: &str = "max_connections";
    pub const UPSTREAMS: &str = "upstreams";
    pub const REQUEST_TIMEOUT_MS: &str = "request_timeout_ms";
    pub const TARGET_URL: &str = "target_url";
    pub const API_KEY: &str = "api_key";
    pub const REQUEST_PATH: &str = "request_path";
    pub const API_KEYS: &str = "api_keys";
    pub const STATIC: &str = "static";
}

/// Create a minimal valid server configuration for testing
pub fn test_server_config() -> ServerConfig {
    ServerConfig {
        bind_address: "127.0.0.1:8080".to_string(),
        max_connections: 100,
    }
}

/// Create a test configuration with optional upstreams and API keys
pub fn test_config(upstreams: Option<UpstreamsConfig>, api_keys: Option<ApiKeysConfig>) -> Config {
    Config {
        version: SUPPORTED_CONFIG_VERSION,
        server: test_server_config(),
        upstreams,
        api_keys,
    }
}

/// Create a test configuration with only server settings
pub fn minimal_test_config() -> Config {
    test_config(None, None)
}

/// Create upstream entry for testing
pub fn test_upstream_entry(target_url: &str, api_key: &str) -> UpstreamEntry {
    // Generate unique request_path based on target_url to avoid duplicates
    let path = target_url
        .split('/')
        .last()
        .unwrap_or("test")
        .replace(":", "-")
        .replace("@", "-");
    UpstreamEntry {
        target_url: target_url.to_string(),
        api_key: api_key.to_string(),
        request_path: format!("/{}", path),
    }
}

/// Create upstream entry with explicit request_path for testing
pub fn test_upstream_entry_with_path(
    target_url: &str,
    api_key: &str,
    request_path: &str,
) -> UpstreamEntry {
    UpstreamEntry {
        target_url: target_url.to_string(),
        api_key: api_key.to_string(),
        request_path: request_path.to_string(),
    }
}

/// Create a simple config with one upstream and one API key for testing
#[allow(dead_code)] // May be useful for future tests
pub fn simple_test_config(
    upstream_name: &str,
    upstream: UpstreamEntry,
    api_key: StaticApiKey,
) -> Config {
    test_config(
        Some(test_upstreams_config(5000, vec![(upstream_name, upstream)])),
        Some(test_api_keys_config(vec![api_key])),
    )
}

/// Create a simple config with one upstream (no API keys) for testing
#[allow(dead_code)] // May be useful for future tests
pub fn simple_upstream_config(upstream_name: &str, upstream: UpstreamEntry) -> Config {
    test_config(
        Some(test_upstreams_config(5000, vec![(upstream_name, upstream)])),
        None,
    )
}

/// Create upstreams config with given entries
pub fn test_upstreams_config(
    request_timeout_ms: u64,
    entries: Vec<(&str, UpstreamEntry)>,
) -> UpstreamsConfig {
    UpstreamsConfig {
        request_timeout_ms,
        upstreams: entries
            .into_iter()
            .map(|(name, entry)| (name.to_string(), entry))
            .collect(),
    }
}

/// Create API keys config with given keys
pub fn test_api_keys_config(keys: Vec<StaticApiKey>) -> ApiKeysConfig {
    ApiKeysConfig {
        static_: keys,
        jwt: None,
    }
}

/// Create API keys config with static and JWT keys
pub fn test_api_keys_config_with_jwt(
    static_keys: Vec<StaticApiKey>,
    jwt_keys: Option<Vec<JwtApiKey>>,
) -> ApiKeysConfig {
    ApiKeysConfig {
        static_: static_keys,
        jwt: jwt_keys,
    }
}

/// Create a JWT API key for testing
pub fn test_jwt_key(id: &str, key: &str) -> JwtApiKey {
    JwtApiKey {
        id: id.to_string(),
        key: key.to_string(),
    }
}

/// Create a static API key for testing
pub fn test_api_key(id: Option<&str>, key: &str, upstreams: Option<Vec<String>>) -> StaticApiKey {
    StaticApiKey {
        id: id.map(|s| s.to_string()),
        key: key.to_string(),
        upstreams,
    }
}

/// Create a config with multiple upstreams for testing
pub fn create_multi_upstream_config(upstream_count: usize) -> (Config, Vec<String>) {
    let mut entries = Vec::new();
    let mut names = Vec::new();
    for i in 1..=upstream_count {
        let name = format!("upstream{}", i);
        names.push(name.clone());
        entries.push((
            name.clone(),
            test_upstream_entry(
                &format!("https://api{}.example.com", i),
                &format!("key{}", i),
            ),
        ));
    }
    let config = test_config(
        Some(UpstreamsConfig {
            request_timeout_ms: 30_000,
            upstreams: entries.into_iter().collect(),
        }),
        None,
    );
    (config, names)
}

/// Create a config with multiple API keys for testing
pub fn create_multi_api_key_config(key_count: usize, upstream_names: &[String]) -> Config {
    let mut keys = Vec::new();
    for i in 1..=key_count {
        keys.push(test_api_key(
            Some(&format!("key{}", i)),
            &format!("token{}", i),
            Some(upstream_names.to_vec()),
        ));
    }
    test_config(
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
                            &format!("upstream-key{}", idx + 1),
                        ),
                    )
                })
                .collect(),
        )),
        Some(test_api_keys_config(keys)),
    )
}

/// Assert that validation error contains specific reason
pub fn assert_validation_error_contains(
    result: Result<(), fluxgate::config::ValidationError>,
    expected_reason: &str,
) {
    let error = result.expect_err("validation should fail");
    assert!(
        error.reasons().iter().any(|r| r.contains(expected_reason)),
        "Expected error reason containing '{}', got: {:?}",
        expected_reason,
        error.reasons()
    );
}

/// Create a valid YAML config string for testing
#[allow(dead_code)]
pub fn create_yaml_config(
    bind_address: &str,
    max_connections: u32,
    upstreams: Option<&[(String, String, String, String)]>, // name, url, key, request_path
    api_keys: Option<&[(String, String, Option<Vec<String>>)]>,
) -> String {
    // Note: This function is kept for backward compatibility but is rarely used.
    // Consider using TestConfig from functional/common.rs for new tests.
    use yaml_fields;

    let mut yaml = format!(
        "{}: 1\n\n{}:\n  {}: \"{}\"\n  {}: {}\n",
        yaml_fields::VERSION,
        yaml_fields::SERVER,
        yaml_fields::BIND_ADDRESS,
        bind_address,
        yaml_fields::MAX_CONNECTIONS,
        max_connections
    );

    if let Some(upstreams_list) = upstreams {
        yaml.push_str(&format!("{}:\n", yaml_fields::UPSTREAMS));
        yaml.push_str(&format!("  {}: 30000\n", yaml_fields::REQUEST_TIMEOUT_MS));
        for (name, url, key, request_path) in upstreams_list {
            yaml.push_str(&format!("  {}:\n", name));
            yaml.push_str(&format!("    {}: \"{}\"\n", yaml_fields::TARGET_URL, url));
            yaml.push_str(&format!("    {}: \"{}\"\n", yaml_fields::API_KEY, key));
            yaml.push_str(&format!(
                "    {}: \"{}\"\n",
                yaml_fields::REQUEST_PATH,
                request_path
            ));
        }
    }

    if let Some(keys_list) = api_keys {
        yaml.push_str(&format!("{}:\n", yaml_fields::API_KEYS));
        yaml.push_str(&format!("  {}:\n", yaml_fields::STATIC));
        for (name, key, upstreams_opt) in keys_list {
            yaml.push_str(&format!("    - id: \"{}\"\n", name));
            yaml.push_str(&format!("      {}: \"{}\"\n", yaml_fields::API_KEY, key));
            if let Some(upstreams) = upstreams_opt {
                yaml.push_str(&format!("      {}:\n", yaml_fields::UPSTREAMS));
                for upstream in upstreams {
                    yaml.push_str(&format!("        - {}\n", upstream));
                }
            }
        }
    }

    yaml
}
