# Testing

## General

T1. All functional requirements must be covered by automated tests, including edge cases.

**Tags:** `testing`, `test-coverage`, `traceability`

T2. Overall automated test coverage must be maintained at or above 90%.

**Tags:** `testing`, `test-coverage`

## Unit Tests

UT1. Unit tests must live under `tests/unit/` and be implemented as Rust module tests. Unit tests MUST NOT be placed in
`src/` files using `#[cfg(test)] mod tests` blocks. All unit tests must be in separate files under the `tests/unit/`
directory, organized by functional area.

**Tags:** `testing`, `unit-tests`, `code-organization`

UT2. Prefer writing module tests when the required case can be covered by a module test.

**Tags:** `testing`, `unit-tests`

UT3. Each unit test must document its preconditions, the action performed, and the expected behaviour in the test
comments using the following format: Precondition, Action, Expected behavior, and Covers Requirements (listing the
requirement IDs covered by the test).

**Tags:** `testing`, `unit-tests`, `documentation`, `traceability`

UT4. Unit tests must not hardcode configuration structures (Config, ServerConfig, UpstreamEntry, etc.). Instead, tests
must use helper functions from `tests/unit/common.rs` to create test configurations. This ensures consistency,
maintainability, and reduces duplication. Available helpers include:

- `test_config(upstreams, api_keys)` - Create a test configuration with optional upstreams and API keys
- `test_server_config()` - Create a minimal valid server configuration
- `test_upstream_entry(target_url, api_key)` - Create an upstream entry for testing
- `test_upstreams_config(request_timeout_ms, entries)` - Create upstreams config with given entries
- `test_api_keys_config(keys)` - Create API keys config with given keys
- `test_api_key(id, key, upstreams)` - Create a static API key for testing
- `create_multi_upstream_config(count)` - Create a config with multiple upstreams
- `create_multi_api_key_config(key_count, upstream_names)` - Create a config with multiple API keys
- `minimal_test_config()` - Create a minimal test configuration with only server settings

See `tests/unit/common.rs` for the complete list of available test helpers and their usage.

**Tags:** `testing`, `unit-tests`, `code-organization`, `maintenance`

## Functional Tests

FT1. Functional tests must reside under `tests/functional/` and exercise the compiled executable end to end by invoking
the binary and asserting its behaviour.

**Tags:** `testing`, `functional-tests`, `code-organization`

FT2. Functional tests must spin up a mock HTTP server for the upstream. Through it, it must be verified that the proxy
sends requests as expected in the test and correctly responds to upstream responses.

**Tags:** `testing`, `functional-tests`

FT3. Functional tests must not be run directly with `cargo test --test functional`; they must be executed using Docker
instead.

**Tags:** `testing`, `functional-tests`, `deployment`

FT4. Test execution targets are defined in the `Makefile`: use `make test-unit` for unit tests and
`make test-functional` for functional tests.

**Tags:** `testing`, `build-system`

FT5. Each functional test must document its preconditions, the action performed, and the expected behaviour. This
documentation is provided in the tables within the requirements (see FT7).

**Tags:** `testing`, `functional-tests`, `documentation`, `traceability`

FT6. Each functional test must be documented in the requirements. All functional tests must be listed in the
requirements documentation (e.g., in `04-testing.md` under FT7 or in appropriate requirement sections) with their test
name, preconditions, actions, expected behavior, and covered requirements. This ensures traceability between tests and
requirements. **CRITICAL:** Every functional test function in `tests/functional/` (excluding helper functions) MUST be
present in the test tables in this document. Use the verification command in `docs/development/requirements/README.md`
to ensure all tests are documented.

**Tags:** `testing`, `functional-tests`, `documentation`, `traceability`

FT7. At minimum, the following tests must be present:

### Error Handling

| Test Name                                             | Precondition                                                  | Action                              | Expected behavior                                                       | Covers Requirements |
|-------------------------------------------------------|---------------------------------------------------------------|-------------------------------------|-------------------------------------------------------------------------|---------------------|
| `proxy_returns_properly_formatted_error_responses`    | Proxy configured without upstreams or with non-matching paths | Send request to proxy               | HTTP 503/404 returned with properly formatted response, not empty reply | F8, F10             |
| `proxy_rejects_connect_method_with_501`               | Valid config with upstreams and API keys                      | Send CONNECT request                | HTTP 501 returned                                                       | F14                 |
| `proxy_rejects_http_upgrade_with_501`                 | Valid config with upstreams and API keys                      | Send request with Upgrade header    | HTTP 501 returned                                                       | F14                 |
| `proxy_rejects_http_1_0_with_505`                     | Valid config with upstreams and API keys                      | Send HTTP/1.0 request               | HTTP 505 returned                                                       | F11                 |
| `proxy_handles_malformed_http_requests`               | Valid config with upstreams and API keys                      | Send malformed HTTP request         | Proper error response returned                                          | F6, F10             |
| `proxy_resists_http_request_smuggling`                | Valid config with upstreams and API keys                      | Send request with smuggling attempt | Request rejected or properly handled                                    | F6, F10             |
| `proxy_handles_upstream_connection_timeout`           | Valid config with upstreams, upstream unreachable             | Send request to proxy               | HTTP 502 or 503 returned after timeout                                  | F7, F9              |
| `proxy_handles_upstream_ssl_errors`                   | Valid config with upstreams, upstream has SSL issues          | Send request to proxy               | HTTP 502 returned                                                       | F7                  |
| `proxy_handles_different_timeout_values`              | Valid config with different timeout values                    | Send requests with various timeouts | Timeouts handled correctly                                              | F7, F9              |
| `proxy_returns_404_when_no_request_path_matches`      | Valid config with upstreams, request path doesn't match       | Send request with non-matching path | HTTP 404 returned                                                       | F8                  |
| `proxy_returns_bad_gateway_when_upstream_unreachable` | Valid config with upstreams, upstream unreachable             | Send request to proxy               | HTTP 502 returned                                                       | F7                  |
| `proxy_handles_invalid_requests`                      | Valid config with upstreams and API keys                      | Send invalid HTTP request           | Proper error response returned                                          | F6, F10             |

### Authentication & Authorization

| Test Name                                                        | Precondition                                                                                               | Action                                                                                   | Expected behavior                                                                                                                  | Covers Requirements            |
|------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------|--------------------------------|
| `proxy_authenticates_and_routes_to_permitted_upstream`           | Valid config with upstreams and API keys                                                                   | Send request with valid API key matching request_path                                    | Request proxied with Authorization replaced, routed to correct upstream                                                            | F1, F2.1, F2.2, F2.3, F2.4, F2.5 |
| `proxy_requires_authentication_header`                           | Valid config with upstreams and API keys                                                                   | Send request without Authorization header                                                | HTTP 401 returned                                                                                                                  | F3                             |
| `proxy_rejects_invalid_auth_token`                               | Valid config with upstreams and API keys                                                                   | Send request with unknown API key                                                        | HTTP 401 returned                                                                                                                  | F3                             |
| `proxy_rejects_api_key_without_upstream_access`                  | Valid config with upstreams and API keys                                                                   | Send request with API key without access                                                 | HTTP 401 returned                                                                                                                  | F3                             |
| `proxy_rejects_non_bearer_authentication_schemes`                | Valid config with upstreams and API keys                                                                   | Send request with non-Bearer auth scheme                                                 | HTTP 401 returned                                                                                                                  | F5                             |
| `proxy_rejects_api_key_with_empty_upstreams_list`                | Valid config with API key having empty upstreams list and no upstreams configured                          | Send request with API key                                                                | HTTP 401 returned                                                                                                                  | F3                             |
| `proxy_authenticates_with_valid_jwt_token`                       | Valid config with JWT keys and upstreams                                                                   | Send request with valid JWT token                                                        | Request proxied with Authorization replaced, routed to correct upstream                                                            | F17.1, F18, F19, F20, F21, F22 |
| `proxy_rejects_jwt_when_static_key_matches_first`                | Valid config with both static and JWT keys                                                                 | Send request with static key that matches configured static key                          | Static key authenticated first, request succeeds; JWT token works when static doesn't match                                        | F17.1                          |
| `proxy_rejects_expired_jwt_token`                                | Valid config with JWT keys and upstreams                                                                   | Send request with expired JWT token (exp in past)                                        | HTTP 401 returned                                                                                                                  | F23                            |
| `proxy_rejects_jwt_token_without_upstreams`                      | Valid config with JWT keys but no upstreams                                                                | Send request with valid JWT token                                                        | HTTP 401 returned                                                                                                                  | F3                             |
| `proxy_rejects_jwt_token_with_invalid_signature`                 | Valid config with JWT keys and upstreams                                                                   | Send request with JWT token signed with wrong secret                                     | HTTP 401 returned                                                                                                                  | F22                            |
| `proxy_routes_jwt_authenticated_requests_by_path`                | Valid config with multiple upstreams and JWT keys, valid JWT token created                                 | Send requests with valid JWT token to different request paths                            | Requests routed to correct upstreams based on path matching, all requests proxied successfully                                     | F2.1, F2.2, F2.3, F2.4, F2.5, F18                        |
| `proxy_selects_longest_matching_path_for_jwt_requests`           | Valid config with multiple upstreams having overlapping paths and JWT keys                                 | Send request with valid JWT token to path matching multiple upstreams                    | Longest matching path selected, request routed to correct upstream                                                                 | F2.2, F2.3, F18                        |
| `proxy_preserves_request_details_for_jwt_authenticated_requests` | Valid config with upstreams and JWT keys, valid JWT token created                                          | Send POST request with valid JWT token, custom headers, and body                         | Request method, headers, and body preserved in proxied request, Authorization header replaced                                      | F1, F2.1, F2.2, F2.4, F2.5, F18                    |
| `proxy_rejects_jwt_token_when_path_doesnt_match`                 | Valid config with upstreams and JWT keys, valid JWT token created, request path doesn't match any upstream | Send request with valid JWT token to non-matching path                                   | Request rejected with HTTP 404 (path not found), upstream does not receive request                                                 | F3, F18                        |
| `proxy_handles_jwt_token_that_looks_like_static_key`             | Valid config with both static keys and JWT keys, JWT token created that doesn't match static key           | Send request with JWT token that doesn't match any static key                            | Static key check fails, JWT validation succeeds, request proxied successfully                                                      | F17.1                          |
| `proxy_handles_concurrent_jwt_authenticated_requests`            | Valid config with upstreams and JWT keys, valid JWT token created                                          | Send 10 concurrent requests with valid JWT token                                         | All requests handled correctly, all proxied to upstream successfully                                                               | F2.1, F2.2, F2.4, F2.5, F18                        |
| `proxy_logs_jwt_key_id_in_request_logs`                          | Valid config with upstreams and JWT keys, valid JWT token created, proxy started with trace log level      | Send request with valid JWT token                                                        | JWT key id appears in request logs, request proxied successfully                                                                   | F2.1, F2.2, F2.4, F2.5, F18, O6                    |
| `proxy_handles_different_http_methods_with_jwt`                  | Valid config with upstreams and JWT keys, valid JWT token created                                          | Send requests with valid JWT token using different HTTP methods (GET, POST, PUT, DELETE) | All HTTP methods handled correctly, all requests proxied to upstream successfully                                                  | F2.1, F2.2, F2.4, F2.5, F18                        |
| `proxy_handles_jwt_authentication_with_query_parameters`         | Valid config with upstreams and JWT keys, valid JWT token created                                          | Send request with valid JWT token to URL with query parameters                           | Query parameters preserved in proxied request, request proxied successfully                                                        | F2.1, F2.2, F2.4, F2.5, F18                        |
| `proxy_handles_jwt_authentication_with_large_request_body`       | Valid config with upstreams and JWT keys, valid JWT token created                                          | Send POST request with valid JWT token and large request body (10KB)                     | Large body handled correctly, request proxied to upstream successfully                                                             | F2.1, F2.2, F2.4, F2.5, F18                        |
| `proxy_handles_jwt_authentication_with_streaming_response`       | Valid config with upstreams and JWT keys, valid JWT token created                                          | Send request with valid JWT token and read streaming response                            | Streaming response handled correctly, request proxied and response streamed successfully                                           | F2.1, F2.2, F2.4, F2.5, F18                        |
| `proxy_prioritizes_static_keys_over_jwt_when_both_configured`    | Valid config with both static keys and JWT keys, valid JWT token created                                   | Send requests with static key and with JWT token separately                              | Static key authenticated first when matches, JWT token authenticated when static doesn't match, both requests proxied successfully | F17.1, F18                     |

### Configuration Logging

| Test Name                                                                                     | Precondition                                                              | Action                                                                      | Expected behavior                                                                                                                                                                        | Covers Requirements |
|-----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------|-----------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------|
| `proxy_logs_single_warning_message_when_config_file_missing_at_startup`                       | Configuration file does not exist at expected path                        | Start proxy without configuration file                                      | Single WARNING-level message with structured fields logged; no duplicate messages                                                                                                        | F15                 |
| `proxy_logs_warning_only_once_when_config_file_missing_during_polling`                        | Proxy running with valid config file, then file is deleted                | Delete configuration file and wait for multiple polling cycles              | Single WARNING-level message logged; no log spam for persistent error condition                                                                                                          | F16                 |
| `proxy_logs_warning_again_when_config_file_becomes_accessible_then_inaccessible`              | Proxy running, configuration file is missing                              | Create config file, wait for detection, then delete it again                | WARNING logged when file first missing, stops when available, logs again when missing again                                                                                              | F16                 |
| `proxy_does_not_log_warning_when_config_file_missing_during_polling_if_started_with_defaults` | Configuration file does not exist at expected path                        | Start proxy without configuration file and wait for multiple polling cycles | Single WARNING-level message at startup; no WARNING messages during polling when file is still missing                                                                                   | F17                 |
| `proxy_does_not_log_false_positive_reload_when_config_file_unchanged`                         | Proxy started with valid configuration file                               | Wait for multiple polling cycles without modifying the configuration file   | No "Configuration file changed, reloaded automatically" messages logged when file is unchanged                                                                                           | C17                 |
| `proxy_logs_misleading_message_when_config_file_deleted_after_being_added`                    | Configuration file does not exist at startup, then is added, then deleted | Start proxy without config file, add config file, then delete it            | Warning message "continuing with last valid configuration" is logged when file is deleted; test documents whether message accurately reflects behavior (using loaded config vs defaults) | F16, F17            |

### Hot Reload

| Test Name                                                           | Precondition                                          | Action                                                        | Expected behavior                                                                                                                                                               | Covers Requirements |
|---------------------------------------------------------------------|-------------------------------------------------------|---------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------|
| `proxy_restarts_on_different_port_when_bind_address_changes`        | Proxy running with initial bind_address configuration | Modify bind_address in configuration file to a different port | Proxy automatically detects the change, gracefully shuts down the old server, and starts listening on the new port. Old port becomes unavailable, new port accepts connections. | C3                  |
| `proxy_applies_hot_reload_when_configuration_file_changes`          | Proxy running with valid configuration file           | Modify configuration file                                     | Proxy detects change and applies new configuration                                                                                                                              | C3, C6, C9          |
| `proxy_configuration_watcher_detects_file_modifications_by_content` | Proxy running with valid configuration file           | Modify configuration file content                             | Proxy detects change by content, not just mtime                                                                                                                                 | C6, C9              |
| `proxy_detects_config_changes_immediately_on_file_modification`     | Proxy running with valid configuration file           | Modify configuration file                                     | Proxy detects change immediately                                                                                                                                                | C6, C9              |
| `proxy_detects_config_changes_on_file_overwrite`                    | Proxy running with valid configuration file           | Overwrite configuration file                                  | Proxy detects change on file overwrite                                                                                                                                          | C6, C9              |
| `proxy_detects_config_changes_on_atomic_file_write`                 | Proxy running with valid configuration file           | Atomically write new configuration file                       | Proxy detects change on atomic write                                                                                                                                            | C6, C9              |
| `proxy_detects_config_when_file_recreated_with_same_name`           | Proxy running, configuration file deleted             | Recreate configuration file with same name                    | Proxy detects new file and loads configuration                                                                                                                                  | C6, C9              |
| `proxy_retains_previous_config_when_invalid_hot_reload_detected`    | Proxy running with valid configuration                | Write invalid configuration to trigger reload                 | Proxy retains previous valid configuration                                                                                                                                      | C10                 |
| `new_requests_use_new_config_after_successful_reload`               | Proxy running, configuration changed                  | Send request after successful reload                          | Request uses new configuration                                                                                                                                                  | C3, C6              |
| `requests_during_reload_use_appropriate_config`                     | Proxy running, configuration being reloaded           | Send request during reload                                    | Request uses appropriate configuration (old or new)                                                                                                                             | C3, C6              |
| `reload_with_partial_configuration_changes`                         | Proxy running with valid configuration                | Change only part of configuration                             | Proxy applies partial changes correctly                                                                                                                                         | C3, C6              |
| `active_connections_persist_through_successful_reload`              | Proxy running with active connections                 | Reload configuration successfully                             | Active connections continue to work                                                                                                                                             | C3, C11             |
| `active_connections_persist_through_failed_reload`                  | Proxy running with active connections                 | Attempt invalid reload                                        | Active connections continue to work with previous config                                                                                                                        | C10, C11            |
| `reload_is_atomic_during_concurrent_requests`                       | Proxy running, concurrent requests in progress        | Reload configuration                                          | Reload is atomic, no partial state visible                                                                                                                                      | C3, C11             |
| `reload_logs_successful_configuration_change_at_info_level`         | Proxy running with valid configuration                | Successfully reload configuration                             | INFO-level log message with structured fields                                                                                                                                   | C12                 |
| `reload_logs_failed_configuration_change_at_info_level`             | Proxy running with valid configuration                | Attempt invalid reload                                        | INFO-level log message for failed reload                                                                                                                                        | C12                 |
| `reload_logs_include_timestamp_and_outcome`                         | Proxy running with valid configuration                | Reload configuration (success or failure)                     | Log messages include timestamp and outcome                                                                                                                                      | C12                 |
| `reload_logs_successful_change_with_structured_fields`              | Proxy running with valid configuration                | Successfully reload configuration                             | Log includes structured fields (timestamp, outcome, path)                                                                                                                       | C12                 |
| `reload_logs_failed_change_with_structured_fields`                  | Proxy running with valid configuration                | Attempt invalid reload                                        | Log includes structured fields for failure                                                                                                                                      | C12                 |
| `proxy_handles_config_file_deletion_during_runtime`                 | Proxy running with valid configuration file           | Delete configuration file                                     | Proxy handles deletion gracefully, retains last valid config                                                                                                                    | C6, C10             |
| `proxy_handles_config_file_permission_denied`                       | Proxy running, file permissions changed               | Attempt to reload when file not readable                      | Proxy handles permission error gracefully                                                                                                                                       | C6, C10             |
| `proxy_handles_config_file_renamed_during_runtime`                  | Proxy running with valid configuration file           | Rename configuration file                                     | Proxy handles rename gracefully                                                                                                                                                 | C6, C10             |
| `proxy_handles_file_content_unchanged_but_mtime_modified`           | Proxy running with valid configuration file           | Modify file mtime without changing content                    | Proxy does not trigger false positive reload                                                                                                                                    | C6, C9              |
| `proxy_handles_partially_written_file_during_reload`                | Proxy running with valid configuration file           | Partially write configuration file during reload              | Proxy handles partial write gracefully                                                                                                                                          | C6, C10             |
| `proxy_rejects_malformed_file_during_active_write`                  | Proxy running with valid configuration file           | Write malformed YAML during active write                      | Proxy rejects malformed file, retains previous config                                                                                                                           | C6, C10             |
| `proxy_handles_config_file_become_too_large`                        | Proxy running with valid configuration file           | Make configuration file exceed size limits                    | Proxy handles large file gracefully or rejects it                                                                                                                               | C6, C10             |
| `proxy_handles_symlink_config_file_changes`                         | Proxy running with symlinked configuration file       | Modify symlink target                                         | Proxy detects changes through symlink                                                                                                                                           | C6, C9              |
| `proxy_handles_file_lock_during_config_read`                        | Proxy running with valid configuration file           | Lock configuration file during read                           | Proxy handles file lock gracefully                                                                                                                                              | C6, C10             |
| `proxy_handles_io_errors_during_config_file_read`                   | Proxy running with valid configuration file           | Cause IO error during config read                             | Proxy handles IO error gracefully                                                                                                                                               | C6, C10             |
| `proxy_handles_transient_file_access_errors`                        | Proxy running with valid configuration file           | Cause transient file access errors                            | Proxy handles transient errors gracefully                                                                                                                                       | C6, C10             |
| `proxy_handles_file_system_full_during_reload`                      | Proxy running with valid configuration file           | Fill filesystem during reload                                 | Proxy handles filesystem full error gracefully                                                                                                                                  | C6, C10             |
| `proxy_handles_concurrent_reload_attempts_atomically`               | Proxy running with valid configuration file           | Trigger multiple concurrent reloads                           | Reloads are handled atomically                                                                                                                                                  | C3, C11             |
| `proxy_handles_multiple_rapid_config_changes`                       | Proxy running with valid configuration file           | Make multiple rapid configuration changes                     | Proxy handles rapid changes correctly                                                                                                                                           | C3, C6              |
| `proxy_recovers_config_when_file_restored_after_deletion`           | Proxy running, configuration file deleted             | Restore configuration file                                    | Proxy recovers and loads restored configuration                                                                                                                                 | C6, C10             |
| `proxy_recovers_config_when_file_permissions_restored`              | Proxy running, file permissions denied                | Restore file permissions                                      | Proxy recovers and loads configuration                                                                                                                                          | C6, C10             |

### Observability

| Test Name                                                                           | Precondition                                            | Action                                           | Expected behavior                                                 | Covers Requirements |
|-------------------------------------------------------------------------------------|---------------------------------------------------------|--------------------------------------------------|-------------------------------------------------------------------|---------------------|
| `proxy_logs_binding_failure_at_warning_level`                                       | First proxy is already running on a port                | Attempt to start a second proxy on the same port | Second proxy logs binding failure at WARNING level (O4) and exits | O4                  |
| `proxy_logs_api_key_names_for_observability`                                        | Valid config with upstreams and API keys                | Send authenticated request                       | API key id appears in logs                                        | O5, O6              |
| `proxy_process_starts_http_server`                                                  | Valid configuration file present                        | Start proxy with configuration                   | Proxy starts HTTP server and outputs listening message            | O1                  |
| `proxy_logs_warning_with_structured_fields_when_config_file_missing_during_polling` | Proxy running with valid config file, then file deleted | Delete configuration file and wait for polling   | WARNING logged with structured fields (timestamp, path, error)    | F16                 |
| `proxy_logs_detailed_errors_during_shutdown`                                        | Proxy running with active connections                   | Shutdown proxy                                   | Detailed errors logged during shutdown                            | O8                  |

### Configuration Loading

| Test Name                                                        | Precondition                                                                        | Action                                                             | Expected behavior                                                                                        | Covers Requirements |
|------------------------------------------------------------------|-------------------------------------------------------------------------------------|--------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|---------------------|
| `proxy_loads_configuration_with_multiple_upstreams_and_api_keys` | YAML configuration file with multiple upstreams and API keys                        | Start proxy with configuration file                                | Proxy loads all upstreams and API keys correctly                                                         | C1, C4              |
| `proxy_handles_missing_configuration_file_with_defaults`         | Configuration file does not exist at expected path                                  | Start proxy without configuration file                             | Proxy uses default configuration                                                                         | C1, C4              |
| `proxy_handles_configuration_validation_errors_gracefully`       | Configuration file with validation errors                                           | Start proxy with invalid configuration                             | Proxy handles validation errors gracefully                                                               | C2, C4              |
| `proxy_configuration_supports_ipv6_bind_addresses`               | Configuration file with IPv6 bind address                                           | Start proxy with IPv6 bind address                                 | Proxy starts successfully with IPv6 address                                                              | C1                  |
| `proxy_configuration_handles_empty_and_whitespace_only_values`   | Configuration file with empty or whitespace-only values                             | Start proxy with such configuration                                | Proxy handles empty/whitespace values correctly                                                          | C1, C2              |
| `proxy_configuration_handles_unknown_configuration_sections`     | Configuration file with unknown sections                                            | Start proxy with unknown sections                                  | Proxy ignores unknown sections or handles gracefully                                                     | C1                  |
| `proxy_configuration_handles_config_file_with_only_comments`     | Configuration file containing only comments                                         | Start proxy with comment-only file                                 | Proxy handles comment-only file correctly                                                                | C1                  |
| `proxy_configuration_handles_config_file_with_bom`               | Configuration file with BOM (Byte Order Mark)                                       | Start proxy with BOM file                                          | Proxy handles BOM correctly                                                                              | C1                  |
| `proxy_loads_config_with_omitted_optional_server_fields`         | Configuration file with server section but bind_address and max_connections omitted | Start proxy with configuration file missing optional server fields | Proxy starts successfully using default values (0.0.0.0:8080 for bind_address, 1024 for max_connections) | C1, C4, C8          |
| `proxy_loads_config_with_omitted_request_timeout_ms`             | Configuration file with upstreams section but request_timeout_ms omitted            | Start proxy and make request to upstream                           | Proxy uses default timeout (120000ms) for upstream requests and successfully proxies requests            | C1, C4, C8, F9      |

### Configuration Validation

| Test Name                                                                   | Precondition                                                        | Action                                             | Expected behavior                              | Covers Requirements |
|-----------------------------------------------------------------------------|---------------------------------------------------------------------|----------------------------------------------------|------------------------------------------------|---------------------|
| `proxy_configuration_validates_missing_required_upstream_fields`            | Configuration file with upstream missing required fields            | Start proxy with incomplete upstream configuration | Validation fails with appropriate errors       | C2, C15             |
| `proxy_configuration_validates_empty_upstream_definitions`                  | Configuration file with empty upstream definitions                  | Start proxy with empty upstream definitions        | Validation fails or handles gracefully         | C2, C15             |
| `proxy_configuration_validates_invalid_upstream_urls`                       | Configuration file with invalid upstream URLs                       | Start proxy with invalid URLs                      | Validation fails with appropriate errors       | C2, C15             |
| `proxy_configuration_validates_empty_api_key_values`                        | Configuration file with empty API key values                        | Start proxy with empty API key values              | Validation fails with appropriate errors       | C2, C16             |
| `proxy_configuration_validates_duplicate_api_key_ids`                       | Configuration file with duplicate API key IDs                       | Start proxy with duplicate IDs                     | Validation fails with appropriate errors       | C2, C16             |
| `proxy_configuration_validates_duplicate_api_key_values`                    | Configuration file with duplicate API key values                    | Start proxy with duplicate key values              | Validation fails with appropriate errors       | C2, C16             |
| `proxy_configuration_validates_empty_api_key_names`                         | Configuration file with empty API key names                         | Start proxy with empty API key names               | Validation fails with appropriate errors       | C2, C16             |
| `proxy_configuration_validates_api_keys_referencing_non_existent_upstreams` | Configuration file with API keys referencing non-existent upstreams | Start proxy with invalid upstream references       | Validation fails with appropriate errors       | C2, C15, C16        |
| `proxy_configuration_validates_invalid_server_bind_address`                 | Configuration file with invalid bind address                        | Start proxy with invalid bind address              | Validation fails with appropriate errors       | C2                  |
| `proxy_configuration_validates_invalid_max_connections_value`               | Configuration file with invalid max_connections value               | Start proxy with invalid max_connections           | Validation fails with appropriate errors       | C2                  |
| `proxy_configuration_validates_nested_upstream_structures`                  | Configuration file with nested upstream structures                  | Start proxy with nested structures                 | Validation handles nested structures correctly | C2, C15             |
| `proxy_configuration_validates_array_values_where_scalars_expected`         | Configuration file with array values where scalars expected         | Start proxy with incorrect value types             | Validation fails with appropriate errors       | C2                  |
| `proxy_configuration_validates_scalar_values_where_arrays_expected`         | Configuration file with scalar values where arrays expected         | Start proxy with incorrect value types             | Validation fails with appropriate errors       | C2                  |
| `proxy_configuration_validates_url_schemes_and_rejects_unsupported_ones`    | Configuration file with unsupported URL schemes                     | Start proxy with unsupported schemes               | Validation fails with appropriate errors       | C2, C15             |
| `proxy_configuration_validates_missing_or_invalid_version`                  | Configuration file with missing or invalid version                  | Start proxy with invalid version                   | Validation fails with appropriate errors       | C2                  |
| `proxy_configuration_validates_missing_request_path`                        | Configuration file with missing request_path                        | Start proxy with missing request_path              | Validation fails with appropriate errors       | C2, C15             |
| `proxy_configuration_validates_empty_request_path`                          | Configuration file with empty request_path                          | Start proxy with empty request_path                | Validation fails with appropriate errors       | C2, C15             |
| `proxy_configuration_validates_invalid_request_path_format`                 | Configuration file with invalid request_path format                 | Start proxy with invalid request_path format       | Validation fails with appropriate errors       | C2, C15             |
| `proxy_configuration_validates_duplicate_request_path`                      | Configuration file with duplicate request_paths                     | Start proxy with duplicate request_paths           | Validation fails with appropriate errors       | C2, C15             |

### Configuration Edge Cases

| Test Name                                             | Precondition                                      | Action                             | Expected behavior                             | Covers Requirements |
|-------------------------------------------------------|---------------------------------------------------|------------------------------------|-----------------------------------------------|---------------------|
| `proxy_configuration_handles_very_large_config_files` | Configuration file is very large (10MB+)          | Start proxy with large config file | Proxy starts successfully or fails gracefully | C1                  |
| `proxy_configuration_handles_trailing_spaces`         | Configuration file with trailing spaces in values | Start proxy with trailing spaces   | Proxy handles trailing spaces correctly       | C1                  |
| `proxy_configuration_handles_very_long_lines`         | Configuration file with very long lines           | Start proxy with long lines        | Proxy handles long lines correctly            | C1                  |
| `proxy_configuration_handles_crlf_line_endings`       | Configuration file with CRLF line endings         | Start proxy with CRLF file         | Proxy handles CRLF line endings correctly     | C1                  |

### Proxy Flow

| Test Name                                                      | Precondition                                                          | Action                                               | Expected behavior                                                    | Covers Requirements |
|----------------------------------------------------------------|-----------------------------------------------------------------------|------------------------------------------------------|----------------------------------------------------------------------|---------------------|
| `proxy_forwards_requests_transparently`                        | Valid config with upstreams and API keys                              | Send request to proxy                                | Request forwarded transparently with method, headers, body preserved | F1, F4              |
| `proxy_forwards_upstream_response_headers`                     | Valid config with upstreams and API keys                              | Send request, upstream returns response with headers | Response headers forwarded correctly                                 | F1, F4              |
| `proxy_preserves_request_fields_except_authorization_and_host` | Valid config with upstreams and API keys                              | Send request with various fields                     | Request fields preserved except Authorization and Host               | F1, F4              |
| `proxy_routes_requests_by_request_path`                        | Valid config with multiple upstreams and different request_paths      | Send requests with different paths                   | Requests routed to correct upstreams based on request_path           | F1, F2              |
| `proxy_selects_longest_matching_request_path`                  | Valid config with overlapping request_paths                           | Send request matching multiple paths                 | Longest matching path selected                                       | F1, F2              |
| `proxy_sets_host_header_from_upstream_target_url`              | Valid config with upstreams and API keys                              | Send request to proxy                                | Host header set from upstream target_url                             | F1, F4              |
| `proxy_sets_host_header_with_non_standard_port`                | Valid config with upstream having non-standard port                   | Send request to proxy                                | Host header includes non-standard port                               | F1, F4              |
| `proxy_omits_authorization_when_api_key_missing`               | Valid config with upstreams, upstream has no api_key                  | Send request to proxy                                | Authorization header omitted when forwarding                         | F1, F4              |
| `proxy_handles_trailing_slash_in_request_path_matching`        | Valid config with upstreams, request_path with/without trailing slash | Send requests with and without trailing slash        | Path matching handles trailing slash correctly                       | F1, F2              |
| `proxy_handles_upstream_errors`                                | Valid config with upstreams, upstream returns error                   | Send request, upstream returns error                 | Upstream error handled correctly                                     | F1, F7              |

### Resilience

| Test Name                                           | Precondition                                            | Action                                  | Expected behavior                                            | Covers Requirements |
|-----------------------------------------------------|---------------------------------------------------------|-----------------------------------------|--------------------------------------------------------------|---------------------|
| `proxy_enforces_max_connections_limit`              | Valid config with max_connections limit                 | Send requests exceeding limit           | Connection limit enforced, excess requests handled correctly | P2, P3              |
| `proxy_handles_concurrent_requests_efficiently`     | Valid config with upstreams and API keys                | Send multiple concurrent requests       | Concurrent requests handled efficiently                      | P1, P2              |
| `proxy_maintains_connection_limits_during_recovery` | Valid config with connection limits, upstream recovers  | Send requests during upstream recovery  | Connection limits maintained during recovery                 | P2, P3              |
| `proxy_maintains_throughput_under_load`             | Valid config with upstreams and API keys                | Send high load of requests              | Throughput maintained under load                             | P1, P2              |
| `proxy_multiplexes_outgoing_connections`            | Valid config with upstreams and API keys                | Send multiple requests to same upstream | Connections multiplexed efficiently                          | P1, P2              |
| `proxy_recovers_from_upstream_temporary_failure`    | Valid config with upstreams, upstream temporarily fails | Send requests during and after failure  | Proxy recovers when upstream becomes available               | F7                  |
| `proxy_recovers_from_high_load_periods`             | Valid config with upstreams and API keys                | Send high load, then normal load        | Proxy recovers from high load periods                        | P1, P2              |
| `proxy_handles_partial_upstream_recovery`           | Valid config with multiple upstreams, one recovers      | Send requests during partial recovery   | Partial recovery handled correctly                           | F7                  |
| `proxy_handles_memory_pressure_gracefully`          | Valid config with upstreams and API keys                | Send requests causing memory pressure   | Memory pressure handled gracefully                           | P3                  |

### Shutdown

| Test Name                                | Precondition                          | Action              | Expected behavior                                       | Covers Requirements |
|------------------------------------------|---------------------------------------|---------------------|---------------------------------------------------------|---------------------|
| `proxy_gracefully_shuts_down_on_sigterm` | Proxy running with active connections | Send SIGTERM signal | Proxy shuts down gracefully, active connections handled | OP1                 |
| `proxy_handles_sigint_interrupt`         | Proxy running with active connections | Send SIGINT signal  | Proxy handles SIGINT gracefully                         | OP1                 |

### CLI

| Test Name                                                | Precondition                                   | Action                                                     | Expected behavior                               | Covers Requirements |
|----------------------------------------------------------|------------------------------------------------|------------------------------------------------------------|-------------------------------------------------|---------------------|
| `help_flag_succeeds_without_configuration`               | No configuration file present                  | Run proxy with --help flag                                 | Help message displayed                          | CLI1                |
| `help_output_lists_subcommands_and_flags`                | No configuration file present                  | Run proxy with --help flag                                 | Help output lists all subcommands and flags     | CLI1                |
| `run_with_explicit_config_path`                          | Valid configuration file at specified path     | Run proxy with --config flag pointing to valid file        | Proxy starts with specified configuration       | CLI2                |
| `run_with_relative_config_path`                          | Valid configuration file at relative path      | Run proxy with --config flag pointing to relative path     | Proxy starts with relative path configuration   | CLI2                |
| `run_with_invalid_config_path`                           | Invalid configuration file at specified path   | Run proxy with --config flag pointing to invalid file      | Proxy handles invalid config gracefully         | CLI2                |
| `run_with_non_existent_config_path`                      | Non-existent configuration file path           | Run proxy with --config flag pointing to non-existent file | Proxy handles missing config gracefully         | CLI2                |
| `run_with_directory_as_config_path`                      | Directory path instead of file path            | Run proxy with --config flag pointing to directory         | Proxy handles directory path gracefully         | CLI2                |
| `run_without_arguments_uses_default_config`              | Default configuration file present             | Run proxy without arguments                                | Proxy uses default configuration file           | CLI2                |
| `run_with_config_flag_without_path`                      | No configuration file specified                | Run proxy with --config flag but no path                   | Proxy handles missing path gracefully           | CLI2                |
| `ignores_environment_configuration_override`             | Environment variables set, config file present | Run proxy with config file                                 | Proxy uses config file, ignores environment     | CLI3                |
| `logging_defaults_to_info_without_environment_overrides` | No environment variables set                   | Run proxy                                                  | INFO-level messages are visible (default log level is TRACE, which includes INFO) | CLI4, O1            |
| `logging_respects_fluxgate_log_directive`                | FLUXGATE_LOG environment variable set          | Run proxy                                                  | Logging respects FLUXGATE_LOG directive         | CLI4                |
| `logging_respects_fluxgate_log_style_setting`            | FLUXGATE_LOG_STYLE environment variable set    | Run proxy                                                  | Logging respects FLUXGATE_LOG_STYLE setting     | CLI4                |
| `unknown_option_is_rejected`                             | Invalid command-line option                    | Run proxy with unknown option                              | Proxy rejects unknown option with error message | CLI1                |

Additional functional tests must cover all functional requirements (F1, F2.1-F2.5, F3-F24) as specified in `02-functional.md`,
including but not limited to configuration loading, validation, hot reloading, CLI configuration override, request
processing, error handling, JWT token authentication (F18-F24), performance, observability, shutdown, and recovery
scenarios.

All functional tests are organized by category in the following test files (per FT5, all tests must be documented):

- **`auth.rs`**: Tests for authentication and authorization (F2.1-F2.5, F3, F5), including API key validation, Bearer token
  scheme validation, and upstream access control.
- **`cli.rs`**: Tests for command-line interface (CLI1-CLI4), including config path override, help flag, and
  default behavior.
- **`config_loading.rs`**: Tests for configuration file loading (C1, C4, C17, F15, F16, F17), including default
  configuration fallback, startup behavior, false positive reload prevention, and accurate logging when config file is
  deleted after being loaded.
- **`config_validation.rs`**: Tests for configuration validation (C2, C15, C16), including request_path validation,
  API key uniqueness (duplicate keys, duplicate ids, empty ids when specified).
- **`config_edge.rs`**: Tests for edge cases in configuration handling, including long keys, special characters, and
  boundary conditions.
- **`error_handling.rs`**: Tests for error responses (F6, F7, F8, F9, F10, F11, F12, F14), including HTTP status codes,
  malformed requests, timeouts, SSL errors, and properly formatted error responses.
- **`hot_reload.rs`**: Tests for configuration hot-reloading (C3, C6, C9, C10, C11, C12, C13, C14, F16), including
  file monitoring, atomic updates, error handling during reload, and bind_address changes triggering server restart.
- **`observability.rs`**: Tests for logging and observability (O1-O8), including log levels, structured fields,
  sensitive data exclusion, and binding failure logging.
- **`proxy_flow.rs`**: Tests for request forwarding (F1, F4, F13), including method preservation, header handling, and
  streaming behavior.
- **`resilience.rs`**: Tests for proxy resilience and performance (P1, P2, P3, P4), including connection limits,
  concurrent requests, and resource management.
- **`shutdown.rs`**: Tests for graceful shutdown (OP1), including signal handling and connection cleanup.

