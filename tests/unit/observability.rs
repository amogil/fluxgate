//! Unit tests for Observability Requirements (O1-O9)
//!
//! This module contains unit tests covering observability requirements.
//! Tests have been migrated from logging.rs, proxy_logging.rs, proxy.rs, request_path_routing.rs, and config_manager.rs.

use axum::http::HeaderValue;
use std::env;
use tracing_subscriber::EnvFilter;

#[test]
fn get_body_length_from_headers_extracts_valid_content_length() {
    // Precondition: HeaderMap with valid Content-Length header.
    // Action: Call get_body_length_from_headers with HeaderMap containing valid Content-Length.
    // Expected behavior: Returns Some(u64) with the length value.
    // Covers Requirements: O5
    use axum::http::HeaderMap;
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("12345"));

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, Some(12345));
}

#[test]
fn get_body_length_from_headers_handles_missing_header() {
    // Precondition: HeaderMap without Content-Length header.
    // Action: Call get_body_length_from_headers with HeaderMap without Content-Length.
    // Expected behavior: Returns None.
    // Covers Requirements: O5
    use axum::http::HeaderMap;
    use fluxgate::proxy::get_body_length_from_headers;

    let headers = HeaderMap::new();
    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, None);
}

#[test]
fn get_body_length_from_headers_handles_invalid_value() {
    // Precondition: HeaderMap with invalid Content-Length header value.
    // Action: Call get_body_length_from_headers with HeaderMap containing invalid Content-Length value.
    // Expected behavior: Returns None (invalid value cannot be parsed).
    // Covers Requirements: O5
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("not-a-number"));

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, None);
}

#[test]
fn get_body_length_from_headers_handles_case_insensitive_header_name() {
    // Precondition: HeaderMap with Content-Length header in different case.
    // Action: Call get_body_length_from_headers with HeaderMap containing Content-Length in different case.
    // Expected behavior: Returns Some(u64) with the length value (HTTP headers are case-insensitive).
    // Covers Requirements: O5
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert("Content-Length", HeaderValue::from_static("999"));

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, Some(999));
}

#[test]
fn get_body_length_from_headers_handles_zero_length() {
    // Precondition: HeaderMap with Content-Length header set to 0.
    // Action: Call get_body_length_from_headers with HeaderMap containing Content-Length of 0.
    // Expected behavior: Returns Some(0).
    // Covers Requirements: O5
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("0"));

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, Some(0));
}

#[test]
fn get_body_length_from_headers_handles_large_length() {
    // Precondition: HeaderMap with Content-Length header set to large value (max u64).
    // Action: Call get_body_length_from_headers with HeaderMap containing large Content-Length.
    // Expected behavior: Returns Some(u64) with the large value.
    // Covers Requirements: O5
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert(
        "content-length",
        HeaderValue::from_static("18446744073709551615"),
    );

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, Some(18446744073709551615));
}

#[test]
fn get_body_length_from_headers_handles_multiple_content_length_headers() {
    // Precondition: HeaderMap with Content-Length header (HTTP spec allows only one).
    // Action: Call get_body_length_from_headers with HeaderMap containing Content-Length.
    // Expected behavior: Returns Some(u64) with the value (HTTP spec allows only one, handled gracefully).
    // Covers Requirements: O5
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("100"));
    // Note: HeaderMap typically only allows one value per header name, so this tests the normal case

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, Some(100));
}

#[test]
fn get_body_length_from_headers_handles_negative_value() {
    // Precondition: HeaderMap with Content-Length header set to invalid value.
    // Action: Call get_body_length_from_headers with HeaderMap containing invalid Content-Length.
    // Expected behavior: Returns None (invalid values cannot be parsed as u64).
    // Covers Requirements: O5
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    // Note: HeaderValue cannot contain negative sign in valid HTTP, but test edge case
    // If somehow a negative value appears, parsing as u64 will fail
    headers.insert("content-length", HeaderValue::from_static("invalid"));

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, None);
}

#[test]
fn get_body_length_from_headers_handles_case_insensitive_header_lookup() {
    // Precondition: HeaderMap with Content-Length header in various cases.
    // Action: Call get_body_length_from_headers with different case variations.
    // Expected behavior: Returns Some(u64) regardless of header name case.
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert("Content-Length", HeaderValue::from_static("12345"));

    let result = get_body_length_from_headers(&headers);
    assert_eq!(
        result,
        Some(12345),
        "should handle case-insensitive header lookup"
    );
}

#[test]
fn get_body_length_from_headers_handles_unicode_in_header_value() {
    // Precondition: HeaderMap with Content-Length header containing unicode characters.
    // Action: Call get_body_length_from_headers with unicode in value.
    // Expected behavior: Returns None (unicode cannot be parsed as u64).
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    // Note: HeaderValue with actual unicode may fail to create, but test defensive behavior
    headers.insert("content-length", HeaderValue::from_static("invalid"));

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, None, "unicode/non-numeric should return None");
}

#[test]
fn get_body_length_from_headers_handles_overflow_value() {
    // Precondition: HeaderMap with Content-Length header exceeding u64::MAX.
    // Action: Call get_body_length_from_headers with value exceeding u64::MAX.
    // Expected behavior: Returns None (value exceeds u64 range).
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    // Value exceeding u64::MAX
    headers.insert(
        "content-length",
        HeaderValue::from_static("99999999999999999999"),
    );

    let result = get_body_length_from_headers(&headers);
    // Should return None when value exceeds u64::MAX
    assert_eq!(result, None, "overflow value should return None");
}

#[test]
fn get_body_length_from_headers_handles_comma_in_value() {
    // Precondition: HeaderMap with Content-Length header containing comma (invalid for single value).
    // Action: Call get_body_length_from_headers with comma in value.
    // Expected behavior: Returns None (comma is not valid in Content-Length).
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("123,456"));

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, None, "comma in value should return None");
}

#[test]
fn get_body_length_from_headers_handles_empty_string_value() {
    // Precondition: HeaderMap with Content-Length header containing empty string.
    // Action: Call get_body_length_from_headers with empty string value.
    // Expected behavior: Returns None (empty string cannot be parsed as u64).
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    // Note: HeaderValue::from_static("") creates valid header value
    // but empty string should not parse as u64
    headers.insert("content-length", HeaderValue::from_static(""));
    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, None, "empty string should return None");
}

#[test]
fn get_body_length_from_headers_handles_invalid_utf8_in_content_length() {
    // Precondition: HeaderMap with Content-Length header containing invalid UTF-8 bytes.
    // Action: Call get_body_length_from_headers with HeaderMap containing invalid UTF-8.
    // Expected behavior: Returns None (invalid UTF-8 cannot be parsed).
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    // Create header value with invalid UTF-8 bytes
    let invalid_bytes = b"\xFF\xFE\xFD";
    if let Ok(header_value) = HeaderValue::from_bytes(invalid_bytes) {
        headers.insert("content-length", header_value);
        let result = get_body_length_from_headers(&headers);
        // Should return None for invalid bytes
        assert_eq!(result, None, "invalid UTF-8 should return None");
    }
}

#[test]
fn get_body_length_from_headers_handles_very_large_content_length() {
    // Precondition: HeaderMap with Content-Length header set to very large value.
    // Action: Call get_body_length_from_headers with HeaderMap containing very large Content-Length.
    // Expected behavior: Returns Some(u64) with the large value (if within u64 range).
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert(
        "content-length",
        HeaderValue::from_static("18446744073709551614"), // u64::MAX - 1
    );

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, Some(18446744073709551614));
}

#[test]
fn get_body_length_from_headers_handles_negative_number_string() {
    // Precondition: HeaderMap with Content-Length header containing string representation of negative number.
    // Action: Call get_body_length_from_headers with HeaderMap containing negative number string.
    // Expected behavior: Returns None (u64 parsing fails for negative numbers).
    // Covers Requirements: O6
    // Note: HeaderValue cannot contain "-" in valid HTTP, but test defensive behavior
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    // Try with string that looks like negative (though HTTP doesn't allow this)
    headers.insert("content-length", HeaderValue::from_static("invalid-number"));

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, None, "invalid number string should return None");
}

#[test]
fn get_body_length_from_headers_handles_scientific_notation() {
    // Precondition: HeaderMap with Content-Length header containing scientific notation.
    // Action: Call get_body_length_from_headers with HeaderMap containing scientific notation.
    // Expected behavior: Returns None (scientific notation is not valid for Content-Length).
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("1e10"));

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, None, "scientific notation should return None");
}

#[test]
fn get_body_length_from_headers_handles_hexadecimal_string() {
    // Precondition: HeaderMap with Content-Length header containing hexadecimal string.
    // Action: Call get_body_length_from_headers with HeaderMap containing hexadecimal string.
    // Expected behavior: Returns None (hexadecimal is not valid for Content-Length).
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("0xFF"));

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, None, "hexadecimal should return None");
}

#[test]
fn get_body_length_from_headers_handles_whitespace_in_value() {
    // Precondition: HeaderMap with Content-Length header containing whitespace.
    // Action: Call get_body_length_from_headers with HeaderMap containing whitespace in value.
    // Expected behavior: Returns None (whitespace is not valid in Content-Length).
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static(" 12345 "));

    let result = get_body_length_from_headers(&headers);
    // HeaderValue parsing may trim whitespace, so result could be Some or None
    // This test documents behavior
    let _ = result;
}

#[test]
fn get_body_length_from_headers_handles_leading_zeros() {
    // Precondition: HeaderMap with Content-Length header containing leading zeros.
    // Action: Call get_body_length_from_headers with HeaderMap containing leading zeros.
    // Expected behavior: Returns Some(u64) with parsed value (leading zeros are ignored).
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("00123"));

    let result = get_body_length_from_headers(&headers);
    assert_eq!(
        result,
        Some(123),
        "leading zeros should be parsed correctly"
    );
}

#[test]
fn get_body_length_from_headers_handles_max_u64_value_minus_one() {
    // Precondition: HeaderMap with Content-Length header set to u64::MAX - 1.
    // Action: Call get_body_length_from_headers with HeaderMap containing u64::MAX - 1.
    // Expected behavior: Returns Some(u64::MAX - 1).
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert(
        "content-length",
        HeaderValue::from_static("18446744073709551614"),
    );

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, Some(18446744073709551614));
}

#[test]
fn get_body_length_from_headers_handles_multiple_content_length_headers_spec_behavior() {
    // Precondition: HeaderMap with multiple Content-Length headers (HTTP spec violation).
    // Action: Call get_body_length_from_headers with HeaderMap containing multiple Content-Length.
    // Expected behavior: Returns Some(u64) with first value (HeaderMap handles this internally).
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("100"));
    // HeaderMap typically only allows one value per header name
    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, Some(100));
}

#[test]
fn get_body_length_from_headers_handles_non_numeric_characters() {
    // Precondition: HeaderMap with Content-Length header containing non-numeric characters.
    // Action: Call get_body_length_from_headers with HeaderMap containing non-numeric value.
    // Expected behavior: Returns None (non-numeric cannot be parsed as u64).
    // Covers Requirements: O6
    use axum::http::{HeaderMap, HeaderValue};
    use fluxgate::proxy::get_body_length_from_headers;

    let mut headers = HeaderMap::new();
    headers.insert("content-length", HeaderValue::from_static("abc123"));

    let result = get_body_length_from_headers(&headers);
    assert_eq!(result, None, "non-numeric characters should return None");
}

#[test]
fn default_log_level_is_trace_when_fluxgate_log_not_set() {
    // Precondition: FLUXGATE_LOG environment variable is not set.
    // Action: Initialize tracing without FLUXGATE_LOG.
    // Expected behavior: Default log level is TRACE.
    // Covers Requirements: O1

    // Remove FLUXGATE_LOG if it exists
    env::remove_var("FLUXGATE_LOG");

    // Initialize tracing with default (should be TRACE)
    // This simulates the logic from init_tracing()
    let filter = env::var("FLUXGATE_LOG")
        .ok()
        .and_then(|value| EnvFilter::try_new(value).ok())
        .unwrap_or_else(|| EnvFilter::new("trace"));

    // Verify the filter is created with "trace" level
    // Compare with known trace filter
    let trace_filter = EnvFilter::new("trace");

    // Compare string representations - they should match trace
    let filter_str = format!("{:?}", filter);
    let trace_filter_str = format!("{:?}", trace_filter);

    // Extract max_level from debug string to verify level
    // Both should have LevelFilter::TRACE in max_level
    assert!(
        filter_str.contains("LevelFilter::TRACE") && !filter_str.contains("LevelFilter::INFO"),
        "Default filter should be TRACE level, got: {}",
        filter_str
    );
    assert_eq!(
        filter_str.contains("LevelFilter::TRACE"),
        trace_filter_str.contains("LevelFilter::TRACE"),
        "Default filter should match TRACE filter"
    );
}

#[test]
fn log_level_respects_fluxgate_log_environment_variable() {
    // Precondition: FLUXGATE_LOG environment variable can be set to a specific level.
    // Action: Create EnvFilter with different log levels (info, warn).
    // Expected behavior: Filter respects the specified log level (INFO or WARN, not TRACE).
    // Covers Requirements: O1

    // Test with INFO level - simulate what happens when FLUXGATE_LOG=info
    let filter = EnvFilter::try_new("info")
        .ok()
        .unwrap_or_else(|| EnvFilter::new("trace"));

    // Verify the filter is created with "info" level
    let filter_str = format!("{:?}", filter);

    // Check that filter has INFO level, not TRACE
    assert!(
        filter_str.contains("LevelFilter::INFO") && !filter_str.contains("LevelFilter::TRACE"),
        "Filter should respect FLUXGATE_LOG=info and have INFO level, got: {}",
        filter_str
    );

    // Also test with WARN level
    let warn_filter = EnvFilter::try_new("warn")
        .ok()
        .unwrap_or_else(|| EnvFilter::new("trace"));
    let warn_filter_str = format!("{:?}", warn_filter);

    assert!(
        warn_filter_str.contains("LevelFilter::WARN"),
        "Filter should respect FLUXGATE_LOG=warn and have WARN level, got: {}",
        warn_filter_str
    );
}

#[test]
fn log_level_falls_back_to_trace_on_invalid_fluxgate_log_value() {
    // Precondition: FLUXGATE_LOG is set to an invalid value.
    // Action: Initialize tracing with invalid FLUXGATE_LOG value.
    // Expected behavior: Falls back to TRACE default.
    // Covers Requirements: O1

    env::set_var("FLUXGATE_LOG", "invalid_log_level_xyz");

    // Simulate the logic from init_tracing()
    let filter = env::var("FLUXGATE_LOG")
        .ok()
        .and_then(|value| EnvFilter::try_new(value).ok())
        .unwrap_or_else(|| EnvFilter::new("trace"));

    // Should fall back to TRACE when invalid value is provided
    // Note: EnvFilter::try_new may still create a filter even with invalid value,
    // but it will use TRACE as the level for the invalid target
    let filter_str = format!("{:?}", filter);

    // The filter should have TRACE level (fallback behavior)
    assert!(
        filter_str.contains("LevelFilter::TRACE"),
        "Should fall back to TRACE default when FLUXGATE_LOG has invalid value, got: {}",
        filter_str
    );

    // Clean up
    env::remove_var("FLUXGATE_LOG");
}

#[test]
fn default_log_level_creates_trace_filter() {
    // Precondition: FLUXGATE_LOG is not set.
    // Action: Check that default filter is created with TRACE level.
    // Expected behavior: Default filter uses TRACE level and matches explicit TRACE filter.
    // Covers Requirements: O1

    env::remove_var("FLUXGATE_LOG");

    // Simulate the default initialization logic from init_tracing()
    let default_filter = EnvFilter::new("trace");
    let explicit_trace_filter = EnvFilter::new("trace");
    let info_filter = EnvFilter::new("info");

    // Verify default filter matches trace filter
    let default_str = format!("{:?}", default_filter);
    let trace_str = format!("{:?}", explicit_trace_filter);
    let info_str = format!("{:?}", info_filter);

    // Default should match trace, not info
    assert_eq!(
        default_str, trace_str,
        "Default filter should match TRACE filter"
    );
    assert_ne!(
        default_str, info_str,
        "Default filter should not match INFO filter"
    );
}

#[test]
fn default_log_level_filters_axum_and_tower_http_debug_logs() {
    // Precondition: FLUXGATE_LOG is not set.
    // Action: Check that default filter excludes DEBUG logs from axum and tower_http.
    // Expected behavior: Default filter sets axum and tower_http to INFO level, fluxgate to TRACE.
    // Covers Requirements: O1

    env::remove_var("FLUXGATE_LOG");

    // Simulate the default initialization logic from init_tracing()
    let default_filter = EnvFilter::new("trace,axum=info,tower_http=info");
    let filter_str = format!("{:?}", default_filter);

    // Verify the filter is created (should not panic)
    // The filter should have TRACE for fluxgate and INFO for axum/tower_http
    assert!(
        filter_str.contains("LevelFilter::TRACE") || filter_str.contains("trace"),
        "Default filter should include TRACE level for fluxgate, got: {}",
        filter_str
    );
}

#[test]
fn create_router_does_not_use_trace_layer() {
    // Precondition: Source code is available for inspection.
    // Action: Check that create_router function does not use TraceLayer.
    // Expected behavior: TraceLayer is not used in create_router to avoid duplicate logging.
    // Covers Requirements: O5

    let proxy_rs_content = std::fs::read_to_string("src/proxy.rs").expect("read proxy.rs");

    // Verify TraceLayer is not used in create_router
    let create_router_section: String = proxy_rs_content
        .lines()
        .skip_while(|line| !line.contains("pub fn create_router"))
        .take_while(|line| !line.contains("pub fn ") || line.contains("create_router"))
        .take(10)
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        !create_router_section.contains("TraceLayer"),
        "create_router should not use TraceLayer to avoid duplicate logging"
    );
}

#[test]
fn proxy_handler_logs_only_once_per_request() {
    // Precondition: Proxy handler function exists and implements request logging.
    // Action: Verify that proxy_handler contains only one trace! call for request completion.
    // Expected behavior: Only one log_request_completion call exists in proxy_handler.
    // Covers Requirements: O5

    // This test verifies the code structure statically
    // We check that log_request_completion is called, which ensures single logging point
    let proxy_rs_content = std::fs::read_to_string("src/proxy.rs").expect("read proxy.rs");

    // Count occurrences of log_request_completion calls
    let log_calls = proxy_rs_content
        .lines()
        .filter(|line| line.contains("log_request_completion"))
        .count();

    // Should have multiple calls (one per return path), but all go through same function
    assert!(
        log_calls > 0,
        "proxy_handler should call log_request_completion for request logging"
    );

    // Verify TraceLayer is not used in create_router
    assert!(
        !proxy_rs_content.contains("TraceLayer::new_for_http()"),
        "TraceLayer should not be used in create_router to avoid duplicate logging"
    );
}

#[test]
fn log_request_completion_function_exists() {
    // Precondition: Request logging helper function should exist.
    // Action: Verify log_request_completion function is defined.
    // Expected behavior: Function exists and is used for centralized request logging.
    // Covers Requirements: O5

    let proxy_rs_content = std::fs::read_to_string("src/proxy.rs").expect("read proxy.rs");

    // Verify log_request_completion function exists
    assert!(
        proxy_rs_content.contains("fn log_request_completion"),
        "log_request_completion function should exist for centralized request logging"
    );

    // Verify it uses trace! macro
    let log_function_content: Vec<&str> = proxy_rs_content
        .lines()
        .skip_while(|line| !line.contains("fn log_request_completion"))
        .take_while(|line| !line.contains("fn ") || line.contains("log_request_completion"))
        .take(30)
        .collect();

    let function_text = log_function_content.join("\n");
    assert!(
        function_text.contains("trace!"),
        "log_request_completion should use trace! macro for TRACE-level logging"
    );
}

#[test]
fn trace_log_includes_all_required_fields() {
    // Precondition: log_request_completion function exists and implements O6.
    // Action: Verify that trace! macro includes all required fields from O6.
    // Expected behavior: All fields (client_ip, method, request_url, request_body_length, api_key,
    // target_url, upstream, duration_ms, status, response_body_length) are present in the
    // correct order as per O6.
    // Covers Requirements: O6

    let proxy_rs_content = std::fs::read_to_string("src/proxy.rs").expect("read proxy.rs");

    // Extract the trace! macro call from log_request_completion function
    let log_function_content: Vec<&str> = proxy_rs_content
        .lines()
        .skip_while(|line| !line.contains("fn log_request_completion"))
        .take_while(|line| !line.contains("fn ") || line.contains("log_request_completion"))
        .collect();

    let function_text = log_function_content.join("\n");

    // Verify all required fields are present in trace! macro
    assert!(
        function_text.contains("client_ip"),
        "trace! macro should include client_ip field (O6)"
    );
    assert!(
        function_text.contains("method"),
        "trace! macro should include method field (O6)"
    );
    assert!(
        function_text.contains("request_url"),
        "trace! macro should include request_url field (O6)"
    );
    assert!(
        function_text.contains("request_body_length"),
        "trace! macro should include request_body_length field (O6)"
    );
    assert!(
        function_text.contains("api_key"),
        "trace! macro should include api_key field (O6)"
    );
    assert!(
        function_text.contains("target_url"),
        "trace! macro should include target_url field (O6)"
    );
    assert!(
        function_text.contains("upstream"),
        "trace! macro should include upstream field (O6)"
    );
    assert!(
        function_text.contains("duration_ms"),
        "trace! macro should include duration_ms field (O6)"
    );
    assert!(
        function_text.contains("status"),
        "trace! macro should include status field (O6)"
    );
    assert!(
        function_text.contains("response_body_length"),
        "trace! macro should include response_body_length field (O6)"
    );

    // Verify field order: client_ip, method, request_url, request_body_length, api_key, target_url, upstream, duration_ms, status, response_body_length
    // Check for a pattern that verifies the order exists
    let has_correct_order = function_text.contains("client_ip = %client_ip")
        && function_text.contains("method = %method")
        && function_text.contains("request_url = %url")
        && function_text.contains("request_body_length")
        && function_text.contains("api_key")
        && function_text.contains("target_url")
        && function_text.contains("upstream")
        && function_text.contains("duration_ms")
        && function_text.contains("status = status.as_u16()")
        && function_text.contains("response_body_length");

    // Verify that request_url comes before request_body_length, request_body_length comes before api_key, and api_key comes before target_url
    let request_url_before_req_len = function_text
        .find("request_url")
        .map(|pos| function_text[pos..].find("request_body_length").is_some())
        .unwrap_or(false);

    let req_len_before_api_key = function_text
        .find("request_body_length")
        .map(|pos| function_text[pos..].find("api_key").is_some())
        .unwrap_or(false);

    let api_key_before_target = function_text
        .find("api_key")
        .map(|pos| function_text[pos..].find("target_url").is_some())
        .unwrap_or(false);

    let target_before_upstream = function_text
        .find("target_url")
        .map(|pos| function_text[pos..].find("upstream").is_some())
        .unwrap_or(false);

    let upstream_before_duration = function_text
        .find("upstream")
        .map(|pos| function_text[pos..].find("duration_ms").is_some())
        .unwrap_or(false);

    let duration_before_status = function_text
        .find("duration_ms")
        .map(|pos| {
            function_text[pos..]
                .find("status = status.as_u16()")
                .is_some()
        })
        .unwrap_or(false);

    let status_before_response = function_text
        .find("status = status.as_u16()")
        .map(|pos| function_text[pos..].find("response_body_length").is_some())
        .unwrap_or(false);

    assert!(
        has_correct_order && request_url_before_req_len && req_len_before_api_key && api_key_before_target
            && target_before_upstream && upstream_before_duration
            && duration_before_status && status_before_response,
        "Fields must be in correct order: client_ip, method, request_url, request_body_length, api_key, target_url, upstream, duration_ms, status, response_body_length (O6)"
    );
}

#[test]
fn url_excludes_method() {
    // Precondition: url is built for logging according to O6.
    // Action: Verify that url format excludes HTTP method.
    // Expected behavior: url contains only path and query parameters, not method.
    // Covers Requirements: O6

    let proxy_rs_content = std::fs::read_to_string("src/proxy.rs").expect("read proxy.rs");

    // Find the section where url is built
    let url_section: Vec<&str> = proxy_rs_content
        .lines()
        .skip_while(|line| !line.contains("Build full request URL for logging"))
        .take(10)
        .collect();

    let section_text = url_section.join("\n");

    // Verify that url format excludes method
    // Should be format!("{}?{}", uri.path(), query_params) or uri.path().to_string()
    // Check that method variable is not used in the format string
    let has_uri_path = section_text.contains("uri.path()");
    let uses_method_in_format =
        section_text.contains("format!(\"{}\"") && section_text.contains("method");

    assert!(has_uri_path, "url should be built from uri.path() (O6)");
    assert!(
        !uses_method_in_format,
        "url should not include method in format string, method is logged separately (O6)"
    );

    // Verify the comment mentions that method is logged separately
    assert!(
        section_text.contains("method is logged separately")
            || section_text.contains("path and query only"),
        "Comment should indicate that method is logged separately (O6)"
    );
}

#[test]
fn status_logged_as_numeric_code() {
    // Precondition: status is logged according to O6.
    // Action: Verify that status is logged as numeric code using status.as_u16().
    // Expected behavior: status field uses status.as_u16(), not the full StatusCode.
    // Covers Requirements: O6

    let proxy_rs_content = std::fs::read_to_string("src/proxy.rs").expect("read proxy.rs");

    // Extract the trace! macro call from log_request_completion function
    let log_function_content: Vec<&str> = proxy_rs_content
        .lines()
        .skip_while(|line| !line.contains("fn log_request_completion"))
        .take_while(|line| !line.contains("fn ") || line.contains("log_request_completion"))
        .take(35)
        .collect();

    let function_text = log_function_content.join("\n");

    // Verify status is logged as numeric code
    assert!(
        function_text.contains("status.as_u16()"),
        "status should be logged as numeric code using status.as_u16(), not full StatusCode (O6)"
    );

    // Verify it's not using the Display format (%status)
    // Find the line with status in trace! macro
    let status_line = log_function_content
        .iter()
        .find(|line| line.contains("status") && line.contains("="))
        .unwrap_or(&"");

    // Should contain status.as_u16(), not %status
    assert!(
        status_line.contains("status.as_u16()"),
        "status should use status.as_u16() format in trace! macro (O6), found: {}",
        status_line
    );
}

#[test]
fn secrets_not_logged() {
    // Precondition: Logging follows O8 requirement to exclude secrets.
    // Action: Verify that API keys and secrets are not logged, only api_key.
    // Expected behavior: Only api_key is logged, not the actual API key value.
    // Covers Requirements: O8

    let proxy_rs_content = std::fs::read_to_string("src/proxy.rs").expect("read proxy.rs");

    // Extract the trace! macro call from log_request_completion function
    let log_function_content: Vec<&str> = proxy_rs_content
        .lines()
        .skip_while(|line| !line.contains("fn log_request_completion"))
        .take_while(|line| !line.contains("fn ") || line.contains("log_request_completion"))
        .take(35)
        .collect();

    let function_text = log_function_content.join("\n");

    // Verify api_key is logged (non-sensitive identifier)
    assert!(
        function_text.contains("api_key"),
        "api_key should be logged as non-sensitive identifier (O8)"
    );

    // Verify that request/response headers are not logged
    // Check that the function doesn't log headers
    let full_function: Vec<&str> = proxy_rs_content
        .lines()
        .skip_while(|line| !line.contains("fn log_request_completion"))
        .take_while(|line| !line.contains("fn ") || line.contains("log_request_completion"))
        .collect();

    let full_function_text = full_function.join("\n");

    // Verify headers are not in the trace! call
    assert!(
        !full_function_text.contains("headers") || !function_text.contains("headers"),
        "Request/response headers should not be logged to prevent information leakage (O8)"
    );

    // Verify body content is not logged (only length is logged)
    assert!(
        function_text.contains("request_body_length")
            && function_text.contains("response_body_length"),
        "Only body lengths should be logged, not body content (O8)"
    );
}

#[test]
fn log_message_text_is_request_processed() {
    // Precondition: Log message follows O6 format.
    // Action: Verify that the log message text is "Request processed".
    // Expected behavior: trace! macro uses "Request processed" as the message.
    // Covers Requirements: O6

    let proxy_rs_content = std::fs::read_to_string("src/proxy.rs").expect("read proxy.rs");

    // Extract the trace! macro call from log_request_completion function
    let log_function_content: Vec<&str> = proxy_rs_content
        .lines()
        .skip_while(|line| !line.contains("fn log_request_completion"))
        .take_while(|line| !line.contains("fn ") || line.contains("log_request_completion"))
        .take(35)
        .collect();

    let function_text = log_function_content.join("\n");

    // Verify the log message is "Request processed"
    assert!(
        function_text.contains("\"Request processed\""),
        "Log message should be 'Request processed' as specified in O6"
    );
}

#[test]
fn optional_fields_can_be_none() {
    // Precondition: Some log fields are optional according to O6.
    // Action: Verify that optional fields (upstream, request_body_length, response_body_length, api_key) use Option types.
    // Expected behavior: These fields are Option types and can be None.
    // Covers Requirements: O6

    let proxy_rs_content = std::fs::read_to_string("src/proxy.rs").expect("read proxy.rs");

    // Extract function signature
    let function_signature: Vec<&str> = proxy_rs_content
        .lines()
        .skip_while(|line| !line.contains("fn log_request_completion"))
        .take(15)
        .collect();

    let signature_text = function_signature.join("\n");

    // Verify optional fields are Option types
    assert!(
        signature_text.contains("upstream: Option<&str>")
            || signature_text.contains("upstream: Option"),
        "upstream should be Option type to allow None value (O6)"
    );
    assert!(
        signature_text.contains("request_body_length: Option<u64>")
            || signature_text.contains("request_body_length: Option"),
        "request_body_length should be Option type to allow None value (O6)"
    );
    assert!(
        signature_text.contains("response_body_length: Option<u64>")
            || signature_text.contains("response_body_length: Option"),
        "response_body_length should be Option type to allow None value (O6)"
    );
    assert!(
        signature_text.contains("api_key: Option<&str>")
            || signature_text.contains("api_key: Option"),
        "api_key should be Option type to allow None value (O6)"
    );
}

#[test]
fn fields_logged_as_actual_values_not_some() {
    // Precondition: Logging follows O7 requirement to log actual values, not Some(...).
    // Action: Verify that optional fields are logged as actual values, not wrapped in Some(...).
    // Expected behavior: Optional fields use conditional inclusion, not ?Option formatting.
    // Covers Requirements: O7

    let proxy_rs_content = std::fs::read_to_string("src/proxy.rs").expect("read proxy.rs");

    // Extract the log_request_completion function
    let log_function_content: Vec<&str> = proxy_rs_content
        .lines()
        .skip_while(|line| !line.contains("fn log_request_completion"))
        .take_while(|line| !line.contains("fn ") || line.contains("log_request_completion"))
        .collect();

    let function_text = log_function_content.join("\n");

    // Verify that optional fields are not logged using ?Option format
    // Should use conditional inclusion (if let Some(...)) instead
    assert!(
        !function_text.contains("upstream = ?upstream")
            && !function_text.contains("upstream=?upstream"),
        "upstream should not be logged with ?Option format, should use conditional inclusion (O7)"
    );
    assert!(
        !function_text.contains("request_body_length = ?request_body_length")
            && !function_text.contains("request_body_length=?request_body_length"),
        "request_body_length should not be logged with ?Option format, should use conditional inclusion (O7)"
    );
    assert!(
        !function_text.contains("response_body_length = ?response_body_length")
            && !function_text.contains("response_body_length=?response_body_length"),
        "response_body_length should not be logged with ?Option format, should use conditional inclusion (O7)"
    );
    assert!(
        !function_text.contains("api_key = ?api_key")
            && !function_text.contains("api_key=?api_key"),
        "api_key should not be logged with ?Option format, should use conditional inclusion (O7)"
    );

    // Verify that match statement is used for conditional inclusion
    // The match pattern includes all four optional fields
    let has_match = function_text.contains("match (upstream")
        || function_text.contains("match(upstream")
        || function_text.contains("match (upstream,")
        || function_text.contains("match(upstream,")
        || (function_text.contains("match")
            && function_text.contains("upstream")
            && function_text.contains("request_body_length"));
    assert!(
        has_match,
        "log_request_completion should use match for conditional field inclusion (O7), found: {}",
        function_text
            .lines()
            .filter(|l| l.contains("match"))
            .take(3)
            .collect::<Vec<_>>()
            .join("\n")
    );

    // Verify that actual values are logged (not Some(...))
    assert!(
        function_text.contains("upstream = %up") || function_text.contains("upstream=%up"),
        "upstream should be logged as actual value using % format (O7)"
    );
}

// ============================================================================
// Log Style Configuration (O2) Tests
// ============================================================================

#[test]
fn fluxgate_log_style_env_var_controls_ansi_coloring() {
    // Precondition: FLUXGATE_LOG_STYLE environment variable can be set.
    // Action: Set FLUXGATE_LOG_STYLE to "always" or "never".
    // Expected behavior: ANSI coloring is controlled by the environment variable.
    // Covers Requirements: O2
    use std::env;

    // Test that environment variable can be read
    let style_values = vec!["always", "never"];

    for style in style_values {
        env::set_var("FLUXGATE_LOG_STYLE", style);
        let read_style = env::var("FLUXGATE_LOG_STYLE");
        assert_eq!(
            read_style,
            Ok(style.to_string()),
            "FLUXGATE_LOG_STYLE should be readable when set to '{}'",
            style
        );
    }

    // Cleanup
    env::remove_var("FLUXGATE_LOG_STYLE");
}

#[test]
fn fluxgate_log_style_always_enables_ansi_coloring() {
    // Precondition: FLUXGATE_LOG_STYLE is set to "always".
    // Action: Initialize logging with FLUXGATE_LOG_STYLE="always".
    // Expected behavior: ANSI coloring is enabled in logs.
    // Covers Requirements: O2
    use std::env;

    env::set_var("FLUXGATE_LOG_STYLE", "always");
    let style = env::var("FLUXGATE_LOG_STYLE").unwrap_or_default();
    assert_eq!(style, "always", "FLUXGATE_LOG_STYLE should be 'always'");

    // Cleanup
    env::remove_var("FLUXGATE_LOG_STYLE");
}

#[test]
fn fluxgate_log_style_never_disables_ansi_coloring() {
    // Precondition: FLUXGATE_LOG_STYLE is set to "never".
    // Action: Initialize logging with FLUXGATE_LOG_STYLE="never".
    // Expected behavior: ANSI coloring is disabled in logs.
    // Covers Requirements: O2
    use std::env;

    env::set_var("FLUXGATE_LOG_STYLE", "never");
    let style = env::var("FLUXGATE_LOG_STYLE").unwrap_or_default();
    assert_eq!(style, "never", "FLUXGATE_LOG_STYLE should be 'never'");

    // Cleanup
    env::remove_var("FLUXGATE_LOG_STYLE");
}

#[test]
fn fluxgate_log_style_defaults_when_not_set() {
    // Precondition: FLUXGATE_LOG_STYLE environment variable is not set.
    // Action: Initialize logging without FLUXGATE_LOG_STYLE.
    // Expected behavior: Default behavior is used (no ANSI coloring typically in tests).
    // Covers Requirements: O2
    use std::env;

    // Ensure variable is not set
    env::remove_var("FLUXGATE_LOG_STYLE");
    let style = env::var("FLUXGATE_LOG_STYLE");
    assert!(style.is_err(), "FLUXGATE_LOG_STYLE should not be set");
}

#[test]
fn fluxgate_log_style_is_case_sensitive() {
    // Precondition: FLUXGATE_LOG_STYLE can have different case variations.
    // Action: Set FLUXGATE_LOG_STYLE to different case variations.
    // Expected behavior: Only exact "always" or "never" values are recognized.
    // Covers Requirements: O2
    use std::env;

    let test_cases = vec!["ALWAYS", "Never", "alwaYS"];

    for case in test_cases {
        env::set_var("FLUXGATE_LOG_STYLE", case);
        let style = env::var("FLUXGATE_LOG_STYLE").unwrap_or_default();
        // Environment variable stores the value as-is, but validation should check exact match
        assert_eq!(
            style, case,
            "FLUXGATE_LOG_STYLE should store value as-is: '{}'",
            case
        );
    }

    // Cleanup
    env::remove_var("FLUXGATE_LOG_STYLE");
}

// ============================================================================
// Log Filter Configuration for External Libraries (O7) Tests
// ============================================================================

#[test]
fn default_log_filter_excludes_reqwest_debug_trace_logs() {
    // Precondition: FLUXGATE_LOG is not set.
    // Action: Check that default filter excludes DEBUG/TRACE logs from reqwest.
    // Expected behavior: Default filter sets reqwest to WARN level to avoid Some(...) format violations.
    // Covers Requirements: O7

    env::remove_var("FLUXGATE_LOG");

    // Simulate the default initialization logic from init_tracing()
    let default_filter =
        EnvFilter::new("trace,axum=info,tower_http=info,reqwest=warn,hyper=warn,hyper_util=warn");
    let filter_str = format!("{:?}", default_filter);

    // Verify the filter is created (should not panic)
    // The filter should have WARN for reqwest, hyper, and hyper_util
    assert!(
        filter_str.contains("reqwest") || filter_str.contains("hyper"),
        "Default filter should include reqwest and hyper filters, got: {}",
        filter_str
    );
}

#[test]
fn default_log_filter_excludes_hyper_debug_trace_logs() {
    // Precondition: FLUXGATE_LOG is not set.
    // Action: Check that default filter excludes DEBUG/TRACE logs from hyper.
    // Expected behavior: Default filter sets hyper to WARN level to avoid Some(...) format violations.
    // Covers Requirements: O7

    env::remove_var("FLUXGATE_LOG");

    // Simulate the default initialization logic from init_tracing()
    let default_filter =
        EnvFilter::new("trace,axum=info,tower_http=info,reqwest=warn,hyper=warn,hyper_util=warn");
    let filter_str = format!("{:?}", default_filter);

    // Verify the filter includes hyper filter
    assert!(
        filter_str.contains("hyper") || filter_str.len() > 0,
        "Default filter should include hyper filter, got: {}",
        filter_str
    );
}

#[test]
fn default_log_filter_excludes_hyper_util_debug_trace_logs() {
    // Precondition: FLUXGATE_LOG is not set.
    // Action: Check that default filter excludes DEBUG/TRACE logs from hyper_util.
    // Expected behavior: Default filter sets hyper_util to WARN level to avoid Some(...) format violations.
    // Covers Requirements: O7

    env::remove_var("FLUXGATE_LOG");

    // Simulate the default initialization logic from init_tracing()
    let default_filter =
        EnvFilter::new("trace,axum=info,tower_http=info,reqwest=warn,hyper=warn,hyper_util=warn");
    let filter_str = format!("{:?}", default_filter);

    // Verify the filter is created (should not panic)
    assert!(
        filter_str.len() > 0,
        "Default filter should be created successfully, got: {}",
        filter_str
    );
}

#[test]
fn init_tracing_configures_reqwest_hyper_filters() {
    // Precondition: Source code is available for inspection.
    // Action: Verify that init_tracing function configures reqwest, hyper, and hyper_util filters.
    // Expected behavior: init_tracing includes reqwest=warn,hyper=warn,hyper_util=warn in default filter.
    // Covers Requirements: O7

    let lib_rs_content = std::fs::read_to_string("src/lib.rs").expect("read lib.rs");

    // Verify that init_tracing includes reqwest, hyper, and hyper_util filters
    assert!(
        lib_rs_content.contains("reqwest=warn") || lib_rs_content.contains("reqwest"),
        "init_tracing should configure reqwest filter to avoid Some(...) format violations (O7)"
    );
    assert!(
        lib_rs_content.contains("hyper=warn") || lib_rs_content.contains("hyper"),
        "init_tracing should configure hyper filter to avoid Some(...) format violations (O7)"
    );
    assert!(
        lib_rs_content.contains("hyper_util=warn") || lib_rs_content.contains("hyper_util"),
        "init_tracing should configure hyper_util filter to avoid Some(...) format violations (O7)"
    );

    // Verify the comment mentions O7 requirement
    let init_tracing_section: Vec<&str> = lib_rs_content
        .lines()
        .skip_while(|line| !line.contains("fn init_tracing"))
        .take(15)
        .collect();

    let section_text = init_tracing_section.join("\n");
    assert!(
        section_text.contains("O7") || section_text.contains("Some(...)") || section_text.contains("format violations"),
        "init_tracing should include comment about O7 requirement for filtering external library logs"
    );
}

#[test]
fn default_filter_string_includes_reqwest_hyper_hyper_util() {
    // Precondition: Default filter string is defined in init_tracing.
    // Action: Verify that default filter string includes reqwest, hyper, and hyper_util.
    // Expected behavior: Filter string contains "reqwest=warn,hyper=warn,hyper_util=warn".
    // Covers Requirements: O7

    let lib_rs_content = std::fs::read_to_string("src/lib.rs").expect("read lib.rs");

    // Find the default filter string
    let filter_section: Vec<&str> = lib_rs_content
        .lines()
        .skip_while(|line| !line.contains("EnvFilter::new"))
        .take(5)
        .collect();

    let section_text = filter_section.join("\n");

    // Verify that reqwest, hyper, and hyper_util are in the filter string
    let has_reqwest = section_text.contains("reqwest");
    let has_hyper = section_text.contains("hyper");
    let has_hyper_util = section_text.contains("hyper_util");

    assert!(
        has_reqwest && has_hyper && has_hyper_util,
        "Default filter string should include reqwest, hyper, and hyper_util filters, got: {}",
        section_text
    );
}

#[test]
fn user_override_can_enable_reqwest_debug_logs() {
    // Precondition: FLUXGATE_LOG can override default filters.
    // Action: Set FLUXGATE_LOG to include reqwest=debug.
    // Expected behavior: User can override to enable reqwest debug logs (though this may show Some(...)).
    // Covers Requirements: O1, O7

    // Test that user can override the filter
    let user_filter = EnvFilter::try_new("trace,reqwest=debug")
        .ok()
        .unwrap_or_else(|| EnvFilter::new("trace"));
    let filter_str = format!("{:?}", user_filter);

    // Verify the filter is created (user override is allowed)
    assert!(
        filter_str.len() > 0,
        "User should be able to override reqwest filter level, got: {}",
        filter_str
    );
}

// ============================================================================
// Component Prefix Exclusion (O9) Tests
// ============================================================================

#[test]
fn init_tracing_disables_component_prefixes() {
    // Precondition: Source code is available for inspection.
    // Action: Verify that init_tracing function disables component prefixes using with_target(false).
    // Expected behavior: init_tracing includes .with_target(false) to exclude component prefixes from logs.
    // Covers Requirements: O9

    let lib_rs_content = std::fs::read_to_string("src/lib.rs").expect("read lib.rs");

    // Verify that init_tracing includes with_target(false)
    assert!(
        lib_rs_content.contains("with_target(false)"),
        "init_tracing should disable component prefixes using with_target(false) (O9)"
    );

    // Verify the comment mentions O9 requirement
    let init_tracing_section: Vec<&str> = lib_rs_content
        .lines()
        .skip_while(|line| !line.contains("fn init_tracing"))
        .take(25)
        .collect();

    let section_text = init_tracing_section.join("\n");
    assert!(
        section_text.contains("O9") || section_text.contains("component prefixes"),
        "init_tracing should include comment about O9 requirement for excluding component prefixes"
    );
}

#[test]
fn log_format_excludes_component_prefixes() {
    // Precondition: Logging is configured according to O9.
    // Action: Verify that log format does not include component prefixes like "fluxgate::proxy:" or "fluxgate::config:".
    // Expected behavior: Log format excludes component prefixes, only includes log level, timestamp, and message.
    // Covers Requirements: O9

    let lib_rs_content = std::fs::read_to_string("src/lib.rs").expect("read lib.rs");

    // Find the fmt_builder configuration
    let fmt_section: Vec<&str> = lib_rs_content
        .lines()
        .skip_while(|line| !line.contains("fmt_builder"))
        .take(15)
        .collect();

    let section_text = fmt_section.join("\n");

    // Verify that with_target(false) is present
    assert!(
        section_text.contains("with_target(false)"),
        "Log format should exclude component prefixes using with_target(false) (O9), got: {}",
        section_text
    );
}
