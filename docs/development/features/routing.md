# Routing Feature

## Overview

The routing feature handles request path matching and upstream selection based on configured `request_path` values.

## Requirement Areas

This feature covers the following requirement areas:

- **routing**: Request path matching and upstream selection
- **path-matching**: Request path prefix matching logic

## Implementation

### Source Files

- `src/proxy.rs`: Path matching and upstream selection logic
- `src/config/mod.rs`: Upstream configuration with `request_path` validation

### Key Functions

```rust
// src/proxy.rs
fn find_upstream_for_path(
    path: &str,
    api_key: &ApiKey,
    config: &Config,
) -> Option<&Upstream> {
    // Finds longest matching request_path for authenticated API key
}
```

## Test Coverage

### Functional Tests

Tests in `tests/functional/proxy_flow.rs`:

| Test                                                    | Requirement Areas       | Description                                       |
|---------------------------------------------------------|-------------------------|---------------------------------------------------|
| `proxy_routes_requests_by_request_path`                 | routing, path-matching  | Routes requests to correct upstream based on path |
| `proxy_selects_longest_matching_request_path`           | routing, path-matching  | Selects upstream with longest matching path       |
| `proxy_returns_404_when_no_request_path_matches`        | routing, error-handling | Returns 404 when no path matches                  |
| `proxy_handles_trailing_slash_in_request_path_matching` | routing, path-matching  | Handles trailing slash normalization              |

### Unit Tests

- `tests/unit/request_path_routing.rs`: Path matching logic unit tests

## Related Features

- [Authentication](./authentication.md): Authentication required before routing
- [Configuration](./configuration.md): `request_path` configuration and validation

