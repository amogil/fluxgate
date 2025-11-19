# Authentication Feature

## Overview

The authentication feature handles client authentication, API key validation, and authorization checks before routing
requests to upstreams.

## Requirement Areas

This feature covers the following requirement areas:

- **authentication**: Client authentication and API key validation
- **authorization**: Upstream access control based on API keys
- **bearer-auth**: Bearer authentication scheme enforcement
- **error-handling**: HTTP 401 error responses for authentication failures

## Implementation

### Source Files

- `src/proxy.rs`:
    - `authenticate_request()`: Validates API key from Authorization header
    - `find_upstream_for_path()`: Routes based on authenticated API key permissions
- `src/config/mod.rs`:
    - `ApiKey`: API key configuration structure
    - `Config::validate()`: Validates API key uniqueness

## Test Coverage

### Functional Tests

All tests in `tests/functional/auth.rs`:

| Test                                                   | Requirement Areas                           | Description                                   |
|--------------------------------------------------------|---------------------------------------------|-----------------------------------------------|
| `proxy_requires_authentication_header`                 | authentication, error-handling              | Rejects requests without Authorization header |
| `proxy_rejects_invalid_auth_token`                     | authentication, error-handling              | Rejects unknown API keys                      |
| `proxy_authenticates_and_routes_to_permitted_upstream` | authentication, request-forwarding, routing | Successful authentication and routing         |
| `proxy_rejects_api_key_without_upstream_access`        | authorization, error-handling               | Rejects API keys without upstream permissions |
| `proxy_rejects_non_bearer_authentication_schemes`      | bearer-auth, error-handling                 | Rejects non-Bearer auth schemes               |
| `proxy_rejects_api_key_with_empty_upstreams_list`      | authentication, error-handling              | Handles empty upstreams list edge case        |

### Unit Tests

- `tests/unit/proxy.rs`: Authentication logic unit tests
- `tests/unit/request_path_routing.rs`: Path matching logic

## Related Features

- [Routing](./routing.md): Uses authentication results for request routing
- [Configuration](./configuration.md): API keys configuration and validation
- [Error Handling](./error-handling.md): HTTP 401 error responses

