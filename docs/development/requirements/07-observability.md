# Observability

## Logging Configuration

O1. Logging verbosity may be overridden via the `FLUXGATE_LOG` environment variable using standard `tracing` directives;
this override does not affect core proxy configuration. When `FLUXGATE_LOG` is not set, the default log level is TRACE.

**Tags:** `logging`, `observability`

O2. ANSI colouring of logs must be controllable via the `FLUXGATE_LOG_STYLE` environment variable with values `always`
or `never`.

**Tags:** `logging`, `observability`

## Log Levels for System Events

O3. System events must be logged at INFO level. System events include, but are not limited to: proxy server startup and
shutdown, configuration changes (successful or rejected), and connection lifecycle events. **This requirement does not
apply to request processing logs** - see O5 for request processing logging requirements.

**Tags:** `logging`, `observability`

O4. System problems and errors must be logged at WARNING level. System problems include, but are not limited to:
configuration file access issues, validation errors, resource limit approaches, and server binding failures (e.g.,
"Address already in use" errors). **This requirement does not apply to request processing logs** - see O5 for request
processing logging requirements.

**Tags:** `logging`, `observability`, `error-handling`

## Request Processing Logging

O5. Every request received by the proxy must be logged at TRACE level when request processing is complete, regardless of
the processing result (successful forwarding, rejection, error, etc.). The request completion log must include all fields
specified in requirement O6. Request body content, response body content, request headers, and response headers must not
be logged to avoid performance degradation and potential information leakage. TRACE-level logging is enabled by default (as
per O1) and must not impact performance, as per performance requirement P1.

**Tags:** `logging`, `observability`, `performance`

O6. The request completion log entry must include the following structured fields with the specified formats and content:

- **`client_ip`**: The IP address of the client that sent the request. Must be formatted as a standard IP address (IPv4 or
  IPv6). This field is always present and must contain the actual client IP address from the connection.

- **`method`**: The HTTP method of the request (e.g., GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS). Must be formatted as
  the uppercase HTTP method string. This field is always present and must match the actual HTTP method from the request.

- **`request_url`**: The complete request URL including path and query parameters (without the HTTP method, which is logged
  separately in the `method` field). Must be formatted as "/path?query" where /path is the request path and ?query is the
  query string (if present). If no query parameters are present, the format must be "/path" without the question mark.
  Examples: "/", "/api/v1/chat?stream=true", "/openai/models". This field is always present.

- **`request_body_length`**: The length of the request body in bytes, as indicated by the `Content-Length` header (if
  present). Must be a non-negative integer representing the number of bytes. This field may be `None` if the request has no
  body, if the `Content-Length` header is not present, or if the request uses chunked transfer encoding (where the body
  length is not known in advance).

- **`api_key`**: The human-readable id of the API key used for authentication (if authentication was used). Must be
  the value from the `api_keys.static[].id` configuration field (for static API keys) or the value from the `api_keys.jwt[].id`
  configuration field that matches the `kid` field in the JWT token header (for JWT tokens). This field may be `None` if
  authentication was not required (no API keys configured), if authentication was not provided (no Authorization header), if
  authentication failed, if the API key does not have an id configured, or if the JWT token's `kid` does not match any
  configured JWT key ID.

- **`target_url`**: The complete URL to which the request was sent to the upstream (if routing was attempted). Must be
  formatted as a full absolute URL including scheme, host, port (if non-standard), path, and query parameters. This field
  may be `None` if no upstream URL was built (e.g., when the request path does not match any configured upstream, when
  authentication failed before routing, when the request was rejected before routing could be attempted, or when the
  upstream URL construction failed).

- **`upstream`**: The identifier of the upstream target to which the request was routed (if routing was attempted). Must
  be the upstream identifier as configured in the `upstreams` section of the configuration file. This field may be `None` if
  no upstream was selected (e.g., when the request path does not match any configured upstream, when authentication failed
  before routing, or when the request was rejected before routing could be attempted).

- **`duration_ms`**: The total time taken to process the request from start to finish, measured in milliseconds. Must be
  a non-negative integer representing the elapsed time. This field is always present and must reflect the actual processing
  duration.

- **`status`**: The HTTP status code of the response sent to the client. Must be formatted as the numeric status code
  only (e.g., 200, 401, 503, 504), without the standard status text. This field is always present and must reflect the
  actual response status code as a numeric value.

- **`response_body_length`**: The length of the response body in bytes, as indicated by the `Content-Length` header (if
  present). Must be a non-negative integer representing the number of bytes. This field may be `None` if the response has
  no body, if the `Content-Length` header is not present, or if the response uses chunked transfer encoding (where the
  body length is not known in advance).


**Tags:** `logging`, `observability`, `performance`

## Log Entry Structure and Security

O7. All fields in log entries must be logged as their actual values, not wrapped in type constructors such as `Some(...)`,
`Ok(...)`, `Err(...)`, or similar. This applies to all log entries across the system, not just request processing logs.
For optional fields, when a value is present, it must be logged as the actual value, not wrapped in `Some(...)`. When the
value is absent, the field must be omitted from the log entry.

**Tags:** `logging`, `observability`

O8. Every log entry must include: a timestamp (automatically provided by the logging framework), the essence of the
action being logged (a human-readable description), and important parameters relevant to the action. Secrets, API keys,
authentication tokens, and other sensitive credentials must never appear in log entries, even when masked or redacted.
Only non-sensitive identifiers (such as API key ids, upstream identifiers, configuration file paths) may be logged for
observability purposes.

**Tags:** `logging`, `observability`, `security`

O9. Log entries must not include component prefixes (such as `fluxgate::proxy:`, `fluxgate::config:`, etc.) in the log
message. The log format must only include the log level, timestamp, and the message content with structured fields, without
module or component path prefixes.

**Tags:** `logging`, `observability`

---

## Unit Tests

Unit tests for observability requirements are organized in the following files:

- **`tests/unit/observability.rs`** - Documentation and organization hub for observability requirement tests
- **`tests/unit/logging.rs`** - Tests for O1 (logging configuration via FLUXGATE_LOG)
- **`tests/unit/proxy_logging.rs`** - Tests for O5, O6, O7, O8, O9 (request logging, log structure, security, component prefixes)
- **`tests/unit/proxy.rs`** - Tests for O5, O6 (body length extraction from headers)
- **`tests/unit/request_path_routing.rs`** - Tests for O6 (log field extraction)
- **`tests/unit/config_manager.rs`** - Tests for F15, F17 (related to O3, O4 for configuration logging)
