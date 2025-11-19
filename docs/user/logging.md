# Logging

Fluxgate uses structured logging with the `tracing` framework to provide observability into proxy operations. All log entries include timestamps and structured fields for easy parsing and analysis.

## Log Configuration

### Log Verbosity

Log verbosity can be controlled via the `FLUXGATE_LOG` environment variable using standard `tracing` directives:

```bash
export FLUXGATE_LOG=info
./fluxgate
```

**Default log level:** `TRACE` (when `FLUXGATE_LOG` is not set)

**Available log levels:** `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`

### ANSI Color Output

ANSI colouring of logs can be controlled via the `FLUXGATE_LOG_STYLE` environment variable:

```bash
export FLUXGATE_LOG_STYLE=never
./fluxgate
```

**Values:**
- `always` - Always use ANSI colors (default)
- `never` - Never use ANSI colors (useful for CI or scripted runs)

## Log Levels

### System Events (INFO)

System events are logged at INFO level, including:

- Proxy server startup and shutdown
- Configuration changes (successful or rejected)
- Connection lifecycle events

### System Problems (WARNING)

System problems and errors are logged at WARNING level, including:

- Configuration file access issues
- Validation errors
- Resource limit approaches
- Server binding failures (e.g., "Address already in use")

### Request Processing (TRACE)

Every request received by the proxy is logged at TRACE level when request processing is complete, regardless of the processing result (successful forwarding, rejection, error, etc.).

**Note:** TRACE-level logging is enabled by default and does not impact performance. Request body content, response body content, request headers, and response headers are not logged to avoid performance degradation and potential information leakage.

## Request Log Fields

Each request completion log entry includes the following structured fields:

### `client_ip`

The IP address of the client that sent the request. Formatted as a standard IP address (IPv4 or IPv6). Always present.

**Example:** `192.168.1.100` or `2001:db8::1`

### `method`

The HTTP method of the request (e.g., GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS). Formatted as the uppercase HTTP method string. Always present.

**Example:** `POST`

### `request_url`

The complete request URL including path and query parameters (without the HTTP method). Formatted as "/path?query" where /path is the request path and ?query is the query string (if present). If no query parameters are present, the format is "/path" without the question mark. Always present.

**Examples:**
- `/`
- `/api/v1/chat?stream=true`
- `/openai/models`

### `request_body_length`

The length of the request body in bytes, as indicated by the `Content-Length` header (if present). A non-negative integer representing the number of bytes. May be `None` if the request has no body, if the `Content-Length` header is not present, or if the request uses chunked transfer encoding.

**Example:** `1024` or omitted if not available

### `api_key`

The human-readable id of the API key used for authentication (if authentication was used). This is the value from the `api_keys.static[].id` configuration field (for static API keys) or the value from the `api_keys.jwt[].id` configuration field that matches the `kid` field in the JWT token header (for JWT tokens). May be `None` if authentication was not required, not provided, failed, or if the API key does not have an id configured.

**Example:** `pr` or `dev` or omitted if not available

### `target_url`

The complete URL to which the request was sent to the upstream (if routing was attempted). Formatted as a full absolute URL including scheme, host, port (if non-standard), path, and query parameters. May be `None` if no upstream URL was built (e.g., when the request path does not match any configured upstream, when authentication failed before routing, or when the request was rejected before routing could be attempted).

**Example:** `https://api.openai.com/v1/models` or omitted if not available

### `upstream`

The identifier of the upstream target to which the request was routed (if routing was attempted). This is the upstream identifier as configured in the `upstreams` section of the configuration file. May be `None` if no upstream was selected (e.g., when the request path does not match any configured upstream, when authentication failed before routing, or when the request was rejected before routing could be attempted).

**Example:** `openai-1` or omitted if not available

### `duration_ms`

The total time taken to process the request from start to finish, measured in milliseconds. A non-negative integer representing the elapsed time. Always present.

**Example:** `125`

### `status`

The HTTP status code of the response sent to the client. Formatted as the numeric status code only (e.g., 200, 401, 503, 504), without the standard status text. Always present.

**Example:** `200`

### `response_body_length`

The length of the response body in bytes, as indicated by the `Content-Length` header (if present). A non-negative integer representing the number of bytes. May be `None` if the response has no body, if the `Content-Length` header is not present, or if the response uses chunked transfer encoding.

**Example:** `2048` or omitted if not available

## Log Entry Structure

All fields in log entries are logged as their actual values, not wrapped in type constructors such as `Some(...)`, `Ok(...)`, or `Err(...)`. For optional fields, when a value is present, it is logged as the actual value. When the value is absent, the field is omitted from the log entry.

Log entries do not include component prefixes (such as `fluxgate::proxy:`, `fluxgate::config:`, etc.) in the log message. The log format only includes the log level, timestamp, and the message content with structured fields.

## Security

Secrets, API keys, authentication tokens, and other sensitive credentials are never logged, even when masked or redacted. Only non-sensitive identifiers (such as API key ids, upstream identifiers, configuration file paths) are logged for observability purposes.

## Example Log Entries

### Successful Request

```
TRACE Fluxgate proxy: Request completed client_ip=192.168.1.100 method=POST request_url=/openai/v1/chat request_body_length=1024 api_key=pr target_url=https://api.openai.com/v1/chat upstream=openai-1 duration_ms=125 status=200 response_body_length=2048
```

### Authentication Failure

```
TRACE Fluxgate proxy: Request completed client_ip=192.168.1.100 method=POST request_url=/openai/v1/chat request_body_length=1024 duration_ms=5 status=401
```

### Upstream Timeout

```
TRACE Fluxgate proxy: Request completed client_ip=192.168.1.100 method=POST request_url=/openai/v1/chat request_body_length=1024 api_key=pr target_url=https://api.openai.com/v1/chat upstream=openai-1 duration_ms=120000 status=504
```

