# Functional Requirements

## Request Forwarding

**F1.** The proxy must forward client requests without mutating the HTTP method, URI, query parameters, body bytes, or
custom headers; the only permitted mutations are setting the `Authorization` header from configured upstream credentials,
setting the `Host` header to the correct value derived from the upstream's target URL, and stripping hop-by-hop headers
required by RFC 7230.

**Tags:** `request-forwarding`, `header-preservation`

**Related Requirements:**
- P4: Streaming to minimize buffering
- F12: Streaming semantics for HTTP/1.1 and HTTP/2

---

## Authentication & Routing

**F2.** The proxy must authenticate inbound requests using the client API key or JWT token from the `Authorization` header
(if authentication is required). The authentication may use either a static API key from `api_keys.static` or a JWT token
from `api_keys.jwt`. The order of authentication attempts is specified in F17.1. After successful authentication, the proxy
must resolve the target upstream according to the request path matching the `request_path` parameter configured for each
upstream, replace the outbound `Authorization` header with the upstream's configured API key, forward the request to the
selected upstream, and stream the upstream response back to the client. The proxy must match the request URI path (excluding
query string) against the `request_path` values of all upstreams accessible to the authenticated API key (or all upstreams
if authentication is not required) and select the upstream whose `request_path` is a prefix of the request path. Path
matching must be performed after normalizing trailing slashes (treating `/path` and `/path/` as equivalent for matching
purposes, but preserving the original path when forwarding to upstream). If multiple upstreams have matching `request_path`
values, the proxy must select the upstream with the longest matching `request_path`. If no upstream matches the request path,
the proxy must reject the request with HTTP 404 (Not Found). Authentication failures must be handled before path matching
(see F3, F17.1, F18-F24).

**Tags:** `authentication`, `routing`, `path-matching`

**Related Requirements:**
- F3: Authentication failure handling
- F17.1: Order of authentication attempts (JWT vs static API key)
- C8: Configuration parameters
- C15: request_path validation

---

## Authentication Failure Handling

**F3.** The proxy must reject requests with HTTP 401 when the inbound `Authorization` header is missing, when the supplied
API key is not defined under `api_keys.static` and the token is not a valid JWT token from `api_keys.jwt`, when the API
key's `upstreams` list is empty and no upstreams are configured, when the API key refers to no permitted upstreams, or
when the configuration does not define any upstreams accessible to the API key. For JWT token authentication failures,
see requirements F18-F24. When `api_keys.static[].upstreams` is empty or omitted and upstreams are configured, the API
key has access to all configured upstreams. When `api_keys.static[].upstreams` is empty and no upstreams are configured,
requests with this API key must be rejected with HTTP 401. JWT tokens from `api_keys.jwt` have access to all configured
upstreams (similar to static API keys with empty or omitted `upstreams`). When JWT token authentication succeeds but no
upstreams are configured, requests with this JWT token must be rejected with HTTP 401. The proxy must reject requests with HTTP 404
(Not Found) when no upstream's `request_path` matches the request URI path.

**Tags:** `authentication`, `error-handling`, `http-401`, `http-404`

**Related Requirements:**
- F2: Authentication and routing (F3 handles failures before F2 routing)
- F5: Bearer authentication scheme
- F18-F24: JWT token authentication

---

## Response Forwarding

**F4.** The proxy must relay the upstream HTTP status code, response headers (excluding hop-by-hop headers as per RFC 7230),
and response body verbatim back to the client.

**Tags:** `request-forwarding`, `response-forwarding`

---

## Bearer Authentication Scheme

**F5.** The proxy must only accept `Authorization` headers using the `Bearer` authentication scheme (format:
`Bearer <api_key_or_jwt_token>`). The Bearer token may be either a static API key (from `api_keys.static`) or a JWT token
(from `api_keys.jwt`). Requests with non-Bearer authentication schemes (e.g., `Token`, `Basic`, `Digest`, or any other
scheme) must be rejected with HTTP 401.

**Tags:** `bearer-auth`, `authentication`, `http-401`

---

## JWT Token Authentication

**F17.1.** When authenticating a Bearer token, the proxy must first attempt to authenticate it as a static API key from
`api_keys.static`. If the token does not match any static API key, the proxy must then attempt to parse it as a JWT token by
checking if it consists of three base64url-encoded parts separated by dots (header.payload.signature format). If the token
can be parsed as a JWT token, the proxy must validate it according to requirements F18-F24. This ensures that static API keys
are checked first (simpler and faster lookup), and JWT tokens are only validated if the token is not a static API key.

**Tags:** `authentication`, `jwt-auth`, `bearer-auth`

**F18.** When authenticating requests using JWT tokens, the proxy must parse the JWT token from the `Authorization` header
using the Bearer scheme. The JWT token must be a valid JWT token consisting of three base64url-encoded parts separated by
dots (header.payload.signature). If the JWT token cannot be parsed or is malformed, the proxy must reject the request with
HTTP 401.

**Tags:** `jwt-auth`, `authentication`, `http-401`

**F19.** The JWT token header must contain the `alg` (algorithm) field, and it must be set to `HS256`. If the `alg` field is
missing, has an unsupported value, or is set to any value other than `HS256`, the proxy must reject the request with HTTP
401.

**Tags:** `jwt-auth`, `authentication`, `http-401`, `jwt-header`

**F20.** The JWT token header must contain the `typ` (type) field, and it must be set to `JWT`. If the `typ` field is missing
or has any value other than `JWT`, the proxy must reject the request with HTTP 401.

**Tags:** `jwt-auth`, `authentication`, `http-401`, `jwt-header`

**F21.** The JWT token header must contain the `kid` (key ID) field, and it must match one of the `id` values defined in the
`api_keys.jwt` configuration section. The proxy must use the corresponding `key` value from the matching JWT configuration
entry to verify the token signature. If the `kid` field is missing, empty, or does not match any configured JWT key ID, the
proxy must reject the request with HTTP 401.

**Tags:** `jwt-auth`, `authentication`, `http-401`, `jwt-header`, `jwt-signature`

**F22.** The proxy must verify the JWT token signature using the `key` value from the `api_keys.jwt` configuration entry
whose `id` matches the `kid` field in the token header. The signature verification must use the HS256 algorithm. If the
signature verification fails, the proxy must reject the request with HTTP 401.

**Tags:** `jwt-auth`, `authentication`, `http-401`, `jwt-signature`

**F23.** If the JWT token payload contains the `exp` (expiration time) claim, the proxy must verify that the current time is
before the expiration time. The `exp` claim must be a numeric value representing the number of seconds since the Unix epoch
(1970-01-01T00:00:00Z). If the token has expired (current time >= exp), the proxy must reject the request with HTTP 401.

**Tags:** `jwt-auth`, `authentication`, `http-401`, `jwt-payload`, `jwt-expiration`

**F24.** If the JWT token payload contains the `nbf` (not before) claim, the proxy must verify that the current time is at or
after the not-before time. The `nbf` claim must be a numeric value representing the number of seconds since the Unix epoch
(1970-01-01T00:00:00Z). If the token is not yet valid (current time < nbf), the proxy must reject the request with HTTP
401.

**Tags:** `jwt-auth`, `authentication`, `http-401`, `jwt-payload`, `jwt-not-before`

---

## Error Handling

**F6.** The proxy must return HTTP 400 (Bad Request) when it receives malformed HTTP requests that cannot be parsed or
processed.

**Tags:** `error-handling`, `http-400`

**F7.** The proxy must return HTTP 502 (Bad Gateway) when the upstream server is unreachable, when upstream connection
failures occur, or when upstream SSL/TLS errors are encountered.

**Tags:** `error-handling`, `http-502`

**F8.** The proxy must return HTTP 503 (Service Unavailable) when the proxy is unable to process requests due to resource
exhaustion (such as memory pressure) or when the maximum connection limit (`server.max_connections`) is reached and new
connections cannot be accepted.

**Tags:** `error-handling`, `http-503`, `connection-management`

**F9.** The proxy must return HTTP 504 (Gateway Timeout) when the upstream server does not respond within the configured
timeout period (`upstreams.request_timeout_ms`).

**Tags:** `error-handling`, `http-504`, `timeout`

**F10.** All error responses specified in requirements F6 through F9 must be properly formatted HTTP responses that are
successfully delivered to the client. The proxy must not return empty responses or fail to send error responses to clients.
Error responses must include the appropriate HTTP status code, standard HTTP headers, and may include an empty body.

**Tags:** `error-handling`, `response-delivery`, `http-responses`

---

## HTTP Protocol Support

**F11.** The proxy must support HTTP/1.1 and HTTP/2 for inbound client connections. Requests using any other HTTP version
(including HTTP/1.0 and HTTP/3) must be rejected with HTTP 505 (HTTP Version Not Supported).

**Tags:** `http-protocol`, `http-505`

**F12.** For each accepted client request, the proxy must use the same HTTP protocol version when establishing connections
to upstream servers whenever the upstream endpoint supports it. HTTP/1.1 client requests must be proxied over HTTP/1.1
upstream connections, and HTTP/2 client requests must be proxied over HTTP/2 upstream connections. When an upstream
cannot negotiate the client's protocol version, the proxy must reject the request with HTTP 502 rather than silently
downgrading or upgrading protocol versions.

**Tags:** `http-protocol`, `http-502`

---

## Streaming

**F13.** In alignment with performance requirement P4, the proxy must stream request and response bodies without loading
them fully into memory whenever possible. For HTTP/1.1, the proxy must support `Transfer-Encoding: chunked` for both
inbound and outbound messages. For HTTP/2, the proxy must preserve streaming semantics by forwarding data using HTTP/2
data frames as they are received, subject to flow control and backpressure.

**Tags:** `streaming`, `performance`, `memory-management`

**Related Requirements:**
- P4: Streaming to minimize buffering

---

## Protocol Restrictions

**F14.** The proxy must not support HTTP/1.1 Upgrade-based protocols (such as WebSocket) or the CONNECT method for
establishing arbitrary tunnels. Requests that require protocol upgrade or use the CONNECT method must be rejected with
HTTP 501 (Not Implemented). The proxy must ensure that partial upgrade handshakes are not forwarded to upstreams.

**Tags:** `http-protocol`, `http-501`, `security`

---

## Configuration Logging

**F15.** When the configuration file is missing or cannot be loaded at startup, the proxy must log a single WARNING-level
message indicating that default configuration is being used due to load failure. The message must not be logged as an
error, as using default configuration is an acceptable fallback behavior. The log message must include structured fields:
timestamp, path, error, status, and cause. The proxy must not log duplicate messages (e.g., both INFO and WARN) for the
same configuration load failure event.

**Tags:** `config-loading`, `logging`, `observability`, `error-handling`

**Related Requirements:**
- C4: Default configuration fallback
- O3: INFO-level logging for significant actions
- O4: WARNING-level logging for problematic situations

**F16.** When the configuration file is missing or inaccessible during runtime polling, the proxy must log a WARNING-level
message only once per error condition. The log message must include structured fields: timestamp, path, error, status, and
cause. The proxy must not spam logs with repeated warnings for the same persistent error condition (e.g., missing file).
The warning must be logged again only if the file becomes accessible and then inaccessible again, allowing operators to
detect when the file status changes.

**Tags:** `hot-reload`, `logging`, `observability`, `error-handling`

**Related Requirements:**
- C11: Configuration file access issues during polling
- O4: WARNING-level logging for problematic situations

**F17.** If the proxy started with default configuration because the configuration file was missing at startup (as per C4 and
F15), the proxy must not log WARNING-level messages during polling when the file is still missing. The proxy must only log
WARNING-level messages during polling if it previously had a valid configuration file that became inaccessible. This
prevents redundant warnings when the proxy is intentionally running without a configuration file.

**Tags:** `hot-reload`, `logging`, `observability`, `error-handling`, `config-loading`

**Related Requirements:**
- C4: Default configuration fallback
- F15: Single WARNING message for missing config at startup
- F16: Single WARNING message per error condition during polling

---

## Unit Tests

Unit tests for functional requirements are organized in the following files:

- **`tests/unit/functional.rs`** - Documentation and organization hub for functional requirement tests
- **`tests/unit/proxy.rs`** - Tests for F1 (URL building, header handling), F11 (HTTP protocol support), F14 (CONNECT/Upgrade)
- **`tests/unit/request_path_routing.rs`** - Tests for F1, F2, F3 (path matching, routing, authentication)
- **`tests/unit/config_manager.rs`** - Tests for F1, F3 (authentication, authenticate method)
- **`tests/unit/jwt_auth.rs`** - Tests for F18-F24 (JWT token authentication, header validation, signature verification, expiration checks)

