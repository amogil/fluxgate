# Fluxgate

Fluxgate is a high-performance proxy that sits between client applications and commercial large language model (LLM)
providers. It centralises request handling, enforces consistent policies, and minimises end-to-end latency so downstream
teams can focus on product features rather than platform plumbing.

## Why Fluxgate?

- **Consistent policy enforcement:** Apply authentication once at the proxy layer instead of duplicating logic in every
  client.
- **Ultra-low overhead:** Engineered for microsecond-scale request handling so model responses stay snappy.
- **Featherweight footprint:** Uses memory-efficient async Rust to keep resident set size and alloc churn to a minimum.
- **Operationally scalable:** Stateless workers linearly scale behind standard load-balancers; no sticky sessions
  required.
- **Secure-by-default:** All external traffic is TLS-protected end-to-end and secrets stay encrypted at rest.
- **Request fidelity:** Streams request and response bodies end-to-end, forwarding client semantics byte-for-byte—
  only rewriting the `Authorization` and `Host` headers when forwarding to upstream. The proxy does not support HTTP
  upgrade mechanisms (such as WebSocket) or the CONNECT method and will reject such requests with `501 Not Implemented`.
- **Observability built-in:** Native `tracing` instrumentation surfaces structured logs for request analytics.

## Running the proxy

Download the latest release bundle, extract it, and run the binary. Fluxgate ships as a single static executable with no
runtime dependencies.

```bash
$ ./fluxgate
```

Starts the proxy using the default configuration path (`fluxgate.yaml` in the current working directory`) and keeps
running until you stop it (Ctrl+C or your supervisor).

```bash
$ ./fluxgate --config /etc/fluxgate/fluxgate.yaml
```

Overrides the configuration path when launching the proxy.

Fluxgate automatically watches the configuration file and applies validated changes without requiring a restart. When a
running instance needs to pick up updates (for example, after pushing a new config via automation), it is sufficient to
write the new YAML to disk. The proxy will validate the revision and activate it automatically within 1 second. Invalid
configurations are rejected without interrupting the running process and the previous configuration is retained.

Prefer installing the binary under `/usr/local/bin` or a similar location and managing the process with systemd,
supervisord, or your orchestrator of choice.

To override log verbosity:

```bash
$ export FLUXGATE_LOG=info
```

To disable ANSI colouring in logs (useful for CI or scripted runs) set:

```bash
$ export FLUXGATE_LOG_STYLE=never
```

## Configuring Fluxgate

Configuration lives in a YAML file. The schema is defined in `src/config/mod.rs` and supports authentication
(static API keys and JWT tokens), multi-upstream routing, and HTTP/1.1 + HTTP/2 proxying. Authentication
is checked in order: static API keys are checked first, then JWT tokens if the token matches JWT format:

| Parameter                       | Default        | Required | Description                                                                                                                                                                                                                                                                                                                                                                                                         |
|---------------------------------|----------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `version`                       | `1`            | Required | Configuration schema version; must be set to `1`.                                                                                                                                                                                                                                                                                                                                                                   |
| `server.bind_address`           | `0.0.0.0:8080` | Optional | Socket address the proxy listens on.                                                                                                                                                                                                                                                                                                                                                                                |
| `server.max_connections`        | `1024`         | Optional | Upper bound on concurrent client connections. When this limit is reached, new connections must be rejected with HTTP 503.                                                                                                                                                                                                                                                                                           |
| `upstreams`                     | _None_         | Optional | Mapping of upstream identifiers to connection settings (may be omitted or empty).                                                                                                                                                                                                                                                                                                                                   |
| `upstreams.request_timeout_ms`  | `120000`       | Optional | Maximum end-to-end duration in milliseconds for the complete upstream request lifecycle. This timeout covers the entire request-to-response cycle: connection establishment (if needed), sending the request headers and body, waiting for the response, receiving response headers, and fully streaming the response body. If this timeout is exceeded at any point, the proxy returns HTTP 504 (Gateway Timeout). |
| `upstreams.<name>.target_url`   | _None_         | Required | Upstream endpoint URL (must be valid absolute URL using http/https).                                                                                                                                                                                                                                                                                                                                                |
| `upstreams.<name>.api_key`      | _None_         | Required | Non-empty API credential that replaces Authorization header.                                                                                                                                                                                                                                                                                                                                                        |
| `upstreams.<name>.request_path` | _None_         | Required | Request path prefix used to route requests to this upstream (must be a valid HTTP path starting with `/`, without host, port, scheme, or query string; must be unique across all configured upstreams).                                                                                                                                                                                                             |
| `api_keys`                      | _None_         | Optional | Collection of inbound authentication credentials (may be omitted or empty).                                                                                                                                                                                                                                                                                                                                         |
| `api_keys.static`               | _None_         | Optional | List of static client API keys (only permitted subsection within api_keys).                                                                                                                                                                                                                                                                                                                                         |
| `api_keys.static[].id`          | _None_         | Optional | Human-readable label for the API key (for observability only, used in logs).                                                                                                                                                                                                                                                                                                                                        |
| `api_keys.static[].key`         | _None_         | Required | API key value that clients must present via Authorization header (must be non-empty string).                                                                                                                                                                                                                                                                                                                        |
| `api_keys.static[].upstreams`   | Empty list     | Optional | List of upstream identifiers this key may access (must match configured upstream names). When empty or omitted, the API key has access to all configured upstreams. When empty and no upstreams are configured, requests with this API key are rejected with HTTP 401.                                                                                                                                              |
| `api_keys.jwt`                  | _None_         | Optional | List of JWT client API keys (may be omitted or empty).                                                                                                                                                                                                                                                                                                                                                              |
| `api_keys.jwt[].id`             | _None_         | Required | Human-readable label for the JWT API key (for observability only, used in logs). Must be non-empty and unique across all JWT API keys.                                                                                                                                                                                                                                                                              |
| `api_keys.jwt[].key`            | _None_         | Required | JWT API key value used for verifying JWT token signatures (must be non-empty string; may be duplicated across different JWT entries).                                                                                                                                                                                                                                                                               |

Example `fluxgate.yaml` (a copyable reference lives at `config/fluxgate.yaml`):

```yaml
version: 1

server:
  bind_address: "0.0.0.0:8080"
  max_connections: 1024

upstreams:
  request_timeout_ms: 120000
  openai-1:
    request_path: "/openai"
    target_url: "https://api.openai.com/v1"
    api_key: "sk-openai-key"
  anthropic-1:
    request_path: "/anthropic"
    target_url: "https://api.anthropic.com"
    api_key: "sk-ant-api-key"

api_keys:
  static:
    - id: pr
      key: 2qqwZ2MrffFMBguNMGVr
      upstreams:
        - openai-1
        - anthropic-1
    - id: marketing
      key: K1Rm67rX9vokI9sh555I
      upstreams:
        - anthropic-1
  jwt:
    - id: dev
      key: "REPLACE_WITH_JWT_SECRET_KEY"
    - id: test
      key: "REPLACE_WITH_JWT_SECRET_KEY"
```

All configurations undergo validation before activation. If the YAML file is missing or invalid at start-up, Fluxgate
boots with safe defaults. The proxy automatically watches the configuration file for changes and applies validated
updates when modifications are detected. When a change is detected, the configuration file is read and validated. If
validation succeeds, the new configuration is applied automatically; if validation fails, the update is rejected without
interrupting the running process and the previous configuration is retained. If the configuration file is inaccessible
during polling (deleted, permission denied, etc.), the proxy continues operating with the last valid configuration
and logs warnings about the file access issues.

## JWT Token Authentication

Fluxgate supports JWT (JSON Web Token) authentication as an alternative to static API keys. JWT tokens provide
time-limited access and can be dynamically generated by your authentication service.

### JWT Token Requirements

JWT tokens must meet the following requirements:

- **Format:** Three base64url-encoded parts separated by dots: `header.payload.signature`
- **Algorithm:** Must use `HS256` (HMAC-SHA256) for signature verification
- **Type:** Header must contain `typ: "JWT"`
- **Key ID:** Header must contain `kid` (key identifier) that matches one of the `id` values in `api_keys.jwt` configuration
- **Expiration:** Optional `exp` claim (Unix timestamp in seconds) - if present, token must not be expired
- **Not Before:** Optional `nbf` claim (Unix timestamp in seconds) - if present, current time must be >= nbf

### Creating JWT Tokens

JWT tokens must be signed using the secret key (`key`) from the matching `api_keys.jwt` entry. The `kid` in the token
header must match the `id` of the JWT key configuration entry.

Example JWT token structure:

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "dev"
  },
  "payload": {
    "exp": 1735689600,
    "nbf": 1735603200
  }
}
```

### Using JWT Tokens

Clients send JWT tokens in the `Authorization` header using the Bearer scheme:

```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRldiJ9..." \
  http://localhost:8080/openai/v1/models
```

### JWT Token Access Control

JWT tokens have access to **all configured upstreams** (similar to static API keys with empty or omitted `upstreams`).
If no upstreams are configured, requests with valid JWT tokens are rejected with HTTP 401.

### Authentication Order

The proxy checks authentication in the following order:

1. **Static API keys** (`api_keys.static`) - checked first for exact string match
2. **JWT tokens** (`api_keys.jwt`) - checked if token matches JWT format (three parts separated by dots)

This ensures static keys are validated quickly, and JWT validation (which is more expensive) only occurs when
the token is not a static key.
