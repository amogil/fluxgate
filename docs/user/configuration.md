# Configuration

Fluxgate is configured using a YAML file. By default, the proxy looks for `fluxgate.yaml` in the current working directory, but you can override this path using the `--config` command-line option.

## Minimal Example

```yaml
version: 1

upstreams:
  request_timeout_ms: 120000
  openai:
    request_path: "/openai"
    target_url: "https://api.openai.com"
    api_key: "<OPENAI_KEY>"

api_keys:
  static:
    - id: pr
      key: "<CLIENT_KEY>"
      upstreams:
        - openai
```

This minimal configuration sets up:

- **`version`**: Configuration schema version (must be `1`)
- **`upstreams`**: Defines one upstream provider:
  - **`request_timeout_ms`**: Maximum request timeout (120 seconds)
  - **`openai`**: Upstream identifier for OpenAI API
    - **`request_path`**: Path prefix `/openai` that routes requests to this upstream
    - **`target_url`**: The actual OpenAI API endpoint (`https://api.openai.com`)
    - **`api_key`**: Provider API key that will be used to authenticate with OpenAI
- **`api_keys.static`**: Defines one client API key:
  - **`id`**: Human-readable label (`pr`) for observability
  - **`key`**: Client API key that clients must use in the Authorization header
  - **`upstreams`**: List of upstreams this key can access (only `openai` in this example)

With this configuration, clients can send requests to `http://localhost:8080/openai/*` using the client API key (`<CLIENT_KEY>`), and Fluxgate will proxy them to OpenAI's API using the provider API key (`<OPENAI_KEY>`).

## Configuration File Location

**Default location:** `fluxgate.yaml` in the current working directory

**Override location:**
```bash
./fluxgate --config /etc/fluxgate/fluxgate.yaml
```

## Hot Reloading

Fluxgate automatically monitors the configuration file by periodically checking for changes (polling every 1 second) and applies validated updates without requiring a restart. When you update the configuration file, the proxy will:

1. Detect the change within 1 second (on the next polling check)
2. Validate the new configuration
3. Apply it automatically if validation succeeds
4. Reject it and retain the previous configuration if validation fails

Invalid configurations are rejected without interrupting the running process. If the configuration file becomes inaccessible (deleted, permission denied, etc.), the proxy continues operating with the last valid configuration and logs warnings about the file access issues.

## Configuration Parameters

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

## Client API Keys

Fluxgate supports two types of client API keys for authenticating incoming requests: **static API keys** and **JWT tokens**. Both types use the `Authorization` header with the Bearer scheme.

### Bearer Authentication Scheme

All authentication must use the `Bearer` authentication scheme:

```
Authorization: Bearer <api_key_or_jwt_token>
```

Requests with non-Bearer authentication schemes (e.g., `Token`, `Basic`, `Digest`) are rejected with HTTP 401.

### Static API Keys

Static API keys are simple string values that clients present directly in the `Authorization` header. They provide a straightforward authentication mechanism suitable for server-to-server communication.

#### How Static Keys Work

1. **Configuration**: Static keys are defined in the `api_keys.static` section with a unique `key` value
2. **Authentication**: Clients send the exact key string in the `Authorization: Bearer <key>` header
3. **Validation**: The proxy performs an exact string match against configured static keys
4. **Access Control**: Each static key can be restricted to specific upstreams via the `upstreams` parameter

#### Structure

```yaml
api_keys:
  static:
    - id: pr                       # Optional: human-readable label for logs
      key: "<CLIENT_KEY>"          # Required: the actual key value
      upstreams:                   # Optional: list of allowed upstreams
        - openai
        - anthropic
```

- **`id`** (optional): A human-readable identifier used in logs for observability. If specified, must be unique across all static API keys
- **`key`** (required): The exact string value that clients must send. Must be unique across all static API keys
- **`upstreams`** (optional): List of upstream identifiers this key can access. When empty or omitted, the key has access to all configured upstreams. If `upstreams` is empty or omitted and no upstreams are configured, requests with this API key are rejected with HTTP 401

#### Usage Example

```bash
curl -H "Authorization: Bearer <CLIENT_KEY>" \
  http://localhost:8080/openai/v1/models
```

The proxy checks static keys first (before JWT tokens) for fast authentication. If the token doesn't match any static key and looks like a JWT (three parts separated by dots), it proceeds to JWT validation.

### JWT Tokens

JWT (JSON Web Token) tokens provide time-limited, cryptographically signed authentication. They are dynamically generated by your authentication service and include expiration and validity windows.

For an introduction to JWT tokens and how they work, see [jwt.io](https://jwt.io/introduction) or the [RFC 7519 specification](https://datatracker.ietf.org/doc/html/rfc7519).

#### How JWT Tokens Work

1. **Configuration**: JWT secret keys are defined in the `api_keys.jwt` section with an `id` and a `key` (secret)
2. **Token Generation**: Your authentication service creates JWT tokens signed with the secret key
3. **Token Structure**: JWT tokens consist of three base64url-encoded parts: `header.payload.signature`
4. **Authentication**: Clients send the complete JWT token in the `Authorization: Bearer <token>` header
5. **Validation**: The proxy validates the token's signature, algorithm, expiration, and key identifier

#### Structure

```yaml
api_keys:
  jwt:
    - id: dev                   # Required: must match 'kid' in JWT header
      key: "your-secret-key-at-least-32-bytes!"  # Required: min 32 bytes
    - id: test                  # Required: unique identifier
      key: "another-secret-key-32-bytes-min!"    # Can be same or different
```

- **`id`** (required): Must match the `kid` (key ID) field in the JWT token header. Must be unique across all JWT API keys
- **`key`** (required): The secret key used to sign and verify JWT tokens. **Must be at least 32 bytes** (256 bits) as required by RFC 7518 for HS256 algorithm. Can be duplicated across different JWT entries (allowing multiple `id` values to share the same secret)

#### JWT Token Requirements

JWT tokens must meet the following requirements:

- **Format:** Three base64url-encoded parts separated by dots: `header.payload.signature`
- **Algorithm:** Must use `HS256` (HMAC-SHA256) for signature verification
- **Type:** Header must contain `typ: "JWT"`
- **Key ID:** Header must contain `kid` (key identifier) that matches one of the `id` values in `api_keys.jwt` configuration
- **Expiration:** Optional `exp` claim (Unix timestamp in seconds) - if present, token must not be expired
- **Not Before:** Optional `nbf` claim (Unix timestamp in seconds) - if present, current time must be >= nbf

#### JWT Token Format

A JWT token has three parts separated by dots:

```
header.payload.signature
```

**Header** (base64url-encoded JSON):
```json
{
  "alg": "HS256",    // Must be HS256
  "typ": "JWT",      // Must be "JWT"
  "kid": "dev"       // Must match an api_keys.jwt[].id
}
```

**Payload** (base64url-encoded JSON):
```json
{
  "exp": 1735689600,  // Optional: expiration time (Unix timestamp)
  "nbf": 1735603200   // Optional: not-before time (Unix timestamp)
}
```

**Signature**: HMAC-SHA256 signature of `header.payload` using the secret key

#### Creating JWT Tokens

JWT tokens must be signed using the secret key (`key`) from the matching `api_keys.jwt` entry. The `kid` in the token header must match the `id` of the JWT key configuration entry.

#### Validation Process

The proxy validates JWT tokens in the following order:

1. **Parse token**: Split into header, payload, and signature parts
2. **Verify algorithm**: Check that `alg` is `HS256`
3. **Verify type**: Check that `typ` is `JWT`
4. **Match key ID**: Find a JWT key configuration where `id` matches the `kid` in the token header
5. **Verify signature**: Recompute the signature using the matching secret key and compare
6. **Check expiration**: If `exp` is present, ensure current time < expiration time
7. **Check not-before**: If `nbf` is present, ensure current time >= not-before time

If any step fails, the request is rejected with HTTP 401.

#### Usage Example

```bash
curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRldiJ9.eyJleHAiOjE3MzU2ODk2MDAsIm5iZiI6MTczNTYwMzIwMH0.signature" \
  http://localhost:8080/openai/v1/models
```

#### Access Control

JWT tokens **always have access to all configured upstreams**. Unlike static API keys, JWT tokens do not support the `upstreams` parameter to restrict access to specific upstreams. If no upstreams are configured, requests with valid JWT tokens are rejected with HTTP 401.

### Authentication Order

The proxy checks authentication in this order:

1. **Static API keys** - Checked first for exact string match (fast lookup)
2. **JWT tokens** - Checked only if the token looks like a JWT (three parts separated by dots)

This ensures static keys are validated quickly, and the more expensive JWT validation only occurs when necessary.

### Authentication Failures

The proxy rejects requests with HTTP 401 in the following cases:

- Missing `Authorization` header
- Non-Bearer authentication scheme
- Static API key not found in `api_keys.static`
- JWT token format invalid (not three parts separated by dots)
- JWT token validation fails (invalid signature, wrong algorithm, expired, etc.)
- API key's `upstreams` list is empty and no upstreams are configured
- API key refers to no permitted upstreams

### Request Routing After Authentication

After successful authentication, the proxy:

1. Resolves the target upstream based on the request path matching the `request_path` parameter
2. Replaces the outbound `Authorization` header with the upstream's configured API key
3. Forwards the request to the selected upstream
4. Streams the upstream response back to the client

If no upstream matches the request path, the proxy rejects the request with HTTP 404 (Not Found).

## Configuration Validation

All configurations undergo validation before activation. If the YAML file is missing or invalid at start-up, Fluxgate boots with safe defaults. The proxy will start but will reject all requests with HTTP 401 since no API keys are configured.

### Validation Rules

- **`request_path`**: Must start with `/`, must not contain scheme (`://`), query string (`?`), or host/port components. Must be unique across all configured upstreams.
- **`api_keys.static[].key`**: Must be unique across all static API keys.
- **`api_keys.static[].id`**: If specified, must be non-empty and unique across all static API keys.
- **`api_keys.jwt[].id`**: Must be present, non-empty, and unique across all JWT API keys.
- **`api_keys.jwt[].key`**: Must be present and non-empty (may be duplicated across different JWT entries).

## Default Configuration

If the configuration file is missing or invalid at startup, Fluxgate uses the following defaults:

- **`server.bind_address`**: `0.0.0.0:8080`
- **`server.max_connections`**: `1024`
- **`upstreams.request_timeout_ms`**: `120000` (120 seconds)
- **`upstreams`**: Empty (no upstreams configured)
- **`api_keys`**: Empty (no API keys configured)

With this default configuration, the proxy will start but will reject all requests with HTTP 401 since no API keys are configured.

## Environment Variables

Fluxgate supports environment variables for runtime configuration that cannot be set via the YAML configuration file.

### Log Configuration

Log verbosity can be controlled via the `FLUXGATE_LOG` environment variable:

```bash
export FLUXGATE_LOG=info
./fluxgate
```

**Default log level:** `TRACE` (when `FLUXGATE_LOG` is not set)

**Available log levels:** `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`

ANSI coloring of logs can be controlled via the `FLUXGATE_LOG_STYLE` environment variable:

```bash
export FLUXGATE_LOG_STYLE=never
./fluxgate
```

**Values:**
- `always` - Always use ANSI colors (default)
- `never` - Never use ANSI colors (useful for CI or scripted runs)

See the [Logging Guide](logging.md) for detailed information about log levels, structured fields, and observability.

## Limitations

The proxy does not support HTTP upgrade mechanisms (such as WebSocket) or the CONNECT method and will reject such requests with `501 Not Implemented`.

## Examples

### Multiple Upstream Providers

This example shows how to configure Fluxgate with multiple upstream providers (OpenAI, Anthropic, and DeepSeek):

```yaml
version: 1

server:
  bind_address: "0.0.0.0:8080"
  max_connections: 1024

upstreams:
  request_timeout_ms: 120000
  openai:
    request_path: "/openai"
    target_url: "https://api.openai.com"
    api_key: "<OPENAI_API_KEY>"
  anthropic:
    request_path: "/anthropic"
    target_url: "https://api.anthropic.com"
    api_key: "<ANTHROPIC_API_KEY>"
  deepseek:
    request_path: "/deepseek"
    target_url: "https://api.deepseek.com"
    api_key: "<DEEPSEEK_API_KEY>"

api_keys:
  static:
    - id: pr
      key: "<CLIENT_KEY_1>"
      upstreams:
        - openai
        - anthropic
    - id: dev
      key: "<CLIENT_KEY_2>"
      upstreams:
        - deepseek
    - id: admin
      key: "<CLIENT_KEY_3>"
      # No upstreams specified - access to all upstreams
```

With this configuration:
- Clients with `CLIENT_KEY_1` can access OpenAI and Anthropic APIs via `/openai/*` and `/anthropic/*` paths
- Clients with `CLIENT_KEY_2` can access DeepSeek API via `/deepseek/*` path
- Clients with `CLIENT_KEY_3` can access all three providers (OpenAI, Anthropic, and DeepSeek)

### JWT Token Authentication

This example shows how to configure Fluxgate using only JWT tokens for authentication:

```yaml
version: 1

server:
  bind_address: "0.0.0.0:8080"
  max_connections: 1024

upstreams:
  request_timeout_ms: 120000
  openai:
    request_path: "/openai"
    target_url: "https://api.openai.com"
    api_key: "<OPENAI_API_KEY>"
  anthropic:
    request_path: "/anthropic"
    target_url: "https://api.anthropic.com"
    api_key: "<ANTHROPIC_API_KEY>"
  deepseek:
    request_path: "/deepseek"
    target_url: "https://api.deepseek.com"
    api_key: "<DEEPSEEK_API_KEY>"

api_keys:
  jwt:
    - id: dev
      key: "<JWT_SECRET_KEY_1>"
    - id: test
      key: "<JWT_SECRET_KEY_2>"
```

With this configuration:
- Clients with JWT tokens signed with `JWT_SECRET_KEY_1` and `kid: "dev"` in the header can access all upstreams (OpenAI, Anthropic, and DeepSeek)
- Clients with JWT tokens signed with `JWT_SECRET_KEY_2` and `kid: "test"` in the header can access all upstreams
