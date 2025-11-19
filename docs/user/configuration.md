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

A complete reference configuration is available at [`config/fluxgate.yaml`](../../config/fluxgate.yaml).

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

## Example Configuration

A complete example configuration file is available at `config/fluxgate.yaml`. Here's a sample:

```yaml
version: 1

server:
  bind_address: "0.0.0.0:8080"
  max_connections: 1024

upstreams:
  request_timeout_ms: 120000
  openai-1:
    request_path: "/openai"
    target_url: "https://api.openai.com"
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

## Configuration Validation

All configurations undergo validation before activation. If the YAML file is missing or invalid at start-up, Fluxgate boots with safe defaults. The proxy will start but will reject all requests with HTTP 401 since no API keys are configured.

### Validation Rules

- **`request_path`**: Must start with `/`, must not contain scheme (`://`), query string (`?`), or host/port components. Must be unique across all configured upstreams.
- **`api_keys.static[].key`**: Must be unique across all configured API keys.
- **`api_keys.static[].id`**: If specified, must be non-empty and unique across all API keys.
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

