# Configuration Management

## Configuration Loading

**C1.** The proxy must load configuration from a YAML file named `fluxgate.yaml` in the current working directory by
default, with support for overriding this path.

**Tags:** `config-loading`, `cli`

**C2.** Configuration files must be validated before activation; validation errors must be logged and prevent applying
the invalid configuration.

**Tags:** `config-validation`, `logging`

**C3.** The system must support hot-reloading configuration changes without requiring a restart. The proxy must
automatically watch the configuration file for changes and apply validated updates when modifications are detected (see
C9).

**Tags:** `hot-reload`, `config-loading`

**C4.** If the configuration file is missing or invalid at startup, the proxy must fall back to a safe, documented
default configuration. Default values are specified in the configuration parameters table (see C8). With this default
configuration, the proxy will start but will reject all requests with HTTP 401 since no API keys are configured. For
logging behavior when the configuration file is missing at startup, see F15.

**Tags:** `config-loading`, `error-handling`

**C4.2.** The proxy must not log the "Fluxgate proxy initialized" message when the configuration was not successfully
loaded from a file and default configuration is being used, as this message would be misleading since the configuration
was not loaded from the specified file path.

**Tags:** `config-loading`, `logging`

**C5.** Configuration must not be controlled via environment variables, except for observability-specific overrides
explicitly documented under Observability requirements.

**Tags:** `config-loading`

**C6.** Configuration file changes must be detected automatically when the file is modified (see C9). When a
change is detected, the configuration file is read and validated. If validation succeeds, the new configuration is
applied; if validation fails, the update is rejected without interrupting the running process and the previous
configuration is retained. If the configuration file is inaccessible during reload attempt (deleted, permission denied,
etc.), the reload attempt must fail, the previous configuration must be retained, and a warning must be logged.

**Tags:** `hot-reload`, `config-validation`, `error-handling`, `logging`

**C7.** The repository must provide a reference configuration at `config/fluxgate.yaml` that documents the `server`,
`upstreams`, and `api_keys` sections (including `api_keys.static` and `api_keys.jwt`), including sample values for
`bind_address`, `max_connections`,
`request_timeout_ms`, `request_path`, illustrative upstream identifiers, and placeholder credentials.

**Tags:** `config-loading`, `documentation`

## Configuration Parameters

**C8.** Configuration parameters must be the following:

| Parameter                       | Default        | Required | Description                                                                                                                                                                                                                                                                                                                                                                                                         |
|---------------------------------|----------------|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `version`                       | `1`            | Required | Configuration schema version; must be set to `1`                                                                                                                                                                                                                                                                                                                                                                    |
| `server`                        | _See defaults_ | Optional | Server configuration section<br>(may be omitted; when omitted, defaults are used for all server fields)                                                                                                                                                                                                                                                                                                             |
| `server.bind_address`           | `0.0.0.0:8080` | Optional | Socket address the proxy listens on                                                                                                                                                                                                                                                                                                                                                                                 |
| `server.max_connections`        | `1024`         | Optional | Upper bound on concurrent client connections<br>When this limit is reached, new connections must be rejected with HTTP 503                                                                                                                                                                                                                                                                                          |
| `upstreams`                     | _None_         | Optional | Mapping of upstream identifiers to connection settings<br>(may be omitted or empty)                                                                                                                                                                                                                                                                                                                                 |
| `upstreams.request_timeout_ms`  | `120000`       | Optional | Maximum end-to-end duration in milliseconds for the complete upstream request lifecycle. This timeout covers the entire request-to-response cycle: connection establishment (if needed), sending the request headers and body, waiting for the response, receiving response headers, and fully streaming the response body. If this timeout is exceeded at any point, the proxy returns HTTP 504 (Gateway Timeout). |
| `upstreams.<name>.target_url`   | _None_         | Required | Upstream endpoint URL (must be valid absolute URL using http/https)                                                                                                                                                                                                                                                                                                                                                 |
| `upstreams.<name>.api_key`      | _None_         | Required | Non-empty API credential that replaces Authorization header                                                                                                                                                                                                                                                                                                                                                         |
| `upstreams.<name>.request_path` | _None_         | Required | Request path prefix used to route requests to this upstream<br>(must be a valid HTTP path starting with `/`, without host, port, scheme, or query string)<br>(must be unique across all configured upstreams)                                                                                                                                                                                                       |
| `api_keys`                      | _None_         | Optional | Collection of inbound authentication credentials<br>(may be omitted or empty)                                                                                                                                                                                                                                                                                                                                       |
| `api_keys.static`               | _None_         | Optional | List of static client API keys                                                                                                                                                                                                                                                                                                                                                                                      |
| `api_keys.static[].id`          | _None_         | Optional | Human-readable label for the API key (for observability only, used in logs)<br>If specified, must be non-empty and unique across all API keys                                                                                                                                                                                                                                                                       |
| `api_keys.static[].key`         | _None_         | Required | API key value that clients must present via Authorization header<br>(must be non-empty string and unique across all API keys)                                                                                                                                                                                                                                                                                       |
| `api_keys.static[].upstreams`   | Empty list     | Optional | List of upstream identifiers this key may access<br>(must match configured upstream names)<br>When empty or omitted, the API key has access to all configured upstreams<br>When empty and no upstreams are configured, requests with this API key are rejected with HTTP 401                                                                                                                                        |
| `api_keys.jwt`                  | _None_         | Optional | List of JWT client API keys<br>(may be omitted or empty)                                                                                                                                                                                                                                                                                                                                                            |
| `api_keys.jwt[].id`             | _None_         | Required | Human-readable label for the JWT API key (for observability only, used in logs)<br>Must be non-empty and unique across all JWT API keys                                                                                                                                                                                                                                                                             |
| `api_keys.jwt[].key`            | _None_         | Required | JWT API key value used for verifying JWT token signatures<br>(must be non-empty string; may be duplicated across different JWT entries)                                                                                                                                                                                                                                                                             |

**Tags:** `config-validation`, `config-loading`

## Hot Reloading

**C9.** Configuration file changes must be detected automatically when the file is modified. The proxy must monitor the
configuration file for changes and detect when the file's modification time or content has changed. When a change is
detected, the file is read and validated, and if validation succeeds, the new configuration is applied automatically.

**Tags:** `hot-reload`, `config-loading`, `config-validation`

**C10.** Configuration polling must be performed in a separate background task to avoid blocking the main proxy
operation.

**Tags:** `hot-reload`, `performance`

**C11.** If the configuration file becomes inaccessible during runtime (deleted, permission denied, etc.) and polling
cannot read the file, the proxy must continue operating with the last valid configuration and log warnings about the
file access issues. Subsequent polling attempts may succeed if the file becomes accessible again. For details on logging
behavior (single warning per error condition, no log spam), see F16.

**Tags:** `hot-reload`, `error-handling`, `logging`

**Related Requirements:**

- F16: Logging behavior for missing/inaccessible configuration file during polling
- F17: No warning during polling if started with defaults

**C12.** Configuration updates must be applied atomically to prevent race conditions between polling, validation, and
request processing.

**Tags:** `hot-reload`, `config-validation`

**C13.** Loading a new configuration or encountering an error during configuration reload must not cause disconnection
of existing client connections. Active requests must continue to be processed using the configuration that was active
when the connection was established, or using the new configuration if it has been successfully applied before the
request arrives.

**Tags:** `hot-reload`, `connection-management`

**C14.** Configuration changes must be logged at INFO level. The log message must include structured fields: timestamp,
path, error (if validation failed), status, and cause. The log must indicate whether the update was successful or
rejected due to validation errors.

**Tags:** `hot-reload`, `logging`, `observability`

**C17.** The proxy must not log configuration reload messages when the configuration file has not actually changed. The
proxy must track the file's modification time and content hash from the initial load, and only log reload messages when
the file content has actually changed. False positive reload messages (e.g., triggered by the first polling cycle after
startup when the file is unchanged) must not be logged.

**Tags:** `hot-reload`, `logging`, `observability`

## Configuration Validation

**C15.** Configuration validation must ensure that `upstreams.<name>.request_path` is present, non-empty, starts with
`/`, does not contain scheme (`://`), query string (`?`), or host/port components. The `request_path` must be a valid
HTTP path component only (e.g., `/api/v1`, `/openai`). The colon character (`:`) is permitted within path segments (
e.g., `/api/v1:2` is valid) but must not be used as a port separator (e.g., `/api:8080` is invalid). The `request_path`
must be unique across all configured upstreams. Validation must reject configurations where `request_path` values are
duplicated or contain invalid characters.

**Tags:** `config-validation`, `path-matching`, `routing`

**C16.** Configuration validation must ensure that `api_keys.static[].key` values are unique across all configured API
keys. If duplicate `key` values are found, validation must reject the configuration. Additionally,
`api_keys.static[].id` is optional and may be omitted. When `api_keys.static[].id` is specified (not omitted), it must
be non-empty and unique across all API keys. Validation must reject configurations where `id` values are duplicated or
empty when specified.

**Tags:** `config-validation`, `authentication`

**C16.1.** Configuration validation must ensure that `api_keys.jwt[].id` is present, non-empty, and unique across all
JWT API keys. If duplicate `id` values are found within `api_keys.jwt`, validation must reject the configuration. If
`id` is missing or empty, validation must reject the configuration.

**Tags:** `config-validation`, `authentication`

**C16.2.** Configuration validation must ensure that `api_keys.jwt[].key` is present and non-empty. If `key` is missing
or empty, validation must reject the configuration. Unlike `api_keys.static[].key`, `api_keys.jwt[].key` values do not
need to be unique and may be duplicated across different JWT configuration entries. There is no conflict if
`api_keys.jwt[].key` values match `api_keys.static[].key` values, because static keys are checked first (as per F17.1),
and JWT tokens are validated using signature verification rather than direct string comparison.

**Tags:** `config-validation`, `authentication`

---

## Unit Tests

Unit tests for configuration requirements are organized in the following files:

- **`tests/unit/configuration.rs`** - Documentation and organization hub for configuration requirement tests
- **`tests/unit/config_manager.rs`** - Tests for C1-C17 (loading, validation, hot-reloading, ConfigManager)
- **`tests/unit/request_path_routing.rs`** - Tests for C15, C16 (request_path validation, api_keys validation)

