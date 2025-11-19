# Fluxgate

<div align="center">

**High-performance proxy for LLM providers**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.0+-orange.svg)](https://www.rust-lang.org/)
[![GitHub stars](https://img.shields.io/github/stars/amogil/fluxgate?style=flat-square&logo=github)](https://github.com/amogil/fluxgate/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/amogil/fluxgate?style=flat-square&logo=github)](https://github.com/amogil/fluxgate/network/members)
[![Status](https://img.shields.io/badge/status-active-success?style=flat-square)](https://github.com/amogil/fluxgate)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square&logo=linux)](https://github.com/amogil/fluxgate)

</div>

---

Fluxgate is a high-performance proxy that sits between client applications and large language model (LLM) providers. It centralizes request handling, enforces consistent policies, and minimizes end-to-end latency so downstream teams can focus on product features rather than platform plumbing.

## ✨ Features

- 🚀 **Ultra-Low Overhead** - Minimal memory footprint and latency overhead; engineered for microsecond-scale request handling with memory-efficient async Rust. Optimized for high-bandwidth workloads including images, audio, and video—stream large payloads efficiently without buffering bottlenecks
- 🔐 **Centralized Access Management** - Secure provider API keys away from clients; one unified key for all providers. Rotate both client and provider keys independently without service disruption
- 📈 **Operationally Scalable** - Stateless workers linearly scale behind standard load-balancers; no sticky sessions required
- 🔄 **Request Fidelity** - Streams request and response bodies end-to-end, forwarding client semantics byte-for-byte—only rewriting the `Authorization` and `Host` headers when forwarding to upstream
- 📝 **Request Logging** - All requests are automatically logged with structured data for subsequent analysis and monitoring
- ⚡ **Zero-Downtime Configuration Updates** - Apply configuration changes instantly without service interruption; update the YAML file and changes take effect within 1 second—no restarts, no dropped connections, no deployment overhead

## 🚀 Quick Start

### Installation

Download the latest release bundle, extract it, and run the binary. Fluxgate ships as a single static executable with no runtime dependencies.

### Running

Start the proxy with default configuration:

```bash
./fluxgate
```

This starts the proxy using `fluxgate.yaml` in the current working directory and keeps running until you stop it (Ctrl+C or your supervisor).

### Custom Configuration Path

```bash
./fluxgate --config /etc/fluxgate/fluxgate.yaml
```

### Process Management

Prefer installing the binary under `/usr/local/bin` or a similar location and managing the process with systemd, supervisord, or your orchestrator of choice.

## 📖 Documentation

- **[Configuration Guide](docs/user/configuration.md)** - Complete configuration reference, parameters, validation rules, and examples
- **[Authentication Guide](docs/user/authentication.md)** - Static API keys and JWT token authentication setup and usage
- **[Logging Guide](docs/user/logging.md)** - Log configuration, levels, structured fields, and observability

## ⚙️ Configuration

### Minimal Example

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

api_keys:
  static:
    - id: pr
      key: 2qqwZ2MrffFMBguNMGVr
      upstreams:
        - openai-1
```

A complete reference configuration is available at [`config/fluxgate.yaml`](config/fluxgate.yaml).

### Hot Reloading

Fluxgate automatically monitors the configuration file by periodically checking for changes and applies validated updates without requiring a restart. When you update the configuration file, the proxy will:

1. Detect the change within 1 second (next polling check)
2. Validate the new configuration
3. Apply it automatically if validation succeeds
4. Reject it and retain the previous configuration if validation fails

Invalid configurations are rejected without interrupting the running process.

## 🔧 Environment Variables

### Log Configuration

Override log verbosity:

```bash
export FLUXGATE_LOG=info
```

Disable ANSI coloring in logs (useful for CI or scripted runs):

```bash
export FLUXGATE_LOG_STYLE=never
```

**Default log level:** `TRACE` (when `FLUXGATE_LOG` is not set)

See the [Logging Guide](docs/user/logging.md) for detailed information about log levels, structured fields, and observability.

## 🔑 Authentication

Fluxgate supports two authentication methods:

- **Static API Keys** - Simple string-based authentication
- **JWT Tokens** - Time-limited tokens with signature verification

Both methods use the `Authorization` header with the Bearer scheme:

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  http://localhost:8080/openai/v1/models
```

See the [Authentication Guide](docs/user/authentication.md) for detailed setup and usage.

## ⚠️ Limitations

The proxy does not support HTTP upgrade mechanisms (such as WebSocket) or the CONNECT method and will reject such requests with `501 Not Implemented`.

## 📝 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
