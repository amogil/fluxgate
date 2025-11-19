# Fluxgate

<div align="center">

**High-performance proxy for LLM providers**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-success?style=flat-square)](https://github.com/amogil/fluxgate)
[![Rust](https://img.shields.io/badge/rust-1.8+-orange.svg)](https://www.rust-lang.org/)
[![GitHub stars](https://img.shields.io/github/stars/amogil/fluxgate?style=flat-square&logo=github)](https://github.com/amogil/fluxgate/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/amogil/fluxgate?style=flat-square&logo=github)](https://github.com/amogil/fluxgate/network/members)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square&logo=linux)](https://github.com/amogil/fluxgate)

</div>

---

Fluxgate is a high-performance proxy that sits between client applications and large language model (LLM) providers. It centralizes request handling, enforces consistent policies, and minimizes end-to-end latency so downstream teams can focus on product features rather than platform plumbing.

## When you need Fluxgate

Fluxgate is ideal when you need to:

- 🔐 **Secure provider API keys away from clients** - Keep sensitive provider API keys (OpenAI, Anthropic, etc.) on the server side, never exposing them to client applications. Use one unified client API key for all providers, simplifying key management across your infrastructure. Rotate both client and provider keys independently without service disruption—update provider keys when they expire or are compromised, and rotate client keys for security compliance, all without downtime or application redeployment.

- 🚀 **Handle high-bandwidth workloads efficiently** - Process large payloads including images, audio, and video files without memory bottlenecks. Fluxgate streams data efficiently, avoiding buffering that can cause memory spikes or timeouts. Built with async Rust for microsecond-scale request handling, it maintains minimal memory footprint and latency overhead even under heavy load.

- 📊 **Monitor and analyze API usage** - Automatically log all requests with structured data for analysis, debugging, and monitoring. Track usage patterns, identify bottlenecks, audit access, and generate reports without instrumenting client applications.

- ⚡ **Update configuration without downtime** - Apply configuration changes instantly without service interruption. Update the YAML file and changes take effect within 1 second—no restarts, no dropped connections, no deployment overhead. Perfect for dynamic environments where you need to add new providers, update routing rules, or adjust authentication settings on the fly.

## ✨ Features

- **Ultra-Low Overhead** - Handles thousands of concurrent connections on modest hardware with typically less than 1ms added latency per request.
- **Centralized Access Management** - Rotate both client and provider keys independently without service disruption. Support for JWT tokens allows issuing client tokens with expiration times to ensure rotation. Client token rotation can be automated by external systems without changing proxy configuration.
- **Operationally Scalable** - Stateless workers linearly scale behind standard load-balancers; no sticky sessions required.
- **Request Fidelity** - Streams request and response bodies end-to-end, forwarding client semantics byte-for-byte—only rewriting the `Authorization` and `Host` headers when forwarding to upstream.
- **Request Logging** - Captures timestamps, client identifiers, provider endpoints, request/response sizes, status codes, and latency metrics. Outputs structured logs with key-value pairs for easy parsing and integration with log aggregation systems.
- **Zero-Downtime Configuration Updates** - Fluxgate monitors the configuration file and automatically reloads settings in the background. Active connections continue processing normally during updates.

## 🚀 Quick Start

1. **Create configuration file `fluxgate.yaml` with OpenAI provider:**

```yaml
version: 1

upstreams:
  openai:
    request_path: "/openai"
    target_url: "https://api.openai.com"
    api_key: "sk-proj-abc123xyz789"

api_keys:
  static:
    - id: my-key
      key: "<CLIENT_KEY>"
```

- Specify your OpenAI API key in the `upstreams` section.
- Generate any string as the client API key in the `api_keys.static` section.

2. **Build and run the container:**

```bash
docker build -t fluxgate:latest .
docker run -d -p 8080:8080 -v $(pwd)/fluxgate.yaml:/app/fluxgate.yaml fluxgate:latest
```

3. **Test it:**

```bash
curl -H "Authorization: Bearer <CLIENT_KEY>" http://localhost:8080/openai/v1/models
```

**Use with OpenAI SDK:**

```python
from openai import OpenAI

client = OpenAI(
    api_key="<CLIENT_KEY>",  # Your client API key from fluxgate.yaml
    base_url="http://localhost:8080/openai"
)

response = client.models.list()
```

Fluxgate can also be deployed as a standalone binary or using container orchestration platforms like Kubernetes, Docker Compose, and others. See the [Deployment Guide](docs/user/deployment.md) for complete deployment options and examples.

## 📖 Documentation

- **[Deployment Guide](docs/user/deployment.md)** - Complete deployment options: Docker, binary installation, Kubernetes, and orchestration platforms
- **[Configuration Guide](docs/user/configuration.md)** - Complete configuration reference, parameters, validation rules, hot reloading, and examples
- **[Authentication Guide](docs/user/authentication.md)** - Static API keys and JWT token authentication setup and usage
- **[Logging Guide](docs/user/logging.md)** - Log configuration, levels, structured fields, and observability

## 📝 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
