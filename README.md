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

1. **Create configuration file `fluxgate.yaml` with two providers (OpenAI and Anthropic):**

```yaml
version: 1

server:
  bind_address: "0.0.0.0:8080"

upstreams:
  openai:
    request_path: "/openai"
    target_url: "https://api.openai.com"
    api_key: "sk-proj-abc123xyz789"
  anthropic:
    request_path: "/anthropic"
    target_url: "https://api.anthropic.com"
    api_key: "sk-ant-api03-abc123xyz789"

api_keys:
  static:
    - id: my-key
      key: "2qqwZ2MrffFMBguNMGVr"
```

- Specify your OpenAI and Anthropic API keys in the `upstreams` section.
- Generate any string as the client API key in the `api_keys.static` section.

2. **Build and run the container:**

```bash
docker build -t fluxgate:latest .
docker run -d -p 8080:8080 -v $(pwd)/fluxgate.yaml:/app/fluxgate.yaml fluxgate:latest
```

3. **Test it:**

```bash
curl -H "Authorization: Bearer 2qqwZ2MrffFMBguNMGVr" http://localhost:8080/openai/v1/models
```

**Use with OpenAI SDK:**

```python
from openai import OpenAI

client = OpenAI(
    api_key="2qqwZ2MrffFMBguNMGVr",  # Your client API key from fluxgate.yaml
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
