# Deployment Guide

Fluxgate can be deployed in several ways depending on your infrastructure and requirements.

## Docker (Recommended)

Fluxgate provides a production-ready Docker image built with multi-stage builds for minimal size and maximum security. The image uses a distroless base and runs as a non-root user.

### Building the Image

```bash
docker build -t fluxgate:latest .
```

### Running with Configuration

The executable is located at `/app/fluxgate` and expects `fluxgate.yaml` in the same directory (`/app/fluxgate.yaml`). The proxy automatically uses `fluxgate.yaml` from the current working directory.

**Run with configuration file (mount your config):**

```bash
docker run -d \
  -p 8080:8080 \
  -v /path/to/your/fluxgate.yaml:/app/fluxgate.yaml \
  fluxgate:latest
```

**Override configuration path:**

```bash
docker run -d \
  -p 8080:8080 \
  -v /path/to/your/config:/app/custom \
  fluxgate:latest \
  --config /app/custom/fluxgate.yaml
```

### Docker Image Features

The Docker image is optimized for production use:
- **Minimal size** - Multi-stage build with distroless base image
- **Secure** - Runs as non-root user with minimal attack surface
- **No build tools** - Only includes the compiled binary and essential runtime dependencies

## Binary Installation

Fluxgate ships as a single static executable with no runtime dependencies. You can download the latest release bundle, extract it, and run the binary directly.

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

## Container Orchestration

### Kubernetes

Deploy Fluxgate using the Docker image in Kubernetes:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fluxgate
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fluxgate
  template:
    metadata:
      labels:
        app: fluxgate
    spec:
      containers:
      - name: fluxgate
        image: fluxgate:latest
        ports:
        - containerPort: 8080
        volumeMounts:
        - name: config
          mountPath: /app/fluxgate.yaml
          subPath: fluxgate.yaml
      volumes:
      - name: config
        configMap:
          name: fluxgate-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluxgate-config
data:
  fluxgate.yaml: |
    version: 1
    server:
      bind_address: "0.0.0.0:8080"
    # ... rest of configuration
```

### Docker Compose

```yaml
version: '3.8'
services:
  fluxgate:
    image: fluxgate:latest
    ports:
      - "8080:8080"
    volumes:
      - ./config/fluxgate.yaml:/app/fluxgate.yaml
    restart: unless-stopped
```

### Other Orchestration Platforms

Fluxgate can be deployed on any container orchestration platform that supports Docker images:
- **Nomad** - Use the Docker driver
- **ECS** - Deploy as a Docker container task
- **Cloud Run** - Deploy as a container service
- **Fly.io** - Deploy using the Dockerfile
- **Railway** - Deploy from Dockerfile

The key requirements are:
- Mount the configuration file to `/app/fluxgate.yaml` (or use `--config` to specify a different path)
- Expose port 8080 (or the port configured in your `bind_address`)
- Ensure the configuration file is accessible and valid

