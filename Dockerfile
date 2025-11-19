# Requirement: OP3 - Production-ready Docker image
# Multi-stage build for minimal production image
# Build stage
FROM rust:1.83-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy dependency manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src/ src/

# Build release binary
RUN cargo build --release

# Runtime stage - using distroless for maximum security and minimal size
FROM gcr.io/distroless/cc-debian12:nonroot

# Create working directory
WORKDIR /app

# Copy binary to working directory
COPY --from=builder /app/target/release/fluxgate /app/fluxgate

# Use non-root user (distroless provides nonroot user)
USER nonroot:nonroot

# Expose default port (if needed, adjust based on config)
EXPOSE 8080

# Run the binary - expects fluxgate.yaml in current directory (/app)
# Mount your configuration file when running the container
ENTRYPOINT ["/app/fluxgate"]

