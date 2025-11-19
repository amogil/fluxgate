# Use Rust official image as base
FROM rust:1.83-slim

# Install required dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo.toml and Cargo.lock first for better caching
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src/ src/
COPY tests/ tests/
COPY config/ config/
COPY docs/ docs/
COPY scripts/ scripts/

# Build the project in debug mode for testing
RUN cargo build

# Run tests
CMD ["cargo", "test", "--test", "functional", "--", "--nocapture"]
