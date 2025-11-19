#!/bin/bash

# Script to run functional tests in Docker

set -e

echo "🚀 Building and running functional tests in Docker..."

# Build the test image
echo "📦 Building Docker image..."
docker build -f test.Dockerfile -t fluxgate-test .

# Run the tests
echo "🧪 Running functional tests..."
docker run --rm fluxgate-test:latest

echo "✅ Tests completed successfully!"