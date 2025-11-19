# Fluxgate Makefile
# Convenience commands for development and testing

.PHONY: help build test test-functional test-unit clean fmt check docs

help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-15s %s\n", $$1, $$2}'

build: ## Build the project in debug mode
	cargo build

release: ## Build the project in release mode
	cargo build --release

test: test-unit test-functional ## Run all available tests

test-functional: ## Run functional tests in Docker
	./run-tests-docker.sh

test-unit: ## Run unit tests natively
	@echo "🧪 Running unit tests..."
	cargo test --test unit

fmt: ## Format code with rustfmt
	cargo fmt

check: ## Run cargo check
	cargo check

clippy: ## Run clippy lints
	cargo clippy -- -D warnings

clean: ## Clean build artifacts
	cargo clean
	# Remove Docker test image if it exists (ignore errors if it doesn't)
	docker rmi fluxgate-test 2>/dev/null || true

run: ## Run the proxy with default config
	cargo run --bin fluxgate

validate-requirements-quality: ## Validate requirements completeness and consistency
	cargo run --bin validate-requirements-quality

validate-requirements-coverage: ## Validate requirements coverage and reference validity
	cargo run --bin validate-requirements-coverage

validate-requirements: validate-requirements-quality validate-requirements-coverage ## Validate requirements quality and coverage

find-requirement: ## Find a requirement by ID or tag (usage: make find-requirement REQ=F2 or make find-requirement TAG=authentication)
	@if [ -n "$(REQ)" ]; then \
		cargo run --bin find-requirement $(REQ); \
	elif [ -n "$(TAG)" ]; then \
		cargo run --bin find-requirement -- --tag $(TAG); \
	else \
		echo "Usage: make find-requirement REQ=F2 or make find-requirement TAG=authentication"; \
	fi

validate: fmt check validate-requirements clippy test-unit ## Run full validation suite (format, check, requirements, clippy, unit tests)

full-validate: validate test-functional ## Run complete validation including functional tests
