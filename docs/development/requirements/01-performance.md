# Performance

P1. The proxy must add the lowest feasible additional latency when processing requests.

**Tags:** `performance`, `latency`

P2. The architecture must support horizontal scaling via stateless workers.

**Tags:** `performance`, `scaling`, `architecture`

P3. The proxy must consume the lowest feasible memory footprint while proxying requests.

**Tags:** `performance`, `memory-management`

P4. The proxy must stream request bodies from clients to upstreams and responses from upstreams to clients whenever
protocol semantics permit, minimizing in-memory buffering to avoid unnecessary latency or memory pressure.

**Tags:** `performance`, `streaming`, `memory-management`

---

## Unit Tests

Unit tests for performance requirements are organized in the following files:

- **`tests/unit/performance.rs`** - Documentation and organization hub for performance requirement tests
- **`tests/unit/proxy.rs`** - Tests for P2 (ConnectionLimiter for horizontal scaling) and P4 (streaming via stream_request_body)

