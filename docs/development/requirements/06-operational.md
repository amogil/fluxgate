# Operational Requirements

OP1. The proxy must support graceful shutdown when receiving SIGTERM or SIGINT signals. During graceful shutdown, the
proxy must stop accepting new connections, complete processing of all active requests, and then terminate. Shutdown
events must be logged at INFO level.

**Tags:** `shutdown`, `logging`, `connection-management`, `observability`

OP2. The proxy must protect against HTTP request smuggling attacks by validating request structure and rejecting
malformed requests that could be exploited for smuggling. When a potential smuggling attempt is detected, the proxy must
reject the request and log a security warning at WARNING level.

**Tags:** `security`, `error-handling`, `http-400`, `logging`

OP3. The project must provide a production-ready Docker image that is maximally thin and minimal. The Docker image must
use multi-stage builds to minimize final image size, include only the compiled binary and essential runtime dependencies,
and use a minimal base image (such as distroless) for security and size optimization. The production Docker image must not
include build tools, development dependencies, or source code.

**Tags:** `deployment`, `platform`, `build-system`, `security`

