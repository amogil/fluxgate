# Operational Requirements

OP1. The proxy must support graceful shutdown when receiving SIGTERM or SIGINT signals. During graceful shutdown, the
proxy must stop accepting new connections, complete processing of all active requests, and then terminate. Shutdown
events must be logged at INFO level.

**Tags:** `shutdown`, `logging`, `connection-management`, `observability`

OP2. The proxy must protect against HTTP request smuggling attacks by validating request structure and rejecting
malformed requests that could be exploited for smuggling. When a potential smuggling attempt is detected, the proxy must
reject the request and log a security warning at WARNING level.

**Tags:** `security`, `error-handling`, `http-400`, `logging`

