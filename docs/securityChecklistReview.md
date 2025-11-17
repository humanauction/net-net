# Stage 4 Security Review Checklist

## Authentication

- [✅] API endpoints require a token (Authorization header or query param).
- [✅] Token is not hardcoded in production; loaded from secure config.
- [✅] Token is long, random, and not guessable.

## Authorization

- [✅] Only authorized requests can access control endpoints (`/control/start`, `/control/stop`, `/control/reload`).
- [✅] Unauthorized requests receive 401 and are logged.

## Input Validation

- [✅] YAML config is validated for required fields.
- [✅] BPF filter strings are sanitized before applying.
- [✅] No user input is passed to system calls.

## Privilege Management

- [✅] Daemon can drop privileges after opening capture device (config: `drop_privileges`).
- [✅] User/group to drop to is configurable.
- [✅] Running as root is only required for capture, not for API.

## Network Exposure

- [✅] API bind address is configurable (default: `127.0.0.1`).
- [✅] API port is configurable.
- [✅] No unnecessary ports are open.

## Error Handling

- [✅] All exceptions are caught and logged.
- [✅] Sensitive errors are not exposed in API responses.

## Logging

- [✅] Auth failures and errors are logged.
- [✅] Log level and file are configurable.
- [✅] Logs do not contain sensitive data (e.g., tokens).

## Persistence

- [✅] SQLite database path is configurable.
- [✅] Database errors are handled gracefully.

## Denial of Service

- [✅] API server is single-threaded or uses a thread pool.
- [✅] Rate limiting is considered for control endpoints (optional).

## Testing

- [✅] Integration tests cover authorized and unauthorized access.
- [✅] Tests cover reload, start, stop, and metrics endpoints.
