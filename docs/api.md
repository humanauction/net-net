# net-net REST API Documentation

Base URL: `http://localhost:8082`

## Authentication

Two authentication methods supported:

1. **API Token** (for scripts/automation):
   - Header: `Authorization: Bearer <token>`
   - Query param: `?token=<token>`

2. **Session Token** (for web UI):
   - Header: `X-Session-Token: <token>`
   - Obtained via `/login` endpoint

---

## Endpoints

### `POST /login`

Authenticate user and create session.

**Request:**

```json
{
  "username": "admin",
  "password": "adminpass"
}
```

**Response (200 OK):**

```json
{
  "token": "a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6",
  "username": "admin",
  "expires_in": 3600
}
```

**Response (401 Unauthorized):**

```json
{
  "error": "invalid credentials"
}
```

---

### `POST /logout`

Invalidate session token.

**Headers:**

```http
X-Session-Token: <token>
```

**Response (200 OK):**

```json
{
  "status": "logged out"
}
```

**Response (401 Unauthorized):**

```json
{
  "error": "invalid session"
}
```

---

### `GET /metrics`

Get current network statistics (updated every aggregation window).

**Headers:**

```http
X-Session-Token: <token>
```

OR

```http
Authorization: Bearer <api_token>
```

**Response (200 OK):**

```json
{
  "window_start": "2025-11-21T10:30:00Z",
  "window_end": "2025-11-21T10:30:10Z",
  "total_bytes": 1234567,
  "total_packets": 8901,
  "protocols": {
    "tcp": 5000,
    "udp": 3000,
    "icmp": 901
  },
  "top_flows": [
    {
      "src_ip": "192.168.1.100",
      "dst_ip": "8.8.8.8",
      "src_port": 54321,
      "dst_port": 443,
      "protocol": "tcp",
      "bytes": 45000,
      "packets": 120
    }
  ]
}
```

**Response (401 Unauthorized):**

```json
{
  "error": "unauthorized"
}
```

---

### `POST /control/start`

Start packet capture (if stopped).

**Headers:**

```http
Authorization: Bearer <api_token>
```

OR

```http
X-Session-Token: <token>
```

**Response (200 OK):**

```json
{
  "status": "started",
  "interface": "en0"
}
```

**Response (429 Too Many Requests):**

```json
{
  "error": "rate limit exceeded"
}
```

**Note:** Rate limited to 1 request per 2 seconds per client.

---

### `POST /control/stop`

Stop packet capture.

**Headers:**

```http
Authorization: Bearer <api_token>
```

OR

```http
X-Session-Token: <token>
```

**Response (200 OK):**

```json
{
  "status": "stopped"
}
```

**Response (429 Too Many Requests):**

```json
{
  "error": "rate limit exceeded"
}
```

**Note:** Rate limited to 1 request per 2 seconds per client.

---

### `POST /control/reload`

Reload configuration from YAML file (hot-reload without restarting daemon).

**Headers:**

```http
Authorization: Bearer <api_token>
```

OR

```http
X-Session-Token: <token>
```

**Response (200 OK):**

```json
{
  "status": "reloaded",
  "config_path": "/etc/net-net/config.yaml"
}
```

**Response (500 Internal Server Error):**

```json
{
  "error": "failed to reload config",
  "details": "YAML parse error at line 42"
}
```

**Response (429 Too Many Requests):**

```json
{
  "error": "rate limit exceeded"
}
```

**Note:** Rate limited to 1 request per 2 seconds per client.

---

## Rate Limiting

Control endpoints (`/control/*`) are rate-limited to **1 request per 2 seconds per client IP**.

Exceeding this limit returns `429 Too Many Requests`.

---

## Session Expiry

Sessions expire after **1 hour of inactivity** (configurable via `api.session_expiry` in config).

Each authenticated request refreshes the session's `last_activity` timestamp.

Expired sessions return `401 Unauthorized` and require re-login.

---

## Error Responses

All error responses follow this format:

```json
{
  "error": "error message here"
}
```

Common status codes:

- `400` - Bad request (malformed JSON, missing fields)
- `401` - Unauthorized (invalid/expired token)
- `429` - Rate limit exceeded
- `500` - Internal server error
