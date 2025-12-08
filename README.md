# net-net

[![CI/CD Pipeline](https://github.com/humanauction/net-net/actions/workflows/ci.yml/badge.svg)](https://github.com/humanauction/net-net/actions/workflows/ci.yml)

Real-Time Network Monitor with Web Dashboard

## Overview

A high-performance, modular network monitoring daemon written in C++17 that captures packets, tracks active connections, and aggregates bandwidth and protocol statistics in real-time. Features a modern web-based dashboard with live visualizations, session-based authentication, and a REST API for programmatic access.

**Key Features:**

- 📊 Real-time bandwidth visualization (D3.js line charts)
- 🔐 Secure session-based authentication with bcrypt
- 🌐 Modern web dashboard with live updates
- 📈 Protocol breakdown pie charts (TCP/UDP/OTHER)
- 🔌 Active connection tracking and display
- 🛡️ Privilege dropping for security
- 📦 SQLite persistence for historical data
- ⚡ Sub-second latency metrics

---

## 🚀 Quick Start

### Prerequisites

- **macOS/Linux** with libpcap installed
- **C++17** compiler (clang++ or g++)
- **CMake 3.16+**
- **Python 3.x** with pip (for integration tests)
- **Root/sudo access** (for packet capture)

### Build & Run

```bash
# Clone repository
git clone https://github.com/humanauction/net-net.git
cd net-net

# Build daemon
make clean
make

# Start daemon (requires sudo for packet capture)
sudo ./build/netnet-daemon --config examples/sample-config.yaml

# Open dashboard in browser
open http://localhost:8082
```

### Default Credentials

- **Username:** `admin`
- **Password:** `adminpass`

⚠️ **Change default passwords in production!** See [Configuration](#️-configuration) section.

---

## 📸 Screenshots

### Dashboard Overview

![Dashboard](docs/screenshots/dashboard.png)
*Real-time bandwidth monitoring with protocol breakdown and active connections*

### Login Screen

![Login](docs/screenshots/login.png)
*Secure session-based authentication*

---

## 🏗️ Architecture

```text
┌─────────────────────────────────────────────────────┐
│                  Web Dashboard                      │
│         (HTML/CSS/JavaScript + D3.js)               │
└───────────────────────┬─────────────────────────────┘
                        │ REST API (HTTP)
┌──────────────────▼──────────────────────────────────┐
│                NetMonDaemon (C++)                   │
│   ┌─────────────────────────────────────────────┐   │
│   │  SessionManager (bcrypt + SQLite)           │   │
│   └─────────────────────────────────────────────┘   │
│   ┌─────────────────────────────────────────────┐   │
│   │  REST API (cpp-httplib)                     │   │
│   │  • /login, /logout, /metrics                │   │
│   │  • /control/{start,stop,reload}             │   │
│   └─────────────────────────────────────────────┘   │
│   ┌─────────────────────────────────────────────┐   │
│   │  StatsAggregator (Metrics)                  │   │
│   └─────────────────────────────────────────────┘   │
│   ┌─────────────────────────────────────────────┐   │
│   │  ConnectionTracker (Flow State)             │   │
│   └─────────────────────────────────────────────┘   │
│   ┌─────────────────────────────────────────────┐   │
│   │  Parser (Ethernet/IPv4/TCP/UDP/ICMP)        │   │
│   └─────────────────────────────────────────────┘   │
│   ┌─────────────────────────────────────────────┐   │
│   │  PcapAdapter (libpcap wrapper)              │   │
│   └─────────────────────────────────────────────┘   │
└───────────────────────┬─────────────────────────────┘
                        │
                ┌───────▼─────────┐
                │    Network      │
                │    Interface    │
                │   (en0, eth0)   │
                └─────────────────┘
```

See [docs/design.md](docs/design.md) for detailed architecture documentation.

---

## 📋 Project Structure

```text
net-net/
├── src/                          # C++ source code
│   ├── Main.cpp                  # Entry point
│   ├── core/                     # Core monitoring logic
│   │   ├── Parser.{cpp,h}        # Packet parsing (Ethernet→IP→TCP/UDP)
│   │   ├── ConnectionTracker.{cpp,h}  # Flow tracking
│   │   ├── StatsAggregator.{cpp,h}    # Metrics aggregation
│   │   ├── StatsPersistence.{cpp,h}   # SQLite storage
│   │   ├── SessionManager.{cpp,h}     # Authentication
│   │   └── PacketMeta.h          # Packet metadata structures
│   ├── net/                      # Network adapters
│   │   └── PcapAdapter.{cpp,h}   # libpcap wrapper
│   └── daemon/                   # Daemon implementation
│       ├── NetMonDaemon.{cpp,h}  # Main daemon class
│       └── (ConfigLoader merged into NetMonDaemon)
├── www/                          # Web dashboard
│   ├── index.html                # Dashboard UI
│   ├── style.css                 # Styling
│   └── app.js                    # JavaScript (D3.js + Chart.js)
├── include/net-net/vendor/       # Third-party code
│   ├── bcrypt.{cpp,h}            # Password hashing
│   └── uuid_gen.{cpp,h}          # Session token generation
├── tests/                        # Test suites
│   ├── unit/                     # C++ unit tests (GoogleTest)
│   ├── integration/              # Integration tests (C++ + Python)
│   └── fixtures/                 # Test PCAP files
├── docs/                         # Documentation
│   ├── design.md                 # Architecture overview
│   ├── api.md                    # REST API reference
│   ├── EntityRelationshipDataModel.md  # Database schema
│   ├── packetFlowDiagram.md      # Packet processing flow
│   └── securityChecklistReview.md      # Security audit
├── examples/
│   └── sample-config.yaml        # Example configuration
├── CMakeLists.txt                # Build configuration
├── Makefile                      # Build wrapper
└── README.md                     # This file
```

---

## ⚙️ Configuration

All settings configured via YAML. Example: [`examples/sample-config.yaml`](examples/sample-config.yaml)

### Capture Settings

```yaml
capture:
  mode: "live"                    # "live" or "offline"
  interface: "en0"                # Network interface (live mode)
  pcap_file: ""                   # PCAP file path (offline mode)
  bpf_filter: ""                  # BPF filter (e.g., "tcp port 80")
  promiscuous: false              # Promiscuous mode
  snaplen: 65535                  # Capture length (bytes)
  timeout_ms: 1000                # Read timeout
```

### API Settings

```yaml
api:
  host: "localhost"
  port: 8082
  token: "your_secure_token_here"  # For /control endpoints
  session_expiry: 3600             # Session timeout (seconds)
```

### Authentication

```yaml
users:
  - username: "admin"
    password_hash: "$2a$12$..."   # bcrypt hash
  - username: "user"
    password_hash: "$2a$12$..."
```

**Generate bcrypt hashes:**

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'yourpassword', bcrypt.gensalt()).decode())"
```

### Privilege Drop (Security)

```yaml
privilege:
  drop: true
  user: "nobody"
  group: "nobody"
```

### Database

```yaml
database:
  path: "netnet.db"
  retention_days: 7
```

### Logging

```yaml
logging:
  level: "info"          # debug, info, warning, error
  file: ""               # Empty = stdout
  timestamps: true
```

---

## 🔌 REST API

### Authentication Endpoints

#### POST `/login`

Authenticate user and receive session token.

**Request:**

```json
{
  "username": "admin",
  "password": "adminpass"
}
```

**Response:**

```json
{
  "token": "550e8400-e29b-41d4-a716-446655440000",
  "username": "admin",
  "expires_in": 3600
}
```

#### POST `/logout`

Invalidate session token.

**Headers:**

```http
X-Session-Token: <token>
```

**Response:**

```json
{
  "message": "Logged out successfully"
}
```

---

### Metrics Endpoints

#### GET `/metrics`

Retrieve current network statistics.

**Headers:**

```http
X-Session-Token: <token>
```

**Response:**

```json
{
  "timestamp": 1732656147000,
  "window_start": 1732656140,
  "total_bytes": 1048576,
  "total_packets": 256,
  "bytes_per_second": 104857,
  "protocol_breakdown": {
    "TCP": 900000,
    "UDP": 148576,
    "OTHER": 0
  },
  "active_flows": [
    {
      "src_ip": "192.168.1.100",
      "src_port": 54321,
      "dst_ip": "142.250.80.46",
      "dst_port": 443,
      "protocol": "TCP",
      "bytes": 15360,
      "packets": 45
    }
  ]
}
```

---

### Control Endpoints

#### POST `/control/start`

Start packet capture.

**Headers:**

```http
Authorization: Bearer <api_token>
```

#### POST `/control/stop`

Stop packet capture.

#### POST `/control/reload`

Reload configuration file.

**Note:** Control endpoints require API token (not session token).

See [docs/api.md](docs/api.md) for complete API documentation.

---

## 🧪 Testing

### Run All Tests

```bash
make test
```

### C++ Unit Tests (GoogleTest)

```bash
./build/test_runner
```

**Test Suites:**

- `test_parser` - Packet parsing logic
- `test_pcap_adapter` - Capture adapter
- `test_connection_tracker` - Flow tracking
- `test_stats_aggregator` - Metrics aggregation
- `test_session_manager` - Authentication

### Integration Tests (Python)

```bash
# Start daemon first
sudo ./build/netnet-daemon --config examples/sample-config.yaml &

# Run Python tests
source .venv-netnet/bin/activate
pytest tests/integration/ -v

# Kill daemon
sudo pkill netnet-daemon
```

**Test Coverage:**

- ✅ 6 C++ unit test suites
- ✅ 16 Python integration tests
- ✅ Authentication (login, logout, token validation)
- ✅ API endpoints (metrics, control)
- ✅ Security (SQL injection, XSS, rate limiting)
- ✅ Concurrency (session expiry, cleanup)

---

## 🔒 Security

### Implemented Safeguards

- ✅ **Privilege Dropping:** Daemon drops to `nobody:nobody` after opening capture device
- ✅ **bcrypt Password Hashing:** All passwords hashed with salt (cost factor: 12)
- ✅ **Session Tokens:** UUID-based tokens, SQLite-backed, configurable expiry
- ✅ **Rate Limiting:** Control endpoints limited to 1 request per 2 seconds per IP
- ✅ **Input Validation:** BPF filter sanitization, JSON schema validation
- ✅ **No Credential Logging:** Passwords never logged or displayed
- ✅ **HTTPS Ready:** Daemon designed for reverse proxy (nginx/Caddy) with TLS

### Production Checklist

- [ ] Change default passwords
- [ ] Use strong API tokens (32+ characters)
- [ ] Enable HTTPS via reverse proxy
- [ ] Restrict API access by IP/firewall
- [ ] Run daemon as dedicated user (not `nobody`)
- [ ] Enable audit logging
- [ ] Review [`docs/securityChecklistReview.md`](docs/securityChecklistReview.md)

---

## 🐛 Troubleshooting

### Permission Denied

```bash
# Run with sudo (required for packet capture)
sudo ./build/netnet-daemon --config examples/sample-config.yaml
```

### Port Already in Use

```bash
# Kill existing daemon
sudo pkill netnet-daemon

# Or change port in config
api:
  port: 8082  # Change from 8080
```

### Interface Not Found

```bash
# List available interfaces
ifconfig -a

# Update config with correct interface
capture:
  interface: "en0"  # Change to your active interface
```

### Dashboard Shows "Connection Refused"

1. Check daemon is running: `ps aux | grep netnet-daemon`
2. Check port: `lsof -i :8082`
3. Check logs: `tail -f /var/log/netnet-daemon.log`
4. Verify config: `cat examples/sample-config.yaml`

### Session Token Invalid

```bash
# Clear browser localStorage
# Open browser console (F12):
localStorage.clear()

# Or delete session database
rm -f netnet.db.sessions
```

### API Returns 401 Unauthorized

```bash
# Test login endpoint
curl -X POST http://localhost:8082/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"adminpass"}'

# If login fails, check password hash in config
```

---

## 📚 Documentation

- [Architecture & Design](docs/design.md)
- [REST API Reference](docs/api.md)
- [Database Schema](docs/EntityRelationshipDataModel.md)
- [Packet Processing Flow](docs/packetFlowDiagram.md)
- [Security Audit](docs/securityChecklistReview.md)

---

## 🛠️ Development Roadmap

### ✅ Stage 0: Planning & Design (Complete)

- Architecture design
- Entity-relationship diagram
- Packet flow diagram
- Config schema definition

### ✅ Stage 1: Core Capture Layer (Complete)

- PcapAdapter implementation
- BPF filter validation
- Unit tests with mocked adapter
- Integration tests with PCAP files

### ✅ Stage 2: Parser & Connection Tracker (Complete)

- Multi-protocol parser (Ethernet/IPv4/IPv6/TCP/UDP/ICMP)
- 5-tuple flow tracking
- Connection state machine
- Per-flow throughput counters

### ✅ Stage 3: Stats Aggregation & Persistence (Complete)

- Rolling-window metrics
- In-memory ring buffer
- SQLite persistence
- Configurable aggregation windows

### ✅ Stage 4: CLI Daemon & REST API (Complete)

- NetMonDaemon headless mode
- REST API with cpp-httplib
- Session-based authentication
- Rate limiting
- Privilege dropping
- Configurable logging

### ✅ Stage 5: Web Dashboard & UI (Complete)

- HTML/CSS/JavaScript frontend
- Real-time bandwidth chart (D3.js)
- Protocol breakdown pie chart (Chart.js)
- Active connections table
- Login/logout UI
- Session token management

### 🔄 Stage 6: Hardening, CI, Docs (In Progress)

- [✅] CI/CD pipeline (GitHub Actions)
- [ ] Code coverage reporting (gcov/lcov)
- [ ] Sanitizer builds (ASan/UBSan/TSan)
- [ ] Docker support with health checks
- [ ] Performance benchmarks
- [ ] Deployment guide (systemd/Docker)
- [ ] Troubleshooting guide
- [ ] Contributing guide

---

## 🚢 Deployment

### systemd Service (Linux)

```bash
# Copy service file
sudo cp scripts/netnet-daemon.service /etc/systemd/system/

# Enable and start
sudo systemctl enable netnet-daemon
sudo systemctl start netnet-daemon

# Check status
sudo systemctl status netnet-daemon
```

### Docker (Coming Soon)

```bash
# Build image
docker build -t netnet:latest .

# Run with host network (for packet capture)
docker run --rm --net=host --cap-add=NET_RAW \
  -v $(pwd)/examples/sample-config.yaml:/etc/netnet/config.yaml \
  netnet:latest
```

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Before submitting:**

- Run tests: `make test`
- Check formatting: `clang-format -i src/**/*.cpp src/**/*.h`
- Update documentation if needed

---

## 📝 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [libpcap](https://www.tcpdump.org/) - Packet capture
- [cpp-httplib](https://github.com/yhirose/cpp-httplib) - HTTP server
- [yaml-cpp](https://github.com/jbeder/yaml-cpp) - YAML parsing
- [nlohmann/json](https://github.com/nlohmann/json) - JSON handling
- [GoogleTest](https://github.com/google/googletest) - Unit testing
- [D3.js](https://d3js.org/) - Data visualization
- [Chart.js](https://www.chartjs.org/) - Pie charts
- [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) - Password hashing

---

## 📧 Contact

- **GitHub Issues:** [github.com/humanauction/net-net/issues](https://github.com/humanauction/net-net/issues)
- **Email:** [humanauction@gmail.com](mailto:humanauction@gmail.com)

---
