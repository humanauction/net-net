# net-net

Real-Time Network Monitor (C++)

## Overview

A modular network monitor that captures packets, tracks active connections, and aggregates per-interface bandwidth and protocol statistics. Includes a web-based dashboard for live visualization.

## Project structure

```bash
net-net/
├─ src/
│  ├─ core/
│  │  ├─ PacketCapture.cpp
│  │  ├─ PacketCapture.h
│  │  ├─ PacketMeta.h
│  │  ├─ Parser.cpp
│  │  ├─ Parser.h
│  │  ├─ ConnectionTracker.cpp
│  │  ├─ ConnectionTracker.h
│  │  ├─ StatsAggregator.cpp
│  │  ├─ StatsAggregator.h
│  │  ├─ StatsPersistence.cpp
│  │  ├─ StatsPersistence.h
│  │  ├─ SessionManager.cpp
│  │  ├─ SessionManager.h
│  │  └─ Utils.h
│  ├─ net/
│  │  ├─ PcapAdapter.cpp
│  │  ├─ PcapAdapter.h
│  │  ├─ RawSocketAdapter.cpp
│  │  └─ RawSocketAdapter.h
│  ├─ daemon/
│  │  ├─ NetMonDaemon.cpp
│  │  ├─ NetMonDaemon.h
│  │  └─ ConfigLoader.cpp
│  └─ Main.cpp
├─ www/
│  ├─ index.html
│  ├─ style.css
│  └─ app.js
├─ include/
│  └─ net-net/   (public headers for library usage)
│     └─ vendor/  (third-party headers, e.g.  bcrypt)
│        ├─ bcrypt.h
│        ├─ bcrypt.cpp
│        ├─ uuid_gen.h
│        └─ uuid_gen.cpp
├─ tests/
│  ├─ fixtures/
│  │  ├─ icmp_sample.pcap
│  │  └─ tcp_sample.pcap
│  ├─ integration/
│  │  ├─ test_api.py
│  │  ├─ test_connection_tracker.cpp
│  │  └─ test_stats_aggregator_integration.cpp
│  └─ unit/
│     ├─ test_parser.cpp
│     ├─ test_pcap_adapter.cpp
│     └─ test_stats_aggregator.cpp
├─ cmake/
│  └─ modules/
├─ scripts/
│  ├─ build.sh
│  └─ run_tests.sh
├─ docker/
│  ├─ Dockerfile
│  └─ docker-compose.yml
├─ docs/
│  ├─ design.md
│  ├─ EntityRelationshipDataModel.md
│  ├─ packetFlowDiagram.md
│  ├─ securityChecklistReview.md
│  ├─ api.md
│  └─ perf.md
├─ examples/
│  └─ sample-config.yaml
├─ .vscode/
│  └─ settings.json
├─ .venv-netnet/
│  └─ ... (virtual environment files)
├─ .clang-format
├─ make_pcap.py
├─ CMakeLists.txt
├─ .gitignore
└─ README.md
```

## Features

- Packet capture via libpcap.
- Parser for Ethernet, IPv4/IPv6, TCP, UDP, ICMP.
- Connection tracking with simple state machine.
- Per-interface, per-protocol bandwidth statistics.
- Configurable sampling and aggregation windows.
- Session-based authentication with bcrypt password hashing.
- User login/logout via REST API.
- Web-based dashboard with live charts and alerts (D3.js).
- CLI daemon mode for headless deployments.

## Requirements

- C++17 or later.

- CMake 3.16+.

- libpcap development headers (or root for raw sockets).

- GoogleTest for unit tests.

- Python 3.x with `requests` and `scapy` (for integration tests).

- Modern web browser (for dashboard).

- Docker.

## Quick start

```bash
git clone https://github.com/humanuaction/net-net.git
cd net-net
make build
make run-daemon-online  # Requires elevated privileges for packet capture
```

Open your browser and navigate to:  
**<http://localhost:8080>**

## Configuration

`sample-config.yaml` lists interfaces, capture mode, aggregation window, alert thresholds, and privilege drop options.

Example:

```yaml
interface:
    name: "en0"
    bpf_filter: "icmp"
    promiscuous: true
    snaplen: 65535
    timeout_ms: 1000

privilege:
    drop: true
    user: "nobody"
    group: "nogroup"

api:
    host: "localhost"
    port: 8080
    token: "your_secure_token"

database:
    path: "netnet.db"
    retention_days: 7

logging:
    level: "info"
    file: ""
    timestamps: true
```

**Note:**

- Privilege drop occurs after opening the capture device, before starting the API server.
- If the specified user/group is invalid or privilege drop fails, the daemon will exit with an error.

## Development Milestones

Development broken down into 6 stages, each divided into several tasks. See stages below for related deliverables and focused tests.

### Stage 0 — Planning and design (Estimate: 2–3 days. Actual: 10 days)

**Completed:**

- ✅ Architecture design documented in `docs/design.md`
- ✅ Entity-relationship diagram created
- ✅ Packet flow diagram created
- ✅ Capture backend selected (libpcap)
- ✅ Privilege drop model designed
- ✅ Config schema defined (YAML): interfaces, samplingInterval, aggregationWindow, alertRules
- ✅ Design review checklist completed

See [`docs/design.md`](docs/design.md) for full architecture.

---

### Stage 1 — Core capture and adapter layer (Estimate: 4–6 days. Actual: 5 days)

**Completed:**

- ✅ Implemented `PcapAdapter` wrapper around libpcap
- ✅ BPF filter validation and sanitization
- ✅ Clean, testable API: `startCapture()`, `stopCapture()`, `setFilter()`
- ✅ Unit tests with mocked adapter
- ✅ Integration test capturing from pcap file
- ✅ Test fixtures: [`icmp_sample.pcap`](tests/fixtures/icmp_sample.pcap), [`sample.pcap`](tests/fixtures/sample.pcap)

**Note:** RawSocketAdapter deferred (libpcap sufficient for target platforms).

---

### Stage 2 — Parser and connection tracker (Estimate: 6–8 days; Actual: 4 days)

**Completed:**

- ✅ Implemented `Parser` for Ethernet → IPv4/IPv6 → TCP/UDP/ICMP
- ✅ Implemented `ConnectionTracker` with 5-tuple flow tracking
- ✅ Connection state tracking (established, closed, idle)
- ✅ Per-flow and per-interface throughput counters
- ✅ Unit tests for packet parsing
- ✅ Integration tests with synthetic pcap files

---

### Stage 3 — Stats aggregation and persistence (Estimate: 4–6 days; Actual: 5 days)

**Completed:**

- ✅ Implemented `StatsAggregator` for rolling-window metrics
- ✅ Configurable aggregation windows (1s, 10s, 60s)
- ✅ In-memory ring buffer for real-time data
- ✅ SQLite-backed persistence for historical queries
- ✅ Unit tests for aggregation math
- ✅ Integration tests with recorded pcap simulation

---

### Stage 4 — CLI daemon + REST API (Estimate:5–7 days; Actual: 9 days)

- ✅ Implement `NetMonDaemon` to run headless.
- ✅ Add REST API (cpp-httplib) for metrics and control endpoints.
- ✅ Add authentication token for API access.
- ✅ Implement rate limiting for control endpoints.
- ✅ Implement privilege drop after opening capture device.
- ✅ Configurable logging (level, file, timestamps).
- ✅ **Session management with bcrypt authentication**
- ✅ **User login/logout endpoints**
- ✅ **Session token validation middleware**

---

### Stage 5 — Web dashboard and authentication UI (Estimate: 6–10 days; Actual: In Progress)

**Completed:**

- ✅ Web-based dashboard using HTML/CSS/JavaScript
- ✅ Dashboard served via REST API at `/` (static files)
- ✅ Backend session management and authentication

**In Progress:**

- ✅ Frontend login form
- ✅ Session token storage (localStorage)
- ✅ Authenticated API requests with X-Session-Token header
- ✅ Logout button and session expiry handling

**Pending:**

- 🔄 Real-time bandwidth visualization (D3.js)
- 🔄 Active connections table
- 🔄 Protocol breakdown charts
- 🔄 Alert threshold configuration UI

---

### Stage 6 — Hardening, CI, docs and deployment (Estimate: 3–5 days; Actual: Pending)

- Add GoogleTest unit suite; CI pipeline (GitHub Actions) to run tests and lint.

- Add sanitizer builds (ASan/UBSan) for debug CI.

- Add Dockerfile for daemon mode.

- Finalize docs, example configs, concise README.

---

## Interfaces and Key Classes (API Sketch)

### PcapAdapter

- `start(iface_or_file, bpf_filter, packetCallback)`
- `stop()`

### Parser

- `parse(rawPacket) -> PacketMeta`  
     Returns: `{ timestamp, iface, layers... }`

### ConnectionTracker

- `ingest(PacketMeta)`
- `getActiveConnections() -> std::vector<FlowInfo>`

### StatsAggregator

- `ingest(ConnectionEvent)`
- `getMetrics(window) -> MetricsJson`

### NetMonDaemon

- `loadConfig(path)`
- `run()`
- REST API: `/metrics`, `/control/start`, `/control/stop`, `/control/reload` (token required)
- Static files served from `www/`

### Web Dashboard

- Real-time charts with D3.js
- Fetches data from REST API (`/metrics`)
- Interactive UI for alerts and connection tracking

---

## Testing, security, deployment, future development, notes (mostly to self)

### Testing

- Use recorded pcap files for deterministic integration tests.
- Mock adapters for unit tests.
- Add fuzz tests for parser with malformed packet samples.

### Security

- Run capture code with minimal privileges; **drop to unprivileged user/group after opening capture device**.
- Configured privilege drop in `sample-config.yaml`
- Sanitized config input; REST API protection via tokens.
- BPF filter validation prevents injection attacks.
- Rate limiting for control endpoints.
- Configurable logging (no sensitive data logged).

### Deployment

- Docker for daemon mode with `CAP_NET_RAW` capability.
- Web dashboard accessible via any modern browser.

---

## Test Fixtures

### icmp_sample.pcap

10 ICMP echo request/reply packets captured from localhost.

**To regenerate:**

```bash
sudo tcpdump -i lo0 -w tests/fixtures/icmp_sample.pcap &
ping -c 5 127.0.0.1
sudo killall tcpdump
```

**To inspect:**

```bash
tcpdump -nnr tests/fixtures/icmp_sample.pcap
tcpdump -xx -r tests/fixtures/icmp_sample.pcap
```

### sample.pcap

10 TCP SYN packets from 10.0.0.1:1234 to 10.0.0.2:80 (synthetic, for integration tests).

**To regenerate:**

```bash
sudo tcpdump -i lo0 tcp and host 10.0.0.1 and port 80 -c 10 -w tests/fixtures/sample.pcap
```

**To inspect:**

```bash
tcpdump -nnr tests/fixtures/sample.pcap
tcpdump -xx -r tests/fixtures/sample.pcap
```

---

## 🐛 Troubleshooting

Error: "Permission denied" when opening interface

```bash
# Run with sudo
sudo ./build/netnet-daemon --config examples/sample-config.yaml
```

Error: "Address already in use"

```bash
# Kill existing daemon
sudo pkill netnet-daemon

# Or change port in config
api:
  port: 8082  # Change from 8080
```

Error: "Could not open device en0"

```bash
# Check available interfaces
ifconfig

# Update config with correct interface
capture:
  interface: "en0"  # Change to your active interface
```

Check daemon logs:

```bash
tail -f /tmp/netnet-daemon.log
```

Test API endpoints:

```bash
# Login
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"adminpass"}'

# Expected response:
# {"token":"<uuid>","username":"admin","expires_in":3600}
```

Open web UI:

```bash
open https://localhost:8080
```

Clean up old Database:

```bash
rm -f netnet.db netnet.db.sessions
```
