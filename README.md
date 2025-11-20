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
│  └─ main.cpp
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

See docs/design.md for full architecture.

- Deliverables: `design.md` with data model, packet flow, modules, public API.
- Entity-relationship diagram and packet flow diagram.
- Decide capture backend (libpcap) and privilege model.

- Define config schema (YAML): interfaces, samplingInterval, aggregationWindow, alertRules.

- Tests: design review checklist.

### Stage 1 — Core capture and adapter layer (Estimate: 4–6 days. Actual: 5 days)

- Implement `PcapAdapter` (wrapper around libpcap) with clean, testable interface.

- Implement RawSocketAdapter only if targeting platforms without libpcap.
- BPF filter validation and sanitization.
- API: `startCapture(interface, callback)`, `stopCapture()`, `setFilter(bpf)`.

- Tests: unit tests mocking adapter; integration test capturing from pcap file (see: [sample.pcap](tests/fixtures/sample.pcap)). Quick Start packet scripts: [regenerate](#samplepcap) localhost ICMP packets.

### Stage 2 — Parser and connection tracker (Estimate: 6–8 days; Actual: 4 days)

- Implement `Parser` for Ethernet -> IPv4/IPv6 -> Transport (TCP/UDP/ICMP).

- Implement `ConnectionTracker`: tracks flows by 5-tuple, timestamps, simple state (established, closed, idle).

- Implement throughput counters per flow and per interface.

- Tests: unit tests for parsing sample packets; synthetic pcap files to validate flow assembly.

### Stage 3 — Stats aggregation and persistence (Estimate: 4–6 days; Actual: 5 days)

- Implement `StatsAggregator` which consumes parsed events and outputs rolling-window metrics.

- Support configurable windows: 1s, 10s, 60s.

- Provide an in-memory ring buffer and disk-backed persistence (SQLite) for historical queries.

- Tests: unit tests for aggregation maths; integration test verifying outputs over recorded pcap simulation.

### Stage 4 — CLI daemon + REST API (Estimate:5–7 days; Actual: 7 days)

- Implement `NetMonDaemon` to run headless.

- Add a small REST API (cpp-httplib) to expose metrics JSON and simple control endpoints (`/control/start`, `/control/stop`, `/control/reload`).
- Add authentication token for API access.
- Implement rate limiting for control endpoints.
- Implement privilege drop after opening capture device.
- Configurable logging (level, file, timestamps).
- Tests: integration tests for REST endpoints; security review checklist. See: `docs/securityChecklistReview.md` for details.

### Stage 5 — Qt dashboard and alerts (Estimate: 6–10 days; Actual: In Progress)

- Implement web-based dashboard using HTML/CSS/JavaScript (D3.js for visualizations).
- Dashboard served via REST API server at `/` (static files in `www/`).
- Visuals: per-interface bandwidth graph, active connections list, protocol pie chart, alerts panel.
- Alerts: threshold rules trigger UI highlight and send webhook on critical events.
- Tests: manual UI acceptance tests; unit tests for alert logic.

### Stage 6 — Hardening, CI, docs and deployment (Estimate: 3–5 days; Actual: Pending)

- Add GoogleTest unit suite; CI pipeline (GitHub Actions) to run tests and lint.

- Add sanitizer builds (ASan/UBSan) for debug CI.

- Add Dockerfile for daemon mode.

- Finalize docs, example configs, concise README.

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
