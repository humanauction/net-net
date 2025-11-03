# net-net

Real-Time Network Monitor (C++)

## Overview

A modular network monitor that captures packets, tracks active connections, and aggregates per-interface bandwidth and protocol statistics. Includes an optional Qt dashboard for live visualization.

## Project structure

```bash
net-net/
├─ src/
│  ├─ core/
│  │  ├─ PacketCapture.cpp
│  │  ├─ PacketCapture.h
│  │  ├─ Parser.cpp
│  │  ├─ Parser.h
│  │  ├─ ConnectionTracker.cpp
│  │  ├─ ConnectionTracker.h
│  │  ├─ StatsAggregator.cpp
│  │  ├─ StatsAggregator.h
│  │  └─ Utils.h
│  ├─ net/
│  │  ├─ PcapAdapter.cpp
│  │  ├─ PcapAdapter.h
│  │  ├─ RawSocketAdapter.cpp
│  │  └─ RawSocketAdapter.h
│  ├─ ui/
│  │  ├─ QtDashboard.cpp
│  │  ├─ QtDashboard.h
│  │  └─ QmlViews/...
│  ├─ daemon/
│  │  ├─ NetMonDaemon.cpp
│  │  └─ ConfigLoader.cpp
│  └─ main.cpp
├─ include/
│  └─ net-net/   (public headers for library usage)
├─ tests/
│  ├─ unit/
│  └─ integration/
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
│  ├─ api.md
│  └─ perf.md
├─ examples/
│  └─ sample-config.yaml
├─ .clang-format
├─ CMakeLists.txt
└─ README.md
```

## Features

Packet capture via libpcap or raw sockets.

Parser for Ethernet, IPv4/IPv6, TCP, UDP, ICMP.

Connection tracking with simple state machine.

Per-interface, per-protocol bandwidth statistics.

Configurable sampling and aggregation windows.

Optional Qt dashboard with live charts and alerts.

CLI daemon mode for headless deployments.

## Requirements

C++17 or later.

CMake 3.16+.

libpcap development headers (or root for raw sockets).

Qt 6 (optional, for dashboard).

GoogleTest for unit tests.

Docker (optional for CI).

## Quick start

git clone ...

mkdir build && cd build

cmake .. && make -j

sudo ./netmon --config ../examples/sample-config.yaml # capture requires privileges

./netmon-ui # launches Qt dashboard (optional)

## Configuration

sample-config.yaml lists interfaces, capture mode, aggregation window, alert thresholds.

## Development stages

See DEVELOPMENT.mds, below.

Development broken down into stages (milestones)
Work divided into five stages. Each stage lists deliverables and focused tests.

### Stage 0 — Planning and design (2–3 days)

See docs/design.md for full architecture.

- Deliverables: design.md with data model, packet flow, modules, public API.

- Decide capture backend (libpcap) and privilege model.

- Define config schema (YAML): interfaces, samplingInterval, aggregationWindow, alertRules.

- Tests: design review checklist.

### Stage 1 — Core capture and adapter layer (4–6 days)

- Implement PcapAdapter (wrapper around libpcap) with clean, testable interface.

- Implement RawSocketAdapter only if targeting platforms without libpcap.

- API: startCapture(interface, callback), stopCapture(), setFilter(bpf).

- Tests: unit tests mocking adapter; integration test capturing from pcap file (see: [sample.pcap](tests/fixtures/sample.pcap)). Quick Start packet script: [regenerate](#samplepcap) localhost ICMP packets.

### Stage 2 — Parser and connection tracker (6–8 days)

- Implement Parser for Ethernet -> IPv4/IPv6 -> Transport (TCP/UDP/ICMP).

- Implement ConnectionTracker: tracks flows by 5-tuple, timestamps, simple state (established, closed, idle).

- Implement throughput counters per flow and per interface.

- Tests: unit tests for parsing sample packets; synthetic pcap files to validate flow assembly.

### Stage 3 — Stats aggregation and persistence (4–6 days)

- Implement StatsAggregator which consumes parsed events and outputs rolling-window metrics.

- Support configurable windows: 1s, 10s, 60s.

- Provide an in-memory ring buffer and optional disk-backed persistence (SQLite) for historical queries.

- Tests: unit tests for aggregation math; integration test verifying outputs over recorded pcap simulation.

### Stage 4 — CLI daemon + REST API (optional) (5–7 days)

Implement NetMonDaemon to run headless.

- Add a small REST API (cpp-httplib or Crow) to expose metrics JSON and simple control endpoints (start/stop, config reload).

- Add authentication token for API access.

- Tests: integration tests for REST endpoints; security review checklist.

### Stage 5 — Qt dashboard and alerts (6–10 days)

- Implement QtDashboard: real-time charts using QChart or QCustomPlot.

- Visuals: per-interface bandwidth graph, active connections list, protocol pie chart, alerts panel.

- Alerts: threshold rules trigger toast or UI highlight; send webhook on critical events.

- Tests: manual UI acceptance tests; unit tests for alert logic.

### Stage 6 — Hardening, CI, docs, and deployment (3–5 days)

- Add GoogleTest unit suite; CI pipeline (GitHub Actions) to run tests and lint.

- Add sanitizer builds (ASan/UBSan) for debug CI.

- Add Dockerfile for daemon mode.

- Finalize docs, example configs,concise README.

## Interfaces and key class examples (API sketch)

- PcapAdapter

  - start(interface, bpfFilter, packetCallback)

  - stop()

- Parser

  - parse(rawPacket) -> ParsedPacket {timestamp, iface, layers...}

- ConnectionTracker

  - ingest(parsedPacket)

  - getActiveConnections()

- StatsAggregator

  - ingest(parsedEvent)

  - getMetrics(window) -> JSON-like struct

- NetMonDaemon

  - loadConfig(path)

  - run()

- QtDashboard

  - subscribeToMetrics(source)

  - render()

## Testing, security, deployment notes

### Testing

- Use recorded pcap files for deterministic integration tests.

- Mock adapters for unit tests.

- Add fuzz tests for parser with malformed packet samples.

### Security

- Run capture code with minimal privileges; drop to unprivileged user after opening capture.

- Sanitize config input; protect REST API with tokens.

- Careful with executing system calls; none should be exposed via API.

### Deployment

- Provide Docker for daemon mode with CAP_NET_RAW capability.

- For desktop users, ship Qt app as separate artifact; use installer or AppImage on Linux.

## Test Fixtures

### sample.pcap

10 ICMP echo request/reply packets captured from localhost.

**To regenerate:**

```bash
sudo tcpdump -i lo0 -w sample.pcap &
ping -c 5 127.0.0.1
sudo killall tcpdump
```
