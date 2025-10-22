# Project name

## Real‑Time Network Monitor

## Purpose

Capture packets, parse layers, track connections, and aggregate per‑interface bandwidth and protocol breakdowns. Provide both headless daemon and optional Qt dashboard.

## Goals

Accurate packet capture with timestamps.

Robust parsing for Ethernet, IPv4, IPv6, TCP, UDP, ICMP.

Connection tracking by 5‑tuple with simple lifecycle.

Rolling window metrics (1s, 10s, 60s).

Safe privilege model for capture on Linux and Windows.

Testable adapters and deterministic test harness using pcap files.

## Non‑Goals

Full TCP reassembly for application payloads.

Stateful protocol analyzers beyond connection state and counters.

Deep DPI or protocol fingerprinting.

## Architecture overview

Adapter layer: abstracts capture backend (PcapAdapter, RawSocketAdapter).

Parser: converts raw frames into ParsedPacket objects.

ConnectionTracker: maintains active flows and states.

StatsAggregator: computes rolling metrics per interface/protocol.

Persistence: optional SQLite store for historical queries.

API / Daemon: exposes REST endpoints for metrics and control.

UI: Qt dashboard subscribes to metrics via local socket/REST/WebSocket.

## Data model (core structs)

-   Data model
    PacketMeta: timestamp, iface, cap_len, orig_len.

-   ParsedPacket: meta, eth_type, src_mac, dst_mac, network, src_ip, dst_ip, transport, src_port, dst_port, payload_len.

-   FlowKey: iface, protocol, src_ip, src_port, dst_ip, dst_port.

-   FlowStats: first_seen, last_seen, bytes/pkts c2s and s2c, state.

## Capture flow

1.  Adapter opens handle and starts capture thread.

2.  Adapter invokes callback with raw packet and PacketMeta.

3.  Parser runs on packet, produces ParsedPacket or error.

4.  ConnectionTracker ingests ParsedPacket to update flows.

5.  StatsAggregator receives events from tracker and parser to update rolling windows.

6.  Expose metrics via API or signals to UI.

## Concurrency model

-   Adapter runs capture thread per interface or multiplexes via pcap_loop.

-   Parsing and tracking run on worker thread pool (std::thread + thread pool, or task queue).

-   StatsAggregator runs single threaded (actor) to avoid locking on high-frequency counters; update via lock-free queue or bounded channel.

-   Shared read APIs use read–copy–update or snapshot technique to avoid blocking capture pipeline.

## Configuration schema (YAML)

-   interfaces: [ "eth0" ]

-   capture.backend: "pcap"

-   capture.bpf: "not port 22"

-   capture.promiscuous: true

-   aggregation.windows: [1,10,60]

-   api.bind: "127.0.0.1:8080"

-   alerts: list of named thresholds

## Security and privilege model

-   Use libpcap.

-   Open handle with elevated privilege or setcap CAP_NET_RAW on binary.

-   Immediately drop privileges (setgid/initgroups/setuid) after handle open.

-   Provide non‑privileged pcap replay mode for CI and dev.

### Recommended Linux sequence:

-   binary owned by root; setcap CAP_NET_RAW+eip (or open as root then drop).

-   open pcap handle while privileged.

-   drop to dedicated unprivileged user (e.g., netmon) using setuid/setgid.

-   verify handle stays usable after drop.

-   validate config and sanitize inputs before applying filters.

## Testing strategy

Unit: parser, FlowKey hashing, aggregator math.

Integration: pcap fixtures in tests/fixtures; PcapAdapter offline mode.

Fuzz: malformed headers to ensure parser defenses.

CI: Linux and macOS matrix; Windows noted for Npcap.

## Observability

Expose metrics via REST (OPTIONAL: Prometheus?).

Structured logs using spdlog.

Health and readiness endpoints.

## Deliverables for Stage 0

-   design.md (this file)
-   sample-config.yaml (examples/)
-   minimal pcap test fixtures
-   buildable adapter and tests
