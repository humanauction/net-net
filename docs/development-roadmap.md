# Network-monitoring development roadmap

## Product direction

Build a production-like, Linux-first sensor that can be developed on macOS. The MVP demonstrates safe packet capture, network evidence generation, threat detection, and export to a future control plane. It collects metadata, DNS names, and TLS SNI for approved monitoring and IOC correlation; it does not collect application payloads.

## Release gates

- **Security gate:** Argon2id password storage, no default credentials or checked-in API token, least-privilege capture, authenticated TLS telemetry transport, and documented data retention/access/deletion controls.
- **Correctness gate:** link-layer-aware parsing, VLAN support, safe truncated/fragmented packet handling, monotonic window scheduling, bounded memory, and capture-loss visibility.
- **Operational gate:** structured logs, health/readiness, metrics, deterministic PCAP replay, and current macOS/Linux CI.

## Phase 0 — make the current monitor trustworthy

**Priority: P0.** This is the prerequisite for every detection feature.

| Deliverable | Why it matters | Acceptance evidence |
| --- | --- | --- |
| C++20/CMake preset migration; pinned HTTP/SQLite dependencies | Reproducible, modern builds without machine paths or a stale vendored HTTP server | Clean configure/build/test on macOS and Linux |
| Deterministic daemon-test isolation | Removes false confidence from API-port collisions | Parallel CTest runs repeatedly without bind failures |
| Capture pipeline ownership | Connect parser → canonical flow tracker → aggregator; safely snapshot reads | Integration test proves live/offline flow expiry and window history |
| Window scheduler and persistence | Live windows must rotate, persist transactionally, and survive restart | PCAP replay and timed test produce exact persisted windows |
| Capture-loss and pipeline-overflow metrics | A sensor that silently drops packets cannot support conclusions | Simulated loss is exposed in health/OpenMetrics and logged |
| Parser hardening | Correct data is a security requirement | Tests cover Ethernet/VLAN, IPv4 options/fragments, IPv6 extensions/fragments, ICMPv6, truncated inputs, and supported PCAP link types |

## Phase 1 — security-relevant flow evidence

**Priority: P0.** Convert packets into useful and defensible network observations.

| Deliverable | Detection value | Acceptance evidence |
| --- | --- | --- |
| Canonical bidirectional flow model | Prevents direction-split flows and produces reliable byte/rate totals | Request/response PCAP maps to one flow with correct sides |
| TCP state and health signals | SYN-only scans, failed handshakes, resets, retransmission indicators, long-lived flows | Fixture tests and documented accuracy/limitations |
| DNS transaction parser | Query name/type, response code, answer TTL/IP, response time, NXDOMAIN bursts | Privacy-filtered DNS event schema and correlation tests |
| TLS ClientHello metadata | SNI, TLS version, ALPN, cipher characteristics; no payload retention | Fragment-safe fixture tests and explicit encrypted-traffic limitations |
| IOC matching engine | Match IP/CIDR, domain, SNI, port/protocol, and JA3-style fingerprint only after validation | Signed/versioned local rule set, explainable alert with rule ID |

## Phase 2 — detection and investigation operations

**Priority: P1.** Make the evidence actionable without becoming a UI project.

| Deliverable | Detection value | Acceptance evidence |
| --- | --- | --- |
| Alert rules and suppression | Thresholds/baselines for scans, beaconing-like periodicity, unusual ports, DNS failures, IOC hits | Versioned YAML rules; tests for trigger, expiry, suppression |
| Event schema and local evidence store | Stable event IDs, UTC timestamps, sensor identity, flow/DNS/TLS linkage | Migration-tested SQLite schema and retention job |
| OpenMetrics/Prometheus endpoint | Capture quality, process health, rule counts, queue depth, exporter health | Scrape test and alert-runbook examples |
| Structured audit logging | Searchable security-relevant lifecycle and configuration changes | JSON logs omit secrets/payload and carry correlation IDs |
| Query/export CLI/API | Time-bounded, paginated, authenticated retrieval for investigations | Contract tests; server-enforced limits |

## Phase 3 — secure control-plane readiness

**Priority: P1.** Prove scale-readiness without building a multi-site system now.

| Deliverable | Design requirement | Acceptance evidence |
| --- | --- | --- |
| Telemetry exporter interface | Batch metadata/events with bounded durable spool and backoff | Offline/receiver failure tests; loss and retry counters |
| Mutual TLS transport | Per-sensor identity, certificate rotation, hostname verification | Local test CA integration test and rotation runbook |
| Retention and integrity policy | Configurable local retention; protected transit/storage; evidence sequencing | Documented defaults, UTC/NTP health signal, deletion test |
| Sensor configuration lifecycle | Schema validation, redacted config audit, safe reload/rollback | Invalid config never changes running capture state |

## Phase 4 — performance and platform maturity

**Priority: P2.** Execute after correctness is measured.

- Multi-interface capture and sensor identity.
- PCAPNG and Linux cooked capture support.
- Bounded worker queues/back-pressure with benchmarked loss behavior.
- eBPF/XDP exploration only behind a capture-adapter interface; retain libpcap compatibility.
- Fuzzing for parser and configuration boundaries; sanitizer and OSS-Fuzz-compatible harnesses.

## Explicitly deferred

- Full TCP reassembly, deep payload inspection, and content exfiltration.
- Automated blocking/response actions.
- A central multi-site UI/control plane.
- ML-based detection without labelled data, explainability, and false-positive controls.

## Recommended next implementation slice

Complete Phase 0 in this order: fix daemon-test resource isolation; introduce a clock-driven window scheduler and persistence; make the flow tracker authoritative and canonical; then harden parser/link-type coverage. This provides reliable evidence for DNS/TLS/IOC work instead of layering detections on counters that are currently incomplete.
