# net-net contributor and agent instructions

## Mission and scope

`net-net` is a production-like network-security monitoring MVP. It is a Linux-first deployment target developed on macOS. Work should demonstrate sound packet-capture, detection-engineering, secure telemetry, and operational practices—not visual polish.

The privacy model permits collection of packet metadata, DNS names, and TLS SNI for security monitoring and IOC correlation. Payload capture, credential collection, and covert collection are out of scope. New telemetry must document its purpose, sensitivity, retention, access control, encryption in transit, and deletion path before it is implemented.

## Non-negotiable engineering rules

- Use C++20 and the CMake presets. Do not reintroduce machine-specific paths or assume a Homebrew Cellar location.
- Treat packet input, PCAPs, BPF expressions, configuration, HTTP requests, and remote telemetry as untrusted input.
- Preserve offline PCAP replay as the deterministic integration-test path. Never require live privileged capture in unit or CI tests.
- Keep capture, parsing, aggregation, persistence, and export on bounded paths. Any queue needs an explicit size, overflow policy, and dropped-event metric.
- Never log packet payload, passwords, API tokens, session tokens, database contents, or raw authorization headers.
- Authentication changes require a migration plan. The current custom component named `bcrypt` is legacy PBKDF2 compatibility code, not bcrypt; do not extend it.
- Use parameterized SQL, constant-time secret comparison, least privilege, secure defaults (loopback bind), TLS for remote transport, and authenticated telemetry export.
- Update API, configuration, threat-model, and operational documentation whenever behavior changes.

## Validation baseline

From a clean working tree:

```bash
cmake --preset dev
cmake --build --preset dev --parallel
ctest --preset dev
```

Run targeted parser and daemon tests when changing capture/API code. Run an AddressSanitizer/UndefinedBehaviorSanitizer configuration before merging parser, concurrency, or persistence changes. CI must test current macOS and Linux; Linux is the release gate.

## Required session handover

Before ending a material session, follow [docs/session-handover.md](docs/session-handover.md). The next contributor must be able to reproduce the exact build, tests, decisions, risks, and unfinished work without relying on chat history.

## Current known constraints

- Live aggregation is not yet window-driven or durably persisted; offline replay currently forces one window.
- `ConnectionTracker` is not yet on the daemon ingest path.
- The parser is Ethernet-II-centric and lacks VLAN, PCAP link-type, IPv6-extension, and fragmentation support.
- Tests that start the daemon share an API-port resource and must remain resource-locked.
- The historical vendored cpp-httplib 0.28.0 is replaced in CMake by a pinned upstream dependency; remove the unused copy only after clean cross-platform CI is green.
