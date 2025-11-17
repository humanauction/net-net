# Packet Flow Diagram

```
flowchart TD
    Start[Network Interface / PCAP File] --> Adapter[PcapAdapter]
    Adapter -->|Raw Packet + PacketMeta| Parser[Parser]
    Parser -->|ParsedPacket| Tracker[ConnectionTracker]
    Parser -->|ParsedPacket| Aggregator[StatsAggregator]
    Tracker -->|Flow Updates| Aggregator
    Aggregator -->|Windowed Stats| Persistence[(StatsPersistence<br/>SQLite)]
    Aggregator -->|Current Metrics| API[REST API<br/>/metrics]
    API --> Client[UI / Webhook / CLI]
    API -->|Control Endpoints| Control[/control/start<br/>/control/stop<br/>/control/reload]
    Control -.->|Signals| Adapter
```
