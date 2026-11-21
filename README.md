\# F1 Telemetry Zero-Trust Gateway



A containerized, low-latency security gateway for high-frequency Formula 1 UDP telemetry streams (EA F1 25, 60Hz on port `20777`). Designed to enforce cryptographic integrity, mutual authentication, and physics-based anomaly detection while keeping end-to-end overhead under \*\*5ms\*\*.



\## Architecture



```text

\[EA F1 25 / 60Hz Car Sim] ── UDP :20777 ──► \[Edge Gateway]

&#x20;                                               │ Perimeter filter + binary framing

\[Red-Team Attack CLI] ──── Spoof / Replay ─────►│ Seq + Timestamp + HMAC-SHA256

&#x20;                                               │ Persistent mTLS 1.3 (TCP :8443)

&#x20;                                               ▼

&#x20;                                       \[Factory Server]

&#x20;                                               │ Verifies mTLS cert, HMAC, anti-replay

&#x20;                                               │ Physics \& frame-drop anomaly checks

&#x20;                                               ▼

&#x20;                                  \[SQLite WAL + NDJSON SIEM]

&#x20;                                               │ WebSocket (10Hz)

&#x20;                                               ▼

&#x20;                                    \[Pit-Wall Web Dashboard]

