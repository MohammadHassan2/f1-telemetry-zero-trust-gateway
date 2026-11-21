$content = @'
# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| `main`  | Yes       |

## Security Architecture Summary

This project enforces defense-in-depth across high-frequency motorsport telemetry streams while targeting sub-5ms processing overhead:

- **Transport Authentication (mTLS 1.3):** Factory server enforces `ssl.CERT_REQUIRED` with TLS 1.3 minimum, rejecting edge clients without a CA-signed certificate.
- **Message Integrity (HMAC-SHA256):** Every forwarded binary frame is verified in constant time (`hmac.compare_digest`) prior to payload parsing.
- **Anti-Replay Protection:** Monotonic sequence tracking and timestamp drift bounds reject captured wire replays and delayed injections.
- **Application-Layer Validation:** Physics bounds (speed ceiling, acceleration delta, RPM limits) and frame-continuity checks detect spoofed or dropped upstream UDP traffic.

## Operational Hardening Notes

- **Secrets:** Never use the default development `F1_HMAC_SECRET` value outside local testing. Inject a high-entropy 32-byte secret via environment variables or a secrets manager.
- **PKI / Certificates:** The included `cert-init` bootstrap generates a local self-signed CA for isolated lab demos. Production deployments should use an internal PKI with short-lived certificates and automated rotation.
- **Key Hygiene:** Private keys (`certs/*.key`), databases (`data/`), and SIEM logs (`logs/`) are excluded via `.gitignore` and must never be committed.

## Reporting a Vulnerability

If you discover a cryptographic flaw, parser crash, or bypass in the gateway or anomaly engine:

1. Do **not** open a public GitHub issue with exploit details.
2. Submit a private report via the repository's **Security** tab (**Report a vulnerability** / GitHub Security Advisories).
3. Include a minimal reproduction script or packet capture along with expected vs. actual behavior.

Reports are acknowledged within 72 hours, and confirmed issues are patched before public disclosure.
'@
[System.IO.File]::WriteAllText("$PWD\SECURITY.md", $content)