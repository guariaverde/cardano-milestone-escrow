# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Security Architecture & Invariants
**WaysToBuildIt (Cardano Milestone Escrow)** enforces defense-in-depth across on-chain Aiken Plutus V3 validators and the off-chain Go reference server:
- **Zero-Key Web Server:** The web server holds zero private signing keys. All payouts require verifiable eUTxO state transitions and authorized signatures.
- **Double-Satisfaction Prevention:** Cardano eUTxO payout transactions enforce tagged output attribution (`SumTaggedPayouts`) and `MinUTxOLovelace` (`1,500,000` lovelace) continuity.
- **4-Layer Anti-Trojan Deliverable Scanner:** Rejects executables (`MZ`/`ELF`), script payloads, and malicious PDF `/JavaScript` or `/Launch` actions before computing `SHA-256` / `Blake2b-256` evidence hashes.
- **Mandatory 2FA & Strict Separation of Duties:** Enforces 2-Step Verification (2FA) and WebAuthn Passkeys for `Committee` and `SysAdmin`, while isolating crypto/testnet configuration strictly to `SysAdmin` and financial disbursement approval strictly to `Committee` after independent `Inspector` verification.

## Reporting a Vulnerability
Please **do not** report security vulnerabilities through public GitHub issues.

Instead, send a detailed report to:
- **Email:** `grants@guariaverde.com`
- **Response SLA:** We acknowledge vulnerability reports within **48 hours** and provide a remediation timeline or patch within **7 days**.
