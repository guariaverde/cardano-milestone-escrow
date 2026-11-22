# Contributing to WaysToBuildIt (Cardano Milestone Escrow)

Thank you for your interest in contributing to **WaysToBuildIt**, an open-source, domain-agnostic Cardano eUTxO milestone escrow, charity auction (*Subasta*), and public accountability framework maintained by **Guaria Verde** (`https://guariaverde.com`).

## Code of Conduct
All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md).

## Development Workflow & Pre-Push Security Checks
1. **Fork & Branch:** Create a feature branch from `main`.
2. **Core Invariants:**
   - **Zero Floating-Point Currency Math:** Always use integer atomic units (`lovelace` on-chain; `uint64` minor units off-chain).
   - **Separation of Duties:** Never allow `SysAdmin`, `Contractor`, `Verifier`, or `Committee` roles to overlap.
   - **Zero PII On-Chain:** Anchor only `Blake2b-256` / `SHA-256` evidence hashes on-chain.
3. **Automated Security & Code Review Gate:**
   Before committing or opening a pull request, run the pre-push verification script:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\scripts\security-and-code-review.ps1
   ```
   This runs:
   - Secret and credential leak scanning
   - Static analysis (`go -C backend vet ./...`)
   - Full unit and adversarial security test suites (`go -C backend test ./...`)

## Pull Request Process
- Ensure all Go tests (`backend/...`) and Aiken validator checks (`contracts/cardano/...`) pass.
- Clearly reference the issue or milestone invariant being addressed.
- Contact `grants@guariaverde.com` for questions regarding ecosystem integrations.
