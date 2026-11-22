# Maintainers & Governance

## Project Stewardship
**WaysToBuildIt (Cardano Milestone Escrow & Civic Accountability Engine)** is maintained under the [Apache-2.0 License](LICENSE) by **Guaria Verde** (`https://guariaverde.com`).

## Active Maintainers

| Name / Organization | Role | Contact | Scope |
| ------------------- | ---- | ------- | ----- |
| **Javier Brizuela** (*Guaria Verde*) | Lead Architect & Core Maintainer | `grants@guariaverde.com` | Cardano Aiken Validators (`contracts/cardano/`), Go Escrow Engine (`backend/`), Civic Transparency UI (`frontend/`) |

## Governance Model & Roadmap
- **Decision Making:** Pull requests require passing automated CI (`go vet`, `go test ./...`, secret leak scanner, and invariant checks) plus maintainer review.
- **Roadmap Milestones:**
  - **M1 (Completed):** Generic eUTxO Milestone Escrow state machine, Aiken Plutus V3 spending validators (`escrow.ak`, `subasta_and_fund.ak`), collision-free Sealed-Bid Subasta engine, hash-chained audit ledger (`audit_ledger.json`), and live bilingual platform (`https://waystobuildit.com`).
  - **M2 (In Progress):** Production Cardano Preview/Preprod indexer integration, Cloudflare R2 encrypted evidence storage, and formal third-party smart-contract audit.
  - **M3 (Planned):** Reusable Go/TypeScript SDK packaging and CONSUL Democracy civic plugin connector.
