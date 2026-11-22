# Base L2 Milestone Escrow & Subasta SDK (`WaysToBuildIt`)

An open-source, domain-agnostic **Base L2 (Solidity) + Go SDK and Reference Framework** for milestone-based escrow, sealed-bid charity auctions (*Subastas*), reentrancy-protected disbursements, and cryptographic deliverable verification.

> **Central Principle:** *Funds are released according to verifiable agreements, not simply because someone requests payment.*

> **Developer Tooling & SDK Architecture:** Built as a reusable, zero-dependency Go domain engine (`backend/escrow/`, `backend/adapters/`) and Base L2 Solidity smart contract (`contracts/base/MilestoneEscrow.sol`) so any Base developer or municipality can integrate multi-stage escrow, 2-of-3 key rotation, anti-trojan evidence hashing, and sealed-bid auctions. Includes a complete Reference Civic Application (`backend/civic/`, `frontend/`) live at **`https://base.waystobuildit.com`**.

---

## Architectural Overview

Base Milestone Escrow is architected as a **generic milestone-based escrow engine** paired with a **dynamically configurable civic/organization application layer**:

1. **Generic Escrow Core (`backend/escrow/`, `contracts/base/`):**
   - Domain-agnostic state machine and Base L2 Solidity smart contract (`MilestoneEscrow.sol`) with `nonReentrant` and Checks-Effects-Interactions guards.
   - Enforces multi-source funding, separation of duties (Sponsor/Client, Administrator, Contractor, Independent Verifier/Inspector, Arbiter), evidence-hash verification, dispute freezes, and exact asset conservation.
2. **Configurable Civic, Marketplace & Treasury Domain Module (`backend/`):**
   - Supports **three transparent collection avenues**:
     1. **Direct Project Crowdfunding ("GoFundMe" with Escrow):** Citizens and sponsors fund a posted project's milestone escrow directly.
     2. **Donated-Item Marketplace (`Fixed Price`, `Open Subasta`, `Blind Subasta`):** Donors give items to the organization, which inspects and lists them. The buyer's payment locks in an **Item Delivery Escrow** until delivery is verified, then releases into the **Committee Public Fund**.
     3. **Direct Organization / Committee Fund Donations:** Donors contribute to the organization's public pool for the committee to allocate across posted projects (e.g., annual/scheduled distributions).
   - **Dynamic Naming & Branding:** Organization names, jurisdiction labels, and roles are driven by configuration—never hardcoded into the engine or UI.
3. **Standalone Civic Web Application (`frontend/`):**
   - Spanish-first (`es-CR`) with English (`en`) support, designed around civic trust (`#17324D` deep navy, `#16866A` emerald green, `#F8FAFC` warm white, `#64748B` slate gray, `#D99A24` amber) without crypto-trading jargon.
4. **Primary Pilot Demonstration:**
   - Configured dynamically for **Municipalidad de Montes de Oca, Costa Rica**, showcasing a fictional **Solar-Powered Public Park Lighting Project** (*Proyecto de Iluminación Solar para Parques Públicos en Montes de Oca*).
   - Because the core engine and accountability services are cleanly decoupled from our standalone frontend and backend shell, the entire system can later be packaged as a plug-in for external platforms (such as a future Phase 7 CONSUL plug-in).

---

## Repository Structure

| Path | Purpose |
| :--- | :--- |
| [`docs/CONTRACT_SPEC.md`](docs/CONTRACT_SPEC.md) | On-chain and domain invariants, actor roles, and eUTxO specification |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contributor guidelines and pre-push security checks |
| [`SECURITY.md`](SECURITY.md) | Security architecture, invariants, and vulnerability disclosure policy |
| [`MAINTAINERS.md`](MAINTAINERS.md) | Project stewardship, active maintainers, and roadmap |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Contributor Covenant Code of Conduct |
| [`config/organization.json`](config/organization.json) | External dynamic organization config |
| [`config/demo_seed.json`](config/demo_seed.json) | External demonstration seed data |
| [`backend/`](backend/) | Go escrow engine (`escrow/`), anti-trojan & fiat bridge (`adapters/`), civic service (`civic/`), and HTTP server (`cmd/server/`) |
| [`contracts/base/`](contracts/base/README.md) | Base L2 Solidity smart contract ([`MilestoneEscrow.sol`](contracts/base/MilestoneEscrow.sol)) |
| [`frontend/`](frontend/README.md) | Standalone bilingual (`es-CR` / `en`) civic transparency & project management interface |

---

## Development Priorities

1. **Generic escrow domain model and state machine** (`backend/escrow/`)
2. **Functional Cardano Preview testnet smart contract** (`contracts/cardano/`)
3. **Milestone verification and controlled payouts**
4. **Standalone municipal/civic project management app** (dynamically named *Montes de Oca* for the pilot)
5. **Community funding and in-kind resource contributions**
6. **Public transparency and audit dashboard**
7. **Future integrations** (e.g., CONSUL Democracy plugin) and additional industry use cases

---

## Quickstart

Requires **Go >= 1.22**. Run the domain invariant test suite:

```bash
cd backend
go test -v ./...
```

Next, read [`docs/CONTRACT_SPEC.md`](docs/CONTRACT_SPEC.md), [`SECURITY.md`](SECURITY.md), and [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Security & Testnet Notice

- Target network: **Cardano Preview Testnet** (`preview`).
- Never commit wallet seed phrases, signing keys (`.skey`), or RPC API secrets.
- Never store personal identifiable information (PII) or raw deliverable files on-chain; store files off-chain and anchor only cryptographic hashes.
