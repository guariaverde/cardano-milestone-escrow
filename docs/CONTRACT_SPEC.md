# Escrow Contract & Domain Specification — V0.2

## 1. Core Principle
**Funds are released according to verifiable agreements, not simply because someone requests payment.**

The escrow engine is **domain-agnostic**. Civic and municipal concepts (such as dynamically named organization headers, *Montes de Oca* pilot metadata, or in-kind community resource pledges) live in an off-chain domain layer and must never be hardcoded into the core escrow state machine or Cardano Aiken validators.

## 2. Three Collection Avenues & On-Chain Custody Flows
All incoming value flows through verifiable escrow and pool contracts so the public can trace every unit from origin to final milestone expenditure:
1. **Avenue 1 — Direct Project Crowdfunding ("GoFundMe" Model):**
   - Backers/citizens/sponsors contribute directly to a specific posted Project Milestone Escrow.
   - Funds remain locked until the contractor submits milestone evidence and the verifier/client approves release.
2. **Avenue 2 — Donated-Item Marketplace (`Fixed Price`, `Open Subasta`, `Blind Best-Offer Subasta`):**
   - Citizens donate items to the organization; the organization inspects the item and lists it under Fixed Price, Open Auction (*Subasta*), or Sealed/Blind Best Offer (*Sobre Cerrado*).
   - The winning buyer locks payment in an **Item Delivery Escrow** (a 1-milestone escrow where the Winning Buyer is the payer/approver, the Organization is the deliverer/inspector, and the payout beneficiary is the **Committee Public Fund**).
   - Once item delivery is verified, the escrow releases the proceeds into the **Committee Public Fund**.
3. **Avenue 3 — Direct Organization / Committee Fund Donations:**
   - Donors contribute directly to the **Committee Public Fund** UTxO/pool.
   - The committee manages the pool publicly and posts scheduled/annual allocations to approved projects.
   - **Pool Invariant:** Funds in the Committee Public Fund can **only** be distributed into publicly posted, approved Project Milestone Escrows—never withdrawn to arbitrary personal wallets.

## 3. Actors & Separation of Duties
Role identifiers are validated on-chain via cryptographic key hashes (`VerificationKeyHash`) or policy tokens, never trusted from HTTP headers or database flags:
- **Client / Project Sponsor (or Approving Authority):** Funds or oversees the escrow and authorizes final milestone payouts (can be configured as a single key, municipal administrator, or multi-sig/verifier policy).
- **Contributors / Backers:** Citizens, businesses, grants, or institutions contributing funds into the project escrow (or recording off-chain in-kind resource contributions).
- **Contractor:** Executes project deliverables, uploads off-chain evidence, and submits the milestone completion claim anchored by an `evidence_hash`.
- **Verifier / Authorized Inspector:** Independently verifies physical or technical completion of a milestone before or alongside Client/Sponsor payout authorization.
- **Arbiter:** Independent dispute-resolution authority empowered to adjudicate frozen escrows when a dispute is raised.

## 4. Non-Negotiable Invariants
- **Primary Chain:** Cardano (`preview` testnet for development). Financial amounts on-chain are integer `lovelace` (or explicit native token units).
- **Full Funding Gate:** All scheduled milestones must be fully funded and locked in the escrow UTxO before execution/release begins (`FundedAmount == Total()`). No zero-value milestones (`Amount > 0`).
- **Evidence Before Release:** A contractor must submit a milestone (`Submitted = true`, accompanied on-chain by an off-chain evidence digest such as `Blake2b-256` / `SHA-256`) before it can be approved for release.
- **No Unilateral Payout on Submission:** Marking a milestone `Submitted` never releases funds on its own.
- **Single Release per Milestone (No Replay / Double Satisfaction):** A submitted milestone can be approved and released at most once (`!m.Released`).
- **Dispute Freeze:** Either the client/sponsor or contractor can initiate a `Disputed` state while active, which immediately freezes ordinary milestone approvals until resolved.
- **Asset Conservation:**
  $$\text{Released} + \text{Remaining Locked} + \text{Authorized Refunds} = \text{Original Principal}$$
  (with Cardano transaction fees and protocol `min-UTxO` deposits accounted for explicitly).
- **Database $\neq$ Custody (Zero-Key Server Architecture):** Off-chain PostgreSQL or Go memory state is an index and workflow coordinator; the hosted web server holds **zero signing keys**. On-chain payouts require a valid transaction signed by the required independent verification keys (ideally hardware-wallet Multi-Sig) and accepted by the on-chain validator. Even a total compromise of the web hosting server cannot steal or redirect escrowed funds.
- **Cost-Capped Non-Profit Maintenance Pool:** Any platform sustainability fee for hosting and maintenance is governed by an explicit on-chain `PeriodCap` (the exact budgeted hosting/maintenance need). Once `MaintenancePoolCollected >= PeriodCap`, the fee automatically drops to `0` (or routes 100% into the Committee Public Fund), preventing excess accumulation. Every maintenance withdrawal requires an anchored invoice/receipt hash.
- **Privacy & Off-Chain Evidence:** Never store personal identifiable information (PII) or raw deliverable files on-chain. Store documents/photos off-chain and anchor only cryptographic hashes on-chain.

## 5. Current Go Reference State Machine Limitations
The code in [`backend/escrow/escrow.go`](../backend/escrow/escrow.go) is the **Stage 1 reference state machine** used to prove state-transition invariants before encoding them into Aiken:
- Its `uint64` amounts do not yet model Cardano `min-UTxO` lovelace requirements, multi-asset bundles, transaction fees, or rollbacks.
- Multi-party inspector co-signing, explicit payout `Beneficiary` (for routing Marketplace Item Escrow proceeds to the Committee Public Fund), evidence hashes, arbiter adjudication, and refund paths will be layered incrementally in subsequent lessons/stages.

## 6. Implementation Order
1. **Stage 1:** Formalize generic escrow state machine, actors, and adversarial unit tests in Go (`backend/escrow/`).
2. **Stage 2:** Implement Cardano Aiken spending/minting validators (`contracts/cardano/`) with adversarial property tests (double-satisfaction, datum continuity, unauthorized signers).
3. **Stage 3:** Build Cardano Preview testnet transaction adapters (`adapters/`) and evidence-hash anchoring.
4. **Stage 4:** Build the standalone Go backend + React/Vite civic application (`frontend/`) with **dynamic organization naming** (defaulting to **Municipalidad de Montes de Oca** and the **Solar-Powered Public Park Lighting** pilot project).
5. **Stage 5:** Implement the **Three Funding Avenues**:
   - Direct Project Crowdfunding ("GoFundMe" into Project Escrow)
   - Donated-Item Marketplace (`Fixed Price`, `Subasta Abierta`, `Blind Subasta` locked in Item Delivery Escrow $\rightarrow$ released upon delivery to Committee Public Fund)
   - Direct Organization / Committee Fund Donations & scheduled distributions to posted projects
6. **Stage 6:** Build the global Public Transparency & Audit Dashboard showing end-to-end money lineage from every funding source to final project milestone expenditures.
7. **Stage 7:** Package the decoupled core as optional plug-ins for external platforms (e.g., a future CONSUL plug-in) and complete independent security review.
