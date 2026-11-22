# Chain & Fiat Bridge Adapters (`adapters/` & `backend/adapters/`)

This layer connects our domain-agnostic Escrow & Subasta Core (`backend/escrow/`) with:
1. **Cryptographic Evidence & Receipt Hashing (`SHA-256`):** [`backend/adapters/bridge.go`](../backend/adapters/bridge.go) (`HashEvidence`, `VerifyEvidenceHash`).
2. **Zero-Exchange Citizen & Contractor Fiat Bridge:**
   - **Inbound (`DepositFiatToProject`):** Accepts **SINPE Móvil (`CRC`)** and **Regulated On-Ramp Card/Bank (`USD`/`CRC`)** deposits with strict webhook idempotency, automatically applies the **Cost-Capped Non-Profit Hosting Fee** (dropping to `0%` once `HostingPeriodCap` is met), and locks the net funds directly into the target Project Escrow.
   - **Outbound (`SettleMilestoneViaSINPE`):** Completes last-mile Colones (`CRC`) payouts to small local contractors after on-chain Inspector + Committee approval, anchoring the `SHA-256` hash of the official SINPE/IBAN bank comprobante onto the milestone.

## Running the Adapter Tests

```bash
cd backend
go test -v ./...
```
