# Cardano Aiken Smart Contracts (`contracts/cardano/`)

This directory contains the **Cardano eUTxO Smart Contract Validators** written in **Aiken** (`plutus = "v3"`), mirroring every invariant proven in [`backend/escrow/`](../../backend/escrow/escrow.go).

## Files

- [`aiken.toml`](aiken.toml) — Aiken project configuration targeting Cardano Plutus V3.
- [`validators/escrow.ak`](validators/escrow.ak) — Core Milestone & Subasta Escrow Validator enforcing:
  - Strict Separation of Duties (`valid_roles`)
  - Datum Continuity (`actors_and_terms_unchanged`)
  - Asset Conservation (`released_amount + refunded_amount + continuing_lovelace == funded_amount`)
  - Mandatory Evidence Hashes (`Submit`), Independent Inspector Verification (`Verify`), and Client Approval (`Approve`)
  - SINPE / Bank Disbursement Receipt Anchoring (`RecordSettlementReceipt`)
  - Griefing-Resistant Dispute Freeze (`Dispute` restricted to `Client`, `Verifier`, or `Arbiter`)
  - Arbiter Adjudication (`ResolveDispute`)
  - 2-of-3 Co-Signed Compromised Key Revocation & Rotation (`RotateContractorKey`)
  - Timeout Liveness Escape Hatch (`Expire`)

## Running the Built-In Aiken Tests

Once the [Aiken CLI](https://aiken-lang.org/installation-instructions) is installed:

```bash
cd contracts/cardano
aiken check
```
