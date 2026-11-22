//// Cardano Milestone Escrow — Core eUTxO Validator (Aiken)
//// Mirrors the proven invariants from `backend/escrow/escrow.go`.
//// Central Principle: Funds are released according to verifiable agreements,
//// not simply because someone requests payment.

pub type VerificationKeyHash =
  ByteArray

pub type Status {
  Created
  Funded
  Submitted
  Disputed
  Completed
  Cancelled
}

pub type MilestoneState {
  amount: Int,
  evidence_hash: ByteArray,
  settlement_receipt_hash: ByteArray,
  resolution_hash: ByteArray,
  submitted: Bool,
  verified: Bool,
  released: Bool,
  refunded: Bool,
}

/// EscrowDatum represents the on-chain state attached to an Escrow UTxO.
/// Notice zero PII and zero organization strings are stored on-chain—only
/// compact key hashes, integer lovelace amounts, and cryptographic hashes.
pub type EscrowDatum {
  escrow_id: ByteArray,
  client: VerificationKeyHash,
  contractor: VerificationKeyHash,
  verifier: VerificationKeyHash,
  arbiter: VerificationKeyHash,
  beneficiary: VerificationKeyHash,
  deadline_unix: Int,
  status: Status,
  funded_amount: Int,
  released_amount: Int,
  refunded_amount: Int,
  milestone: MilestoneState,
}

/// EscrowRedeemer represents the action being authorized in a transaction.
pub type EscrowRedeemer {
  Submit { evidence_hash: ByteArray }
  Verify
  Approve
  RecordSettlementReceipt { receipt_hash: ByteArray }
  Dispute
  ResolveDispute { release_to_contractor: Bool, resolution_hash: ByteArray }
  RotateContractorKey { new_contractor: VerificationKeyHash, proof_hash: ByteArray }
  Expire { current_unix: Int }
}

// -----------------------------------------------------------------------------
// Helper Functions (Pure On-Chain Invariant Checks)
// -----------------------------------------------------------------------------

/// Checks whether a required VerificationKeyHash signed the transaction.
pub fn is_signed_by(
  signatories: List<VerificationKeyHash>,
  required_key: VerificationKeyHash,
) -> Bool {
  when signatories is {
    [] -> False
    [head, ..tail] ->
      if head == required_key {
        True
      } else {
        is_signed_by(tail, required_key)
      }
  }
}

/// Returns the payout destination: `beneficiary` if configured (e.g., Committee Public Fund
/// for Subasta item escrows, or SINPE disburser for small contractors), else `contractor`.
pub fn payout_recipient(datum: EscrowDatum) -> VerificationKeyHash {
  if datum.beneficiary != "" {
    datum.beneficiary
  } else {
    datum.contractor
  }
}

/// Enforces strict Separation of Duties: Client, Contractor, Verifier, and Arbiter
/// must all be distinct keys.
pub fn valid_roles(datum: EscrowDatum) -> Bool {
  let base_distinct =
    datum.client != "" && datum.contractor != "" && datum.client != datum.contractor
  let verifier_distinct =
    datum.verifier == "" || (
      datum.verifier != datum.client && datum.verifier != datum.contractor && datum.verifier != datum.arbiter
    )
  let arbiter_distinct =
    datum.arbiter == "" || (
      datum.arbiter != datum.client && datum.arbiter != datum.contractor
    )
  base_distinct && verifier_distinct && arbiter_distinct
}

/// Enforces Datum Continuity: ensures immutable escrow parameters cannot be tampered with
/// when producing the continuing Escrow UTxO.
pub fn actors_and_terms_unchanged(old: EscrowDatum, new: EscrowDatum) -> Bool {
  old.escrow_id == new.escrow_id && old.client == new.client && old.contractor == new.contractor && old.verifier == new.verifier && old.arbiter == new.arbiter && old.beneficiary == new.beneficiary && old.deadline_unix == new.deadline_unix && old.funded_amount == new.funded_amount && old.milestone.amount == new.milestone.amount
}

/// PayoutOutput models a transaction output paying `lovelace` to `recipient`,
/// tagged with `payment_tag` (the unique `escrow_id` / UTxO reference) to prevent
/// Double Satisfaction attacks when multiple script UTxOs are spent.
pub type PayoutOutput {
  recipient: VerificationKeyHash,
  lovelace: Int,
  payment_tag: ByteArray,
}

/// Sums ONLY the payout outputs delivered to `expected_recipient` whose `payment_tag`
/// matches `expected_escrow_id`. Because each escrow has a unique `escrow_id`, a single
/// payout output can NEVER satisfy two different Escrow inputs (blocking Double Satisfaction!).
pub fn sum_tagged_payouts(
  outputs: List<PayoutOutput>,
  expected_recipient: VerificationKeyHash,
  expected_escrow_id: ByteArray,
) -> Int {
  when outputs is {
    [] -> 0
    [out, ..rest] ->
      if out.recipient == expected_recipient && out.payment_tag == expected_escrow_id && out.lovelace > 0 {
        out.lovelace + sum_tagged_payouts(
          rest,
          expected_recipient,
          expected_escrow_id,
        )
      } else {
        sum_tagged_payouts(rest, expected_recipient, expected_escrow_id)
      }
  }
}

/// Enforces the Asset Conservation Equation:
/// ReleasedAmount + RefundedAmount + RemainingLocked == FundedAmount
pub fn asset_conservation_holds(
  datum: EscrowDatum,
  continuing_lovelace: Int,
) -> Bool {
  datum.milestone.amount > 0 && datum.funded_amount == datum.milestone.amount && datum.released_amount + datum.refunded_amount + continuing_lovelace == datum.funded_amount
}

// -----------------------------------------------------------------------------
// Core State Transition Validator
// -----------------------------------------------------------------------------

/// Validates a state transition from `old_datum` to `new_datum` given `redeemer`,
/// transaction `signatories`, `continuing_lovelace` remaining locked in the script,
/// and `paid_to_recipient` lovelace delivered to `payout_recipient(old_datum)`.
pub fn validate_transition(
  old_datum: EscrowDatum,
  new_datum: EscrowDatum,
  redeemer: EscrowRedeemer,
  signatories: List<VerificationKeyHash>,
  continuing_lovelace: Int,
  paid_to_recipient: Int,
) -> Bool {
  if !valid_roles(old_datum) || !asset_conservation_holds(
    new_datum,
    continuing_lovelace,
  ) {
    False
  } else {
    when redeemer is {
      // 1. Contractor submits deliverable with non-empty cryptographic evidence hash.
      //    Invariant: Submission NEVER releases funds (`continuing_lovelace == funded_amount`).
      Submit { evidence_hash } ->
        actors_and_terms_unchanged(old_datum, new_datum) && is_signed_by(
          signatories,
          old_datum.contractor,
        ) && old_datum.status == Funded && !old_datum.milestone.released && !old_datum.milestone.refunded && evidence_hash != "" && new_datum.status == Submitted && new_datum.milestone.submitted && new_datum.milestone.evidence_hash == evidence_hash && new_datum.released_amount == 0 && new_datum.refunded_amount == 0 && continuing_lovelace == old_datum.funded_amount

      // 2. Independent Verifier (Inspector) verifies the submitted evidence hash.
      Verify ->
        actors_and_terms_unchanged(old_datum, new_datum) && old_datum.verifier != "" && is_signed_by(
          signatories,
          old_datum.verifier,
        ) && old_datum.status == Submitted && old_datum.milestone.submitted && old_datum.milestone.evidence_hash != "" && !old_datum.milestone.released && new_datum.status == Submitted && new_datum.milestone.verified && new_datum.released_amount == 0 && continuing_lovelace == old_datum.funded_amount

      // 3. Client (Committee / Subasta Buyer) approves payout release.
      //    Requires Inspector verification first if `verifier` is configured!
      Approve -> {
        let inspector_ok =
          old_datum.verifier == "" || old_datum.milestone.verified
        actors_and_terms_unchanged(old_datum, new_datum) && is_signed_by(
          signatories,
          old_datum.client,
        ) && old_datum.status == Submitted && old_datum.milestone.submitted && !old_datum.milestone.released && !old_datum.milestone.refunded && inspector_ok && new_datum.milestone.released && new_datum.released_amount == old_datum.milestone.amount && new_datum.status == Completed && continuing_lovelace == 0 && paid_to_recipient >= old_datum.milestone.amount
      }

      // 4. Anchors SINPE / Bank Comprobante hash when paying a small contractor via Disburser.
      RecordSettlementReceipt { receipt_hash } ->
        actors_and_terms_unchanged(old_datum, new_datum) && (
          is_signed_by(signatories, old_datum.client) || is_signed_by(
            signatories,
            old_datum.beneficiary,
          )
        ) && old_datum.milestone.released && old_datum.milestone.settlement_receipt_hash == "" && receipt_hash != "" && new_datum.milestone.settlement_receipt_hash == receipt_hash

      // 5. Dispute freeze: Only Client, Verifier, or Arbiter can trigger on-chain Dispute
      //    (protects against donor griefing or compromised contractor phones).
      Dispute -> {
        let authorized =
          is_signed_by(signatories, old_datum.client) || (
            old_datum.verifier != "" && is_signed_by(
              signatories,
              old_datum.verifier,
            )
          ) || (
            old_datum.arbiter != "" && is_signed_by(
              signatories,
              old_datum.arbiter,
            )
          )
        actors_and_terms_unchanged(old_datum, new_datum) && authorized && (
          old_datum.status == Funded || old_datum.status == Submitted
        ) && new_datum.status == Disputed && continuing_lovelace == old_datum.funded_amount
      }

      // 6. Arbiter adjudicates an active Dispute with a mandatory resolution_hash.
      ResolveDispute { release_to_contractor, resolution_hash } ->
        actors_and_terms_unchanged(old_datum, new_datum) && old_datum.arbiter != "" && is_signed_by(
          signatories,
          old_datum.arbiter,
        ) && old_datum.status == Disputed && !old_datum.milestone.released && !old_datum.milestone.refunded && resolution_hash != "" && new_datum.milestone.resolution_hash == resolution_hash && new_datum.status == Completed && continuing_lovelace == 0 && if release_to_contractor {
          new_datum.milestone.released && new_datum.released_amount == old_datum.milestone.amount && paid_to_recipient >= old_datum.milestone.amount
        } else {
          new_datum.milestone.refunded && new_datum.refunded_amount == old_datum.milestone.amount
        }

      // 7. 2-of-3 Co-Signed Key Rotation: Client + Arbiter co-sign to revoke a compromised
      //    Contractor key and assign the individual's new key.
      RotateContractorKey { new_contractor, proof_hash } ->
        old_datum.status != Completed && old_datum.status != Cancelled && proof_hash != "" && new_contractor != "" && is_signed_by(
          signatories,
          old_datum.client,
        ) && is_signed_by(signatories, old_datum.arbiter) && new_datum.contractor == new_contractor && valid_roles(
          new_datum,
        ) && continuing_lovelace == old_datum.funded_amount - old_datum.released_amount - old_datum.refunded_amount

      // 8. Liveness / Timeout Escape Hatch after deadline_unix passes.
      Expire { current_unix } ->
        actors_and_terms_unchanged(old_datum, new_datum) && old_datum.deadline_unix > 0 && current_unix > old_datum.deadline_unix && (
          is_signed_by(signatories, old_datum.client) || is_signed_by(
            signatories,
            old_datum.arbiter,
          )
        ) && !old_datum.milestone.released && !old_datum.milestone.refunded && new_datum.milestone.refunded && new_datum.refunded_amount == old_datum.funded_amount && new_datum.status == Completed && continuing_lovelace == 0
    }
  }
}

// -----------------------------------------------------------------------------
// Built-In Aiken Unit & Adversarial Tests (`aiken check`)
// -----------------------------------------------------------------------------

fn sample_datum() -> EscrowDatum {
  EscrowDatum {
    escrow_id: "montes-de-oca-solar-001",
    client: "committee_key",
    contractor: "don_carlos_key",
    verifier: "inspector_dan_key",
    arbiter: "arbiter_carol_key",
    beneficiary: "org_sinpe_disburser_key",
    deadline_unix: 1700000000,
    status: Funded,
    funded_amount: 100_000_000,
    released_amount: 0,
    refunded_amount: 0,
    milestone: MilestoneState {
      amount: 100_000_000,
      evidence_hash: "",
      settlement_receipt_hash: "",
      resolution_hash: "",
      submitted: False,
      verified: False,
      released: False,
      refunded: False,
    },
  }
}

test submit_requires_contractor_signature_and_evidence_hash() {
  let old = sample_datum()
  let new =
    EscrowDatum {
      ..old,
      status: Submitted,
      milestone: MilestoneState {
        ..old.milestone,
        submitted: True,
        evidence_hash: "blake2b256:solar_pole_photo",
      },
    }
  // Valid contractor submission succeeds and keeps 100 ADA locked
  let ok =
    validate_transition(
      old,
      new,
      Submit { evidence_hash: "blake2b256:solar_pole_photo" },
      ["don_carlos_key"],
      100_000_000,
      0,
    )
  // Empty evidence hash is rejected
  let rejected_empty_hash =
    !validate_transition(
      old,
      new,
      Submit { evidence_hash: "" },
      ["don_carlos_key"],
      100_000_000,
      0,
    )
  ok && rejected_empty_hash
}

test approve_blocked_without_inspector_verification_and_succeeds_after() {
  let base = sample_datum()
  let submitted =
    EscrowDatum {
      ..base,
      status: Submitted,
      milestone: MilestoneState {
        ..base.milestone,
        submitted: True,
        evidence_hash: "blake2b256:solar_pole_photo",
      },
    }
  let approved_datum =
    EscrowDatum {
      ..submitted,
      status: Completed,
      released_amount: 100_000_000,
      milestone: MilestoneState {
        ..submitted.milestone,
        verified: True,
        released: True,
      },
    }

  // 1. Client CANNOT approve before Inspector ("inspector_dan_key") verifies!
  let blocked_before_inspector =
    !validate_transition(
      submitted,
      approved_datum,
      Approve,
      ["committee_key"],
      0,
      100_000_000,
    )

  // 2. Once Verified = True, Client approval releases the 100 ADA to PayoutRecipient
  let verified_datum =
    EscrowDatum {
      ..submitted,
      milestone: MilestoneState { ..submitted.milestone, verified: True },
    }
  let allowed_after_inspector =
    validate_transition(
      verified_datum,
      approved_datum,
      Approve,
      ["committee_key"],
      0,
      100_000_000,
    )

  blocked_before_inspector && allowed_after_inspector
}

test compromised_contractor_cannot_dispute_and_key_rotation_requires_two_signers() {
  let old = sample_datum()
  let disputed = EscrowDatum { ..old, status: Disputed }

  // Compromised contractor key CANNOT freeze the contract via Dispute
  let contractor_dispute_blocked =
    !validate_transition(
      old,
      disputed,
      Dispute,
      ["don_carlos_key"],
      100_000_000,
      0,
    )

  // Rotating contractor key requires BOTH Client ("committee_key") AND Arbiter ("arbiter_carol_key")
  let rotated = EscrowDatum { ..old, contractor: "don_carlos_new_key" }
  let single_signer_blocked =
    !validate_transition(
      old,
      rotated,
      RotateContractorKey {
        new_contractor: "don_carlos_new_key",
        proof_hash: "blake2b256:affidavit",
      },
      ["committee_key"],
      100_000_000,
      0,
    )
  let co_signed_rotation_ok =
    validate_transition(
      old,
      rotated,
      RotateContractorKey {
        new_contractor: "don_carlos_new_key",
        proof_hash: "blake2b256:affidavit",
      },
      ["committee_key", "arbiter_carol_key"],
      100_000_000,
      0,
    )

  contractor_dispute_blocked && single_signer_blocked && co_signed_rotation_ok
}

test double_satisfaction_attack_is_blocked_by_tagged_payouts() {
  let escrow_a = sample_datum()
  let escrow_b =
    EscrowDatum { ..sample_datum(), escrow_id: "montes-de-oca-bench-002" }

  // Attacker creates only ONE 100-ADA output tagged for `escrow_a` ("montes-de-oca-solar-001")
  // and tries to use it to satisfy BOTH `escrow_a` and `escrow_b`!
  let tx_outputs =
    [
      PayoutOutput {
        recipient: "org_sinpe_disburser_key",
        lovelace: 100_000_000,
        payment_tag: "montes-de-oca-solar-001",
      },
    ]

  let paid_for_a =
    sum_tagged_payouts(
      tx_outputs,
      payout_recipient(escrow_a),
      escrow_a.escrow_id,
    )
  let paid_for_b =
    sum_tagged_payouts(
      tx_outputs,
      payout_recipient(escrow_b),
      escrow_b.escrow_id,
    )

  // Escrow A sees its 100 ADA, while Escrow B sees 0 ADA and rejects the transaction!
  paid_for_a == 100_000_000 && paid_for_b == 0
}
