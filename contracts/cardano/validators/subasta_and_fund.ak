//// Cardano Milestone Escrow — Lesson 08:
//// 1. Collision-Free Individual-UTxO Subasta Bid Validator (with 9-Loser Batch Refund)
//// 2. Restricted Committee Public Fund Validator with M-of-N Committee Quorum,
////    Target EscrowDatum Inspection, and Quorum+Arbiter Governed Contract Upgrades.

use escrow.{
  EscrowDatum, Funded, VerificationKeyHash, is_signed_by, valid_roles,
}

// =============================================================================
// PART 1: Collision-Free Subasta Bid Ticket Validator
// =============================================================================

pub type SubastaBidDatum {
  subasta_id: ByteArray,
  bidder: VerificationKeyHash,
  organization: VerificationKeyHash,
  committee_fund_id: VerificationKeyHash,
  bid_amount: Int,
  close_unix: Int,
}

pub type SubastaBidRedeemer {
  WinToDeliveryEscrow
  RefundLosingBid { current_unix: Int }
}

pub fn validate_subasta_bid(
  bid_datum: SubastaBidDatum,
  redeemer: SubastaBidRedeemer,
  signatories: List<VerificationKeyHash>,
  created_delivery_escrow: EscrowDatum,
  lovelace_locked_in_escrow: Int,
  lovelace_refunded_to_bidder: Int,
) -> Bool {
  if bid_datum.bid_amount <= 0 || bid_datum.bidder == "" || bid_datum.organization == "" || bid_datum.bidder == bid_datum.organization {
    False
  } else {
    when redeemer is {
      WinToDeliveryEscrow ->
        is_signed_by(signatories, bid_datum.organization) && lovelace_locked_in_escrow >= bid_datum.bid_amount && created_delivery_escrow.status == Funded && created_delivery_escrow.client == bid_datum.bidder && created_delivery_escrow.contractor == bid_datum.organization && created_delivery_escrow.beneficiary == bid_datum.committee_fund_id && created_delivery_escrow.funded_amount == bid_datum.bid_amount && created_delivery_escrow.milestone.amount == bid_datum.bid_amount && !created_delivery_escrow.milestone.released

      RefundLosingBid { current_unix } -> {
        let authorized_refund =
          is_signed_by(signatories, bid_datum.organization) || (
            current_unix > bid_datum.close_unix && is_signed_by(
              signatories,
              bid_datum.bidder,
            )
          )
        authorized_refund && lovelace_refunded_to_bidder >= bid_datum.bid_amount
      }
    }
  }
}

// =============================================================================
// PART 2: Committee Public Fund Validator (M-of-N Multi-Sig Quorum & Guarded Upgrades)
// =============================================================================

/// Counts how many distinct committee members from `committee_members` signed the transaction.
pub fn count_committee_signatures(
  committee_members: List<VerificationKeyHash>,
  signatories: List<VerificationKeyHash>,
) -> Int {
  when committee_members is {
    [] -> 0
    [member, ..rest] ->
      if is_signed_by(signatories, member) {
        1 + count_committee_signatures(rest, signatories)
      } else {
        count_committee_signatures(rest, signatories)
      }
  }
}

/// CommitteeFundDatum enforces M-of-N Multi-Sig governance over the public pool.
/// - `committee_members`: list of individual committee member keys (e.g. 3 or 5 members)
/// - `required_quorum`: minimum members who must co-sign (e.g. 2 of 3, or 3 of 5)
/// - `governance_arbiter`: independent arbiter required to co-sign any contract hash upgrade
/// - `escrow_script_hash`: immutable hash of the official Project Milestone Escrow validator
pub type CommitteeFundDatum {
  fund_id: ByteArray,
  committee_key: VerificationKeyHash,
  committee_members: List<VerificationKeyHash>,
  required_quorum: Int,
  governance_arbiter: VerificationKeyHash,
  escrow_script_hash: ByteArray,
  balance: Int,
}

pub type CommitteeFundRedeemer {
  /// Allocates funds to an official Project Milestone Escrow (requires M-of-N Committee Quorum)
  AllocateToProject { project_id: ByteArray, amount: Int }
  /// Upgrades the official `escrow_script_hash` (requires M-of-N Committee Quorum + Independent Arbiter)
  UpgradeEscrowScript {
    new_escrow_script_hash: ByteArray,
    audit_report_hash: ByteArray,
  }
}

/// Validates any spend or governance update on the Committee Public Fund UTxO.
pub fn validate_committee_fund_allocation(
  old_pool: CommitteeFundDatum,
  new_pool: CommitteeFundDatum,
  redeemer: CommitteeFundRedeemer,
  signatories: List<VerificationKeyHash>,
  continuing_pool_lovelace: Int,
  destination_script_hash: ByteArray,
  lovelace_sent_to_project: Int,
  target_project_escrow: EscrowDatum,
) -> Bool {
  // Verify that the required quorum of committee members (at least 2) co-signed this transaction!
  let quorum_met =
    old_pool.required_quorum >= 2 && count_committee_signatures(
      old_pool.committee_members,
      signatories,
    ) >= old_pool.required_quorum

  when redeemer is {
    AllocateToProject { project_id, amount } -> {
      // 1. Datum Continuity on the continuing Committee Pool UTxO (no changing quorum or script hash!)
      let pool_terms_unchanged =
        old_pool.fund_id == new_pool.fund_id && old_pool.committee_key == new_pool.committee_key && old_pool.committee_members == new_pool.committee_members && old_pool.required_quorum == new_pool.required_quorum && old_pool.governance_arbiter == new_pool.governance_arbiter && old_pool.escrow_script_hash == new_pool.escrow_script_hash

      // 2. Balance Conservation: exact remaining balance stays locked in the pool
      let balance_conserved =
        amount > 0 && amount <= old_pool.balance && new_pool.balance == old_pool.balance - amount && continuing_pool_lovelace == new_pool.balance

      // 3. Target Project Escrow Integrity Check:
      //    Not only must the money go to `old_pool.escrow_script_hash`, the target project's
      //    `EscrowDatum` MUST have valid distinct roles, an independent Inspector (`verifier != ""`),
      //    and an independent Arbiter (`arbiter != ""`)!
      let valid_target_project =
        project_id != "" && destination_script_hash == old_pool.escrow_script_hash && lovelace_sent_to_project >= amount && target_project_escrow.client == old_pool.committee_key && target_project_escrow.verifier != "" && target_project_escrow.arbiter != "" && valid_roles(
          target_project_escrow,
        )

      quorum_met && pool_terms_unchanged && balance_conserved && valid_target_project
    }

    // 4. Guarded Contract Upgrade: Changing `escrow_script_hash` requires:
    //    - M-of-N Committee Quorum (multiple committee members), AND
    //    - The Independent `governance_arbiter` signature, AND
    //    - A non-empty `audit_report_hash`
    //    - Zero lovelace can leave the pool during an upgrade (`continuing_pool_lovelace == old_pool.balance`)!
    UpgradeEscrowScript { new_escrow_script_hash, audit_report_hash } -> {
      let governance_unchanged =
        old_pool.fund_id == new_pool.fund_id && old_pool.committee_key == new_pool.committee_key && old_pool.committee_members == new_pool.committee_members && old_pool.required_quorum == new_pool.required_quorum && old_pool.governance_arbiter == new_pool.governance_arbiter && old_pool.balance == new_pool.balance && continuing_pool_lovelace == old_pool.balance

      quorum_met && old_pool.governance_arbiter != "" && is_signed_by(
        signatories,
        old_pool.governance_arbiter,
      ) && new_escrow_script_hash != "" && audit_report_hash != "" && new_pool.escrow_script_hash == new_escrow_script_hash && governance_unchanged
    }
  }
}

// =============================================================================
// Built-In Aiken Unit & Adversarial Tests (`aiken check`)
// =============================================================================

fn sample_bid() -> SubastaBidDatum {
  SubastaBidDatum {
    subasta_id: "subasta-bike-001",
    bidder: "bidder_ana_key",
    organization: "committee_key",
    committee_fund_id: "committee_public_fund_key",
    bid_amount: 50_000_000,
    close_unix: 1700000000,
  }
}

fn dummy_delivery_escrow() -> EscrowDatum {
  EscrowDatum {
    escrow_id: "delivery-subasta-bike-001",
    client: "bidder_ana_key",
    contractor: "committee_key",
    verifier: "",
    arbiter: "arbiter_carol_key",
    beneficiary: "committee_public_fund_key",
    deadline_unix: 1700500000,
    status: Funded,
    funded_amount: 50_000_000,
    released_amount: 0,
    refunded_amount: 0,
    milestone: escrow.MilestoneState {
      amount: 50_000_000,
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

fn valid_target_project_escrow() -> EscrowDatum {
  EscrowDatum {
    escrow_id: "proj-solar-lighting-001",
    client: "committee_key",
    contractor: "don_carlos_key",
    verifier: "inspector_dan_key",
    arbiter: "arbiter_carol_key",
    beneficiary: "org_sinpe_disburser_key",
    deadline_unix: 1700500000,
    status: Funded,
    funded_amount: 150_000_000,
    released_amount: 0,
    refunded_amount: 0,
    milestone: escrow.MilestoneState {
      amount: 150_000_000,
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

test bidder_cannot_back_out_before_subasta_closes() {
  let bid = sample_bid()
  let dummy_escrow = dummy_delivery_escrow()

  let early_backout_blocked =
    !validate_subasta_bid(
      bid,
      RefundLosingBid { current_unix: 1699990000 },
      ["bidder_ana_key"],
      dummy_escrow,
      0,
      50_000_000,
    )

  let org_settlement_refund_ok =
    validate_subasta_bid(
      bid,
      RefundLosingBid { current_unix: 1699990000 },
      ["committee_key"],
      dummy_escrow,
      0,
      50_000_000,
    )

  let winner_to_escrow_ok =
    validate_subasta_bid(
      bid,
      WinToDeliveryEscrow,
      ["committee_key"],
      dummy_escrow,
      50_000_000,
      0,
    )

  early_backout_blocked && org_settlement_refund_ok && winner_to_escrow_ok
}

test committee_fund_requires_multi_member_quorum_and_guards_contract_upgrade() {
  let old_pool =
    CommitteeFundDatum {
      fund_id: "montes-de-oca-public-pool",
      committee_key: "committee_key",
      committee_members: ["member_1", "member_2", "member_3"],
      required_quorum: 2,
      governance_arbiter: "arbiter_carol_key",
      escrow_script_hash: "official_project_escrow_v1_hash",
      balance: 200_000_000,
    }
  let new_pool = CommitteeFundDatum { ..old_pool, balance: 50_000_000 }
  let target_escrow = valid_target_project_escrow()
  let alloc_redeemer =
    AllocateToProject {
      project_id: "proj-solar-lighting-001",
      amount: 150_000_000,
    }

  // 1. Single Committee Member alone ("member_1") CANNOT allocate funds -> BLOCKED!
  let single_member_blocked =
    !validate_committee_fund_allocation(
      old_pool,
      new_pool,
      alloc_redeemer,
      ["member_1"],
      50_000_000,
      "official_project_escrow_v1_hash",
      150_000_000,
      target_escrow,
    )

  // 2. 2-of-3 Committee Quorum ("member_1" + "member_2") allocating to valid Project Escrow -> ALLOWED!
  let quorum_allocation_ok =
    validate_committee_fund_allocation(
      old_pool,
      new_pool,
      alloc_redeemer,
      ["member_1", "member_2"],
      50_000_000,
      "official_project_escrow_v1_hash",
      150_000_000,
      target_escrow,
    )

  // 3. Upgrading `escrow_script_hash` WITHOUT the Independent Arbiter -> BLOCKED!
  let upgraded_pool =
    CommitteeFundDatum {
      ..old_pool,
      escrow_script_hash: "official_project_escrow_v2_hash",
    }
  let upgrade_without_arbiter_blocked =
    !validate_committee_fund_allocation(
      old_pool,
      upgraded_pool,
      UpgradeEscrowScript {
        new_escrow_script_hash: "official_project_escrow_v2_hash",
        audit_report_hash: "sha256:security_audit_v2",
      },
      ["member_1", "member_2"],
      200_000_000,
      "",
      0,
      target_escrow,
    )

  // 4. Upgrading `escrow_script_hash` WITH 2-of-3 Committee Quorum + Independent Arbiter -> ALLOWED!
  let upgrade_with_quorum_and_arbiter_ok =
    validate_committee_fund_allocation(
      old_pool,
      upgraded_pool,
      UpgradeEscrowScript {
        new_escrow_script_hash: "official_project_escrow_v2_hash",
        audit_report_hash: "sha256:security_audit_v2",
      },
      ["member_1", "member_3", "arbiter_carol_key"],
      200_000_000,
      "",
      0,
      target_escrow,
    )

  single_member_blocked && quorum_allocation_ok && upgrade_without_arbiter_blocked && upgrade_with_quorum_and_arbiter_ok
}
