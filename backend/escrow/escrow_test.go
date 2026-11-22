package escrow

import "testing"

func sample() *Escrow {
	return &Escrow{
		Client:     "alice",
		Contractor: "bob",
		Arbiter:    "carol",
		Status:     Created,
		Milestones: []Milestone{{Amount: 100}, {Amount: 200}},
	}
}

func TestLifecycle(t *testing.T) {
	e := sample()
	if err := e.Fund("alice", 300); err != nil {
		t.Fatal(err)
	}
	if err := e.Submit("bob", 0); err != nil {
		t.Fatal(err)
	}
	if err := e.Approve("alice", 0); err != nil {
		t.Fatal(err)
	}
	if e.ReleasedAmount != 100 || e.Status != Funded {
		t.Fatal("wrong first payout")
	}
	if err := e.Submit("bob", 1); err != nil {
		t.Fatal(err)
	}
	if err := e.Approve("alice", 1); err != nil {
		t.Fatal(err)
	}
	if e.Status != Completed || e.ReleasedAmount != 300 {
		t.Fatal("wrong final state")
	}
}

func TestUnauthorizedAndDoubleRelease(t *testing.T) {
	e := sample()
	if e.Fund("bob", 300) == nil {
		t.Fatal("non-client funded")
	}
	if err := e.Fund("alice", 300); err != nil {
		t.Fatal(err)
	}
	if e.Approve("alice", 0) == nil {
		t.Fatal("approved without submission")
	}
	if e.Submit("alice", 0) == nil {
		t.Fatal("client submitted")
	}
	if err := e.Submit("bob", 0); err != nil {
		t.Fatal(err)
	}
	if e.Approve("bob", 0) == nil {
		t.Fatal("contractor approved")
	}
	if err := e.Approve("alice", 0); err != nil {
		t.Fatal(err)
	}
	if e.Approve("alice", 0) == nil {
		t.Fatal("double release")
	}
}

func TestDisputeBlocksApproval(t *testing.T) {
	e := sample()
	_ = e.Fund("alice", 300)
	_ = e.Submit("bob", 0)
	// Donors and compromised contractor accounts cannot unilaterally freeze the escrow
	if e.Dispute("donor_maria") == nil {
		t.Fatal("donor must not be able to trigger dispute")
	}
	if e.Dispute("bob") == nil {
		t.Fatal("contractor account alone must not be able to trigger dispute")
	}
	// Authorized oversight role (Client, Verifier, or Arbiter) initiates the dispute
	if err := e.Dispute("carol"); err != nil {
		t.Fatal(err)
	}
	if e.Approve("alice", 0) == nil {
		t.Fatal("dispute must freeze approval")
	}
}

func TestCannotApproveMilestoneTwice(t *testing.T) {
	e := sample()
	if err := e.Fund("alice", 300); err != nil {
		t.Fatal(err)
	}
	if err := e.Submit("bob", 0); err != nil {
		t.Fatal(err)
	}
	if err := e.Submit("bob", 1); err != nil {
		t.Fatal(err)
	}
	if err := e.Approve("alice", 0); err != nil {
		t.Fatal(err)
	}
	if e.Approve("alice", 0) == nil {
		t.Fatal("client approved milestone 0 twice")
	}
	if e.ReleasedAmount != 100 || e.Status != Submitted {
		t.Fatalf("unexpected state after blocked second approval: released=%d status=%s", e.ReleasedAmount, e.Status)
	}
}

func TestZeroValueMilestoneRejected(t *testing.T) {
	e := &Escrow{
		Client:     "alice",
		Contractor: "bob",
		Arbiter:    "carol",
		Status:     Created,
		Milestones: []Milestone{{Amount: 0}, {Amount: 200}},
	}
	if _, err := e.Total(); err == nil {
		t.Fatal("expected Total() to reject zero-value milestone")
	}
	if err := e.Fund("alice", 200); err == nil {
		t.Fatal("expected Fund() to reject escrow with zero-value milestone")
	}
}

func TestInspectorVerificationAndEvidenceHash(t *testing.T) {
	e := sample()
	e.Verifier = "inspector_dan"
	if err := e.Fund("alice", 300); err != nil {
		t.Fatal(err)
	}
	// Empty evidence hash must be rejected
	if err := e.SubmitWithEvidence("bob", 0, ""); err == nil {
		t.Fatal("expected empty evidence hash to be rejected")
	}
	// Submit with valid Blake2b-256 / SHA-256 hash
	hash0 := "blake2b256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if err := e.SubmitWithEvidence("bob", 0, hash0); err != nil {
		t.Fatal(err)
	}
	// Client cannot approve before Inspector verifies!
	if err := e.Approve("alice", 0); err == nil {
		t.Fatal("expected approval to fail before inspector verification")
	}
	// Contractor or Client cannot impersonate the Inspector
	if err := e.Verify("bob", 0); err == nil {
		t.Fatal("contractor must not be able to verify own work")
	}
	if err := e.Verify("alice", 0); err == nil {
		t.Fatal("client must not bypass independent inspector")
	}
	// Inspector verifies milestone 0
	if err := e.Verify("inspector_dan", 0); err != nil {
		t.Fatal(err)
	}
	// Now Client approval succeeds
	if err := e.Approve("alice", 0); err != nil {
		t.Fatal(err)
	}
	if e.ReleasedAmount != 100 {
		t.Fatalf("expected 100 released after inspector verification, got %d", e.ReleasedAmount)
	}
}

func TestSubastaBeneficiaryRouting(t *testing.T) {
	projectEscrow := sample()
	if projectEscrow.PayoutRecipient() != "bob" {
		t.Fatalf("expected default PayoutRecipient to be contractor bob, got %s", projectEscrow.PayoutRecipient())
	}

	subastaItemEscrow := &Escrow{
		Client:      "winning_bidder_ana",
		Contractor:  "montes_de_oca_org_delivery",
		Beneficiary: "committee_public_fund",
		Status:      Created,
		Milestones:  []Milestone{{Amount: 2000}},
	}
	if subastaItemEscrow.PayoutRecipient() != "committee_public_fund" {
		t.Fatalf("expected Subasta escrow payout recipient to be committee_public_fund, got %s", subastaItemEscrow.PayoutRecipient())
	}

	// Small local contractor mode: Beneficiary is the organization's SINPE disbursement account,
	// which then anchors the SINPE/Factura receipt hash after releasing the milestone.
	smallContractorEscrow := &Escrow{
		Client:      "montes_de_oca_admin",
		Contractor:  "taller_don_carlos",
		Beneficiary: "org_sinpe_disburser",
		Status:      Created,
		Milestones:  []Milestone{{Amount: 500}},
	}
	_ = smallContractorEscrow.Fund("montes_de_oca_admin", 500)
	_ = smallContractorEscrow.SubmitWithEvidence("taller_don_carlos", 0, "blake2b256:work_photos_hash")
	// Cannot record SINPE receipt before milestone is approved/released
	if err := smallContractorEscrow.RecordSettlementReceipt("org_sinpe_disburser", 0, "blake2b256:sinpe_receipt_001"); err == nil {
		t.Fatal("expected error recording settlement receipt before milestone release")
	}
	_ = smallContractorEscrow.Approve("montes_de_oca_admin", 0)
	if err := smallContractorEscrow.RecordSettlementReceipt("org_sinpe_disburser", 0, "blake2b256:sinpe_receipt_001"); err != nil {
		t.Fatal(err)
	}
	// Cannot overwrite an already anchored settlement receipt
	if err := smallContractorEscrow.RecordSettlementReceipt("org_sinpe_disburser", 0, "blake2b256:different_hash"); err == nil {
		t.Fatal("expected error when attempting to overwrite anchored settlement receipt")
	}
}

func TestCostCappedMaintenanceFee(t *testing.T) {
	// Period hosting cap = 150 units; fee = 100 bps (1%)
	periodCap := uint64(150)
	feeBps := uint64(100)

	// 1. First transaction of 10,000 units -> 1% fee is 100 units (collected so far = 0)
	fee1, err := CalculateCappedFee(10000, feeBps, 0, periodCap)
	if err != nil || fee1 != 100 {
		t.Fatalf("expected fee1=100, got %d (err=%v)", fee1, err)
	}

	// 2. Second transaction of 10,000 units -> 1% would be 100, but only 50 room left before 150 cap!
	fee2, err := CalculateCappedFee(10000, feeBps, 100, periodCap)
	if err != nil || fee2 != 50 {
		t.Fatalf("expected fee2 capped at 50, got %d (err=%v)", fee2, err)
	}

	// 3. Third transaction after cap (150) is reached -> fee automatically drops to 0!
	fee3, err := CalculateCappedFee(50000, feeBps, 150, periodCap)
	if err != nil || fee3 != 0 {
		t.Fatalf("expected fee3=0 once periodCap is reached, got %d (err=%v)", fee3, err)
	}
}

func TestThreeCollectionAvenuesAndTenBidderSubasta(t *testing.T) {
	committee := "montes_de_oca_committee"
	fund := &CommitteeFund{
		ID:        "committee_public_fund",
		Committee: committee,
	}

	// --- AVENUE 2: Donated Item in a Blind Subasta (10 bidders each lock $20) ---
	subasta := &SubastaListing{
		ID:              "subasta-bicycle-001",
		ItemDonor:       "vecino_sabanilla",
		Organization:    committee,
		CommitteeFundID: fund.ID,
		Mode:            BlindSubasta,
		MinimumPrice:    20,
	}
	for i := 0; i < 10; i++ {
		bidder := "bidder_" + string(rune('0'+i))
		if err := subasta.PlaceBid(bidder, 20); err != nil {
			t.Fatalf("bid %d failed: %v", i, err)
		}
	}

	// Settle Subasta picking bidder_3 as winner -> 9 losers must be refunded, 1 winner locked in Item Delivery Escrow
	itemEscrow, err := subasta.Settle(committee, 3)
	if err != nil {
		t.Fatal(err)
	}
	refundedCount := 0
	for i, b := range subasta.Bids {
		if i == 3 {
			if !b.Winner || b.Refunded {
				t.Fatal("winner bid should be marked Winner=true and Refunded=false")
			}
		} else {
			if !b.Refunded || b.Winner {
				t.Fatalf("losing bid %d should be marked Refunded=true", i)
			}
			refundedCount++
		}
	}
	if refundedCount != 9 {
		t.Fatalf("expected 9 losing bidders refunded, got %d", refundedCount)
	}

	// Committee CANNOT claim Subasta money before delivering the item to the winner!
	if err := fund.ClaimSubastaProceeds(itemEscrow); err == nil {
		t.Fatal("expected error claiming subasta proceeds before item delivery is approved")
	}

	// Organization delivers inspected item -> Winner (bidder_3) approves delivery -> Committee Fund claims $20
	if err := itemEscrow.SubmitWithEvidence(committee, 0, "blake2b256:item_inspection_and_delivery_photo"); err != nil {
		t.Fatal(err)
	}
	if err := itemEscrow.Approve("bidder_3", 0); err != nil {
		t.Fatal(err)
	}
	if err := fund.ClaimSubastaProceeds(itemEscrow); err != nil {
		t.Fatal(err)
	}
	if fund.Balance != 20 {
		t.Fatalf("expected CommitteeFund balance=20 after Subasta delivery, got %d", fund.Balance)
	}

	// --- AVENUE 3: Direct Donation to the Committee General Fund ($80) ---
	if err := fund.Donate("donor_general_carlos", 80); err != nil {
		t.Fatal(err)
	}
	if fund.Balance != 100 {
		t.Fatalf("expected CommitteeFund balance=100, got %d", fund.Balance)
	}

	// --- AVENUE 1: Specific Project Escrow overseen by Committee (Total Target = $300) ---
	solarProject := &Escrow{
		Client:     committee, // Committee oversees the project escrow
		Contractor: "taller_solar_del_este",
		Verifier:   "inspector_municipal",
		Status:     Created,
		Milestones: []Milestone{{Amount: 100}, {Amount: 200}},
	}

	// Direct project-specific contributions ($120 + $80 = $200 earmarked strictly for solarProject)
	if err := solarProject.Contribute("ciudadana_maria", 120); err != nil {
		t.Fatal(err)
	}
	if err := solarProject.Contribute("ferreteria_cedros", 80); err != nil {
		t.Fatal(err)
	}
	if solarProject.Status != Created || solarProject.FundedAmount != 200 {
		t.Fatal("project should still be in Created state with 200/300 funded")
	}

	// Committee allocates the remaining $100 from the Committee Public Fund to solarProject!
	if err := fund.AllocateToProject(committee, "solar-park-001", solarProject, 100); err != nil {
		t.Fatal(err)
	}
	if solarProject.Status != Funded || solarProject.FundedAmount != 300 || fund.Balance != 0 {
		t.Fatalf("expected solarProject to be fully Funded (300) and fund.Balance=0, got status=%s funded=%d balance=%d",
			solarProject.Status, solarProject.FundedAmount, fund.Balance)
	}
	if len(solarProject.Contributions) != 3 || len(fund.Allocations) != 1 {
		t.Fatal("expected full audit trail of all 3 contributions and committee allocation")
	}
}

func TestArbiterDisputeResolutionAndAssetConservation(t *testing.T) {
	e := sample()
	if err := e.Fund("alice", 300); err != nil {
		t.Fatal(err)
	}
	if err := e.SubmitWithEvidence("bob", 0, "blake2b256:milestone0_evidence"); err != nil {
		t.Fatal(err)
	}

	// 1. Arbiter CANNOT intervene when there is no active dispute!
	if err := e.ResolveDispute("carol", 0, true, "blake2b256:ruling_0"); err == nil {
		t.Fatal("arbiter must not be able to resolve when Status != Disputed")
	}

	// 2. Contractor brings proof to Arbiter because Client refuses to approve completed Milestone 0;
	// Arbiter initiates the on-chain Dispute
	if err := e.Dispute("carol"); err != nil {
		t.Fatal(err)
	}
	// Neither Client nor Contractor can resolve their own dispute, and Arbiter must provide resolutionHash
	if err := e.ResolveDispute("alice", 0, false, "blake2b256:ruling_0"); err == nil {
		t.Fatal("client must not resolve dispute")
	}
	if err := e.ResolveDispute("carol", 0, true, ""); err == nil {
		t.Fatal("arbiter resolution must require non-empty resolutionHash")
	}

	// Arbiter rules in favor of Contractor on Milestone 0 (100 released, 200 remaining locked)
	if err := e.ResolveDispute("carol", 0, true, "blake2b256:ruling_pay_m0"); err != nil {
		t.Fatal(err)
	}
	if e.ReleasedAmount != 100 || e.RefundedAmount != 0 || e.RemainingLocked() != 200 || e.Status != Funded {
		t.Fatalf("unexpected state after Milestone 0 resolution: released=%d refunded=%d remaining=%d status=%s",
			e.ReleasedAmount, e.RefundedAmount, e.RemainingLocked(), e.Status)
	}

	// 3. Contractor abandons Milestone 1 (200); Client raises dispute; Arbiter refunds the 200!
	if err := e.Dispute("alice"); err != nil {
		t.Fatal(err)
	}
	if err := e.ResolveDispute("carol", 1, false, "blake2b256:ruling_refund_m1"); err != nil {
		t.Fatal(err)
	}

	// Asset Conservation Check: Released (100) + Refunded (200) + RemainingLocked (0) == Funded (300)
	if e.ReleasedAmount != 100 || e.RefundedAmount != 200 || e.RemainingLocked() != 0 || e.Status != Completed {
		t.Fatalf("asset conservation failed: released=%d refunded=%d remaining=%d status=%s",
			e.ReleasedAmount, e.RefundedAmount, e.RemainingLocked(), e.Status)
	}
	if e.ReleasedAmount+e.RefundedAmount+e.RemainingLocked() != e.FundedAmount {
		t.Fatal("asset conservation invariant violated")
	}
}

func TestFixedPriceAndOpenSubastaModes(t *testing.T) {
	// FixedPrice mode rejects wrong amounts and accepts exact price
	fixed := &SubastaListing{
		ID:              "fixed-001",
		Organization:    "committee",
		CommitteeFundID: "fund",
		Mode:            FixedPrice,
		MinimumPrice:    50,
	}
	if err := fixed.PlaceBid("buyer1", 40); err == nil {
		t.Fatal("expected FixedPrice to reject wrong amount")
	}
	if err := fixed.PlaceBid("buyer1", 50); err != nil {
		t.Fatal(err)
	}

	// OpenSubasta mode requires strictly ascending bids and settling to the highest bid
	open := &SubastaListing{
		ID:              "open-001",
		Organization:    "committee",
		CommitteeFundID: "fund",
		Mode:            OpenSubasta,
		MinimumPrice:    50,
	}
	if err := open.PlaceBid("bidder1", 50); err != nil {
		t.Fatal(err)
	}
	if err := open.PlaceBid("bidder2", 50); err == nil {
		t.Fatal("expected OpenSubasta to reject equal bid")
	}
	if err := open.PlaceBid("bidder2", 75); err != nil {
		t.Fatal(err)
	}
	if _, err := open.Settle("committee", 0); err == nil {
		t.Fatal("expected OpenSubasta to reject settling to non-highest bid")
	}
	if _, err := open.Settle("committee", 1); err != nil {
		t.Fatal(err)
	}
}

func TestCompromisedAccountRevocationAndKeyRotation(t *testing.T) {
	e := sample() // Client: "alice", Contractor: "bob", Arbiter: "carol"
	e.Verifier = "inspector_dan"
	if err := e.Fund("alice", 300); err != nil {
		t.Fatal(err)
	}

	// Suppose Bob's original account ("bob") is compromised.
	// 1. The hacker cannot rotate the key themselves or with only 1 authority
	if err := e.RotateRoleKey("contractor", "hacker_key", "bob", "alice", "blake2b256:fake"); err == nil {
		t.Fatal("compromised contractor must not be able to co-sign key rotation")
	}
	if err := e.RotateRoleKey("contractor", "bob_new_key", "alice", "alice", "blake2b256:proof"); err == nil {
		t.Fatal("single authority must not be able to rotate key alone")
	}

	// 2. Client ("alice") + Independent Arbiter ("carol") verify Bob's identity off-chain and co-sign
	// the revocation of "bob" and assignment of "bob_new_key"
	proofHash := "blake2b256:signed_id_verification_and_revocation_001"
	if err := e.RotateRoleKey("contractor", "bob_new_key", "alice", "carol", proofHash); err != nil {
		t.Fatal(err)
	}

	// 3. Old compromised account ("bob") is immediately dead and cannot submit milestones!
	if err := e.SubmitWithEvidence("bob", 0, "blake2b256:malicious_submission"); err == nil {
		t.Fatal("revoked contractor account must be blocked from submitting")
	}

	// 4. Bob's new verified account ("bob_new_key") works seamlessly
	if err := e.SubmitWithEvidence("bob_new_key", 0, "blake2b256:valid_solar_pole_photo"); err != nil {
		t.Fatal(err)
	}
	if len(e.KeyRotations) != 1 || e.KeyRotations[0].RevokedActor != "bob" || e.KeyRotations[0].NewActor != "bob_new_key" {
		t.Fatal("expected immutable audit record of key rotation")
	}
}

func TestFourAuditorSecurityProtections(t *testing.T) {
	// 1. Strict Role Distinctness (Prevent 1 person holding 2 roles) + Arbiter Key Rotation
	colluding := sample()
	colluding.Arbiter = "alice" // Illegal: Client == Arbiter!
	if err := colluding.Fund("alice", 300); err == nil {
		t.Fatal("expected Fund() to reject escrow where Client == Arbiter")
	}

	e := sample()
	e.Verifier = "inspector_dan"
	_ = e.Fund("alice", 300)
	// Rotating Arbiter to collide with Client ("alice") must fail and roll back
	if err := e.RotateRoleKey("arbiter", "alice", "alice", "inspector_dan", "blake2b256:bad_rotation"); err == nil {
		t.Fatal("expected key rotation into existing Client role to fail")
	}
	// Rotating compromised Arbiter ("carol") to a distinct new key ("carol_new") via Client + Verifier succeeds
	if err := e.RotateRoleKey("arbiter", "carol_new", "alice", "inspector_dan", "blake2b256:arbiter_rot"); err != nil {
		t.Fatal(err)
	}
	if e.Arbiter != "carol_new" {
		t.Fatal("expected Arbiter to be updated to carol_new")
	}

	// 2. Underfunded Campaign Cancellation & 100% Donor Refund
	underfunded := sample()
	_ = underfunded.Contribute("donor_1", 120)
	_ = underfunded.Contribute("donor_2", 80) // Only 200 / 300 raised
	if err := underfunded.CancelBeforeFunding("alice"); err != nil {
		t.Fatal(err)
	}
	if underfunded.Status != Cancelled || underfunded.RefundedAmount != 200 || underfunded.RemainingLocked() != 0 {
		t.Fatalf("expected Cancelled status and 200 refunded, got status=%s refunded=%d", underfunded.Status, underfunded.RefundedAmount)
	}

	// 3. Deadline / Timeout Liveness Escape Hatch (when Contractor stalls past DeadlineUnix)
	stalled := sample()
	stalled.DeadlineUnix = 1700000000
	_ = stalled.Fund("alice", 300)
	_ = stalled.Submit("bob", 0)
	_ = stalled.Approve("alice", 0) // Milestone 0 (100) paid; Milestone 1 (200) never done
	// Cannot expire before deadline
	if err := stalled.ExpireStalledEscrow("alice", 1699999999); err == nil {
		t.Fatal("expected error expiring before DeadlineUnix")
	}
	// After DeadlineUnix passes, remaining 200 is refunded cleanly
	if err := stalled.ExpireStalledEscrow("alice", 1700000001); err != nil {
		t.Fatal(err)
	}
	if stalled.ReleasedAmount != 100 || stalled.RefundedAmount != 200 || stalled.RemainingLocked() != 0 || stalled.Status != Completed {
		t.Fatalf("unexpected state after timeout expiry: released=%d refunded=%d status=%s",
			stalled.ReleasedAmount, stalled.RefundedAmount, stalled.Status)
	}

	// 4. Anti-Shill-Bidding (ItemDonor blocked) & FixedPrice Single-Buyer Lock
	subasta := &SubastaListing{
		ID:              "subasta-shill-check",
		ItemDonor:       "item_donor_luis",
		Organization:    "committee",
		CommitteeFundID: "fund",
		Mode:            OpenSubasta,
		MinimumPrice:    25,
	}
	if err := subasta.PlaceBid("item_donor_luis", 30); err == nil {
		t.Fatal("expected ItemDonor shill bid to be rejected")
	}

	fixed := &SubastaListing{
		ID:              "fixed-single-lock",
		Organization:    "committee",
		CommitteeFundID: "fund",
		Mode:            FixedPrice,
		MinimumPrice:    50,
	}
	if err := fixed.PlaceBid("buyer_1", 50); err != nil {
		t.Fatal(err)
	}
	if err := fixed.PlaceBid("buyer_2", 50); err == nil {
		t.Fatal("expected second FixedPrice buyer to be rejected once locked")
	}

	// 5. Committee Public Fund M-of-N Quorum & Guarded Contract Upgrade
	pool := &CommitteeFund{
		ID:                "montes-de-oca-pool",
		Committee:         "committee_key",
		CommitteeMembers:  []string{"member_1", "member_2", "member_3"},
		RequiredQuorum:    2,
		GovernanceArbiter: "arbiter_carol",
		EscrowScriptHash:  "official_escrow_v1_hash",
	}
	// Single member (or duplicate signature from same member) fails quorum
	if pool.HasCommitteeQuorum([]string{"member_1", "member_1"}) {
		t.Fatal("duplicate signature from 1 member must not satisfy 2-of-3 quorum")
	}
	// Upgrading contract without Arbiter fails
	if err := pool.UpgradeEscrowContract([]string{"member_1", "member_2"}, "wrong_arbiter", "official_escrow_v2_hash", "sha256:audit"); err == nil {
		t.Fatal("expected contract upgrade without independent arbiter to fail")
	}
	// Upgrading contract with 2-of-3 Committee Quorum + Independent Arbiter + Audit Hash succeeds
	if err := pool.UpgradeEscrowContract([]string{"member_1", "member_3"}, "arbiter_carol", "official_escrow_v2_hash", "sha256:audit"); err != nil {
		t.Fatal(err)
	}
	if pool.EscrowScriptHash != "official_escrow_v2_hash" {
		t.Fatal("expected EscrowScriptHash to update after quorum + arbiter approval")
	}
}
