package escrow

import "errors"

type Status string

const (
	Created   Status = "created"
	Funded    Status = "funded"
	Submitted Status = "submitted"
	Disputed  Status = "disputed"
	Completed Status = "completed"
	Cancelled Status = "cancelled"
)

type Milestone struct {
	Amount                uint64 // smallest on-chain currency unit (lovelace or wei)
	EvidenceHash          string // cryptographic hash (SHA-256 / Blake2b-256) of off-chain deliverable proof
	SettlementReceiptHash string // cryptographic hash of off-chain SINPE/bank payout receipt (when paid via Beneficiary disburser)
	ResolutionHash        string // cryptographic hash of the Arbiter's ruling if resolved via dispute
	Submitted             bool
	Verified              bool // true once independent Verifier/Inspector signs off (when Verifier is configured)
	Released              bool
	Refunded              bool // true if refunded to funders/buyer by Arbiter after a dispute
}

type Contribution struct {
	Donor  string
	Amount uint64
}

type KeyRotationRecord struct {
	Role              string // "client", "contractor", or "verifier"
	RevokedActor      string
	NewActor          string
	AuthorizedByA     string
	AuthorizedByB     string
	RotationProofHash string
}

type Escrow struct {
	Client         string // The Committee / Organization overseeing this project (or Winning Buyer in an Item Delivery Escrow)
	Contractor     string
	Verifier       string // optional independent inspector/verifier (must verify before Client approves)
	Arbiter        string
	Beneficiary    string // optional payout destination (e.g., Committee Public Fund for Subasta sales; defaults to Contractor)
	DeadlineUnix   uint64 // optional unix timestamp deadline for liveness/timeout recovery
	Status         Status
	FundedAmount   uint64
	ReleasedAmount uint64
	RefundedAmount uint64
	Milestones     []Milestone
	Contributions  []Contribution      // tracks every direct donor contribution or Committee Fund allocation to this project
	KeyRotations   []KeyRotationRecord // immutable audit trail of revoked compromised accounts and their replacements
}

// ValidateRoles enforces strict separation of duties: Client, Contractor, Verifier, and Arbiter
// must never share the same account key (preventing 1 person from acting as 2 independent authorities).
func (e *Escrow) ValidateRoles() error {
	if e.Client == "" || e.Contractor == "" || e.Client == e.Contractor {
		return errors.New("client and contractor must be non-empty and distinct")
	}
	if e.Verifier != "" && (e.Verifier == e.Client || e.Verifier == e.Contractor || (e.Arbiter != "" && e.Verifier == e.Arbiter)) {
		return errors.New("verifier must be distinct from client, contractor, and arbiter")
	}
	if e.Arbiter != "" && (e.Arbiter == e.Client || e.Arbiter == e.Contractor) {
		return errors.New("arbiter must be distinct from client and contractor")
	}
	return nil
}

// PayoutRecipient returns Beneficiary if explicitly configured (such as a Committee Public Fund
// for Marketplace/Subasta item delivery escrows), or defaults to Contractor for project escrows.
func (e *Escrow) PayoutRecipient() string {
	if e.Beneficiary != "" {
		return e.Beneficiary
	}
	return e.Contractor
}

func (e *Escrow) Total() (uint64, error) {
	var n uint64
	for _, m := range e.Milestones {
		if m.Amount == 0 || n > ^uint64(0)-m.Amount {
			return 0, errors.New("invalid milestone amount")
		}
		n += m.Amount
	}
	return n, nil
}

func (e *Escrow) Fund(actor string, amount uint64) error {
	if err := e.ValidateRoles(); err != nil {
		return err
	}
	total, err := e.Total()
	if err != nil {
		return err
	}
	if e.Status != Created || actor != e.Client || amount != total || len(e.Milestones) == 0 {
		return errors.New("invalid funding")
	}
	e.FundedAmount = amount
	e.Contributions = append(e.Contributions, Contribution{Donor: actor, Amount: amount})
	e.Status = Funded
	return nil
}

// Contribute allows any donor (citizen, business, or the Committee Public Fund) to contribute
// directly toward this specific project's escrow under the Committee's oversight.
// Once FundedAmount reaches Total(), the escrow automatically transitions to Funded.
func (e *Escrow) Contribute(donor string, amount uint64) error {
	if err := e.ValidateRoles(); err != nil {
		return err
	}
	total, err := e.Total()
	if err != nil {
		return err
	}
	if e.Status != Created || donor == "" || amount == 0 || len(e.Milestones) == 0 {
		return errors.New("invalid contribution")
	}
	if amount > total-e.FundedAmount {
		return errors.New("contribution exceeds remaining project target")
	}
	e.FundedAmount += amount
	e.Contributions = append(e.Contributions, Contribution{Donor: donor, Amount: amount})
	if e.FundedAmount == total {
		e.Status = Funded
	}
	return nil
}

// CancelBeforeFunding cancels a campaign that is still in Created status (has not yet reached
// 100% of its funding goal) and refunds 100% of any partial donor contributions.
func (e *Escrow) CancelBeforeFunding(actor string) error {
	if e.Status != Created || (actor != e.Client && (e.Arbiter == "" || actor != e.Arbiter)) {
		return errors.New("cancellation before funding forbidden")
	}
	e.RefundedAmount = e.FundedAmount
	e.Status = Cancelled
	return nil
}

// Submit marks a milestone as submitted (backward-compatible helper for Lesson 01).
func (e *Escrow) Submit(actor string, idx int) error {
	if actor != e.Contractor || (e.Status != Funded && e.Status != Submitted) || idx < 0 || idx >= len(e.Milestones) || e.Milestones[idx].Released {
		return errors.New("submission forbidden")
	}
	e.Milestones[idx].Submitted = true
	e.Status = Submitted
	return nil
}

// SubmitWithEvidence requires a non-empty cryptographic hash (Blake2b-256 / SHA-256) of the
// off-chain deliverable proof or Subasta item delivery receipt.
func (e *Escrow) SubmitWithEvidence(actor string, idx int, evidenceHash string) error {
	if evidenceHash == "" {
		return errors.New("evidence hash required")
	}
	if err := e.Submit(actor, idx); err != nil {
		return err
	}
	e.Milestones[idx].EvidenceHash = evidenceHash
	return nil
}

// Verify allows the configured independent Verifier (Inspector) to confirm a submitted milestone's
// deliverable evidence before the Client releases payment.
func (e *Escrow) Verify(actor string, idx int) error {
	if e.Verifier == "" || actor != e.Verifier || e.Status != Submitted || idx < 0 || idx >= len(e.Milestones) {
		return errors.New("verification forbidden")
	}
	m := &e.Milestones[idx]
	if !m.Submitted || m.Released || m.EvidenceHash == "" {
		return errors.New("milestone not ready for verification")
	}
	m.Verified = true
	return nil
}

func (e *Escrow) Approve(actor string, idx int) error {
	if actor != e.Client || e.Status != Submitted || idx < 0 || idx >= len(e.Milestones) {
		return errors.New("approval forbidden")
	}
	m := &e.Milestones[idx]
	if !m.Submitted || m.Released || m.Refunded || e.ReleasedAmount+e.RefundedAmount > e.FundedAmount-m.Amount {
		return errors.New("invalid milestone release")
	}
	// If an independent Verifier/Inspector is configured on this escrow, require their verification first!
	if e.Verifier != "" && !m.Verified {
		return errors.New("inspector verification required before approval")
	}
	m.Released = true
	e.ReleasedAmount += m.Amount
	if e.ReleasedAmount+e.RefundedAmount == e.FundedAmount {
		e.Status = Completed
	} else {
		e.Status = Funded
	}
	for _, item := range e.Milestones {
		if item.Submitted && !item.Released && !item.Refunded && e.Status != Completed {
			e.Status = Submitted
		}
	}
	return nil
}

// Dispute freezes ordinary milestone approvals until the Arbiter resolves the dispute.
// Security rule: Donors/givers and Contractors CANNOT unilaterally freeze the contract on-chain
// (protecting against griefing or compromised contractor phones/accounts).
// Only the Client (Committee/Buyer), the independent Verifier (Inspector), or the Arbiter
// can initiate an on-chain Dispute.
func (e *Escrow) Dispute(actor string) error {
	isAuthorized := actor == e.Client || (e.Verifier != "" && actor == e.Verifier) || (e.Arbiter != "" && actor == e.Arbiter)
	if !isAuthorized || (e.Status != Funded && e.Status != Submitted) {
		return errors.New("dispute forbidden")
	}
	e.Status = Disputed
	return nil
}

// RotateRoleKey revokes a compromised or lost account ("contractor", "verifier", or "client")
// and assigns a new account key for that same individual.
// Requires TWO independent uncompromised authorities to co-sign (e.g. Client + Arbiter for
// contractor/verifier rotation; or Arbiter + Verifier for client rotation) plus a rotationProofHash.
func (e *Escrow) RotateRoleKey(role string, newActor string, signerA string, signerB string, rotationProofHash string) error {
	if e.Status == Completed || newActor == "" || rotationProofHash == "" || signerA == "" || signerB == "" || signerA == signerB {
		return errors.New("invalid key rotation parameters")
	}
	hasPair := func(a, b, req1, req2 string) bool {
		return req1 != "" && req2 != "" && ((a == req1 && b == req2) || (a == req2 && b == req1))
	}

	var revoked string
	switch role {
	case "contractor":
		if !hasPair(signerA, signerB, e.Client, e.Arbiter) {
			return errors.New("contractor key rotation requires Client and Arbiter co-signatures")
		}
		revoked = e.Contractor
		e.Contractor = newActor
	case "verifier":
		if !hasPair(signerA, signerB, e.Client, e.Arbiter) {
			return errors.New("verifier key rotation requires Client and Arbiter co-signatures")
		}
		revoked = e.Verifier
		e.Verifier = newActor
	case "client":
		if !hasPair(signerA, signerB, e.Arbiter, e.Verifier) {
			return errors.New("client key rotation requires Arbiter and Verifier co-signatures")
		}
		revoked = e.Client
		e.Client = newActor
	case "arbiter":
		if !hasPair(signerA, signerB, e.Client, e.Verifier) {
			return errors.New("arbiter key rotation requires Client and Verifier co-signatures")
		}
		revoked = e.Arbiter
		e.Arbiter = newActor
	default:
		return errors.New("unsupported role for key rotation")
	}

	// Ensure the new key does not violate role separation of duties!
	if err := e.ValidateRoles(); err != nil {
		// Roll back on role collision
		switch role {
		case "contractor":
			e.Contractor = revoked
		case "verifier":
			e.Verifier = revoked
		case "client":
			e.Client = revoked
		case "arbiter":
			e.Arbiter = revoked
		}
		return err
	}

	e.KeyRotations = append(e.KeyRotations, KeyRotationRecord{
		Role:              role,
		RevokedActor:      revoked,
		NewActor:          newActor,
		AuthorizedByA:     signerA,
		AuthorizedByB:     signerB,
		RotationProofHash: rotationProofHash,
	})
	return nil
}

// ExpireStalledEscrow provides a liveness/timeout escape hatch when DeadlineUnix has passed
// and uncompleted milestones remain locked, preventing funds from being trapped forever if a
// contractor vanishes. Unreleased funds are refunded while preserving any already-released milestones.
func (e *Escrow) ExpireStalledEscrow(actor string, currentUnix uint64) error {
	if e.DeadlineUnix == 0 || currentUnix <= e.DeadlineUnix {
		return errors.New("escrow deadline has not expired")
	}
	if actor != e.Client && (e.Arbiter == "" || actor != e.Arbiter) {
		return errors.New("timeout expiry forbidden")
	}
	if e.Status == Completed || e.Status == Cancelled {
		return errors.New("escrow already finalized")
	}
	if e.Status == Created {
		return e.CancelBeforeFunding(actor)
	}
	for i := range e.Milestones {
		m := &e.Milestones[i]
		if !m.Released && !m.Refunded {
			m.Refunded = true
			e.RefundedAmount += m.Amount
		}
	}
	e.Status = Completed
	return nil
}

// ResolveDispute allows ONLY the independent Arbiter to adjudicate a milestone while the escrow is Disputed.
// If releaseToContractor is true, the milestone is paid out; if false, the milestone is refunded.
// Requires a non-empty resolutionHash anchoring the Arbiter's written ruling.
func (e *Escrow) ResolveDispute(actor string, idx int, releaseToContractor bool, resolutionHash string) error {
	if e.Arbiter == "" || actor != e.Arbiter || e.Status != Disputed || idx < 0 || idx >= len(e.Milestones) || resolutionHash == "" {
		return errors.New("arbiter resolution forbidden")
	}
	m := &e.Milestones[idx]
	if m.Released || m.Refunded || e.ReleasedAmount+e.RefundedAmount > e.FundedAmount-m.Amount {
		return errors.New("milestone already settled")
	}
	m.ResolutionHash = resolutionHash
	if releaseToContractor {
		m.Released = true
		e.ReleasedAmount += m.Amount
	} else {
		m.Refunded = true
		e.RefundedAmount += m.Amount
	}
	if e.ReleasedAmount+e.RefundedAmount == e.FundedAmount {
		e.Status = Completed
	} else {
		e.Status = Funded
		for _, item := range e.Milestones {
			if item.Submitted && !item.Released && !item.Refunded {
				e.Status = Submitted
			}
		}
	}
	return nil
}

// RemainingLocked returns the exact amount of funds still locked inside the escrow contract,
// satisfying: ReleasedAmount + RefundedAmount + RemainingLocked() == FundedAmount.
func (e *Escrow) RemainingLocked() uint64 {
	settled := e.ReleasedAmount + e.RefundedAmount
	if settled >= e.FundedAmount {
		return 0
	}
	return e.FundedAmount - settled
}

// RecordSettlementReceipt anchors the cryptographic hash of an off-chain bank/SINPE transfer receipt
// (e.g., Comprobante SINPE + Hacienda Factura Electrónica) after a milestone payout is released
// through a dedicated disbursement Beneficiary account for a small local contractor.
func (e *Escrow) RecordSettlementReceipt(actor string, idx int, receiptHash string) error {
	if (actor != e.Client && actor != e.Beneficiary) || idx < 0 || idx >= len(e.Milestones) || receiptHash == "" {
		return errors.New("settlement receipt forbidden")
	}
	m := &e.Milestones[idx]
	if !m.Released || m.SettlementReceiptHash != "" {
		return errors.New("milestone not eligible for settlement receipt")
	}
	m.SettlementReceiptHash = receiptHash
	return nil
}

// CalculateCappedFee computes the non-profit hosting/maintenance fee in basis points (100 bps = 1%),
// strictly capped so total fees collected in a period never exceed periodCap.
// Once collected >= periodCap, the fee automatically drops to 0.
func CalculateCappedFee(amount uint64, feeBps uint64, collected uint64, periodCap uint64) (uint64, error) {
	if feeBps > 10000 {
		return 0, errors.New("invalid fee basis points")
	}
	if collected >= periodCap || feeBps == 0 || amount == 0 {
		return 0, nil
	}
	if amount > ^uint64(0)/feeBps {
		return 0, errors.New("fee calculation overflow")
	}
	rawFee := (amount * feeBps) / 10000
	remainingRoom := periodCap - collected
	if rawFee > remainingRoom {
		return remainingRoom, nil
	}
	return rawFee, nil
}
