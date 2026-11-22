package escrow

import "errors"

type SaleMode string

const (
	FixedPrice   SaleMode = "fixed_price"
	OpenSubasta  SaleMode = "open_subasta"
	BlindSubasta SaleMode = "blind_subasta"
)

type Bid struct {
	Bidder   string
	Amount   uint64
	Winner   bool
	Refunded bool
}

// SubastaListing models a physical item donated to the organization/committee and listed in the
// marketplace under FixedPrice, OpenSubasta, or BlindSubasta.
// Every bid locks funds upfront so bidders cannot back out.
type SubastaListing struct {
	ID              string
	ItemDonor       string
	Organization    string // The Committee / Organization that inspects & delivers the item
	CommitteeFundID string // The Committee Public Fund that receives proceeds after delivery
	Mode            SaleMode
	MinimumPrice    uint64 // Fixed price (for FixedPrice) or minimum reserve bid (for Subasta modes)
	Settled         bool
	Bids            []Bid
	DeliveryEscrow  *Escrow
}

// PlaceBid locks a bidder's funds into the Subasta listing so they cannot back out.
// Prevents shill-bidding by blocking both the Organization and the ItemDonor from bidding.
func (s *SubastaListing) PlaceBid(bidder string, amount uint64) error {
	if s.Settled || bidder == "" || bidder == s.Organization || (s.ItemDonor != "" && bidder == s.ItemDonor) || amount == 0 || s.MinimumPrice == 0 {
		return errors.New("bid forbidden")
	}
	switch s.Mode {
	case FixedPrice:
		if len(s.Bids) >= 1 {
			return errors.New("fixed price item already locked by a buyer")
		}
		if amount != s.MinimumPrice {
			return errors.New("fixed price mode requires exact price")
		}
	case OpenSubasta:
		if amount < s.MinimumPrice {
			return errors.New("bid below minimum price")
		}
		// In OpenSubasta, each new bid must strictly exceed the current highest bid
		for _, b := range s.Bids {
			if amount <= b.Amount {
				return errors.New("open subasta bid must beat current highest bid")
			}
		}
	case BlindSubasta:
		// In BlindSubasta (Sobre Cerrado / Best Offer), multiple people can lock the same or different
		// offers (>= MinimumPrice) simultaneously without seeing or colliding with others.
		if amount < s.MinimumPrice {
			return errors.New("blind subasta offer below minimum price")
		}
	default:
		return errors.New("invalid sale mode")
	}

	s.Bids = append(s.Bids, Bid{Bidder: bidder, Amount: amount})
	return nil
}

// HighestBidIndex returns the index of the highest bid (breaking ties by earliest bid).
func (s *SubastaListing) HighestBidIndex() int {
	if len(s.Bids) == 0 {
		return -1
	}
	bestIdx := 0
	for i, b := range s.Bids {
		if b.Amount > s.Bids[bestIdx].Amount {
			bestIdx = i
		}
	}
	return bestIdx
}

// Settle selects the winning bid (which MUST equal the highest bid amount), automatically refunds
// all losing bidders, and locks the 1 winner's payment into an Item Delivery Escrow payable to
// the Committee Public Fund upon item delivery.
func (s *SubastaListing) Settle(actor string, winningBidIdx int) (*Escrow, error) {
	if s.Settled || actor != s.Organization || winningBidIdx < 0 || winningBidIdx >= len(s.Bids) || s.CommitteeFundID == "" {
		return nil, errors.New("subasta settlement forbidden")
	}
	// Highest-Bidder Invariant: Neither OpenSubasta nor BlindSubasta can pick a bid lower than the maximum offer!
	highestIdx := s.HighestBidIndex()
	if s.Bids[winningBidIdx].Amount < s.Bids[highestIdx].Amount {
		return nil, errors.New("subasta winner must be the highest bid amount")
	}
	if s.Mode == OpenSubasta && winningBidIdx != highestIdx {
		return nil, errors.New("open subasta must select highest bid")
	}

	for i := range s.Bids {
		if i == winningBidIdx {
			s.Bids[i].Winner = true
		} else {
			s.Bids[i].Refunded = true // All other bidders are immediately refunded!
		}
	}

	winner := s.Bids[winningBidIdx]
	itemEscrow := &Escrow{
		Client:      winner.Bidder,     // Winning buyer approves once item is delivered
		Contractor:  s.Organization,    // Organization inspects & delivers the item
		Beneficiary: s.CommitteeFundID, // Proceeds go to the Committee Public Fund!
		Status:      Created,
		Milestones:  []Milestone{{Amount: winner.Amount}},
	}
	if err := itemEscrow.Fund(winner.Bidder, winner.Amount); err != nil {
		return nil, err
	}

	s.Settled = true
	s.DeliveryEscrow = itemEscrow
	return itemEscrow, nil
}

// ConfirmDeliveryByCommitteeQuorum provides an assisted-delivery override when a winning citizen
// does not use technology to click confirm themselves: requires that the delivery evidence hash was
// already uploaded AND at least 2 distinct committee members co-sign the physical delivery proof.
func (s *SubastaListing) ConfirmDeliveryByCommitteeQuorum(memberA string, memberB string, signedReceiptHash string) error {
	e := s.DeliveryEscrow
	if !s.Settled || e == nil || len(e.Milestones) == 0 {
		return errors.New("subasta delivery escrow not active")
	}
	if memberA == "" || memberB == "" || memberA == memberB || signedReceiptHash == "" {
		return errors.New("assisted delivery override requires 2 distinct committee members and a signed delivery proof hash")
	}
	m := &e.Milestones[0]
	if !m.Submitted || m.EvidenceHash == "" || m.Released || m.Refunded {
		return errors.New("physical delivery proof must be uploaded first before committee quorum confirmation")
	}
	m.SettlementReceiptHash = signedReceiptHash
	m.Verified = true
	m.Released = true
	e.ReleasedAmount += m.Amount
	e.Status = Completed
	return nil
}

type AllocationRecord struct {
	ProjectID string
	Amount    uint64
}

// CommitteeFund models the Organization's Public Treasury Pool.
// It receives funds from (1) Direct unrestricted donations to the Committee and (2) Completed Subasta
// item delivery escrows, and can ONLY distribute funds into posted Project Milestone Escrows.
type CommitteeFund struct {
	ID                string
	Committee         string
	CommitteeMembers  []string // optional M-of-N individual committee member keys
	RequiredQuorum    int      // minimum distinct committee members required when CommitteeMembers is set (e.g. 2 of 3)
	GovernanceArbiter string   // independent arbiter required to co-sign any official contract hash upgrade
	EscrowScriptHash  string   // hash of the official Project Milestone Escrow smart contract
	Balance           uint64
	TotalReceived     uint64
	Allocations       []AllocationRecord
	ClaimedSales      map[*Escrow]bool `json:"-"`
}

// HasCommitteeQuorum counts how many distinct members from CommitteeMembers signed.
func (f *CommitteeFund) HasCommitteeQuorum(signers []string) bool {
	if f.RequiredQuorum < 2 || len(f.CommitteeMembers) < f.RequiredQuorum {
		return false
	}
	seen := make(map[string]bool)
	count := 0
	for _, s := range signers {
		if seen[s] {
			continue
		}
		for _, member := range f.CommitteeMembers {
			if s == member {
				seen[s] = true
				count++
				break
			}
		}
	}
	return count >= f.RequiredQuorum
}

// UpgradeEscrowContract updates the official EscrowScriptHash ONLY when both the M-of-N Committee Quorum
// AND the independent GovernanceArbiter co-sign with a non-empty security audit report hash.
func (f *CommitteeFund) UpgradeEscrowContract(committeeSigners []string, arbiterSigner string, newScriptHash string, auditReportHash string) error {
	if !f.HasCommitteeQuorum(committeeSigners) || f.GovernanceArbiter == "" || arbiterSigner != f.GovernanceArbiter || newScriptHash == "" || auditReportHash == "" {
		return errors.New("contract upgrade requires M-of-N committee quorum, independent arbiter, and audit report hash")
	}
	f.EscrowScriptHash = newScriptHash
	return nil
}

// Donate allows anyone to donate directly to the Committee's General Fund (Avenue 3).
func (f *CommitteeFund) Donate(donor string, amount uint64) error {
	if donor == "" || amount == 0 || f.Balance > ^uint64(0)-amount {
		return errors.New("invalid donation to committee fund")
	}
	f.Balance += amount
	f.TotalReceived += amount
	return nil
}

// ClaimSubastaProceeds transfers the released funds from a completed Subasta Item Delivery Escrow
// into the Committee Public Fund (Avenue 2) ONLY after item delivery has been verified & approved.
func (f *CommitteeFund) ClaimSubastaProceeds(itemEscrow *Escrow) error {
	if itemEscrow == nil || itemEscrow.Status != Completed || itemEscrow.PayoutRecipient() != f.ID {
		return errors.New("subasta item escrow not completed or wrong beneficiary")
	}
	if f.ClaimedSales == nil {
		f.ClaimedSales = make(map[*Escrow]bool)
	}
	if f.ClaimedSales[itemEscrow] {
		return errors.New("subasta escrow proceeds already claimed")
	}
	f.ClaimedSales[itemEscrow] = true
	f.Balance += itemEscrow.ReleasedAmount
	f.TotalReceived += itemEscrow.ReleasedAmount
	return nil
}

// AllocateToProject distributes funds from the Committee Public Fund into a specific posted
// Project Milestone Escrow. There is NO function to withdraw funds to a private wallet.
func (f *CommitteeFund) AllocateToProject(actor string, projectID string, targetProject *Escrow, amount uint64) error {
	if actor != f.Committee || projectID == "" || targetProject == nil || amount == 0 || amount > f.Balance {
		return errors.New("committee allocation forbidden")
	}
	// Ensure the target project is managed under the Committee's oversight
	if targetProject.Client != f.Committee {
		return errors.New("target project must be overseen by the committee")
	}
	if err := targetProject.Contribute(f.ID, amount); err != nil {
		return err
	}
	f.Balance -= amount
	f.Allocations = append(f.Allocations, AllocationRecord{ProjectID: projectID, Amount: amount})
	return nil
}
