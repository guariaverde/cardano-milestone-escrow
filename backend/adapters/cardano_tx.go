package adapters

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// MinUTxOLovelace is the Cardano protocol minimum lovelace (1.5 ADA = 1,500,000 lovelace)
// required on every active UTxO output to prevent ledger dust spam.
const MinUTxOLovelace uint64 = 1_500_000

// CardanoEscrowInput represents an unspent Escrow UTxO being consumed by a Cardano transaction.
type CardanoEscrowInput struct {
	UTxORef        string // e.g., "txhash#0"
	EscrowID       string // unique project escrow identifier (used to tag payouts and block Double Satisfaction)
	ClientKey      string
	ContractorKey  string
	VerifierKey    string
	BeliefRecipient string // payout destination (Beneficiary or Contractor)
	LockedLovelace uint64
	MilestoneLovelace uint64
	Verified       bool
}

// CardanoTxOutput represents an output created by a Cardano transaction.
type CardanoTxOutput struct {
	Address     string
	Lovelace    uint64
	PaymentTag  string // must match EscrowID to count toward that escrow's payout (blocks Double Satisfaction!)
	IsContinuingScript bool
}

// CardanoUnsignedTx represents an unsigned Cardano eUTxO transaction constructed by our zero-key server
// for client/committee wallet signing.
type CardanoUnsignedTx struct {
	Network          string // strictly "preview" for testnet safety
	EscrowInputs     []CardanoEscrowInput
	FeePayerInputLovelace uint64
	Outputs          []CardanoTxOutput
	FeeLovelace      uint64
	RequiredSigners  []string
}

// SumTaggedPayouts mirrors `sum_tagged_payouts` in `contracts/cardano/validators/escrow.ak`:
// it counts ONLY outputs paying `recipient` whose `PaymentTag` equals `escrowID`.
func SumTaggedPayouts(outputs []CardanoTxOutput, recipient string, escrowID string) uint64 {
	var sum uint64
	for _, out := range outputs {
		if !out.IsContinuingScript && out.Address == recipient && out.PaymentTag == escrowID {
			sum += out.Lovelace
		}
	}
	return sum
}

// ValidateCardanoEscrowPayoutTx verifies that a proposed Cardano transaction:
// 1. Targets "preview" testnet only (never mainnet without explicit audit override).
// 2. Satisfies Cardano's MinUTxOLovelace (1.5 ADA) rule on every output.
// 3. Prevents Double Satisfaction: every spent EscrowInput must have its own uniquely tagged
//    payout output (`PaymentTag == in.EscrowID`) paying at least `in.MilestoneLovelace`.
// 4. Conserves lovelace across all inputs, outputs, and transaction fee.
func ValidateCardanoEscrowPayoutTx(tx CardanoUnsignedTx, signatures []string) (string, error) {
	if tx.Network != "preview" {
		return "", errors.New("only cardano preview testnet is permitted in this phase")
	}
	if len(tx.EscrowInputs) == 0 || len(tx.Outputs) == 0 || tx.FeeLovelace == 0 {
		return "", errors.New("invalid transaction inputs, outputs, or fee")
	}

	signed := make(map[string]bool)
	for _, sig := range signatures {
		signed[sig] = true
	}

	var totalIn uint64 = tx.FeePayerInputLovelace
	seenUTxO := make(map[string]bool)
	seenEscrowID := make(map[string]bool)

	for _, in := range tx.EscrowInputs {
		if in.UTxORef == "" || in.EscrowID == "" || seenUTxO[in.UTxORef] || seenEscrowID[in.EscrowID] {
			return "", errors.New("duplicate or empty escrow input / escrow_id in transaction")
		}
		seenUTxO[in.UTxORef] = true
		seenEscrowID[in.EscrowID] = true

		if in.VerifierKey != "" && !in.Verified {
			return "", errors.New("inspector verification required before building payout transaction")
		}
		if !signed[in.ClientKey] {
			return "", errors.New("missing required client/committee signature for escrow " + in.EscrowID)
		}
		if in.MilestoneLovelace < MinUTxOLovelace || in.LockedLovelace < in.MilestoneLovelace {
			return "", errors.New("escrow milestone or locked balance below Cardano min-UTxO (1.5 ADA)")
		}

		// Double-Satisfaction Check: count ONLY outputs explicitly tagged with `in.EscrowID`!
		taggedPaid := SumTaggedPayouts(tx.Outputs, in.BeliefRecipient, in.EscrowID)
		if taggedPaid < in.MilestoneLovelace {
			return "", fmt.Errorf("double-satisfaction / underpayment guard: escrow %s requires %d lovelace tagged with %s, but found %d",
				in.EscrowID, in.MilestoneLovelace, in.EscrowID, taggedPaid)
		}

		// If partial payout leaves continuing funds in the escrow, the continuing UTxO must also satisfy MinUTxOLovelace
		remaining := in.LockedLovelace - in.MilestoneLovelace
		if remaining > 0 && remaining < MinUTxOLovelace {
			return "", errors.New("continuing escrow UTxO would fall below Cardano min-UTxO (1.5 ADA)")
		}

		totalIn += in.LockedLovelace
	}

	var totalOut uint64
	for _, out := range tx.Outputs {
		if out.Lovelace < MinUTxOLovelace {
			return "", errors.New("transaction output violates Cardano min-UTxO (1.5 ADA minimum)")
		}
		totalOut += out.Lovelace
	}

	if totalIn != totalOut+tx.FeeLovelace {
		return "", fmt.Errorf("cardano transaction lovelace imbalance: inputs=%d != outputs(%d)+fee(%d)",
			totalIn, totalOut, tx.FeeLovelace)
	}

	// Compute deterministic Cardano transaction hash
	digest := sha256.Sum256([]byte(fmt.Sprintf("%+v", tx)))
	return "cardano_preview_tx:" + hex.EncodeToString(digest[:]), nil
}
