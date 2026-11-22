package adapters

import "testing"

func TestCardanoDoubleSatisfactionAttackBlockedAndValidTxSucceeds(t *testing.T) {
	escrowA := CardanoEscrowInput{
		UTxORef:           "tx_aaa#0",
		EscrowID:          "proj-solar-001",
		ClientKey:         "committee_key",
		ContractorKey:     "don_carlos_key",
		VerifierKey:       "inspector_dan_key",
		BeliefRecipient:   "org_sinpe_disburser_key",
		LockedLovelace:    100_000_000, // 100 ADA
		MilestoneLovelace: 100_000_000, // 100 ADA
		Verified:          true,
	}
	escrowB := CardanoEscrowInput{
		UTxORef:           "tx_bbb#0",
		EscrowID:          "proj-bench-002",
		ClientKey:         "committee_key",
		ContractorKey:     "don_carlos_key",
		VerifierKey:       "inspector_dan_key",
		BeliefRecipient:   "org_sinpe_disburser_key",
		LockedLovelace:    100_000_000, // 100 ADA
		MilestoneLovelace: 100_000_000, // 100 ADA
		Verified:          true,
	}

	// 1. ATTACK: Attacker spends BOTH escrowA (100 ADA) and escrowB (100 ADA) in one transaction,
	//    pays only ONE 100-ADA output to `org_sinpe_disburser_key` (tagged "proj-solar-001"),
	//    and tries to steal the other 100 ADA to `attacker_wallet`!
	doubleSatisfactionAttackTx := CardanoUnsignedTx{
		Network:               "preview",
		EscrowInputs:          []CardanoEscrowInput{escrowA, escrowB},
		FeePayerInputLovelace: 200_000, // 0.2 ADA fee input
		FeeLovelace:           200_000,
		Outputs: []CardanoTxOutput{
			{
				Address:    "org_sinpe_disburser_key",
				Lovelace:   100_000_000,
				PaymentTag: "proj-solar-001", // Only tagged for escrowA!
			},
			{
				Address:    "attacker_wallet",
				Lovelace:   100_000_000, // Attacker tries to pocket escrowB's 100 ADA!
				PaymentTag: "stolen",
			},
		},
	}

	if _, err := ValidateCardanoEscrowPayoutTx(doubleSatisfactionAttackTx, []string{"committee_key"}); err == nil {
		t.Fatal("expected Double Satisfaction attack transaction to be REJECTED!")
	}

	// 2. Cardano min-UTxO check: an output with only 500,000 lovelace (0.5 ADA < 1.5 ADA) MUST be rejected!
	dustTx := CardanoUnsignedTx{
		Network:               "preview",
		EscrowInputs:          []CardanoEscrowInput{escrowA},
		FeePayerInputLovelace: 200_000,
		FeeLovelace:           200_000,
		Outputs: []CardanoTxOutput{
			{
				Address:    "org_sinpe_disburser_key",
				Lovelace:   99_500_000,
				PaymentTag: "proj-solar-001",
			},
			{
				Address:    "change_wallet",
				Lovelace:   500_000, // Below 1.5 ADA min-UTxO!
				PaymentTag: "",
			},
		},
	}
	if _, err := ValidateCardanoEscrowPayoutTx(dustTx, []string{"committee_key"}); err == nil {
		t.Fatal("expected output below Cardano 1.5 ADA min-UTxO to be rejected")
	}

	// 3. VALID TRANSACTION: Spending both escrows when BOTH have their own uniquely tagged 100-ADA payout output!
	validBatchPayoutTx := CardanoUnsignedTx{
		Network:               "preview",
		EscrowInputs:          []CardanoEscrowInput{escrowA, escrowB},
		FeePayerInputLovelace: 200_000,
		FeeLovelace:           200_000,
		Outputs: []CardanoTxOutput{
			{
				Address:    "org_sinpe_disburser_key",
				Lovelace:   100_000_000,
				PaymentTag: "proj-solar-001",
			},
			{
				Address:    "org_sinpe_disburser_key",
				Lovelace:   100_000_000,
				PaymentTag: "proj-bench-002",
			},
		},
	}
	txHash, err := ValidateCardanoEscrowPayoutTx(validBatchPayoutTx, []string{"committee_key"})
	if err != nil || txHash == "" {
		t.Fatalf("expected valid tagged Cardano transaction to succeed, got err=%v", err)
	}
}
