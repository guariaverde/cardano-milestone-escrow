package adapters

import (
	"path/filepath"
	"testing"
)

func TestHashChainLedgerPersistenceAndTamperDetection(t *testing.T) {
	ledger := &HashChainLedger{}

	if _, err := ledger.Append("CONTRIBUTION", "Vecina Maria", 200, "proj-solar-lighting-001"); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Append("MILESTONE_VERIFIED", "inspector_dan", 400, "Hito-0"); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Append("MILESTONE_APPROVED", "committee_key", 400, "Hito-0"); err != nil {
		t.Fatal(err)
	}

	// 1. Save to disk and reload -> VerifyIntegrity passes!
	tmpFile := filepath.Join(t.TempDir(), "audit_ledger.json")
	if err := ledger.SaveToFile(tmpFile); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadLedgerFromFile(tmpFile)
	if err != nil || len(reloaded.Entries) != 3 {
		t.Fatalf("expected clean reload of 3 chained entries, got err=%v", err)
	}

	// 2. Simulate an attacker editing Entry #0's amount on disk from 200 to 50 -> caught immediately!
	reloaded.Entries[0].Amount = 50
	if err := reloaded.VerifyIntegrity(); err == nil {
		t.Fatal("expected VerifyIntegrity() to catch tampered historical amount in Entry #0")
	}

	// 3. Fast Checkpoint Verification: Anchor Entry #1 on-chain, append Entry #3, and verify ONLY from Checkpoint #1 forward!
	cp, err := ledger.CreateCheckpoint("cardano_preview_tx:anchor_001")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = ledger.Append("SINPE_SETTLED", "disburser", 400, "Hito-0-SINPE")
	if err := ledger.VerifyFromCheckpoint(cp); err != nil {
		t.Fatalf("expected fast VerifyFromCheckpoint to succeed, got %v", err)
	}
}
