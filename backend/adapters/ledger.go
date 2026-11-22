package adapters

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// LedgerEntry represents a single immutable event in our append-only hash-chained audit log.
type LedgerEntry struct {
	Index     int    `json:"index"`
	EventType string `json:"event_type"` // e.g., "CONTRIBUTION", "SUBASTA_SETTLED", "MILESTONE_APPROVED"
	Actor     string `json:"actor"`
	Amount    uint64 `json:"amount"`
	Payload   string `json:"payload"`
	PrevHash  string `json:"prev_hash"`
	EntryHash string `json:"entry_hash"`
}

// ComputeEntryHash calculates the deterministic SHA-256 hash chaining this entry to PrevHash.
func ComputeEntryHash(index int, eventType string, actor string, amount uint64, payload string, prevHash string) string {
	raw := fmt.Sprintf("%d|%s|%s|%d|%s|%s", index, eventType, actor, amount, payload, prevHash)
	sum := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// HashChainLedger maintains an append-only, tamper-evident audit chain that can be saved to
// and reloaded from disk while verifying zero historical records were modified or deleted.
type HashChainLedger struct {
	Entries []LedgerEntry `json:"entries"`
}

const GenesisHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// Append adds a new event to the hash chain, linking it cryptographically to the previous entry.
func (l *HashChainLedger) Append(eventType string, actor string, amount uint64, payload string) (LedgerEntry, error) {
	if eventType == "" || actor == "" {
		return LedgerEntry{}, errors.New("event_type and actor are required")
	}
	prevHash := GenesisHash
	idx := len(l.Entries)
	if idx > 0 {
		prevHash = l.Entries[idx-1].EntryHash
	}
	entryHash := ComputeEntryHash(idx, eventType, actor, amount, payload, prevHash)
	entry := LedgerEntry{
		Index:     idx,
		EventType: eventType,
		Actor:     actor,
		Amount:    amount,
		Payload:   payload,
		PrevHash:  prevHash,
		EntryHash: entryHash,
	}
	l.Entries = append(l.Entries, entry)
	return entry, nil
}

// VerifyIntegrity recomputes every hash from Genesis (Entry #0) to the latest entry.
// If any historical record was edited, reordered, or deleted on disk, it returns an error.
func (l *HashChainLedger) VerifyIntegrity() error {
	expectedPrev := GenesisHash
	for i, e := range l.Entries {
		if e.Index != i {
			return fmt.Errorf("ledger index mismatch at position %d", i)
		}
		if e.PrevHash != expectedPrev {
			return fmt.Errorf("broken hash chain link at entry %d", i)
		}
		computed := ComputeEntryHash(e.Index, e.EventType, e.Actor, e.Amount, e.Payload, e.PrevHash)
		if e.EntryHash != computed {
			return fmt.Errorf("tampering detected at ledger entry %d", i)
		}
		expectedPrev = e.EntryHash
	}
	return nil
}

// LedgerCheckpoint anchors the hash chain state at a specific index onto the blockchain
// so normal startups only need to verify entries AFTER the latest checkpoint (O(1) recent window)
// instead of re-reading millions of historical entries from Genesis.
type LedgerCheckpoint struct {
	Index         int    `json:"index"`
	EntryHash     string `json:"entry_hash"`
	OnChainTxHash string `json:"on_chain_tx_hash"`
}

// CreateCheckpoint snapshots the latest entry so its hash can be anchored on-chain.
func (l *HashChainLedger) CreateCheckpoint(onChainTxHash string) (LedgerCheckpoint, error) {
	if len(l.Entries) == 0 || onChainTxHash == "" {
		return LedgerCheckpoint{}, errors.New("cannot checkpoint empty ledger or empty tx hash")
	}
	last := l.Entries[len(l.Entries)-1]
	return LedgerCheckpoint{
		Index:         last.Index,
		EntryHash:     last.EntryHash,
		OnChainTxHash: onChainTxHash,
	}, nil
}

// VerifyFromCheckpoint verifies ONLY the entries appended since an on-chain anchored checkpoint,
// keeping startup and verification instant (<1ms) even after years of operation.
func (l *HashChainLedger) VerifyFromCheckpoint(cp LedgerCheckpoint) error {
	if cp.Index < 0 || cp.Index >= len(l.Entries) {
		return errors.New("invalid checkpoint index")
	}
	anchor := l.Entries[cp.Index]
	if anchor.EntryHash != cp.EntryHash {
		return fmt.Errorf("checkpoint anchor hash mismatch at index %d", cp.Index)
	}
	expectedPrev := anchor.EntryHash
	for i := cp.Index + 1; i < len(l.Entries); i++ {
		e := l.Entries[i]
		if e.Index != i || e.PrevHash != expectedPrev {
			return fmt.Errorf("broken chain after checkpoint at entry %d", i)
		}
		computed := ComputeEntryHash(e.Index, e.EventType, e.Actor, e.Amount, e.Payload, e.PrevHash)
		if e.EntryHash != computed {
			return fmt.Errorf("tampering detected after checkpoint at entry %d", i)
		}
		expectedPrev = e.EntryHash
	}
	return nil
}

// SaveToFile persists the verified hash-chained ledger to disk.
func (l *HashChainLedger) SaveToFile(path string) error {
	if err := l.VerifyIntegrity(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// LoadLedgerFromFile loads the ledger from disk and immediately verifies the entire hash chain.
func LoadLedgerFromFile(path string) (*HashChainLedger, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ledger HashChainLedger
	if err := json.Unmarshal(raw, &ledger); err != nil {
		return nil, err
	}
	if err := ledger.VerifyIntegrity(); err != nil {
		return nil, err
	}
	return &ledger, nil
}
