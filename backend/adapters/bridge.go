package adapters

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"

	"example.com/milestone-escrow/backend/escrow"
)

// MaxEvidenceBytes caps direct file uploads at 25 MB (25 * 1024 * 1024 bytes)
// to prevent memory-exhaustion (DoS) attacks and keep non-profit hosting storage lean.
const MaxEvidenceBytes = 25 * 1024 * 1024

// MalwareScanner defines the pluggable antivirus interface (e.g., ClamAV clamd daemon in production).
type MalwareScanner interface {
	Scan(content []byte) error
}

// InspectAndScanEvidence enforces our 4-Layer Anti-Trojan & Malware Standard on uploaded files:
// 1. Enforces MaxEvidenceBytes (25 MB) size cap.
// 2. Blocks executable binaries (Windows MZ/.exe, Linux ELF), scripts, and EICAR virus signatures.
// 3. Verifies binary Magic Bytes (MIME type) against our safe allowlist (JPEG, PNG, WEBP, PDF, or plain receipt text).
// 4. Scans PDFs for embedded active-content exploits (/JavaScript, /JS, /Launch, /OpenAction).
// 5. Runs the external MalwareScanner (e.g., ClamAV) if provided.
func InspectAndScanEvidence(content []byte, scanner MalwareScanner) (string, error) {
	if len(content) == 0 {
		return "", errors.New("cannot inspect empty file content")
	}
	if len(content) > MaxEvidenceBytes {
		return "", errors.New("evidence file exceeds maximum allowed size (25 MB)")
	}

	// Block Windows PE executables ("MZ"), Linux ELF binaries ("\x7fELF"), and EICAR antivirus test signature
	if bytes.HasPrefix(content, []byte("MZ")) || bytes.HasPrefix(content, []byte("\x7fELF")) {
		return "", errors.New("executable binary file rejected (potential trojan)")
	}
	if bytes.Contains(content, []byte("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) {
		return "", errors.New("malware signature detected by built-in scanner")
	}
	// Block HTML/SVG active script tags disguised inside uploads
	lower := bytes.ToLower(content)
	if bytes.Contains(lower, []byte("<script")) || bytes.Contains(lower, []byte("javascript:")) {
		return "", errors.New("embedded script content rejected")
	}

	// Inspect binary Magic Bytes using standard library net/http.DetectContentType
	mimeType := http.DetectContentType(content)
	switch mimeType {
	case "image/jpeg", "image/png", "image/webp":
		// Safe raster image formats
	case "application/pdf":
		// Block malicious PDFs containing auto-executing JavaScript or system Launch actions
		if bytes.Contains(content, []byte("/JavaScript")) ||
			bytes.Contains(content, []byte("/JS")) ||
			bytes.Contains(content, []byte("/Launch")) ||
			bytes.Contains(content, []byte("/OpenAction")) {
			return "", errors.New("malicious active-content PDF tags (/JavaScript or /Launch) rejected")
		}
	case "text/plain; charset=utf-8":
		// Allowed for structured SINPE/gateway receipt payloads
	default:
		return "", errors.New("unsupported or unsafe file magic bytes: " + mimeType)
	}

	if scanner != nil {
		if err := scanner.Scan(content); err != nil {
			return "", err
		}
	}
	return mimeType, nil
}

// HashEvidence inspects the file for Trojans/malware and returns a deterministic "sha256:<hex>" digest.
func HashEvidence(content []byte) (string, error) {
	if _, err := InspectAndScanEvidence(content, nil); err != nil {
		return "", err
	}
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// VerifyEvidenceHash checks whether an off-chain file matches the cryptographic hash anchored on-chain.
// If even 1 bit of the file was modified after anchoring, VerifyEvidenceHash returns false.
func VerifyEvidenceHash(content []byte, anchoredHash string) bool {
	if len(content) == 0 || anchoredHash == "" {
		return false
	}
	computed, err := HashEvidence(content)
	if err != nil {
		return false
	}
	return computed == anchoredHash
}

type PaymentRail string

const (
	RailSINPEMovil     PaymentRail = "SINPE_MOVIL"
	RailRegulatedOnRamp PaymentRail = "REGULATED_ONRAMP_CARD"
)

type FiatDeposit struct {
	IdempotencyKey string      // unique bank/gateway reference (prevents duplicate webhook processing)
	Donor          string      // donor identifier
	Currency       string      // "CRC" or "USD"
	Rail           PaymentRail // SINPE_MOVIL or REGULATED_ONRAMP_CARD
	AmountUnits    uint64      // atomic on-chain units equivalent after integer conversion
	ReceiptBytes   []byte      // raw bank/gateway confirmation payload to be hashed
}

type DepositAuditRecord struct {
	IdempotencyKey  string
	Donor           string
	Currency        string
	Rail            PaymentRail
	GrossUnits      uint64
	HostingFeeUnits uint64
	NetEscrowUnits  uint64
	ReceiptHash     string
}

// FiatBridgeAdapter bridges non-crypto citizens (paying via SINPE Móvil or Cards) and small local
// contractors (paid via SINPE/IBAN) with our on-chain Escrow & Committee Fund engine.
type FiatBridgeAdapter struct {
	DisburserAccount     string // on-chain Beneficiary account for last-mile SINPE/IBAN contractor payouts
	HostingFeeBps        uint64 // e.g. 100 bps (1%) non-profit operating & gas micro-fee
	HostingPeriodCap     uint64 // maximum cloud hosting + on-chain settlement gas budget needed per period
	GasReservePeriodCap  uint64 // portion of HostingPeriodCap reserved for atomic on-chain settlement gas fees
	OnChainSettlements   uint64 // count of atomic on-chain payout settlements sponsored from the gas pool
	HostingPoolCollected uint64 // operating + gas fees collected so far this period (drops fee to 0 once == Cap)
	LockedReserveUnits   uint64 // verified available backing reserve (CRC/USD) locked for active escrows
	TotalDisbursedUnits  uint64 // cumulative units disbursed and settled via SINPE/off-ramp
	ProcessedDeposits    map[string]bool
	AuditTrail           []DepositAuditRecord
}

// VerifyReserveSolvency enforces Proof-of-Reserve: verifies that the bridge's available
// LockedReserveUnits has NOT been depleted below the funds required by the active escrow.
func (b *FiatBridgeAdapter) VerifyReserveSolvency(requiredLockedUnits uint64) error {
	if b.LockedReserveUnits < requiredLockedUnits {
		return errors.New("critical solvency error: backing reserve is depleted below required escrow balance")
	}
	return nil
}

// DepositFiatToProject processes a citizen's SINPE Móvil or Card deposit, enforces webhook idempotency,
// deducts the cost-capped non-profit hosting fee (0% once HostingPeriodCap is reached), hashes the
// payment receipt, and locks the net funds directly into the target Project Escrow.
func (b *FiatBridgeAdapter) DepositFiatToProject(dep FiatDeposit, targetProject *escrow.Escrow) (*DepositAuditRecord, error) {
	if dep.IdempotencyKey == "" || dep.Donor == "" || dep.AmountUnits == 0 || targetProject == nil {
		return nil, errors.New("invalid fiat deposit parameters")
	}
	if dep.Currency != "CRC" && dep.Currency != "USD" {
		return nil, errors.New("unsupported fiat currency")
	}
	if b.ProcessedDeposits == nil {
		b.ProcessedDeposits = make(map[string]bool)
	}
	if b.ProcessedDeposits[dep.IdempotencyKey] {
		return nil, errors.New("duplicate deposit idempotency key rejected")
	}

	receiptHash, err := HashEvidence(dep.ReceiptBytes)
	if err != nil {
		return nil, err
	}

	fee, err := escrow.CalculateCappedFee(dep.AmountUnits, b.HostingFeeBps, b.HostingPoolCollected, b.HostingPeriodCap)
	if err != nil {
		return nil, err
	}
	if fee >= dep.AmountUnits {
		fee = 0
	}
	netToEscrow := dep.AmountUnits - fee

	if err := targetProject.Contribute(dep.Donor, netToEscrow); err != nil {
		return nil, err
	}

	b.ProcessedDeposits[dep.IdempotencyKey] = true
	b.HostingPoolCollected += fee
	b.LockedReserveUnits += netToEscrow

	record := DepositAuditRecord{
		IdempotencyKey:  dep.IdempotencyKey,
		Donor:           dep.Donor,
		Currency:        dep.Currency,
		Rail:            dep.Rail,
		GrossUnits:      dep.AmountUnits,
		HostingFeeUnits: fee,
		NetEscrowUnits:  netToEscrow,
		ReceiptHash:     receiptHash,
	}
	b.AuditTrail = append(b.AuditTrail, record)
	return &record, nil
}

// SettleMilestoneViaSINPE completes the last-mile payout in Colones (CRC) to a small local contractor
// after the Inspector and Committee have approved the milestone on-chain, verifying first that the
// backing reserve has not been depleted, deducting the payout from LockedReserveUnits, and anchoring
// the SHA-256 hash of the official SINPE/IBAN bank comprobante directly onto the milestone.
func (b *FiatBridgeAdapter) SettleMilestoneViaSINPE(project *escrow.Escrow, milestoneIdx int, sinpeComprobanteBytes []byte) (string, error) {
	if project == nil || b.DisburserAccount == "" || milestoneIdx < 0 || milestoneIdx >= len(project.Milestones) {
		return "", errors.New("invalid project, milestone index, or disburser account")
	}
	m := project.Milestones[milestoneIdx]
	if !m.Released {
		return "", errors.New("milestone has not been approved and released on-chain yet")
	}
	// Anti-Depletion Check: verify the backing reserve actually holds the required milestone funds
	// plus any remaining locked milestones on the project!
	if err := b.VerifyReserveSolvency(m.Amount + project.RemainingLocked()); err != nil {
		return "", err
	}
	receiptHash, err := HashEvidence(sinpeComprobanteBytes)
	if err != nil {
		return "", err
	}
	if err := project.RecordSettlementReceipt(b.DisburserAccount, milestoneIdx, receiptHash); err != nil {
		return "", err
	}
	b.LockedReserveUnits -= m.Amount
	b.TotalDisbursedUnits += m.Amount
	b.OnChainSettlements++
	return receiptHash, nil
}
