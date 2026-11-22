package adapters

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"example.com/milestone-escrow/backend/escrow"
)

// ComputeWebhookHMAC generates an "hmac-sha256:<hex>" signature for server-to-server plugin calls.
func ComputeWebhookHMAC(payload []byte, secret string) (string, error) {
	if len(payload) == 0 || secret == "" {
		return "", errors.New("payload and secret must be non-empty")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyWebhookHMAC verifies an incoming plugin/webhook signature in constant time.
func VerifyWebhookHMAC(payload []byte, signature string, secret string) bool {
	expected, err := ComputeWebhookHMAC(payload, secret)
	if err != nil || signature == "" {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(signature))
}

// WidgetSummary is a lightweight, zero-PII read-only snapshot designed to be embedded
// inside external civic portals (such as a Phase 7 CONSUL Democracy plugin widget).
type WidgetSummary struct {
	ExternalRef        string `json:"external_ref"`
	Status             string `json:"status"`
	TargetAmount       uint64 `json:"target_amount"`
	FundedAmount       uint64 `json:"funded_amount"`
	ReleasedAmount     uint64 `json:"released_amount"`
	ProgressPct        uint64 `json:"progress_pct"`
	MilestonesTotal    int    `json:"milestones_total"`
	MilestonesReleased int    `json:"milestones_released"`
}

// BuildWidgetSummary extracts a public, PII-free summary from any generic *escrow.Escrow.
func BuildWidgetSummary(externalRef string, e *escrow.Escrow) (WidgetSummary, error) {
	if externalRef == "" || e == nil {
		return WidgetSummary{}, errors.New("external_ref and escrow are required")
	}
	total, err := e.Total()
	if err != nil {
		return WidgetSummary{}, err
	}
	var pct uint64
	if total > 0 {
		pct = (e.FundedAmount * 100) / total
		if pct > 100 {
			pct = 100
		}
	}
	releasedCount := 0
	for _, m := range e.Milestones {
		if m.Released {
			releasedCount++
		}
	}
	return WidgetSummary{
		ExternalRef:        externalRef,
		Status:             string(e.Status),
		TargetAmount:       total,
		FundedAmount:       e.FundedAmount,
		ReleasedAmount:     e.ReleasedAmount,
		ProgressPct:        pct,
		MilestonesTotal:    len(e.Milestones),
		MilestonesReleased: releasedCount,
	}, nil
}
