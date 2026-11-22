package adapters

import (
	"testing"

	"example.com/milestone-escrow/backend/escrow"
)

func TestPluginWebhookHMACAndEmbeddableWidgetSummary(t *testing.T) {
	payload := []byte(`{"source":"consul","proposal_id":"224","resolution":"RES-2026-042"}`)
	secret := "shared-server-to-server-secret"

	sig, err := ComputeWebhookHMAC(payload, secret)
	if err != nil {
		t.Fatal(err)
	}
	// 1. Valid signature passes
	if !VerifyWebhookHMAC(payload, sig, secret) {
		t.Fatal("expected valid HMAC signature to pass")
	}
	// 2. Modified payload or wrong secret is rejected
	if VerifyWebhookHMAC([]byte(`{"source":"consul","proposal_id":"999"}`), sig, secret) {
		t.Fatal("expected tampered webhook payload to fail HMAC verification")
	}
	if VerifyWebhookHMAC(payload, sig, "wrong-secret") {
		t.Fatal("expected wrong webhook secret to fail HMAC verification")
	}

	// 3. Zero-PII WidgetSummary snapshot
	e := &escrow.Escrow{
		Client:     "committee_key",
		Contractor: "don_carlos_key",
		Status:     escrow.Created,
		Milestones: []escrow.Milestone{{Amount: 400}, {Amount: 600}},
	}
	_ = e.Contribute("Vecina Maria", 400)
	summary, err := BuildWidgetSummary("consul:budget_investment:224", e)
	if err != nil {
		t.Fatal(err)
	}
	if summary.ProgressPct != 40 || summary.TargetAmount != 1000 || summary.FundedAmount != 400 {
		t.Fatalf("unexpected widget summary: %+v", summary)
	}
}
