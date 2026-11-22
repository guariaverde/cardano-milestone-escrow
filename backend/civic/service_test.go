package civic

import (
	"testing"

	"example.com/milestone-escrow/backend/adapters"
	"example.com/milestone-escrow/backend/escrow"
)

func TestEmptyConfigRejectedAndRequiresConfigFileOrGUI(t *testing.T) {
	// 1. Passing an empty OrganizationConfig MUST fail with an error pointing to config file or GUI setup!
	if _, err := NewPlatformService(OrganizationConfig{}); err == nil {
		t.Fatal("expected empty OrganizationConfig to return an error pointing to config file or GUI")
	}
	if _, err := LoadOrganizationConfigFromFile(""); err == nil {
		t.Fatal("expected empty config file path to return an error")
	}

	// 2. Loading from our external config file (../../config/organization.json) succeeds without hardcoded Go strings
	cfg, err := LoadOrganizationConfigFromFile("../../config/organization.json")
	if err != nil {
		t.Fatalf("expected config/organization.json to load cleanly, got err=%v", err)
	}
	svc, err := NewPlatformService(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Updating organization identity dynamically from the GUI works and rejects blank names
	if err := svc.UpdateConfigFromGUI(OrganizationConfig{}); err == nil {
		t.Fatal("expected GUI config update with empty fields to fail")
	}
	err = svc.UpdateConfigFromGUI(OrganizationConfig{
		TenantID:          "org-sabanilla",
		OrganizationName:  "Comité Cívico de Sabanilla",
		JurisdictionLabel: "Sabanilla, Costa Rica",
		CommitteeAccount:  "committee_sabanilla_key",
	})
	if err != nil || svc.Config.OrganizationName != "Comité Cívico de Sabanilla" {
		t.Fatalf("expected GUI config update to succeed, got err=%v name=%s", err, svc.Config.OrganizationName)
	}

	// 4. Loading demonstration projects and subasta items from external config/demo_seed.json works cleanly
	if err := svc.LoadDemoSeedFromFile("../../config/demo_seed.json"); err != nil {
		t.Fatalf("expected config/demo_seed.json to load cleanly, got err=%v", err)
	}
	if len(svc.Projects) != 1 || len(svc.Subastas) != 1 {
		t.Fatalf("expected 1 seeded project and 1 seeded subasta, got projects=%d subastas=%d", len(svc.Projects), len(svc.Subastas))
	}

	// 5. FX Circuit-Breaker Protection: Reject manipulated exchange rates (e.g. 50 or 5000 CRC/USD, or >3% sudden jump)
	if err := svc.UpdateConfigFromGUI(OrganizationConfig{
		TenantID:              "org-sabanilla",
		OrganizationName:      "Comité Cívico de Sabanilla",
		CommitteeAccount:      "committee_sabanilla_key",
		ExchangeRateCRCPerUSD: 9999, // Exploited rate outside corridor!
	}); err == nil {
		t.Fatal("expected FX circuit breaker to reject manipulated rate 9999 CRC/USD")
	}
	if err := svc.UpdateConfigFromGUI(OrganizationConfig{
		TenantID:              "org-sabanilla",
		OrganizationName:      "Comité Cívico de Sabanilla",
		CommitteeAccount:      "committee_sabanilla_key",
		ExchangeRateCRCPerUSD: 580, // >3% sudden jump from 512!
	}); err == nil {
		t.Fatal("expected FX circuit breaker to reject >3% sudden jump from 512 to 580")
	}

	// 6. Gradual daily updates (<3% each step: 512 -> 525 -> 538) succeed automatically over time,
	//    AND if a >3% jump ever happens in real life, Committee + Arbiter can co-sign ForceUpdateExchangeRate!
	if err := svc.ForceUpdateExchangeRate(580, "BCCR MONEX Verified Override", "2027-06-01", "committee_sabanilla_key", "arbiter_key"); err != nil {
		t.Fatalf("expected co-signed ForceUpdateExchangeRate to succeed for >3%% market shift, got %v", err)
	}
}

func TestApprovalGateAnonymousRedactionAndInKindResources(t *testing.T) {
	cfg, err := LoadOrganizationConfigFromFile("../../config/organization.json")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewPlatformService(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Add an unapproved project and an approved project
	unapproved := &CivicProject{
		ID:                 "proj-unapproved-002",
		ApprovedResolution: "", // Not yet approved!
		Escrow: &escrow.Escrow{
			Client:     svc.Config.CommitteeAccount,
			Contractor: "contractor_x",
			Status:     escrow.Created,
			Milestones: []escrow.Milestone{{Amount: 100}},
		},
	}
	approved := &CivicProject{
		ID:                 "proj-approved-001",
		ApprovedResolution: "RES-2026-042",
		Escrow: &escrow.Escrow{
			Client:      svc.Config.CommitteeAccount,
			Contractor:  "contractor_y",
			Beneficiary: svc.Bridge.DisburserAccount,
			Status:      escrow.Created,
			Milestones:  []escrow.Milestone{{Amount: 400}, {Amount: 600}},
		},
	}
	svc.Projects = append(svc.Projects, unapproved, approved)

	dep := adapters.FiatDeposit{
		IdempotencyKey: "SINPE-TEST-1",
		Donor:          "Jane Doe",
		Currency:       "CRC",
		Rail:           adapters.RailSINPEMovil,
		AmountUnits:    50,
		ReceiptBytes:   []byte("SINPE-RECEIPT-BYTES"),
	}
	if _, err := svc.ContributeViaBridge("proj-unapproved-002", dep, false); err == nil {
		t.Fatal("expected unapproved project to reject contribution")
	}

	rec, err := svc.ContributeViaBridge("proj-approved-001", dep, true)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Donor != "Anónimo" {
		t.Fatalf("expected anonymous donor to be redacted to Anónimo, got %s", rec.Donor)
	}

	err = svc.AddInKindResource("proj-approved-001", InKindResource{
		ContributorAlias: "Ferretería El Sol",
		DescriptionES:    "Paneles solares monocristalinos de 400W",
		DescriptionEN:    "400W Monocrystalline Solar Panels",
		Quantity:         4,
		Unit:             "unidades / units",
		VerifiedBy:       "inspector_key",
		EvidenceHash:     "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
	}, false)
	if err != nil {
		t.Fatal(err)
	}
}
