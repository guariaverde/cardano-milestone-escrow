package adapters

import (
	"testing"

	"example.com/milestone-escrow/backend/escrow"
)

func TestEvidenceHashingAndTamperDetection(t *testing.T) {
	originalPhoto := []byte("JPEG-SOLAR-POLE-INSTALLED-PARQUE-CEDROS-2026-11-19")
	hash, err := HashEvidence(originalPhoto)
	if err != nil || hash == "" {
		t.Fatalf("expected valid sha256 hash, got err=%v", err)
	}

	// 1. Original unmodified file passes verification
	if !VerifyEvidenceHash(originalPhoto, hash) {
		t.Fatal("expected original photo to match anchored hash")
	}

	// 2. Modifying even 1 byte of the photo is immediately caught as tampering!
	tamperedPhoto := []byte("JPEG-SOLAR-POLE-INSTALLED-PARQUE-CEDROS-2026-11-18")
	if VerifyEvidenceHash(tamperedPhoto, hash) {
		t.Fatal("expected tampered photo to FAIL hash verification")
	}
}

func TestAntiTrojanMagicBytesAndMalwareScanner(t *testing.T) {
	// 1. Windows .exe Trojan disguised as a photo ("MZ..." bytes) MUST be rejected!
	disguisedExeTrojan := []byte("MZ\x90\x00\x03\x00\x00\x00_FAKE_SOLAR_PHOTO.JPG")
	if _, err := HashEvidence(disguisedExeTrojan); err == nil {
		t.Fatal("expected disguised Windows .exe Trojan (MZ header) to be rejected")
	}

	// 2. PDF containing embedded /JavaScript or /Launch exploit MUST be rejected!
	maliciousPDF := []byte("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.launchURL('http://evil')) >> >>\nendobj")
	if _, err := HashEvidence(maliciousPDF); err == nil {
		t.Fatal("expected PDF with embedded /JavaScript and /OpenAction exploit to be rejected")
	}

	// 3. EICAR Standard Antivirus Test Signature MUST be rejected!
	eicarVirusTest := []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
	if _, err := HashEvidence(eicarVirusTest); err == nil {
		t.Fatal("expected EICAR antivirus test file to be rejected")
	}

	// 4. Clean PDF (valid %PDF- magic bytes without exploit tags) and clean JPEG (FF D8 FF) succeed!
	cleanPDF := []byte("%PDF-1.7\n% Clean Hacienda Factura Electronica #0041 - Taller Don Carlos\n%%EOF")
	if _, err := HashEvidence(cleanPDF); err != nil {
		t.Fatalf("expected clean PDF invoice to pass inspection, got err=%v", err)
	}
	cleanJPEG := []byte("\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00SOLAR_POLE_IMAGE_DATA")
	if _, err := HashEvidence(cleanJPEG); err != nil {
		t.Fatalf("expected clean JPEG photo to pass inspection, got err=%v", err)
	}
}

func TestFiatBridgeSINPEDepositCappedFeeAndContractorPayout(t *testing.T) {
	bridge := &FiatBridgeAdapter{
		DisburserAccount: "org_sinpe_disburser",
		HostingFeeBps:    100, // 1% non-profit hosting fee
		HostingPeriodCap: 5,   // Hosting budget needs only 5 units total this period!
	}

	// Montes de Oca Solar Park Project requiring 300 net units
	solarProject := &escrow.Escrow{
		Client:      "montes_de_oca_committee",
		Contractor:  "taller_don_carlos",
		Verifier:    "inspector_dan",
		Arbiter:     "arbiter_carol",
		Beneficiary: "org_sinpe_disburser",
		Status:      escrow.Created,
		Milestones:  []escrow.Milestone{{Amount: 300}},
	}

	// 1. Citizen Maria sends 205 units via SINPE Móvil:
	//    1% of 205 is 2 units, but let's see: HostingPeriodCap is 5, so fee = 2, net = 203!
	dep1 := FiatDeposit{
		IdempotencyKey: "SINPE-BCR-0001",
		Donor:          "ciudadana_maria",
		Currency:       "CRC",
		Rail:           RailSINPEMovil,
		AmountUnits:    202, // 1% fee = 2 units -> net 200 units into project!
		ReceiptBytes:   []byte("COMPROBANTE-SINPE-BCR-0001-MARIA-CRC"),
	}
	rec1, err := bridge.DepositFiatToProject(dep1, solarProject)
	if err != nil {
		t.Fatal(err)
	}
	if rec1.HostingFeeUnits != 2 || rec1.NetEscrowUnits != 200 || bridge.HostingPoolCollected != 2 {
		t.Fatalf("unexpected first deposit breakdown: %+v", rec1)
	}

	// 2. Duplicate replay of the exact same SINPE webhook ("SINPE-BCR-0001") MUST be rejected!
	if _, err := bridge.DepositFiatToProject(dep1, solarProject); err == nil {
		t.Fatal("expected duplicate SINPE webhook idempotency key to be rejected")
	}

	// 3. Business contributes remaining 103 units via Card On-Ramp:
	//     Only 3 units of room remain in HostingPeriodCap (5 - 2 = 3), so fee is 1 (1% of 103 = 1) or let's set HostingPoolCollected to 5:
	bridge.HostingPoolCollected = 5 // Hosting budget is now 100% met!
	dep2 := FiatDeposit{
		IdempotencyKey: "ONRAMP-CARD-0002",
		Donor:          "ferreteria_sabanilla",
		Currency:       "USD",
		Rail:           RailRegulatedOnRamp,
		AmountUnits:    100, // Since HostingPeriodCap (5) is met, fee is 0 and 100% (100) goes to project!
		ReceiptBytes:   []byte("ONRAMP-RECEIPT-0002-USD"),
	}
	rec2, err := bridge.DepositFiatToProject(dep2, solarProject)
	if err != nil {
		t.Fatal(err)
	}
	if rec2.HostingFeeUnits != 0 || rec2.NetEscrowUnits != 100 || solarProject.Status != escrow.Funded {
		t.Fatalf("expected 0 hosting fee once cap reached and project Funded, got rec2=%+v status=%s", rec2, solarProject.Status)
	}

	// 4. Don Carlos completes work -> hashes photo -> Inspector verifies -> Committee approves -> SINPE Off-Ramp pays Don Carlos!
	workPhotoHash, _ := HashEvidence([]byte("PHOTO-SOLAR-LIGHT-POLE-01.JPG"))
	if err := solarProject.SubmitWithEvidence("taller_don_carlos", 0, workPhotoHash); err != nil {
		t.Fatal(err)
	}
	if err := solarProject.Verify("inspector_dan", 0); err != nil {
		t.Fatal(err)
	}
	if err := solarProject.Approve("montes_de_oca_committee", 0); err != nil {
		t.Fatal(err)
	}

	// 5. Disburser sends Colones via SINPE to Don Carlos and anchors the official SINPE comprobante hash!
	sinpePayoutReceipt := []byte("SINPE-OUT-BNCR-99812-PAGADO-A-TALLER-DON-CARLOS-FACTURA-0041")
	anchoredHash, err := bridge.SettleMilestoneViaSINPE(solarProject, 0, sinpePayoutReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyEvidenceHash(sinpePayoutReceipt, solarProject.Milestones[0].SettlementReceiptHash) || anchoredHash == "" {
		t.Fatal("expected SINPE payout receipt to be cryptographically verifiable against the milestone")
	}
	if bridge.LockedReserveUnits != 0 || bridge.TotalDisbursedUnits != 300 {
		t.Fatalf("expected LockedReserveUnits=0 and TotalDisbursedUnits=300 after settlement, got locked=%d disbursed=%d",
			bridge.LockedReserveUnits, bridge.TotalDisbursedUnits)
	}
}

func TestReserveDepletionBlocksSettlement(t *testing.T) {
	bridge := &FiatBridgeAdapter{
		DisburserAccount: "org_sinpe_disburser",
	}
	project := &escrow.Escrow{
		Client:      "committee",
		Contractor:  "contractor_bob",
		Beneficiary: "org_sinpe_disburser",
		Status:      escrow.Created,
		Milestones:  []escrow.Milestone{{Amount: 100}},
	}
	_, _ = bridge.DepositFiatToProject(FiatDeposit{
		IdempotencyKey: "DEP-1",
		Donor:          "donor1",
		Currency:       "CRC",
		Rail:           RailSINPEMovil,
		AmountUnits:    100,
		ReceiptBytes:   []byte("SINPE-100"),
	}, project)
	_ = project.SubmitWithEvidence("contractor_bob", 0, "sha256:work")
	_ = project.Approve("committee", 0)

	// Simulate an unexpected reserve depletion (only 80 available when 100 is needed!)
	bridge.LockedReserveUnits = 80
	if err := bridge.VerifyReserveSolvency(100); err == nil {
		t.Fatal("expected VerifyReserveSolvency to fail when reserve is depleted")
	}
	if _, err := bridge.SettleMilestoneViaSINPE(project, 0, []byte("SINPE-RECEIPT")); err == nil {
		t.Fatal("expected SettleMilestoneViaSINPE to block payout when reserve is depleted")
	}
}
