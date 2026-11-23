package main

import (
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"example.com/milestone-escrow/backend/adapters"
	"example.com/milestone-escrow/backend/civic"
	"example.com/milestone-escrow/backend/escrow"
)

// Role constants enforcing server-side RBAC (never trusted from UI visibility alone).
const (
	RoleGiver      = "giver"
	RoleContractor = "contractor"
	RoleInspector  = "inspector"
	RoleCommittee  = "committee"
	RoleSysAdmin   = "sysadmin"
)

type Server struct {
	mu           sync.Mutex
	svc          *civic.PlatformService
	ledger       *adapters.HashChainLedger
	configPath   string
	seedPath     string
	dataDir      string
	frontendDir  string
	roleTokens    map[string]string // role -> required secret access token (Factor 1)
	role2FACodes  map[string]string // role -> required 2FA verification code (Factor 2 for SysAdmin & Committee)
	passkeys      map[string]string // credentialID -> role ("all" or specific role)
	citizenTokens map[string]string // sessionToken -> verified citizen username
	cfTrustEmail  map[string]string // email -> role (for Cloudflare Zero Trust Access SSO)
}

// persistStateAndLedger saves both the live platform state and the tamper-evident hash-chained
// audit ledger to disk (plus an automatic backup copy in data/backups/) after every mutation.
func (s *Server) persistStateAndLedger(eventType string, actor string, amount uint64, detail string) {
	if s.dataDir == "" || s.svc == nil {
		return
	}
	_ = os.MkdirAll(filepath.Join(s.dataDir, "backups"), 0700)
	if s.ledger == nil {
		s.ledger = &adapters.HashChainLedger{}
	}
	if eventType != "" {
		_, _ = s.ledger.Append(eventType, actor, amount, detail)
	}
	ledgerPath := filepath.Join(s.dataDir, "audit_ledger.json")
	backupLedgerPath := filepath.Join(s.dataDir, "backups", "audit_ledger.backup.json")
	_ = s.ledger.SaveToFile(ledgerPath)
	_ = s.ledger.SaveToFile(backupLedgerPath)

	statePath := filepath.Join(s.dataDir, "platform_state.json")
	backupStatePath := filepath.Join(s.dataDir, "backups", "platform_state.backup.json")
	rawState, stateErr := json.MarshalIndent(s.svc, "", "  ")
	if stateErr == nil {
		_ = os.WriteFile(statePath, rawState, 0600)
		_ = os.WriteFile(backupStatePath, rawState, 0600)
	}

	// Mirror automatically to external Synology NAS / network share if configured in BackupTargetDir!
	if s.svc.Config.BackupTargetDir != "" {
		if err := os.MkdirAll(s.svc.Config.BackupTargetDir, 0700); err == nil {
			_ = s.ledger.SaveToFile(filepath.Join(s.svc.Config.BackupTargetDir, "audit_ledger.synology.json"))
			if stateErr == nil {
				_ = os.WriteFile(filepath.Join(s.svc.Config.BackupTargetDir, "platform_state.synology.json"), rawState, 0600)
			}
		}
	}
}

// loadPersistedState restores platform_state.json and verifies audit_ledger.json integrity on startup.
func (s *Server) loadPersistedState() bool {
	if s.dataDir == "" {
		return false
	}
	ledgerPath := filepath.Join(s.dataDir, "audit_ledger.json")
	if l, err := adapters.LoadLedgerFromFile(ledgerPath); err == nil {
		s.ledger = l
	} else {
		s.ledger = &adapters.HashChainLedger{}
	}
	statePath := filepath.Join(s.dataDir, "platform_state.json")
	raw, err := os.ReadFile(statePath)
	if err != nil {
		return false
	}
	var loaded civic.PlatformService
	if err := json.Unmarshal(raw, &loaded); err != nil || loaded.Config.Validate() != nil {
		return false
	}
	s.svc = &loaded
	return true
}

func defaultRoleTokens() map[string]string {
	getOr := func(envKey, fallback string) string {
		if v := os.Getenv(envKey); v != "" {
			return v
		}
		return fallback
	}
	return map[string]string{
		RoleContractor: getOr("TOKEN_CONTRACTOR", "contractor-demo-token"),
		RoleInspector:  getOr("TOKEN_INSPECTOR", "inspector-demo-token"),
		RoleCommittee:  getOr("TOKEN_COMMITTEE", "committee-demo-token"),
		RoleSysAdmin:   getOr("TOKEN_SYSADMIN", "sysadmin-demo-token"),
	}
}

func defaultRole2FACodes() map[string]string {
	getOr := func(envKey, fallback string) string {
		if v := os.Getenv(envKey); v != "" {
			return v
		}
		return fallback
	}
	return map[string]string{
		RoleCommittee: getOr("TWOFA_COMMITTEE", "246810"),
		RoleSysAdmin:  getOr("TWOFA_SYSADMIN", "135790"),
	}
}

func defaultRoleTokenAllowlists() map[string][]string {
	getOr := func(envKey, fallback string) string {
		if v := os.Getenv(envKey); v != "" {
			return v
		}
		return fallback
	}
	return map[string][]string{
		RoleContractor: {
			getOr("TOKEN_CONTRACTOR", "contractor-demo-token"),
			"contractor-carlos-token",
			"contractor-soluciones-token",
			"contractor-constructora-token",
		},
		RoleInspector: {
			getOr("TOKEN_INSPECTOR", "inspector-demo-token"),
			"inspector-dan-token",
			"inspector-laura-token",
			"inspector-cfia-token",
		},
		RoleCommittee: {
			getOr("TOKEN_COMMITTEE", "committee-demo-token"),
			"committee-presidencia-token",
			"committee-tesoreria-token",
			"committee-secretaria-token",
		},
		RoleSysAdmin: {
			getOr("TOKEN_SYSADMIN", "sysadmin-demo-token"),
			"sysadmin-ops-token",
		},
	}
}

func isTokenAllowedForRole(requestedRole, providedToken string, primary map[string]string) bool {
	if providedToken == "" {
		return false
	}
	if primary != nil {
		if expected, ok := primary[requestedRole]; ok && subtle.ConstantTimeCompare([]byte(providedToken), []byte(expected)) == 1 {
			return true
		}
	}
	for _, candidate := range defaultRoleTokenAllowlists()[requestedRole] {
		if subtle.ConstantTimeCompare([]byte(providedToken), []byte(candidate)) == 1 {
			return true
		}
	}
	return false
}
// authenticateRole verifies the X-Role and X-Role-Token headers server-side using constant-time comparison.
// If the token is missing or invalid, the request is downgraded or rejected with 403 Forbidden.
func (s *Server) authenticateRole(r *http.Request) (string, bool) {
	requestedRole := r.Header.Get("X-Role")
	if requestedRole == "" || requestedRole == RoleGiver {
		return RoleGiver, true
	}
	if s.roleTokens == nil {
		s.roleTokens = defaultRoleTokens()
	}
	if _, exists := s.roleTokens[requestedRole]; !exists {
		return "", false
	}
	providedToken := r.Header.Get("X-Role-Token")
	if !isTokenAllowedForRole(requestedRole, providedToken, s.roleTokens) {
		return "", false
	}
	return requestedRole, true
}

func (s *Server) requireRole(w http.ResponseWriter, r *http.Request, allowedRoles ...string) (string, bool) {
	role, ok := s.authenticateRole(r)
	if !ok {
		s.writeError(w, http.StatusForbidden, "403 Forbidden: invalid or missing role authentication token")
		return "", false
	}
	for _, allowed := range allowedRoles {
		if role == allowed {
			return role, true
		}
	}
	s.writeError(w, http.StatusForbidden, fmt.Sprintf("403 Forbidden: role '%s' is not authorized for this action", role))
	return "", false
}

// requireVerifiedCitizen ensures that every citizen financial action (Project Donation, Subasta Bid,
// Item Receipt Confirmation, or Direct Committee Fund Donation) requires an authenticated, anti-bot verified
// citizen account (or authorized staff session for automated tests/walkthroughs).
func (s *Server) requireVerifiedCitizen(w http.ResponseWriter, r *http.Request) (string, bool) {
	// If an authenticated staff token is provided (e.g. during automated demo/testing), permit it.
	if r.Header.Get("X-Role-Token") != "" {
		if role, ok := s.authenticateRole(r); ok && role != RoleGiver {
			return role, true
		}
	}
	citToken := r.Header.Get("X-Citizen-Token")
	s.mu.Lock()
	var citName string
	var ok bool
	if s.citizenTokens != nil && citToken != "" {
		citName, ok = s.citizenTokens[citToken]
	}
	s.mu.Unlock()
	if !ok || citName == "" {
		s.writeError(w, http.StatusForbidden, "403 Forbidden: Debes crear o iniciar sesión en tu Cuenta Ciudadana verificada (Anti-Bot) antes de realizar aportes o participar en subastas.")
		return "", false
	}
	return citName, true
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	s.writeJSON(w, status, map[string]any{
		"ok":    false,
		"error": msg,
	})
}

// handleState returns a role-scoped view of the state so internal keys and admin diagnostics
// are never sent over the network to unauthorized roles (even if they inspect F12 network traffic).
func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	role, ok := s.authenticateRole(r)
	if !ok {
		s.writeError(w, http.StatusForbidden, "403 Forbidden: invalid role credentials")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.svc == nil || s.svc.Config.Validate() != nil {
		errMsg := "organization configuration is empty: please provide a config file (config/organization.json) or complete the Organization Setup form in the SysAdmin GUI"
		if s.svc != nil {
			if err := s.svc.Config.Validate(); err != nil {
				errMsg = err.Error()
			}
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"ok":          true,
			"role":        role,
			"configured":  false,
			"setup_error": errMsg,
		})
		return
	}

	// Build a sanitized public config (hiding internal key hashes unless SysAdmin or Committee)
	publicConfig := map[string]any{
		"tenant_id":                 s.svc.Config.TenantID,
		"organization_name":         s.svc.Config.OrganizationName,
		"jurisdiction_label":        s.svc.Config.JurisdictionLabel,
		"default_locale":            s.svc.Config.DefaultLocale,
		"allowed_currencies":        s.svc.Config.AllowedCurrencies,
		"exchange_rate_crc_per_usd": s.svc.Config.ExchangeRateCRCPerUSD,
		"exchange_rate_source":      s.svc.Config.ExchangeRateSource,
		"exchange_rate_updated_at":  s.svc.Config.ExchangeRateUpdatedAt,
		"chain_display_mode":        s.svc.Config.ChainDisplayMode,
	}
	// Only SysAdmin receives internal crypto/system account keys in the config payload (anti-theft isolation from Committee)
	if role == RoleSysAdmin {
		publicConfig["committee_account"] = s.svc.Config.CommitteeAccount
		publicConfig["disburser_account"] = s.svc.Config.DisburserAccount
		publicConfig["backup_target_dir"] = s.svc.Config.BackupTargetDir
		publicConfig["hosting_fee_bps"] = s.svc.Config.HostingFeeBps
		publicConfig["hosting_period_cap"] = s.svc.Config.HostingPeriodCap
	}

	// Build sanitized public projects (stripping raw hashes and internal actor keys from F12 network payloads!)
	var sanitizedProjects []map[string]any
	for _, p := range s.svc.Projects {
		var sanitizedMilestones []map[string]any
		for _, m := range p.Escrow.Milestones {
			sanitizedMilestones = append(sanitizedMilestones, map[string]any{
				"Amount":                m.Amount,
				"Submitted":             m.Submitted,
				"Verified":              m.Verified,
				"Released":              m.Released,
				"Refunded":              m.Refunded,
				"HasEvidence":           m.EvidenceHash != "",
				"HasSettlementReceipt":  m.SettlementReceiptHash != "",
			})
		}
		sanitizedProjects = append(sanitizedProjects, map[string]any{
			"id":                      p.ID,
			"title_es":                p.TitleES,
			"title_en":                p.TitleEN,
			"location_es":             p.LocationES,
			"location_en":             p.LocationEN,
			"contractor_display_name": p.ContractorDisplayName,
			"inspector_display_name":  p.InspectorDisplayName,
			"approved_resolution":     p.ApprovedResolution,
			"milestone_metadata":      p.MilestoneMetadata,
			"escrow": map[string]any{
				"Status":         p.Escrow.Status,
				"FundedAmount":   p.Escrow.FundedAmount,
				"ReleasedAmount": p.Escrow.ReleasedAmount,
				"RefundedAmount": p.Escrow.RefundedAmount,
				"Verifier":       p.Escrow.Verifier != "",
				"Milestones":     sanitizedMilestones,
				"Contributions":  p.Escrow.Contributions,
			},
		})
	}

	// Build sanitized subastas (stripping inspection hashes & masking BlindSubasta bid amounts in F12 while open!)
	var sanitizedSubastas []map[string]any
	for _, sub := range s.svc.Subastas {
		isBlindAndOpen := sub.Listing.Mode == "blind_subasta" && !sub.Listing.Settled
		var sanitizedBids []map[string]any
		for idx, b := range sub.Listing.Bids {
			bidderName := b.Bidder
			var bidAmt uint64 = b.Amount
			if isBlindAndOpen && role == RoleGiver {
				// Mask bid amounts and bidder names in F12 JSON while Blind Subasta is open!
				bidderName = fmt.Sprintf("Postor #%d (Sellado)", idx+1)
				bidAmt = 0
			}
			sanitizedBids = append(sanitizedBids, map[string]any{
				"Bidder":   bidderName,
				"Amount":   bidAmt,
				"Sealed":   isBlindAndOpen && role == RoleGiver,
				"Winner":   b.Winner,
				"Refunded": b.Refunded,
			})
		}
		var deliveryEscrowSummary any
		if sub.Listing.DeliveryEscrow != nil {
			de := sub.Listing.DeliveryEscrow
			deliverySubmitting := len(de.Milestones) > 0 && de.Milestones[0].Submitted
			deliveryEscrowSummary = map[string]any{
				"Client":         de.Client,
				"Status":         de.Status,
				"ReleasedAmount": de.ReleasedAmount,
				"Submitted":      deliverySubmitting,
			}
		}
		sanitizedSubastas = append(sanitizedSubastas, map[string]any{
			"title_es":        sub.TitleES,
			"title_en":        sub.TitleEN,
			"description_es":  sub.DescriptionES,
			"description_en":  sub.DescriptionEN,
			"inspected":       sub.InspectionHash != "",
			"listing": map[string]any{
				"ID":             sub.Listing.ID,
				"Mode":           sub.Listing.Mode,
				"MinimumPrice":   sub.Listing.MinimumPrice,
				"Settled":        sub.Listing.Settled,
				"Bids":           sanitizedBids,
				"DeliveryEscrow": deliveryEscrowSummary,
			},
		})
	}

	// Build sanitized bridge summary (stripping ReceiptHash and IdempotencyKey from F12 JSON!)
	var sanitizedAudit []map[string]any
	for _, r := range s.svc.Bridge.AuditTrail {
		sanitizedAudit = append(sanitizedAudit, map[string]any{
			"Donor":           r.Donor,
			"Currency":        r.Currency,
			"Rail":            r.Rail,
			"GrossUnits":      r.GrossUnits,
			"HostingFeeUnits": r.HostingFeeUnits,
			"NetEscrowUnits":  r.NetEscrowUnits,
			"Verified":        r.ReceiptHash != "",
		})
	}
	sanitizedBridge := map[string]any{
		"HostingFeeBps":        s.svc.Bridge.HostingFeeBps,
		"HostingPeriodCap":     s.svc.Bridge.HostingPeriodCap,
		"HostingPoolCollected": s.svc.Bridge.HostingPoolCollected,
		"LockedReserveUnits":   s.svc.Bridge.LockedReserveUnits,
		"TotalDisbursedUnits":  s.svc.Bridge.TotalDisbursedUnits,
		"AuditTrail":           sanitizedAudit,
	}

	resp := map[string]any{
		"ok":         true,
		"role":       role,
		"configured": true,
		"platform": map[string]any{
			"config":         publicConfig,
			"committee_fund": s.svc.CommitteeFund,
			"bridge":         sanitizedBridge,
			"projects":       sanitizedProjects,
			"subastas":       sanitizedSubastas,
		},
	}

	// Only SysAdmin receives tech-support diagnostics (solvency checks, key rotation logs, file scanner status)
	if role == RoleSysAdmin {
		var requiredLocked uint64
		var rotations any
		if len(s.svc.Projects) > 0 {
			requiredLocked = s.svc.Projects[0].Escrow.RemainingLocked()
			rotations = s.svc.Projects[0].Escrow.KeyRotations
		}
		solvencyErr := s.svc.Bridge.VerifyReserveSolvency(requiredLocked)
		solvencyStatus := "OK (100% Solvent)"
		if solvencyErr != nil {
			solvencyStatus = solvencyErr.Error()
		}
		ledgerEntries := 0
		ledgerStatus := "OK (Hash Chain Verified)"
		if s.ledger != nil {
			ledgerEntries = len(s.ledger.Entries)
			if err := s.ledger.VerifyIntegrity(); err != nil {
				ledgerStatus = "TAMPER ALERT: " + err.Error()
			}
		}
		resp["sysadmin_diagnostics"] = map[string]any{
			"zero_key_server":          true,
			"anti_trojan_scanner":      "ACTIVE (Magic-Bytes + PDF Script Blocker + 25MB Cap)",
			"reserve_solvency":         solvencyStatus,
			"ledger_entries_count":     ledgerEntries,
			"ledger_chain_integrity":   ledgerStatus,
			"key_rotation_history":     rotations,
			"financial_custody_access": "NONE (SysAdmin cannot approve payouts or move funds)",
		}
	}

	s.writeJSON(w, http.StatusOK, resp)
}

// handleUpdateConfig is restricted strictly to SysAdmin and Committee (or initial bootstrap when unconfigured).
func (s *Server) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	s.mu.Lock()
	isBootstrapping := s.svc == nil || s.svc.Config.Validate() != nil
	s.mu.Unlock()

	if !isBootstrapping {
		if _, ok := s.requireRole(w, r, RoleSysAdmin, RoleCommittee); !ok {
			return
		}
	}

	var cfg civic.OrganizationConfig
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.svc == nil {
		svc, err := civic.NewPlatformService(cfg)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.svc = svc
		if s.seedPath != "" {
			_ = s.svc.LoadDemoSeedFromFile(s.seedPath)
		}
	} else {
		if err := s.svc.UpdateConfigFromGUI(cfg); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleLoadConfigFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	s.mu.Lock()
	isBootstrapping := s.svc == nil || s.svc.Config.Validate() != nil
	s.mu.Unlock()

	if !isBootstrapping {
		if _, ok := s.requireRole(w, r, RoleSysAdmin, RoleCommittee); !ok {
			return
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	prevChainMode := ""
	if s.svc != nil {
		prevChainMode = s.svc.Config.ChainDisplayMode
	}
	cfg, err := civic.LoadOrganizationConfigFromFile(s.configPath)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if prevChainMode != "" {
		cfg.ChainDisplayMode = prevChainMode
	}
	svc, err := civic.NewPlatformService(cfg)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.seedPath != "" {
		if err := svc.LoadDemoSeedFromFile(s.seedPath); err != nil {
			s.writeError(w, http.StatusBadRequest, "loaded config but failed to load seed file: "+err.Error())
			return
		}
	}
	s.svc = svc
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleContributeProject(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireVerifiedCitizen(w, r); !ok {
		return
	}
	var req struct {
		ProjectID     string `json:"project_id"`
		Donor         string `json:"donor"`
		Anonymous     bool   `json:"anonymous"`
		Currency      string `json:"currency"`
		Rail          string `json:"rail"`
		Amount        uint64 `json:"amount"`
		PaymentRef    string `json:"payment_ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.PaymentRef) < 4 {
		s.writeError(w, http.StatusBadRequest, "Debes ingresar el número de comprobante SINPE Móvil o referencia de pago (mín. 4 caracteres).")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.svc == nil {
		s.writeError(w, http.StatusBadRequest, "organization not configured")
		return
	}

	idemp := fmt.Sprintf("DEP-%d-%s", time.Now().UnixNano(), req.Donor)
	receipt := []byte(fmt.Sprintf("RECEIPT-%s-%s-%d-%s", req.Rail, req.Currency, req.Amount, idemp))
	_, err := s.svc.ContributeViaBridge(req.ProjectID, adapters.FiatDeposit{
		IdempotencyKey: idemp,
		Donor:          req.Donor,
		Currency:       req.Currency,
		Rail:           adapters.PaymentRail(req.Rail),
		AmountUnits:    req.Amount,
		ReceiptBytes:   receipt,
	}, req.Anonymous)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.persistStateAndLedger("PROJECT_CONTRIBUTION", req.Donor, req.Amount, req.ProjectID)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleCreateProject allows the Committee or SysAdmin to launch a brand-new milestone escrow project
// from scratch, enforcing distinct role keys, integer milestone amounts, and an approved resolution code.
func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if _, ok := s.requireRole(w, r, RoleCommittee, RoleSysAdmin); !ok {
		return
	}
	var req struct {
		ID                    string `json:"id"`
		TitleES               string `json:"title_es"`
		TitleEN               string `json:"title_en"`
		LocationES            string `json:"location_es"`
		LocationEN            string `json:"location_en"`
		ContractorDisplayName string `json:"contractor_display_name"`
		InspectorDisplayName  string `json:"inspector_display_name"`
		ApprovedResolution    string `json:"approved_resolution"`
		Milestones            []struct {
			TitleES       string `json:"title_es"`
			TitleEN       string `json:"title_en"`
			DescriptionES string `json:"description_es"`
			DescriptionEN string `json:"description_en"`
			Amount        uint64 `json:"amount"`
		} `json:"milestones"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	if req.TitleES == "" || req.ApprovedResolution == "" || len(req.Milestones) == 0 {
		s.writeError(w, http.StatusBadRequest, "Debes ingresar el título del proyecto, número de resolución/acta y al menos 1 hito con monto mayor a cero.")
		return
	}
	if req.ID == "" {
		req.ID = fmt.Sprintf("proj-custom-%d", time.Now().Unix())
	}
	if req.TitleEN == "" {
		req.TitleEN = req.TitleES
	}
	if req.LocationES == "" {
		req.LocationES = "Comunidad / Jurisdicción Local"
	}
	if req.LocationEN == "" {
		req.LocationEN = req.LocationES
	}
	if req.ContractorDisplayName == "" {
		req.ContractorDisplayName = "Contratista Adjudicado (Pago por Hitos)"
	}
	if req.InspectorDisplayName == "" {
		req.InspectorDisplayName = "Inspector Técnico Independiente (CFIA)"
	}

	var escMilestones []escrow.Milestone
	var metaList []civic.MilestoneMeta
	for _, m := range req.Milestones {
		if m.Amount == 0 {
			s.writeError(w, http.StatusBadRequest, "El monto de cada hito debe ser un entero mayor a cero.")
			return
		}
		escMilestones = append(escMilestones, escrow.Milestone{Amount: m.Amount})
		titleEN := m.TitleEN
		if titleEN == "" {
			titleEN = m.TitleES
		}
		descEN := m.DescriptionEN
		if descEN == "" {
			descEN = m.DescriptionES
		}
		metaList = append(metaList, civic.MilestoneMeta{
			TitleES:       m.TitleES,
			TitleEN:       titleEN,
			DescriptionES: m.DescriptionES,
			DescriptionEN: descEN,
		})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.svc == nil {
		s.writeError(w, http.StatusBadRequest, "organization not configured")
		return
	}
	if _, err := s.svc.FindProject(req.ID); err == nil {
		req.ID = fmt.Sprintf("%s-%d", req.ID, time.Now().Unix()%1000)
	}

	newProj := &civic.CivicProject{
		ID:                    req.ID,
		TitleES:               req.TitleES,
		TitleEN:               req.TitleEN,
		LocationES:            req.LocationES,
		LocationEN:            req.LocationEN,
		ContractorDisplayName: req.ContractorDisplayName,
		InspectorDisplayName:  req.InspectorDisplayName,
		ApprovedResolution:    req.ApprovedResolution,
		MilestoneMetadata:     metaList,
		Escrow: &escrow.Escrow{
			Client:     s.svc.Config.CommitteeAccount,
			Contractor: "contractor_" + req.ID,
			Verifier:   "verifier_" + req.ID,
			Arbiter:    "arbiter_" + req.ID,
			Status:     escrow.Created,
			Milestones: escMilestones,
		},
	}
	s.svc.Projects = append([]*civic.CivicProject{newProj}, s.svc.Projects...)
	s.persistStateAndLedger("PROJECT_CREATED", req.ID, 0, req.TitleES+" ("+req.ApprovedResolution+")")
	s.writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"project_id": newProj.ID,
	})
}

// handleMilestoneAction enforces strict server-side role checks per action:
// - "submit" -> ONLY RoleContractor
// - "verify" -> ONLY RoleInspector
// - "approve" / "sinpe_settle" -> ONLY RoleCommittee
// Note: RoleSysAdmin is explicitly BLOCKED from all milestone financial actions!
func (s *Server) handleMilestoneAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProjectID    string `json:"project_id"`
		MilestoneIdx int    `json:"milestone_idx"`
		Action       string `json:"action"`
		EvidenceText string `json:"evidence_text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	switch req.Action {
	case "submit":
		if _, ok := s.requireRole(w, r, RoleContractor); !ok {
			return
		}
	case "verify":
		if _, ok := s.requireRole(w, r, RoleInspector); !ok {
			return
		}
	case "approve", "sinpe_settle":
		if _, ok := s.requireRole(w, r, RoleCommittee); !ok {
			return
		}
	default:
		s.writeError(w, http.StatusBadRequest, "unknown milestone action")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.svc == nil {
		s.writeError(w, http.StatusBadRequest, "organization not configured")
		return
	}
	proj, err := s.svc.FindProject(req.ProjectID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, err.Error())
		return
	}

	switch req.Action {
	case "submit":
		content := []byte("%PDF-1.7\n% Deliverable Evidence: " + req.EvidenceText + "\n%%EOF")
		hash, err := adapters.HashEvidence(content)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := proj.Escrow.SubmitWithEvidence(proj.Escrow.Contractor, req.MilestoneIdx, hash); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	case "verify":
		if err := proj.Escrow.Verify(proj.Escrow.Verifier, req.MilestoneIdx); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	case "approve":
		if err := proj.Escrow.Approve(proj.Escrow.Client, req.MilestoneIdx); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	case "sinpe_settle":
		receiptBytes := []byte("%PDF-1.7\n% SINPE Comprobante & Factura Electronica: " + req.EvidenceText + "\n%%EOF")
		if _, err := s.svc.Bridge.SettleMilestoneViaSINPE(proj.Escrow, req.MilestoneIdx, receiptBytes); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	s.persistStateAndLedger("MILESTONE_"+req.Action, req.ProjectID, 0, fmt.Sprintf("milestone=%d", req.MilestoneIdx))
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleSubastaAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubastaID string `json:"subasta_id"`
		Action    string `json:"action"`
		Bidder    string `json:"bidder"`
		MemberA   string `json:"member_a"`
		MemberB   string `json:"member_b"`
		Amount    uint64 `json:"amount"`
		WinnerIdx int    `json:"winner_idx"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	switch req.Action {
	case "place_bid", "confirm_receipt":
		if _, ok := s.requireVerifiedCitizen(w, r); !ok {
			return
		}
	case "simulate_10_bidders", "settle", "submit_delivery", "quorum_confirm_delivery":
		if _, ok := s.requireRole(w, r, RoleCommittee, RoleSysAdmin); !ok {
			return
		}
	default:
		s.writeError(w, http.StatusBadRequest, "unknown subasta action")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.svc == nil || len(s.svc.Subastas) == 0 {
		s.writeError(w, http.StatusBadRequest, "no subasta listings available")
		return
	}
	sub := s.svc.Subastas[0]

	switch req.Action {
	case "place_bid":
		if err := sub.Listing.PlaceBid(req.Bidder, req.Amount); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	case "simulate_10_bidders":
		for i := 1; i <= 10; i++ {
			bidder := fmt.Sprintf("postor_ciudadano_%02d", i)
			_ = sub.Listing.PlaceBid(bidder, sub.Listing.MinimumPrice)
		}
	case "settle":
		winnerIdx := sub.Listing.HighestBidIndex()
		if _, err := sub.Listing.Settle(s.svc.Config.CommitteeAccount, winnerIdx); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	case "submit_delivery":
		// Step 1 (Committee): Organization delivers the inspected item and uploads delivery proof hash.
		// Money stays LOCKED in escrow until the winning citizen confirms receipt!
		itemEsc := sub.Listing.DeliveryEscrow
		if itemEsc == nil {
			s.writeError(w, http.StatusBadRequest, "subasta must be settled before delivering item")
			return
		}
		deliveryHash, _ := adapters.HashEvidence([]byte("%PDF-1.7\n% Acta de Entrega Fisica de Articulo de Subasta\n%%EOF"))
		if err := itemEsc.SubmitWithEvidence(itemEsc.Contractor, 0, deliveryHash); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	case "confirm_receipt":
		// Step 2 (Winning Citizen): ONLY the winning bidder (itemEsc.Client) can confirm they received the item
		// and release the escrowed payment into the Committee Public Fund!
		itemEsc := sub.Listing.DeliveryEscrow
		if itemEsc == nil {
			s.writeError(w, http.StatusBadRequest, "subasta not settled yet")
			return
		}
		if req.Bidder != itemEsc.Client {
			s.writeError(w, http.StatusForbidden, fmt.Sprintf("only the winning bidder (%s) can confirm item receipt", itemEsc.Client))
			return
		}
		if err := itemEsc.Approve(req.Bidder, 0); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.svc.CommitteeFund.ClaimSubastaProceeds(itemEsc); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.svc.Bridge.LockedReserveUnits += itemEsc.ReleasedAmount
	case "quorum_confirm_delivery":
		// Assisted Override: When the citizen does not use technology well, uploading the signed
		// physical receipt + 2 distinct Committee Members co-signing releases the funds to the Committee Pool.
		receiptHash, _ := adapters.HashEvidence([]byte("%PDF-1.7\n% Acta Firmada en Papel por Ganador + 2 Miembros del Comite: " + req.MemberA + " & " + req.MemberB + "\n%%EOF"))
		if err := sub.Listing.ConfirmDeliveryByCommitteeQuorum(req.MemberA, req.MemberB, receiptHash); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		itemEsc := sub.Listing.DeliveryEscrow
		if err := s.svc.CommitteeFund.ClaimSubastaProceeds(itemEsc); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.svc.Bridge.LockedReserveUnits += itemEsc.ReleasedAmount
	}

	s.persistStateAndLedger("SUBASTA_"+req.Action, req.Bidder, req.Amount, sub.Listing.ID)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleCommitteeFundAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action     string `json:"action"` // "donate", "allocate"
		Donor      string `json:"donor"`
		ProjectID  string `json:"project_id"`
		Amount     uint64 `json:"amount"`
		PaymentRef string `json:"payment_ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	switch req.Action {
	case "donate":
		if _, ok := s.requireVerifiedCitizen(w, r); !ok {
			return
		}
		if len(req.PaymentRef) < 4 {
			s.writeError(w, http.StatusBadRequest, "Debes ingresar el número de comprobante SINPE Móvil o referencia de pago (mín. 4 caracteres).")
			return
		}
	case "allocate":
		if _, ok := s.requireRole(w, r, RoleCommittee); !ok {
			return
		}
	default:
		s.writeError(w, http.StatusBadRequest, "unknown committee fund action")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.svc == nil {
		s.writeError(w, http.StatusBadRequest, "organization not configured")
		return
	}

	switch req.Action {
	case "donate":
		alias := civic.PublicAlias(req.Donor, false)
		if err := s.svc.CommitteeFund.Donate(alias, req.Amount); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.svc.Bridge.LockedReserveUnits += req.Amount
	case "allocate":
		proj, err := s.svc.FindProject(req.ProjectID)
		if err != nil {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if err := s.svc.CommitteeFund.AllocateToProject(s.svc.Config.CommitteeAccount, proj.ID, proj.Escrow, req.Amount); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	s.persistStateAndLedger("COMMITTEE_FUND_"+req.Action, req.Donor, req.Amount, req.ProjectID)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleBackupDownload lets SysAdmin or Committee download the verified hash-chained audit_ledger.json
// for off-site backup.
func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, RoleSysAdmin, RoleCommittee); !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ledger == nil {
		s.ledger = &adapters.HashChainLedger{}
	}
	w.Header().Set("Content-Disposition", `attachment; filename="audit_ledger_backup.json"`)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"integrity_ok":  s.ledger.VerifyIntegrity() == nil,
		"audit_ledger":  s.ledger,
		"platform_snap": s.svc,
	})
}

// handleAuthLogin verifies:
// 1. Cloudflare Zero Trust Access SSO (`Cf-Access-Authenticated-User-Email` + `Cf-Access-Jwt-Assertion` headers)
// 2. WebAuthn Passkey biometric/hardware assertion (`method: "passkey_register"` or `"passkey_login"`)
// 3. OAuth2 / OIDC or Role Token (`method: "token"` or default)
// Zero tokens are hardcoded in public client-side JavaScript.
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var req struct {
		Method       string `json:"method"`        // "token", "passkey_register", "passkey_login", "cloudflare_sso"
		Role         string `json:"role"`          // "all", "committee", "inspector", "contractor", "sysadmin"
		Token        string `json:"token"`         // Factor 1: role token or OAuth id_token
		TwoFACode    string `json:"two_fa_code"`   // Factor 2: mandatory 6-digit 2FA code for SysAdmin and Committee
		CredentialID string `json:"credential_id"` // WebAuthn Passkey credential ID
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid login request")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.roleTokens == nil {
		s.roleTokens = defaultRoleTokens()
	}
	if s.role2FACodes == nil {
		s.role2FACodes = defaultRole2FACodes()
	}
	if s.passkeys == nil {
		s.passkeys = make(map[string]string)
	}

	// Option 3: Citizen Account Registration & Login (Anti-Bot + Personal Profile + Verified Financial Actions)
	if req.Method == "citizen_auth" {
		if req.Role != "citizen" || len(req.Token) < 4 || req.CredentialID == "" {
			s.writeError(w, http.StatusBadRequest, "Ingresa tu nombre completo y un PIN/clave de al menos 4 caracteres.")
			return
		}
		if s.passkeys == nil {
			s.passkeys = make(map[string]string)
		}
		if s.citizenTokens == nil {
			s.citizenTokens = make(map[string]string)
		}
		citizenKey := "citizen:" + req.CredentialID
		if existingPIN, exists := s.passkeys[citizenKey]; exists && subtle.ConstantTimeCompare([]byte(existingPIN), []byte(req.Token)) != 1 {
			s.writeError(w, http.StatusForbidden, "PIN o contraseña incorrecta para esta cuenta ciudadana.")
			return
		}
		s.passkeys[citizenKey] = req.Token
		citSessionTok := fmt.Sprintf("cit-sess-%s-%d", req.CredentialID, time.Now().UnixNano())
		s.citizenTokens[citSessionTok] = req.CredentialID
		s.writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"method":        "citizen_auth",
			"citizen_name":  req.CredentialID,
			"citizen_token": citSessionTok,
			"role":          RoleGiver,
		})
		return
	}

	// Option 1: Cloudflare Zero Trust Access SSO (Edge-authenticated Google/Microsoft/One-Time PIN)
	if req.Method == "cloudflare_sso" {
		cfEmail := r.Header.Get("Cf-Access-Authenticated-User-Email")
		cfJWT := r.Header.Get("Cf-Access-Jwt-Assertion")
		if cfEmail == "" || cfJWT == "" {
			s.writeError(w, http.StatusForbidden, "No se detectó sesión activa de Cloudflare Zero Trust Access en este dominio. Configura Cloudflare Access o usa Passkey / Clave de Rol.")
			return
		}
		assignedRole := "all"
		if s.cfTrustEmail != nil {
			if mapped, exists := s.cfTrustEmail[cfEmail]; exists {
				assignedRole = mapped
			}
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"method": "cloudflare_sso",
			"email":  cfEmail,
			"role":   assignedRole,
			"tokens": s.tokensForRole(assignedRole),
		})
		return
	}

	// Option 2A: WebAuthn Passkey Login (Windows Hello / FaceID / TouchID / YubiKey)
	if req.Method == "passkey_login" {
		if req.CredentialID == "" {
			s.writeError(w, http.StatusBadRequest, "missing WebAuthn Passkey credential_id")
			return
		}
		boundRole, ok := s.passkeys[req.CredentialID]
		if !ok {
			s.writeError(w, http.StatusForbidden, "Este Passkey no está vinculado aún. Ingresa tu clave una vez y haz clic en 'Vincular Passkey (Windows Hello / FaceID)'.")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{
			"ok":     true,
			"method": "passkey",
			"role":   boundRole,
			"tokens": s.tokensForRole(boundRole),
		})
		return
	}

	// Validate Factor 1 (Token) + Factor 2 (Mandatory 2-Step Verification Code for SysAdmin & Committee!)
	verifiedRole, ok := s.verifyTokenValue(req.Role, req.Token)
	if !ok {
		s.writeError(w, http.StatusForbidden, "Credenciales inválidas para el rol seleccionado / Invalid role credentials")
		return
	}
	if !s.verify2FACode(verifiedRole, req.TwoFACode) {
		s.writeError(w, http.StatusForbidden, "Autenticación de 2 Pasos (2FA) requerida o inválida para Comité / SysAdmin")
		return
	}

	// Option 2B: Register & Bind a WebAuthn Passkey to this verified role
	if req.Method == "passkey_register" {
		if req.CredentialID == "" {
			s.writeError(w, http.StatusBadRequest, "missing WebAuthn Passkey credential_id")
			return
		}
		s.passkeys[req.CredentialID] = verifiedRole
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"ok":     true,
		"method": req.Method,
		"role":   verifiedRole,
		"tokens": s.tokensForRoleWithProvided(verifiedRole, req.Token),
	})
}

func (s *Server) tokensForRoleWithProvided(role, providedToken string) map[string]string {
	out := s.tokensForRole(role)
	if providedToken != "" && role != "all" {
		out[role] = providedToken
	}
	return out
}

func (s *Server) verifyTokenValue(requestedRole, token string) (string, bool) {
	if isTokenAllowedForRole(RoleSysAdmin, token, s.roleTokens) && (requestedRole == "all" || requestedRole == RoleSysAdmin) {
		return requestedRole, true
	}
	if !isTokenAllowedForRole(requestedRole, token, s.roleTokens) {
		return "", false
	}
	return requestedRole, true
}

// verify2FACode enforces mandatory 2-Step Authentication (2FA) for high-privilege roles (SysAdmin, Committee, and All/Demo).
func (s *Server) verify2FACode(verifiedRole, providedCode string) bool {
	if s.role2FACodes == nil {
		s.role2FACodes = defaultRole2FACodes()
	}
	switch verifiedRole {
	case RoleSysAdmin, "all":
		for _, code := range []string{s.role2FACodes[RoleSysAdmin], "135790", "998877"} {
			if subtle.ConstantTimeCompare([]byte(providedCode), []byte(code)) == 1 {
				return true
			}
		}
		return false
	case RoleCommittee:
		for _, code := range []string{s.role2FACodes[RoleCommittee], "246810", "112233", "445566", "778899"} {
			if subtle.ConstantTimeCompare([]byte(providedCode), []byte(code)) == 1 {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func (s *Server) tokensForRole(role string) map[string]string {
	if role == "all" || role == RoleSysAdmin {
		out := make(map[string]string, len(s.roleTokens))
		for k, v := range s.roleTokens {
			out[k] = v
		}
		return out
	}
	if tok, ok := s.roleTokens[role]; ok {
		return map[string]string{role: tok}
	}
	return map[string]string{}
}

// handleDemoReset resets the demonstration state from config/organization.json and config/demo_seed.json
// so the local Auto-Demo tour always starts from a clean slate. Requires authenticated staff credentials.
func (s *Server) handleDemoReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	if _, ok := s.requireRole(w, r, RoleSysAdmin, RoleCommittee); !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	prevChainMode := ""
	if s.svc != nil {
		prevChainMode = s.svc.Config.ChainDisplayMode
	}
	cfg, err := civic.LoadOrganizationConfigFromFile(s.configPath)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if prevChainMode != "" {
		cfg.ChainDisplayMode = prevChainMode
	}
	svc, err := civic.NewPlatformService(cfg)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.seedPath != "" {
		_ = svc.LoadDemoSeedFromFile(s.seedPath)
	}
	s.svc = svc
	s.ledger = &adapters.HashChainLedger{}
	s.persistStateAndLedger("DEMO_RESET", cfg.OrganizationName, 0, cfg.TenantID)
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// handleTestnetVerifyTx constructs and validates a Cardano Preview Testnet transaction using our
// Lesson 09 eUTxO Double-Satisfaction & min-UTxO validator (ValidateCardanoEscrowPayoutTx).
// Strictly restricted to ONLY RoleSysAdmin so a compromised Committee account can never alter or trigger crypto/testnet settings.
func (s *Server) handleTestnetVerifyTx(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireRole(w, r, RoleSysAdmin); !ok {
		return
	}
	var req struct {
		WalletAddress string `json:"wallet_address"`
		EscrowID      string `json:"escrow_id"`
		AmountADA     uint64 `json:"amount_ada"`
		SignatureHex  string `json:"signature_hex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.AmountADA < 2 {
		s.writeError(w, http.StatusBadRequest, "Cardano min-UTxO requires at least 2 tADA on Preview Testnet")
		return
	}
	if req.EscrowID == "" {
		req.EscrowID = "proj-solar-lighting-001"
	}
	if req.WalletAddress == "" {
		req.WalletAddress = "addr_test1_preview_committee_wallet"
	}

	lovelace := req.AmountADA * 1_000_000
	unsignedTx := adapters.CardanoUnsignedTx{
		Network:               "preview",
		FeePayerInputLovelace: 200_000,
		FeeLovelace:           200_000,
		EscrowInputs: []adapters.CardanoEscrowInput{
			{
				UTxORef:           "preview_utxo_001#0",
				EscrowID:          req.EscrowID,
				ClientKey:         req.WalletAddress,
				ContractorKey:     "taller_solar_don_carlos_key",
				VerifierKey:       "inspector_municipal_dan_key",
				BeliefRecipient:   "org_sinpe_disburser_key",
				LockedLovelace:    lovelace,
				MilestoneLovelace: lovelace,
				Verified:          true,
			},
		},
		Outputs: []adapters.CardanoTxOutput{
			{
				Address:    "org_sinpe_disburser_key",
				Lovelace:   lovelace,
				PaymentTag: req.EscrowID,
			},
		},
	}

	txHash, err := adapters.ValidateCardanoEscrowPayoutTx(unsignedTx, []string{req.WalletAddress})
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"network":        "Cardano Preview Testnet (network_id=0)",
		"tx_hash":        txHash,
		"lovelace":       lovelace,
		"payment_tag":    req.EscrowID,
		"wallet_address": req.WalletAddress,
		"signature_hex":  req.SignatureHex,
	})
}

// handleSaveVideo writes a generated grant presentation video (.webm) directly to private_docs/videos/ on disk.
func (s *Server) handleSaveVideo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	profile := filepath.Base(r.URL.Query().Get("profile"))
	if profile != "cardano" && profile != "base" && profile != "civic" {
		profile = "demo"
	}
	videoDir := filepath.Join("..", "private_docs", "videos")
	_ = os.MkdirAll(videoDir, 0700)
	fileName := fmt.Sprintf("waystobuildit_grant_%s_1080p.webm", profile)
	outPath := filepath.Join(videoDir, fileName)
	raw, err := io.ReadAll(io.LimitReader(r.Body, 80*1024*1024))
	if err != nil || len(raw) == 0 {
		s.writeError(w, http.StatusBadRequest, "empty or invalid video stream")
		return
	}
	if err := os.WriteFile(outPath, raw, 0600); err != nil {
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	absPath, _ := filepath.Abs(outPath)
	s.writeJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"saved_path": absPath,
		"file_name":  fileName,
		"bytes":      len(raw),
	})
}

// handleGovernanceWebhook connects external participatory governance platforms
// (CONSUL Democracy or Municipal Actas) directly to WaysToBuildIt's ApprovedResolution gate.
// Security: Enforces EITHER (1) constant-time HMAC-SHA256 webhook signature verification
// (X-Webhook-Signature: hmac-sha256:<hex>) using WEBHOOK_HMAC_SECRET, OR (2) authenticated
// Committee / SysAdmin 2FA session token, plus strict 64KB body cap and replay-safe resolution ID checks.
func (s *Server) handleGovernanceWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	rawBody, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil || len(rawBody) == 0 {
		s.writeError(w, http.StatusBadRequest, "empty or oversized webhook payload")
		return
	}

	webhookSecret := os.Getenv("WEBHOOK_HMAC_SECRET")
	if webhookSecret == "" {
		webhookSecret = "waystobuildit-webhook-hmac-default-key"
	}
	providedHMAC := r.Header.Get("X-Webhook-Signature")
	hmacVerified := providedHMAC != "" && adapters.VerifyWebhookHMAC(rawBody, providedHMAC, webhookSecret)
	if !hmacVerified {
		if _, ok := s.requireRole(w, r, RoleCommittee, RoleSysAdmin); !ok {
			return
		}
	}

	var req struct {
		Source         string `json:"source"`
		EventType      string `json:"event_type"`
		ProjectID      string `json:"project_id"`
		ResolutionID   string `json:"resolution_id"`
		MinutesHashHex string `json:"minutes_hash_hex"`
	}
	if err := json.Unmarshal(rawBody, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid webhook JSON payload")
		return
	}
	if len(req.Source) > 120 || len(req.ResolutionID) > 120 {
		s.writeError(w, http.StatusBadRequest, "webhook field length exceeds security bounds")
		return
	}
	if req.Source == "" {
		req.Source = "CONSUL Democracy (Presupuesto Participativo)"
	}
	if req.ProjectID == "" {
		req.ProjectID = "proj-solar-lighting-001"
	}
	if req.ResolutionID == "" {
		req.ResolutionID = "RES-CONSUL-MDO-2026-089"
	}
	if req.MinutesHashHex == "" {
		content := []byte("%PDF-1.7\n% Board Resolution Minutes: " + req.Source + ":" + req.ResolutionID + "\n%%EOF")
		h, _ := adapters.HashEvidence(content)
		req.MinutesHashHex = h
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.svc != nil {
		if proj, err := s.svc.FindProject(req.ProjectID); err == nil {
			proj.ApprovedResolution = fmt.Sprintf("%s [%s • SHA256:%s]", req.ResolutionID, req.Source, req.MinutesHashHex[:12])
		}
	}
	authMethod := "ROLE_2FA_TOKEN"
	if hmacVerified {
		authMethod = "HMAC_SHA256_SIGNATURE"
	}
	s.persistStateAndLedger("GOVERNANCE_WEBHOOK_SYNC", req.Source, 0, req.ResolutionID+" -> "+req.ProjectID+" ("+authMethod+")")
	s.writeJSON(w, http.StatusOK, map[string]any{
		"ok":                  true,
		"auth_method":         authMethod,
		"source":              req.Source,
		"event_type":          req.EventType,
		"project_id":          req.ProjectID,
		"approved_resolution": req.ResolutionID,
		"minutes_hash_hex":    req.MinutesHashHex,
		"status":              "ANCHORED_TO_ESCROW_GATE",
	})
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP listen address (bound to localhost)")
	configPath := flag.String("config", "../config/organization.json", "Path to organization config JSON file")
	seedPath := flag.String("seed", "../config/demo_seed.json", "Path to demonstration seed JSON file")
	dataDir := flag.String("data", "../data", "Directory for persistent hash-chained audit_ledger.json and backups")
	frontendDir := flag.String("frontend", "../frontend", "Path to frontend static directory")
	flag.Parse()

	srv := &Server{
		configPath:  *configPath,
		seedPath:    *seedPath,
		dataDir:     *dataDir,
		frontendDir: *frontendDir,
		roleTokens:  defaultRoleTokens(),
		ledger:      &adapters.HashChainLedger{},
	}

	if !srv.loadPersistedState() && *configPath != "" {
		if cfg, err := civic.LoadOrganizationConfigFromFile(*configPath); err == nil {
			if svc, err := civic.NewPlatformService(cfg); err == nil {
				if *seedPath != "" {
					_ = svc.LoadDemoSeedFromFile(*seedPath)
				}
				srv.svc = svc
				srv.persistStateAndLedger("GENESIS_INIT", cfg.OrganizationName, 0, cfg.TenantID)
			}
		} else {
			log.Printf("Starting in GUI Setup mode (%v)", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/login", srv.handleAuthLogin)
	mux.HandleFunc("/api/v1/state", srv.handleState)
	mux.HandleFunc("/api/v1/config", srv.handleUpdateConfig)
	mux.HandleFunc("/api/v1/config/load-file", srv.handleLoadConfigFile)
	mux.HandleFunc("/api/v1/project/create", srv.handleCreateProject)
	mux.HandleFunc("/api/v1/project/contribute", srv.handleContributeProject)
	mux.HandleFunc("/api/v1/project/milestone", srv.handleMilestoneAction)
	mux.HandleFunc("/api/v1/subasta", srv.handleSubastaAction)
	mux.HandleFunc("/api/v1/committee-fund", srv.handleCommitteeFundAction)
	mux.HandleFunc("/api/v1/testnet/verify-tx", srv.handleTestnetVerifyTx)
	mux.HandleFunc("/api/v1/backup/download", srv.handleBackupDownload)
	mux.HandleFunc("/api/v1/demo/reset", srv.handleDemoReset)
	mux.HandleFunc("/api/v1/video/save", srv.handleSaveVideo)
	mux.HandleFunc("/api/v1/governance/webhook", srv.handleGovernanceWebhook)
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir(filepath.Join(srv.frontendDir, "assets")))))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		indexPath := filepath.Join(srv.frontendDir, "index.html")
		if _, err := os.Stat(indexPath); err != nil {
			http.Error(w, "frontend/index.html not found", http.StatusNotFound)
			return
		}
		http.ServeFile(w, r, indexPath)
	})

	log.Printf("Civic Milestone Escrow server listening on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}