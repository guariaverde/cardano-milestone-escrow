package civic

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"

	"example.com/milestone-escrow/backend/adapters"
	"example.com/milestone-escrow/backend/escrow"
)

// OrganizationConfig holds the dynamic, non-hardcoded identity of the host organization.
// Must be provided via a JSON configuration file (e.g. config/organization.json) or filled out in the GUI.
type OrganizationConfig struct {
	TenantID              string   `json:"tenant_id"`
	OrganizationName      string   `json:"organization_name"`
	JurisdictionLabel     string   `json:"jurisdiction_label"`
	DefaultLocale         string   `json:"default_locale"`
	AllowedCurrencies     []string `json:"allowed_currencies"`
	ExchangeRateCRCPerUSD uint64   `json:"exchange_rate_crc_per_usd"`
	ExchangeRateSource    string   `json:"exchange_rate_source"`
	ExchangeRateUpdatedAt string   `json:"exchange_rate_updated_at"`
	CommitteeAccount      string   `json:"committee_account"`
	DisburserAccount      string   `json:"disburser_account"`
	BackupTargetDir       string   `json:"backup_target_dir"` // e.g., Synology NAS SMB path (\\SYNOLOGY\backups\waystobuildit)
	HostingFeeBps         uint64   `json:"hosting_fee_bps"`
	HostingPeriodCap      uint64   `json:"hosting_period_cap"`
	ChainDisplayMode      string   `json:"chain_display_mode"` // "cardano" (Cardano Native), "base" (Base L2 Native), or "civic" (Zero Crypto Branding)
}

// FX Circuit-Breaker Constants: Prevents oracle manipulation, flash-crash exploits, or admin tampering
// of the CRC/USD exchange rate.
const (
	MinSanityCRCPerUSD uint64 = 400 // Hard floor (rejects manipulated low rates like 1 or 50 CRC/USD)
	MaxSanityCRCPerUSD uint64 = 700 // Hard ceiling (rejects manipulated high rates like 5000 CRC/USD)
	MaxFXStepChangeBps uint64 = 300 // Max 3.00% (300 bps) deviation allowed in a single update
)

// ValidateExchangeRate checks that an exchange rate lies within the BCCR sanity corridor
// and, if updating from an existing rate, does not jump by more than 3% (300 bps) at once.
func ValidateExchangeRate(oldRate uint64, newRate uint64) error {
	if newRate < MinSanityCRCPerUSD || newRate > MaxSanityCRCPerUSD {
		return errors.New("exchange rate rejected by circuit breaker: outside BCCR sanity corridor (400-700 CRC/USD)")
	}
	if oldRate >= MinSanityCRCPerUSD && oldRate <= MaxSanityCRCPerUSD {
		var diff uint64
		if newRate > oldRate {
			diff = newRate - oldRate
		} else {
			diff = oldRate - newRate
		}
		maxAllowedDiff := (oldRate * MaxFXStepChangeBps) / 10000
		if diff > maxAllowedDiff {
			return errors.New("exchange rate rejected by circuit breaker: single update exceeds 3% maximum deviation")
		}
	}
	return nil
}

// Validate checks that required organization identity fields and FX circuit-breaker bounds are valid.
func (c OrganizationConfig) Validate() error {
	if strings.TrimSpace(c.OrganizationName) == "" ||
		strings.TrimSpace(c.TenantID) == "" ||
		strings.TrimSpace(c.CommitteeAccount) == "" {
		return errors.New("organization configuration is missing required fields (organization_name, tenant_id, committee_account): please provide a config file (e.g. config/organization.json) or complete the Organization Setup in the GUI")
	}
	if c.ExchangeRateCRCPerUSD != 0 {
		if err := ValidateExchangeRate(0, c.ExchangeRateCRCPerUSD); err != nil {
			return err
		}
	}
	return nil
}

// LoadOrganizationConfigFromFile loads and validates OrganizationConfig from a JSON file path.
func LoadOrganizationConfigFromFile(path string) (OrganizationConfig, error) {
	if strings.TrimSpace(path) == "" {
		return OrganizationConfig{}, errors.New("config file path is empty: please provide a config file or configure the organization via the GUI")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return OrganizationConfig{}, errors.New("failed to read organization config file (" + path + "): provide a valid config file or complete setup in the GUI")
	}
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	var cfg OrganizationConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return OrganizationConfig{}, errors.New("invalid JSON in organization config file: " + err.Error())
	}
	if err := cfg.Validate(); err != nil {
		return OrganizationConfig{}, err
	}
	return cfg, nil
}

type InKindResource struct {
	ContributorAlias string `json:"contributor_alias"`
	DescriptionES    string `json:"description_es"`
	DescriptionEN    string `json:"description_en"`
	Quantity         uint64 `json:"quantity"`
	Unit             string `json:"unit"`
	VerifiedBy       string `json:"verified_by"`
	EvidenceHash     string `json:"evidence_hash"`
}

type MilestoneMeta struct {
	TitleES       string `json:"title_es"`
	TitleEN       string `json:"title_en"`
	DescriptionES string `json:"description_es"`
	DescriptionEN string `json:"description_en"`
}

// CivicProject wraps a generic on-chain *escrow.Escrow with bilingual civic metadata,
// an explicit administrative approval gate, and in-kind resource tracking.
type CivicProject struct {
	ID                    string           `json:"id"`
	TitleES               string           `json:"title_es"`
	TitleEN               string           `json:"title_en"`
	LocationES            string           `json:"location_es"`
	LocationEN            string           `json:"location_en"`
	ContractorDisplayName string           `json:"contractor_display_name"`
	InspectorDisplayName  string           `json:"inspector_display_name"`
	ApprovedResolution    string           `json:"approved_resolution"` // Mandatory gate before accepting contributions
	MilestoneMetadata     []MilestoneMeta  `json:"milestone_metadata"`
	InKindContributions   []InKindResource `json:"in_kind_contributions"`
	Escrow                *escrow.Escrow   `json:"escrow"`
}

type CivicSubasta struct {
	TitleES        string                 `json:"title_es"`
	TitleEN        string                 `json:"title_en"`
	DescriptionES  string                 `json:"description_es"`
	DescriptionEN  string                 `json:"description_en"`
	InspectionHash string                 `json:"inspection_hash"`
	Listing        *escrow.SubastaListing `json:"listing"`
}

// PlatformService is our decoupled, plugin-ready core service managing the 3 funding avenues,
// dynamic organization branding, in-kind resources, and global public audit summaries.
type PlatformService struct {
	Config        OrganizationConfig          `json:"config"`
	CommitteeFund *escrow.CommitteeFund       `json:"committee_fund"`
	Bridge        *adapters.FiatBridgeAdapter `json:"bridge"`
	Projects      []*CivicProject             `json:"projects"`
	Subastas      []*CivicSubasta             `json:"subastas"`
}

// NewPlatformService initializes the platform from an explicit OrganizationConfig.
// Returns an error if the config is empty/incomplete, prompting the user to supply a config file or use the GUI setup.
func NewPlatformService(cfg OrganizationConfig) (*PlatformService, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.DefaultLocale == "" {
		cfg.DefaultLocale = "es-CR"
	}
	if len(cfg.AllowedCurrencies) == 0 {
		cfg.AllowedCurrencies = []string{"CRC", "USD"}
	}
	if cfg.ExchangeRateCRCPerUSD == 0 {
		cfg.ExchangeRateCRCPerUSD = 512
	}
	if cfg.ExchangeRateSource == "" {
		cfg.ExchangeRateSource = "Banco Central de Costa Rica (BCCR — Referencia MONEX)"
	}
	if cfg.DisburserAccount == "" {
		cfg.DisburserAccount = "org_sinpe_disburser_key"
	}
	if cfg.ChainDisplayMode == "" {
		cfg.ChainDisplayMode = "cardano"
	}

	fund := &escrow.CommitteeFund{
		ID:        "committee_public_fund",
		Committee: cfg.CommitteeAccount,
	}
	bridge := &adapters.FiatBridgeAdapter{
		DisburserAccount: cfg.DisburserAccount,
		HostingFeeBps:    cfg.HostingFeeBps,
		HostingPeriodCap: cfg.HostingPeriodCap,
	}

	return &PlatformService{
		Config:        cfg,
		CommitteeFund: fund,
		Bridge:        bridge,
		Projects:      []*CivicProject{},
		Subastas:      []*CivicSubasta{},
	}, nil
}

// UpdateConfigFromGUI allows an operator to set or update the organization's identity
// directly from the Web GUI setup form while enforcing the FX circuit-breaker against rate tampering.
func (s *PlatformService) UpdateConfigFromGUI(newCfg OrganizationConfig) error {
	if newCfg.ExchangeRateCRCPerUSD == 0 {
		newCfg.ExchangeRateCRCPerUSD = s.Config.ExchangeRateCRCPerUSD
	}
	if newCfg.ChainDisplayMode == "" {
		newCfg.ChainDisplayMode = s.Config.ChainDisplayMode
	}
	if err := newCfg.Validate(); err != nil {
		return err
	}
	if err := ValidateExchangeRate(s.Config.ExchangeRateCRCPerUSD, newCfg.ExchangeRateCRCPerUSD); err != nil {
		return err
	}
	s.Config = newCfg
	s.CommitteeFund.Committee = newCfg.CommitteeAccount
	if newCfg.DisburserAccount != "" {
		s.Bridge.DisburserAccount = newCfg.DisburserAccount
	}
	return nil
}

// ForceUpdateExchangeRate allows the Committee + Independent Arbiter to co-sign a larger (>3%)
// exchange-rate adjustment if the market moved significantly over time or between infrequent syncs.
func (s *PlatformService) ForceUpdateExchangeRate(newRate uint64, source string, updatedAt string, committeeSigner string, arbiterSigner string) error {
	if committeeSigner == "" || arbiterSigner == "" || committeeSigner != s.Config.CommitteeAccount || committeeSigner == arbiterSigner {
		return errors.New("large exchange rate override requires both Committee and independent Arbiter co-signatures")
	}
	if newRate == 0 || source == "" {
		return errors.New("invalid exchange rate or source")
	}
	s.Config.ExchangeRateCRCPerUSD = newRate
	s.Config.ExchangeRateSource = source
	s.Config.ExchangeRateUpdatedAt = updatedAt
	return nil
}

// PublicAlias redacts any empty or private donor string to "Anónimo" for public transparency endpoints.
func PublicAlias(alias string, remainAnonymous bool) string {
	if remainAnonymous || alias == "" {
		return "Anónimo"
	}
	return alias
}

// ContributeViaBridge enforces the Administrative Approval Gate (ApprovedResolution != "")
// before allowing any citizen or business deposit to enter the project's escrow via the Fiat Bridge.
func (s *PlatformService) ContributeViaBridge(projectID string, dep adapters.FiatDeposit, anonymous bool) (*adapters.DepositAuditRecord, error) {
	proj, err := s.FindProject(projectID)
	if err != nil {
		return nil, err
	}
	if proj.ApprovedResolution == "" {
		return nil, errors.New("project lacks formal administrative approval resolution")
	}
	dep.Donor = PublicAlias(dep.Donor, anonymous)
	return s.Bridge.DepositFiatToProject(dep, proj.Escrow)
}

// AddInKindResource records a verified non-cash material or labor contribution (e.g., donated poles
// or engineering hours) anchored by an inspection evidence hash.
func (s *PlatformService) AddInKindResource(projectID string, res InKindResource, anonymous bool) error {
	proj, err := s.FindProject(projectID)
	if err != nil {
		return err
	}
	if proj.ApprovedResolution == "" || res.Quantity == 0 || res.Unit == "" || res.EvidenceHash == "" || res.VerifiedBy == "" {
		return errors.New("invalid or unverified in-kind resource contribution")
	}
	res.ContributorAlias = PublicAlias(res.ContributorAlias, anonymous)
	proj.InKindContributions = append(proj.InKindContributions, res)
	return nil
}

func (s *PlatformService) FindProject(projectID string) (*CivicProject, error) {
	for _, p := range s.Projects {
		if p.ID == projectID {
			return p, nil
		}
	}
	return nil, errors.New("project not found")
}
