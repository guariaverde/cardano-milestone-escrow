package civic

import (
	"encoding/json"
	"os"

	"example.com/milestone-escrow/backend/escrow"
)

type demoSeedFile struct {
	Projects []struct {
		ID                    string           `json:"id"`
		TitleES               string           `json:"title_es"`
		TitleEN               string           `json:"title_en"`
		LocationES            string           `json:"location_es"`
		LocationEN            string           `json:"location_en"`
		ContractorDisplayName string           `json:"contractor_display_name"`
		ContractorKey         string           `json:"contractor_key"`
		InspectorDisplayName  string           `json:"inspector_display_name"`
		VerifierKey           string           `json:"verifier_key"`
		ArbiterKey            string           `json:"arbiter_key"`
		ApprovedResolution    string           `json:"approved_resolution"`
		Milestones            []struct {
			Amount        uint64 `json:"amount"`
			TitleES       string `json:"title_es"`
			TitleEN       string `json:"title_en"`
			DescriptionES string `json:"description_es"`
			DescriptionEN string `json:"description_en"`
		} `json:"milestones"`
		InKindContributions []InKindResource `json:"in_kind_contributions"`
	} `json:"projects"`
	Subastas []struct {
		ID             string          `json:"id"`
		TitleES        string          `json:"title_es"`
		TitleEN        string          `json:"title_en"`
		DescriptionES  string          `json:"description_es"`
		DescriptionEN  string          `json:"description_en"`
		ItemDonor      string          `json:"item_donor"`
		Mode           escrow.SaleMode `json:"mode"`
		MinimumPrice   uint64          `json:"minimum_price"`
		InspectionHash string          `json:"inspection_hash"`
	} `json:"subastas"`
}

// LoadDemoSeedFromFile populates projects and subastas from an external JSON seed file
// (e.g. config/demo_seed.json) so zero demonstration strings are hardcoded in Go source.
func (s *PlatformService) LoadDemoSeedFromFile(path string) error {
	if err := s.Config.Validate(); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var seed demoSeedFile
	if err := json.Unmarshal(raw, &seed); err != nil {
		return err
	}

	s.Projects = nil
	for _, p := range seed.Projects {
		var milestones []escrow.Milestone
		var metas []MilestoneMeta
		for _, m := range p.Milestones {
			milestones = append(milestones, escrow.Milestone{Amount: m.Amount})
			metas = append(metas, MilestoneMeta{
				TitleES:       m.TitleES,
				TitleEN:       m.TitleEN,
				DescriptionES: m.DescriptionES,
				DescriptionEN: m.DescriptionEN,
			})
		}
		esc := &escrow.Escrow{
			Client:      s.Config.CommitteeAccount,
			Contractor:  p.ContractorKey,
			Verifier:    p.VerifierKey,
			Arbiter:     p.ArbiterKey,
			Beneficiary: s.Bridge.DisburserAccount,
			Status:      escrow.Created,
			Milestones:  milestones,
		}
		s.Projects = append(s.Projects, &CivicProject{
			ID:                    p.ID,
			TitleES:               p.TitleES,
			TitleEN:               p.TitleEN,
			LocationES:            p.LocationES,
			LocationEN:            p.LocationEN,
			ContractorDisplayName: p.ContractorDisplayName,
			InspectorDisplayName:  p.InspectorDisplayName,
			ApprovedResolution:    p.ApprovedResolution,
			MilestoneMetadata:     metas,
			InKindContributions:   p.InKindContributions,
			Escrow:                esc,
		})
	}

	s.Subastas = nil
	for _, sub := range seed.Subastas {
		s.Subastas = append(s.Subastas, &CivicSubasta{
			TitleES:        sub.TitleES,
			TitleEN:        sub.TitleEN,
			DescriptionES:  sub.DescriptionES,
			DescriptionEN:  sub.DescriptionEN,
			InspectionHash: sub.InspectionHash,
			Listing: &escrow.SubastaListing{
				ID:              sub.ID,
				ItemDonor:       sub.ItemDonor,
				Organization:    s.Config.CommitteeAccount,
				CommitteeFundID: s.CommitteeFund.ID,
				Mode:            sub.Mode,
				MinimumPrice:    sub.MinimumPrice,
			},
		})
	}
	return nil
}
