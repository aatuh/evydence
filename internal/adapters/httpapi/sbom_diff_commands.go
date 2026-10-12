package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SBOMDiffCommands interface {
	AuthorizeCreateSBOMDiff(context.Context, identitydomain.Actor, evidenceapp.CreateSBOMDiffInput) error
	CreateSBOMDiff(context.Context, identitydomain.Actor, evidenceapp.CreateSBOMDiffInput) (evidencedomain.SBOMDiff, error)
}

func (s *Server) createDurableSBOMDiff(w http.ResponseWriter, r *http.Request) {
	var in evidenceapp.CreateSBOMDiffInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			BaseSBOMID   string `json:"base_sbom_id"`
			TargetSBOMID string `json:"target_sbom_id"`
			ReleaseID    string `json:"release_id"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "base_sbom_id", "target_sbom_id", "release_id"); err != nil {
			return err
		}
		in = evidenceapp.CreateSBOMDiffInput{BaseSBOMID: req.BaseSBOMID, TargetSBOMID: req.TargetSBOMID, ReleaseID: req.ReleaseID}
		return mapEvidenceCreationCommandError(s.sbomDiffCommands.AuthorizeCreateSBOMDiff(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.sbomDiffCommands.CreateSBOMDiff(ctx, a, in)
		return http.StatusCreated, domain.SBOMDiffFromContext(v), mapEvidenceCreationCommandError(err)
	})
}
