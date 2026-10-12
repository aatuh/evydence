package httpapi

import (
	"context"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type ContractDiffCommands interface {
	AuthorizeCreateContractDiff(context.Context, identitydomain.Actor, evidenceapp.CreateContractDiffInput) error
	CreateContractDiff(context.Context, identitydomain.Actor, evidenceapp.CreateContractDiffInput) (evidencedomain.ContractDiff, error)
}

func (s *Server) createDurableContractDiff(w http.ResponseWriter, r *http.Request) {
	var in evidenceapp.CreateContractDiffInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var req struct {
			BaseContractID   string `json:"base_contract_id"`
			TargetContractID string `json:"target_contract_id"`
			ReleaseID        string `json:"release_id"`
		}
		if err := decodeJSON(body, &req); err != nil {
			return err
		}
		if err := validateNonNullableObjectFields(body, "base_contract_id", "target_contract_id", "release_id"); err != nil {
			return err
		}
		in = evidenceapp.CreateContractDiffInput{BaseContractID: req.BaseContractID, TargetContractID: req.TargetContractID, ReleaseID: req.ReleaseID}
		return mapEvidenceCreationCommandError(s.contractDiffCommands.AuthorizeCreateContractDiff(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.contractDiffCommands.CreateContractDiff(ctx, a, in)
		return http.StatusCreated, domain.ContractDiffFromContext(v), mapEvidenceCreationCommandError(err)
	})
}
