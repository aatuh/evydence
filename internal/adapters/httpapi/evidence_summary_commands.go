package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	packageapp "github.com/aatuh/evydence/internal/package/app"
	packagedomain "github.com/aatuh/evydence/internal/package/domain"
)

type EvidenceSummaryCommands interface {
	AuthorizeCreateEvidenceSummary(context.Context, identitydomain.Actor, packageapp.CreateEvidenceSummaryInput) error
	CreateEvidenceSummary(context.Context, identitydomain.Actor, packageapp.CreateEvidenceSummaryInput) (packagedomain.EvidenceSummary, error)
}

func decodeEvidenceSummaryRequest(body []byte) (packageapp.CreateEvidenceSummaryInput, error) {
	var req struct {
		SubjectType string   `json:"subject_type"`
		SubjectID   string   `json:"subject_id"`
		EvidenceIDs []string `json:"evidence_ids"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return packageapp.CreateEvidenceSummaryInput{}, err
	}
	if err := validateNonNullableObjectFields(body, "subject_type", "subject_id", "evidence_ids"); err != nil {
		return packageapp.CreateEvidenceSummaryInput{}, err
	}
	in, err := packageapp.NormalizeEvidenceSummaryInput(packageapp.CreateEvidenceSummaryInput{SubjectType: req.SubjectType, SubjectID: req.SubjectID, EvidenceIDs: req.EvidenceIDs})
	return in, mapCustomerPackageAccessError(err)
}

func (s *Server) createDurableEvidenceSummary(w http.ResponseWriter, r *http.Request) {
	var in packageapp.CreateEvidenceSummaryInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeEvidenceSummaryRequest(body)
		if err != nil {
			return err
		}
		return mapCustomerPackageAccessError(s.evidenceSummaryCommands.AuthorizeCreateEvidenceSummary(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.evidenceSummaryCommands.CreateEvidenceSummary(ctx, a, in)
		if err != nil {
			return 0, nil, mapCustomerPackageAccessError(err)
		}
		encoded, err := packageapp.EncodeEvidenceSummary(v)
		return http.StatusCreated, json.RawMessage(encoded), err
	})
}
