package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type AnomalyReportCommands interface {
	AuthorizeGenerateAnomalyReport(context.Context, identitydomain.Actor, experimentalapp.AnomalyReportInput) error
	GenerateAnomalyReport(context.Context, identitydomain.Actor, experimentalapp.AnomalyReportInput) (experimentaldomain.AnomalyReport, error)
}

func mapAnomalyReportError(err error) error {
	switch {
	case errors.Is(err, experimentalapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, experimentalapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, experimentalapp.ErrConflict):
		return app.ErrConflict
	default:
		return mapCustomerPackageAccessError(err)
	}
}
func decodeAnomalyReportRequest(body []byte) (experimentalapp.AnomalyReportInput, error) {
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return experimentalapp.AnomalyReportInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "subject_type", "subject_id"); err != nil {
		return experimentalapp.AnomalyReportInput{}, err
	}
	v, err := experimentalapp.NormalizeAnomalyInput(experimentalapp.AnomalyReportInput{SubjectType: req.SubjectType, SubjectID: req.SubjectID})
	return v, mapAnomalyReportError(err)
}
func (s *Server) generateDurableAnomalyReport(w http.ResponseWriter, r *http.Request) {
	var in experimentalapp.AnomalyReportInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeAnomalyReportRequest(body)
		if err != nil {
			return err
		}
		return mapAnomalyReportError(s.anomalyReportCommands.AuthorizeGenerateAnomalyReport(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.anomalyReportCommands.GenerateAnomalyReport(ctx, a, in)
		if err != nil {
			return 0, nil, mapAnomalyReportError(err)
		}
		raw, err := experimentalapp.EncodeAnomalyReport(v)
		return http.StatusCreated, json.RawMessage(raw), err
	})
}
