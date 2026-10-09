package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/domain"
	experimentalapp "github.com/aatuh/evydence/internal/experimental/app"
	experimentaldomain "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SaaSProfileCommands interface {
	AuthorizeCreateSaaSProfile(context.Context, identitydomain.Actor, experimentalapp.SaaSProfileInput) error
	CreateSaaSProfile(context.Context, identitydomain.Actor, experimentalapp.SaaSProfileInput) (experimentaldomain.SaaSEditionProfile, error)
}

func decodeSaaSProfileRequest(body []byte) (experimentalapp.SaaSProfileInput, error) {
	var req struct {
		Name           string `json:"name"`
		Region         string `json:"region"`
		AdminTenantID  string `json:"admin_tenant_id"`
		IsolationModel string `json:"isolation_model"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return experimentalapp.SaaSProfileInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "name", "region", "admin_tenant_id", "isolation_model"); err != nil {
		return experimentalapp.SaaSProfileInput{}, err
	}
	in := experimentalapp.SaaSProfileInput{Name: req.Name, Region: req.Region, AdminTenantID: req.AdminTenantID, IsolationModel: req.IsolationModel}
	_, err := experimentalapp.NormalizeSaaSProfileInput(in)
	// Keep raw field values for the existing configuration-hash commitment.
	return in, mapAnomalyReportError(err)
}
func (s *Server) createDurableSaaSProfile(w http.ResponseWriter, r *http.Request) {
	var in experimentalapp.SaaSProfileInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeSaaSProfileRequest(body)
		if err != nil {
			return err
		}
		return mapAnomalyReportError(s.saasProfileCommands.AuthorizeCreateSaaSProfile(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.saasProfileCommands.CreateSaaSProfile(ctx, a, in)
		if err != nil {
			return 0, nil, mapAnomalyReportError(err)
		}
		raw, err := experimentalapp.EncodeSaaSProfile(v)
		return http.StatusCreated, json.RawMessage(raw), err
	})
}
