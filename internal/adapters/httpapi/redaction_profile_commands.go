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

type RedactionProfileCommands interface {
	AuthorizeCreateRedactionProfile(context.Context, identitydomain.Actor, packageapp.CreateRedactionProfileInput) error
	CreateRedactionProfile(context.Context, identitydomain.Actor, packageapp.CreateRedactionProfileInput) (packagedomain.RedactionProfile, error)
}

func decodeRedactionProfileRequest(body []byte) (packageapp.CreateRedactionProfileInput, error) {
	var req struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		Preset         string   `json:"preset"`
		AllowedTypes   []string `json:"allowed_types"`
		ExcludedFields []string `json:"excluded_fields"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return packageapp.CreateRedactionProfileInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "name", "description", "preset", "allowed_types", "excluded_fields"); err != nil {
		return packageapp.CreateRedactionProfileInput{}, err
	}
	for _, name := range []string{"allowed_types", "excluded_fields"} {
		if err := validateNonNullableArrayItems(body, name); err != nil {
			return packageapp.CreateRedactionProfileInput{}, err
		}
	}
	in, err := packageapp.NormalizeRedactionProfileInput(packageapp.CreateRedactionProfileInput{Name: req.Name, Description: req.Description, Preset: req.Preset, AllowedTypes: req.AllowedTypes, ExcludedFields: req.ExcludedFields})
	return in, mapCustomerPackageAccessError(err)
}

func (s *Server) createDurableRedactionProfile(w http.ResponseWriter, r *http.Request) {
	var in packageapp.CreateRedactionProfileInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeRedactionProfileRequest(body)
		if err != nil {
			return err
		}
		return mapCustomerPackageAccessError(s.redactionProfileCommands.AuthorizeCreateRedactionProfile(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.redactionProfileCommands.CreateRedactionProfile(ctx, a, in)
		if err != nil {
			return 0, nil, mapCustomerPackageAccessError(err)
		}
		encoded, err := packageapp.EncodeRedactionProfile(v)
		return http.StatusCreated, json.RawMessage(encoded), err
	})
}
