package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/aatuh/evydence/internal/domain"
	identityapp "github.com/aatuh/evydence/internal/identity/app"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type SAMLProviderBindingCommands interface {
	AuthorizeConfigureSAMLProviderBinding(context.Context, identitydomain.Actor, string, identityapp.ConfigureSAMLProviderBindingInput) error
	ConfigureSAMLProviderBinding(context.Context, identitydomain.Actor, string, identityapp.ConfigureSAMLProviderBindingInput) (identitydomain.SAMLProviderBinding, error)
	GetSAMLProviderBinding(context.Context, identitydomain.Actor, string) (identitydomain.SAMLProviderBinding, error)
}
type samlProviderBindingMetadata struct {
	TenantID      string    `json:"tenant_id"`
	ProviderID    string    `json:"provider_id"`
	Recipient     string    `json:"recipient"`
	NameIDFormat  string    `json:"name_id_format"`
	SchemaVersion string    `json:"schema_version"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func samlBindingMetadata(b identitydomain.SAMLProviderBinding) samlProviderBindingMetadata {
	return samlProviderBindingMetadata{TenantID: b.TenantID, ProviderID: b.ProviderID, Recipient: b.Recipient, NameIDFormat: b.NameIDFormat, SchemaVersion: b.SchemaVersion, UpdatedAt: b.UpdatedAt}
}
func decodeSAMLBindingRequest(body []byte) (identityapp.ConfigureSAMLProviderBindingInput, error) {
	var req struct {
		Recipient    string  `json:"recipient"`
		NameIDFormat *string `json:"name_id_format"`
	}
	if err := decodeMembershipJSON(body, &req); err != nil {
		return identityapp.ConfigureSAMLProviderBindingInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "recipient", "name_id_format"); err != nil {
		return identityapp.ConfigureSAMLProviderBindingInput{}, err
	}
	format := ""
	if req.NameIDFormat != nil {
		format = *req.NameIDFormat
		if _, valid := identitydomain.NormalizeSAMLNameIDFormat(format); !valid || format == "" {
			return identityapp.ConfigureSAMLProviderBindingInput{}, mapIdentityCommandError(identityapp.ErrValidation)
		}
	}
	return identityapp.ConfigureSAMLProviderBindingInput{Recipient: req.Recipient, NameIDFormat: format}, nil
}
func (s *Server) configureSAMLProviderBinding(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in identityapp.ConfigureSAMLProviderBindingInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodeSAMLBindingRequest(body)
		if err != nil {
			return err
		}
		return mapIdentityCommandError(s.samlProviderBindingCommands.AuthorizeConfigureSAMLProviderBinding(ctx, a, id, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		b, err := s.samlProviderBindingCommands.ConfigureSAMLProviderBinding(ctx, a, id, in)
		return http.StatusOK, samlBindingMetadata(b), mapIdentityCommandError(err)
	})
}
func (s *Server) getSAMLProviderBinding(w http.ResponseWriter, r *http.Request) {
	a, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	b, err := s.samlProviderBindingCommands.GetSAMLProviderBinding(r.Context(), a, r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, mapIdentityCommandError(err))
		return
	}
	writeData(w, http.StatusOK, samlBindingMetadata(b))
}
