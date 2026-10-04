package httpapi

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type PublicTransparencyMetadataCommands interface {
	AuthorizeCreatePublicTransparencyLog(context.Context, identitydomain.Actor, e.PublicTransparencyLogInput) error
	CreatePublicTransparencyLog(context.Context, identitydomain.Actor, e.PublicTransparencyLogInput) (d.PublicTransparencyLog, error)
	AuthorizePublishPublicTransparencyLogEntry(context.Context, identitydomain.Actor, e.PublicTransparencyPublicationInput) error
	PublishPublicTransparencyLogEntry(context.Context, identitydomain.Actor, e.PublicTransparencyPublicationInput) (d.PublicTransparencyLogEntry, error)
}

func decodePublicTransparencyLog(body []byte) (e.PublicTransparencyLogInput, error) {
	var v struct {
		Name      string `json:"name"`
		Endpoint  string `json:"endpoint"`
		PublicKey string `json:"public_key"`
	}
	if err := decodeMembershipJSON(body, &v); err != nil {
		return e.PublicTransparencyLogInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "name", "endpoint", "public_key"); err != nil {
		return e.PublicTransparencyLogInput{}, err
	}
	in, err := e.NormalizePublicTransparencyLogInput(e.PublicTransparencyLogInput{Name: v.Name, Endpoint: v.Endpoint, PublicKey: v.PublicKey})
	return in, mapAnomalyReportError(err)
}
func decodePublicTransparencyPublication(body []byte) (e.PublicTransparencyPublicationInput, error) {
	var v struct {
		LogID        string `json:"log_id"`
		CheckpointID string `json:"checkpoint_id"`
		ExternalID   string `json:"external_id"`
	}
	if err := decodeMembershipJSON(body, &v); err != nil {
		return e.PublicTransparencyPublicationInput{}, err
	}
	if err := validateExactNonNullableObjectFields(body, "log_id", "checkpoint_id", "external_id"); err != nil {
		return e.PublicTransparencyPublicationInput{}, err
	}
	in, err := e.NormalizePublicTransparencyPublicationInput(e.PublicTransparencyPublicationInput{LogID: v.LogID, CheckpointID: v.CheckpointID, ExternalID: v.ExternalID})
	return in, mapAnomalyReportError(err)
}
func legacyPublicTransparencyLogInput(v e.PublicTransparencyLogInput) app.CreatePublicTransparencyLogInput {
	return app.CreatePublicTransparencyLogInput{Name: v.Name, Endpoint: v.Endpoint, PublicKey: v.PublicKey}
}
func legacyPublicTransparencyPublicationInput(v e.PublicTransparencyPublicationInput) app.PublishPublicTransparencyLogEntryInput {
	return app.PublishPublicTransparencyLogEntryInput{LogID: v.LogID, CheckpointID: v.CheckpointID, ExternalID: v.ExternalID}
}
func (s *Server) createDurablePublicTransparencyLog(w http.ResponseWriter, r *http.Request) {
	var in e.PublicTransparencyLogInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodePublicTransparencyLog(body)
		if err != nil {
			return err
		}
		return mapAnomalyReportError(s.publicTransparencyMetadata.AuthorizeCreatePublicTransparencyLog(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.publicTransparencyMetadata.CreatePublicTransparencyLog(ctx, a, in)
		if err != nil {
			return 0, nil, mapAnomalyReportError(err)
		}
		raw, err := e.EncodePublicTransparencyLog(v)
		return http.StatusCreated, json.RawMessage(raw), err
	})
}
func (s *Server) publishDurablePublicTransparencyLogEntry(w http.ResponseWriter, r *http.Request) {
	var in e.PublicTransparencyPublicationInput
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		var err error
		in, err = decodePublicTransparencyPublication(body)
		if err != nil {
			return err
		}
		return mapAnomalyReportError(s.publicTransparencyMetadata.AuthorizePublishPublicTransparencyLogEntry(ctx, a, in))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.publicTransparencyMetadata.PublishPublicTransparencyLogEntry(ctx, a, in)
		if err != nil {
			return 0, nil, mapAnomalyReportError(err)
		}
		raw, err := e.EncodePublicTransparencyPublication(v)
		return http.StatusCreated, json.RawMessage(raw), err
	})
}
