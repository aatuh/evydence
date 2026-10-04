package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	e "github.com/aatuh/evydence/internal/experimental/app"
	d "github.com/aatuh/evydence/internal/experimental/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
)

type PublicTransparencyFetchCommands interface {
	AuthorizeFetchPublicTransparencyLogEntryProof(context.Context, identitydomain.Actor, string) error
	FetchAndVerifyPublicTransparencyLogEntry(context.Context, identitydomain.Actor, string) (d.PublicTransparencyLogEntry, error)
}

func decodePublicTransparencyFetch(body []byte, id string) error {
	if _, err := e.NormalizePublicTransparencyFetchID(id); err != nil {
		return app.ErrValidation
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var v struct{}
	if err := decodeMembershipJSON(body, &v); err != nil {
		return err
	}
	return validateExactNonNullableObjectFields(body)
}
func (s *Server) fetchDurablePublicTransparencyLogEntryProof(w http.ResponseWriter, r *http.Request) {
	s.createDurable(w, r, func(ctx context.Context, a domain.Actor, body []byte) error {
		if err := decodePublicTransparencyFetch(body, r.PathValue("id")); err != nil {
			return err
		}
		return mapAnomalyReportError(s.publicTransparencyFetch.AuthorizeFetchPublicTransparencyLogEntryProof(ctx, a, r.PathValue("id")))
	}, func(ctx context.Context, a domain.Actor, _ []byte) (int, any, error) {
		v, err := s.publicTransparencyFetch.FetchAndVerifyPublicTransparencyLogEntry(ctx, a, r.PathValue("id"))
		if err != nil {
			return 0, nil, mapAnomalyReportError(err)
		}
		raw, err := e.EncodePublicTransparencyVerification(v)
		return http.StatusOK, json.RawMessage(raw), err
	})
}
