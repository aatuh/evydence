package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	releaseapp "github.com/aatuh/evydence/internal/release/app"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
)

// BuildAttestationCommands exposes ingestion only, without unrelated release
// commands or a transport dependency in the application service.
type BuildAttestationCommands interface {
	AuthorizeBuildAttestationCreation(context.Context, identitydomain.Actor, string) error
	UploadBuildAttestation(context.Context, identitydomain.Actor, string, []byte) (releasedomain.BuildAttestation, error)
}

func (s *Server) uploadBuildAttestation(w http.ResponseWriter, r *http.Request) {
	if err := validateSSOCookieMutation(r); err != nil {
		writeProblem(w, r, err)
		return
	}
	id, err := releaseapp.NormalizeBuildAttestationBuildID(r.PathValue("id"))
	if err != nil {
		writeProblem(w, r, mapBuildAttestationCommandError(err))
		return
	}
	if s.buildAttestationCommands != nil {
		s.createDurableWithLimit(w, r, releaseapp.BuildAttestationPayloadLimit, func(ctx context.Context, a domain.Actor, raw []byte) error {
			if len(raw) == 0 {
				return app.NewValidationError(app.FieldViolation{Field: "/body", Code: "invalid_size"})
			}
			return mapBuildAttestationCommandError(s.buildAttestationCommands.AuthorizeBuildAttestationCreation(ctx, a, id))
		}, func(ctx context.Context, a domain.Actor, raw []byte) (int, any, error) {
			v, err := s.buildAttestationCommands.UploadBuildAttestation(ctx, a, id, raw)
			return http.StatusCreated, buildAttestationFromCommand(v), mapBuildAttestationCommandError(err)
		})
		return
	}
	s.createWithActorFingerprint(w, r, releaseapp.BuildAttestationPayloadLimit, func(s *Server, ctx requestContext, a domain.Actor, raw []byte) (int, any, error) {
		v, err := s.releaseCatalog.UploadBuildAttestation(ctx, a, id, raw)
		v.PayloadRef = ""
		return http.StatusCreated, v, err
	}, func(r *http.Request, a domain.Actor, body []byte) ([]byte, error) {
		if len(body) == 0 {
			return nil, app.NewValidationError(app.FieldViolation{Field: "/body", Code: "invalid_size"})
		}
		return body, s.releaseCatalog.AuthorizeBuildAttestationCreation(r.Context(), a, id)
	})
}

func buildAttestationFromCommand(v releasedomain.BuildAttestation) domain.BuildAttestation {
	// Internal object coordinates are sensitive and absent from stored replay.
	// Do not expose them on a fresh HTTP response either.
	return domain.BuildAttestation{
		ID: v.ID, TenantID: v.TenantID, BuildID: v.BuildID, EvidenceID: v.EvidenceID,
		PayloadHash: v.PayloadHash, PayloadSize: v.PayloadSize,
		PayloadType: v.PayloadType, PredicateType: v.PredicateType,
		SubjectDigests: append([]string(nil), v.SubjectDigests...),
		BuilderID:      v.BuilderID, BuildType: v.BuildType, MaterialsCount: v.MaterialsCount,
		SignatureCount: v.SignatureCount, VerificationStatus: v.VerificationStatus,
		SchemaVersion: v.SchemaVersion, CreatedAt: v.CreatedAt,
	}
}

func mapBuildAttestationCommandError(err error) error {
	switch {
	case errors.Is(err, releaseapp.ErrValidation):
		return app.ErrValidation
	case errors.Is(err, releaseapp.ErrNotFound):
		return app.ErrNotFound
	case errors.Is(err, releaseapp.ErrConflict):
		return app.ErrConflict
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	default:
		return err
	}
}
