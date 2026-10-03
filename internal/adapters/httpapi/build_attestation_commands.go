package httpapi

import (
	"context"
	"errors"

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
	UploadBuildAttestation(context.Context, identitydomain.Actor, string, []byte) (releasedomain.BuildAttestation, error)
}

func buildAttestationFromCommand(v releasedomain.BuildAttestation) domain.BuildAttestation {
	return domain.BuildAttestation{
		ID: v.ID, TenantID: v.TenantID, BuildID: v.BuildID, EvidenceID: v.EvidenceID,
		PayloadRef: v.PayloadRef, PayloadHash: v.PayloadHash, PayloadSize: v.PayloadSize,
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
