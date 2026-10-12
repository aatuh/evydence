package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func artifactSignatureFromQuery(signature verificationdomain.ArtifactSignature) domain.ArtifactSignature {
	return domain.ArtifactSignature{
		ID: signature.ID, TenantID: signature.TenantID, ArtifactID: signature.ArtifactID,
		SubjectDigest: signature.SubjectDigest, Algorithm: signature.Algorithm,
		KeyID: signature.KeyID, Signature: signature.Signature,
		PayloadRef: signature.PayloadRef, PayloadHash: signature.PayloadHash,
		VerificationStatus: signature.VerificationStatus, SchemaVersion: signature.SchemaVersion,
		CreatedAt: signature.CreatedAt,
	}
}

func mapArtifactSignatureQueryError(err error) error {
	switch {
	case errors.Is(err, verificationquery.ErrSignatureValidation):
		return app.ErrValidation
	case errors.Is(err, verificationquery.ErrSignatureNotFound):
		return app.ErrNotFound
	case errors.Is(err, verificationquery.ErrSignatureProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
