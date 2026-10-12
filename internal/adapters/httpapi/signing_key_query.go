package httpapi

import (
	"errors"

	"github.com/aatuh/evydence/internal/app"
	appquery "github.com/aatuh/evydence/internal/app/query"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func signingKeyFromQuery(key verificationdomain.SigningKey) domain.SigningKey {
	return domain.SigningKey{
		ID: key.ID, TenantID: key.TenantID, KID: key.KID, Version: key.Version,
		Provider: key.Provider, Algorithm: key.Algorithm, Status: key.Status.String(),
		PublicKey: key.PublicKey, PublicKeyFingerprint: key.PublicKeyFingerprint,
		ValidFrom: key.ValidFrom, ValidUntil: key.ValidUntil, CreatedAt: key.CreatedAt,
		RevokedAt: key.RevokedAt, RevocationReason: key.RevocationReason,
		RevocationSemantics:      key.RevocationSemantics,
		HistoricalValidityPolicy: key.HistoricalValidityPolicy, CompromisedAt: key.CompromisedAt,
	}
}

func mapSigningKeyQueryError(err error) error {
	switch {
	case errors.Is(err, verificationquery.ErrSigningKeyValidation), errors.Is(err, appquery.ErrInvalidPage), errors.Is(err, appquery.ErrInvalidCursor):
		return app.ErrValidation
	case errors.Is(err, verificationquery.ErrSigningKeyProjection):
		return app.ErrConflict
	case errors.Is(err, application.ErrUnauthorized):
		return app.ErrUnauthorized
	case errors.Is(err, application.ErrForbidden):
		return app.ErrForbidden
	default:
		return err
	}
}
