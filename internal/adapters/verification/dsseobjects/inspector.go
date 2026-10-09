// Package dsseobjects binds bounded finalized object reads to the offline DSSE
// cryptographic adapter. Policy aggregation and receipt writes remain in core.
package dsseobjects

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/adapters/verification/dsse"
	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
)

type Inspector struct{ Objects app.BoundedObjectReader }

func (i Inspector) VerifyDSSE(ctx context.Context, snapshot verificationapp.DSSEVerificationSnapshot) (verificationapp.DSSEVerificationFacts, error) {
	if ctx == nil {
		return verificationapp.DSSEVerificationFacts{}, verificationapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return verificationapp.DSSEVerificationFacts{}, err
	}
	if i.Objects == nil || !snapshot.PayloadFinalized || snapshot.PayloadSize < 1 || snapshot.PayloadSize > verificationapp.MaxDSSEPayloadBytes {
		return verificationapp.DSSEVerificationFacts{}, verificationapp.ErrValidation
	}
	_, key, err := app.CanonicalObjectPayloadKeys(snapshot.Subject.TenantID, snapshot.PayloadHash)
	if err != nil || snapshot.PayloadRef != "object://"+key {
		return verificationapp.DSSEVerificationFacts{}, verificationapp.ErrValidation
	}
	for _, root := range snapshot.Roots {
		if root.TenantID != snapshot.Subject.TenantID {
			return verificationapp.DSSEVerificationFacts{}, verificationapp.ErrConflict
		}
	}
	object, err := i.Objects.GetBounded(ctx, key, snapshot.PayloadSize)
	if err != nil {
		return verificationapp.DSSEVerificationFacts{}, objectReadError(err)
	}
	if object.Key != key || object.TenantID != snapshot.Subject.TenantID || object.Digest != snapshot.PayloadHash || int64(len(object.Bytes)) != snapshot.PayloadSize || !app.ObjectMediaTypesMatch(snapshot.PayloadMediaType, object.MediaType) || app.VerifyObjectDigestBytes(snapshot.PayloadHash, object.Bytes) != nil {
		return verificationapp.DSSEVerificationFacts{}, verificationapp.ErrValidation
	}
	return (dsse.PolicyVerifier{}).VerifyDSSEPolicies(ctx, verificationapp.DSSEPolicyVerification{
		TenantID: snapshot.Subject.TenantID, Envelope: object.Bytes,
		Roots: snapshot.Roots, ExpectedSubjectDigests: snapshot.ExpectedSubjectDigests,
	})
}
func objectReadError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return verificationapp.ErrValidation
	case errors.Is(err, app.ErrConflict):
		return verificationapp.ErrConflict
	case errors.Is(err, app.ErrNotFound):
		return verificationapp.ErrNotFound
	default:
		return err
	}
}
