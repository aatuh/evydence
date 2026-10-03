// Package dsseobjects binds bounded finalized object reads to the offline DSSE
// cryptographic adapter. Policy aggregation and receipt writes remain in core.
package dsseobjects

import (
	"context"
	"errors"

	"github.com/aatuh/evydence/internal/adapters/verification/dsse"
	"github.com/aatuh/evydence/internal/app"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
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
	policies := make([]dsse.Policy, 0, len(snapshot.Roots))
	for _, root := range snapshot.Roots {
		if root.TenantID != snapshot.Subject.TenantID {
			return verificationapp.DSSEVerificationFacts{}, verificationapp.ErrConflict
		}
		if !verificationapp.ValidDSSETrustRoot(root) {
			continue
		}
		policies = append(policies, dsse.Policy{Roots: []dsse.TrustRoot{{ID: root.ID, KeyID: root.KeyID, Algorithm: root.Algorithm, PublicKey: root.PublicKey}}, AllowedPredicateTypes: root.AllowedPredicateTypes, ExpectedBuilderIDs: root.ExpectedBuilderIDs, RequiredClaims: root.RequiredClaims, ExpectedSubjectDigests: snapshot.ExpectedSubjectDigests})
	}
	object, err := i.Objects.GetBounded(ctx, key, snapshot.PayloadSize)
	if err != nil {
		return verificationapp.DSSEVerificationFacts{}, objectReadError(err)
	}
	if object.Key != key || object.TenantID != snapshot.Subject.TenantID || object.Digest != snapshot.PayloadHash || int64(len(object.Bytes)) != snapshot.PayloadSize || !app.ObjectMediaTypesMatch(snapshot.PayloadMediaType, object.MediaType) || app.VerifyObjectDigestBytes(snapshot.PayloadHash, object.Bytes) != nil {
		return verificationapp.DSSEVerificationFacts{}, verificationapp.ErrValidation
	}
	result, err := dsse.VerifyConfiguredPolicies(ctx, object.Bytes, policies)
	if err != nil {
		if ctx.Err() != nil {
			return verificationapp.DSSEVerificationFacts{}, ctx.Err()
		}
		return verificationapp.DSSEVerificationFacts{}, verificationapp.ErrValidation
	}
	facts := verificationapp.DSSEVerificationFacts{AcceptedRootIDs: append([]string(nil), result.AcceptedRootIDs...)}
	for _, check := range result.Checks {
		facts.Checks = append(facts.Checks, verificationdomain.VerifyCheck{Name: check.Name, Result: check.Result, Detail: check.Detail})
	}
	return facts, nil
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
