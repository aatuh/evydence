package app

import (
	"context"

	"github.com/aatuh/evydence/internal/authz"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
)

// Historical aggregate signing/trust behavior is test-only. Production and
// HTTP fixture composition use the focused commands over current repositories.
type CreateSigningProviderInput struct {
	Name      string
	Type      string
	KeyRef    string
	Encrypted bool
}

type SigningKeyRevocationInput struct {
	Reason                   string
	Semantics                string
	HistoricalValidityPolicy string
}

type CreateDSSETrustRootInput struct {
	Name                  string
	KeyID                 string
	Algorithm             string
	PublicKey             string
	AllowedPredicateTypes []string
	ExpectedBuilderIDs    []string
	RequiredClaims        []string
}

// AuthorizeSigningKeyRevocation preserves the legacy test fixture's replay
// policy. Native HTTP uses the flat transactional ownership guard instead.
func (l *Ledger) AuthorizeSigningKeyRevocation(ctx context.Context, a domain.Actor, raw string) error {
	if err := authz.Authorize(ctx, a, authz.Request{Action: authz.ActionSigningKeysManage}); err != nil {
		return fromVerificationContextError(err)
	}
	id, err := verificationapp.NormalizeSigningKeyID(raw)
	if err != nil {
		return ErrValidation
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key, ok := l.signingKeys[id]
	if !ok || key.TenantID != a.TenantID {
		return ErrNotFound
	}
	return nil
}

func (l *Ledger) RotateSigningKey(ctx context.Context, actor domain.Actor, reason string) (domain.SigningKey, error) {
	value, err := l.legacyVerificationCommands().RotateSigningKey(ctx, actor, reason)
	return signingKeyFromVerificationContext(value, nil), fromVerificationContextError(err)
}

func (l *Ledger) RevokeSigningKeyWithPolicy(ctx context.Context, actor domain.Actor, keyID string, in SigningKeyRevocationInput) (domain.SigningKey, error) {
	value, err := l.legacyVerificationCommands().RevokeSigningKey(ctx, actor, keyID, verificationapp.SigningKeyRevocationInput{
		Reason: in.Reason, Semantics: in.Semantics, HistoricalValidityPolicy: in.HistoricalValidityPolicy,
	})
	return signingKeyFromVerificationContext(value, nil), fromVerificationContextError(err)
}

func (l *Ledger) CreateSigningProvider(ctx context.Context, actor domain.Actor, in CreateSigningProviderInput) (domain.SigningProvider, error) {
	value, err := l.legacyVerificationCommands().CreateSigningProvider(ctx, actor, verificationapp.CreateSigningProviderInput{
		Name: in.Name, Type: in.Type, KeyRef: in.KeyRef, Encrypted: in.Encrypted,
	})
	return signingProviderFromVerificationService(value), fromVerificationContextError(err)
}

func signingProviderFromVerificationService(value verificationdomain.SigningProvider) domain.SigningProvider {
	return domain.SigningProviderFromContextModel(value)
}
func (l *Ledger) CreateDSSETrustRoot(ctx context.Context, actor domain.Actor, in CreateDSSETrustRootInput) (domain.DSSETrustRoot, error) {
	value, err := l.legacyVerificationCommands().CreateDSSETrustRoot(ctx, actor, verificationapp.CreateDSSETrustRootInput{
		Name: in.Name, KeyID: in.KeyID, Algorithm: in.Algorithm, PublicKey: in.PublicKey,
		AllowedPredicateTypes: append([]string(nil), in.AllowedPredicateTypes...),
		ExpectedBuilderIDs:    append([]string(nil), in.ExpectedBuilderIDs...), RequiredClaims: append([]string(nil), in.RequiredClaims...),
	})
	return dsseTrustRootFromVerificationContext(value), fromVerificationContextError(err)
}
