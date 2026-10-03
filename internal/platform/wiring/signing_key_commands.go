package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/adapters/signing/localed25519"
	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func BuildSigningKeyCommands(factory app.UnitOfWorkFactory) (*verificationapp.SigningKeyCommands, error) {
	if factory == nil {
		return nil, errors.New("signing-key transactions are required")
	}
	return verificationapp.NewSigningKeyCommands(verificationapp.SigningKeyCommandConfig{Transactions: signingKeyTransactions{factory}, KeyFactory: localed25519.KeyFactory{}, Authorizer: verificationquery.NewSigningKeyAdminAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type signingKeyMetadataLocker interface {
	ListLocalSigningKeysForUpdate(context.Context, string) ([]verificationdomain.SigningKey, error)
	GetSigningKeyForUpdate(context.Context, string, string) (verificationdomain.SigningKey, error)
}
type signingKeyTransactions struct{ factory app.UnitOfWorkFactory }

func (t signingKeyTransactions) ExecuteSigningKeyCommand(ctx context.Context, command func(context.Context, verificationapp.SigningKeyTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Signatures.(signingKeyMetadataLocker)
		if !ok || repos.Audit == nil {
			return app.ErrValidation
		}
		return command(ctx, signingKeyTransaction{reader, repos.Signatures, repos.Audit})
	}))
}

type signingKeyTransaction struct {
	reader     signingKeyMetadataLocker
	signatures app.SignatureRepository
	audit      app.AuditRepository
}

func (t signingKeyTransaction) ListLocalSigningKeysForUpdate(ctx context.Context, tenant string) ([]verificationdomain.SigningKey, error) {
	keys, err := t.reader.ListLocalSigningKeysForUpdate(ctx, tenant)
	return keys, mapSigningKeyWriteError(err)
}
func (t signingKeyTransaction) GetSigningKeyForUpdate(ctx context.Context, tenant, id string) (verificationdomain.SigningKey, error) {
	key, err := t.reader.GetSigningKeyForUpdate(ctx, tenant, id)
	return key, mapSigningKeyWriteError(err)
}
func (t signingKeyTransaction) UpdateSigningKey(ctx context.Context, key verificationdomain.SigningKey, expected string) error {
	return mapSigningKeyWriteError(t.signatures.UpdateSigningKey(ctx, signingKeyToLegacy(key), expected))
}
func (t signingKeyTransaction) InsertSigningKey(ctx context.Context, prepared verificationapp.PreparedSigningKey) error {
	key := signingKeyToLegacy(prepared.Key)
	key.Private = prepared.PrivateMaterial
	return mapSigningKeyWriteError(t.signatures.InsertSigningKey(ctx, key))
}
func (t signingKeyTransaction) Authorize(ctx context.Context, actor identitydomain.Actor, request application.AuthorizationRequest) error {
	return verificationquery.NewSigningKeyAdminAuthorizer().Authorize(ctx, actor, request)
}
func (t signingKeyTransaction) AppendAudit(ctx context.Context, event application.AuditEvent) (application.AuditReceipt, error) {
	receipt, err := appendAuditEvent(ctx, t.audit, event)
	return receipt, mapSigningKeyWriteError(err)
}
func signingKeyToLegacy(key verificationdomain.SigningKey) domain.SigningKey {
	return domain.SigningKey{ID: key.ID, TenantID: key.TenantID, KID: key.KID, Version: key.Version, Provider: key.Provider, Algorithm: key.Algorithm, Status: key.Status.String(), PublicKey: key.PublicKey, PublicKeyFingerprint: key.PublicKeyFingerprint, ValidFrom: key.ValidFrom, ValidUntil: key.ValidUntil, CreatedAt: key.CreatedAt, RevokedAt: key.RevokedAt, RevocationReason: key.RevocationReason, RevocationSemantics: key.RevocationSemantics, HistoricalValidityPolicy: key.HistoricalValidityPolicy, CompromisedAt: key.CompromisedAt}
}
func mapSigningKeyWriteError(err error) error {
	switch {
	case errors.Is(err, app.ErrValidation):
		return verificationapp.ErrValidation
	case errors.Is(err, app.ErrNotFound):
		return verificationapp.ErrNotFound
	case errors.Is(err, app.ErrConflict):
		return verificationapp.ErrConflict
	default:
		return err
	}
}
