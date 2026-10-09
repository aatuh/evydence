package wiring

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	identitydomain "github.com/aatuh/evydence/internal/identity/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

func BuildMerkleCreationCommands(factory app.UnitOfWorkFactory) (*verificationapp.MerkleCreationCommands, error) {
	if factory == nil {
		return nil, errors.New("merkle creation transactions are required")
	}
	return verificationapp.NewMerkleCreationCommands(verificationapp.MerkleCreationConfig{Transactions: merkleCreationTransactions{factory}, Authorizer: verificationquery.NewSigningKeyAdminAuthorizer(), Clock: application.ClockFunc(time.Now), IDs: application.IDGeneratorFunc(application.NewID)})
}

type merkleRootSigner interface {
	SignMerkleRoot(context.Context, verificationapp.SigningRequest) (verificationapp.SigningResult, error)
}
type merkleCreationTransactions struct{ factory app.UnitOfWorkFactory }

func (t merkleCreationTransactions) ExecuteMerkleCreation(ctx context.Context, fn func(context.Context, verificationapp.MerkleCreationTransaction) error) error {
	return mapSigningKeyWriteError(app.ExecuteUnitOfWork(ctx, t.factory, func(ctx context.Context, repos app.Repositories) error {
		reader, ok := repos.Integrity.(verificationapp.MerkleCreationReader)
		signer, valid := repos.Signatures.(merkleRootSigner)
		guard, guarded := repos.Identity.(trustConfigurationTenantGuard)
		if !ok || !valid || !guarded || repos.Audit == nil {
			return app.ErrValidation
		}
		return fn(ctx, merkleCreationTransaction{reader: reader, signer: signer, integrity: repos.Integrity, signatures: repos.Signatures, audit: repos.Audit, guard: guard})
	}))
}

type merkleCreationTransaction struct {
	reader     verificationapp.MerkleCreationReader
	signer     merkleRootSigner
	integrity  app.IntegrityRepository
	signatures app.SignatureRepository
	audit      app.AuditRepository
	guard      trustConfigurationTenantGuard
}

func (t merkleCreationTransaction) LockMerkleCreationView(ctx context.Context, tenant string) (verificationapp.MerkleCreationView, error) {
	v, err := t.reader.LockMerkleCreationView(ctx, tenant)
	return v, mapSigningKeyWriteError(err)
}
func (t merkleCreationTransaction) ReadMerkleCreationLeaves(ctx context.Context, tenant string, from, to int64) ([]verificationapp.AuditChainLeaf, error) {
	v, err := t.reader.ReadMerkleCreationLeaves(ctx, tenant, from, to)
	return v, mapSigningKeyWriteError(err)
}
func (t merkleCreationTransaction) SignMerkleRoot(ctx context.Context, r verificationapp.SigningRequest) (verificationapp.SigningResult, error) {
	v, err := t.signer.SignMerkleRoot(ctx, r)
	return v, mapSigningKeyWriteError(err)
}
func (t merkleCreationTransaction) InsertSigningKey(ctx context.Context, k verificationapp.PreparedSigningKey) error {
	v := signingKeyToLegacy(k.Key)
	v.Private = k.PrivateMaterial
	return mapSigningKeyWriteError(t.signatures.InsertSigningKey(ctx, v))
}
func (t merkleCreationTransaction) InsertSignature(ctx context.Context, s verificationdomain.Signature) error {
	return mapSigningKeyWriteError(t.signatures.InsertSignature(ctx, domain.Signature(s)))
}
func (t merkleCreationTransaction) InsertMerkleBatch(ctx context.Context, b verificationdomain.MerkleBatch) error {
	return mapSigningKeyWriteError(t.integrity.InsertMerkleBatch(ctx, domain.MerkleBatch(b)))
}
func (t merkleCreationTransaction) Authorize(ctx context.Context, a identitydomain.Actor, r application.AuthorizationRequest) error {
	if err := verificationquery.NewSigningKeyAdminAuthorizer().Authorize(ctx, a, r); err != nil {
		return err
	}
	return mapSigningKeyWriteError(t.guard.LockAPIKeyCreation(ctx, a.TenantID))
}
func (t merkleCreationTransaction) AppendAudit(ctx context.Context, a application.AuditEvent) (application.AuditReceipt, error) {
	r, err := appendAuditEvent(ctx, t.audit, a)
	return r, mapSigningKeyWriteError(err)
}
