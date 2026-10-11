package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	verificationapp "github.com/aatuh/evydence/internal/verification/app"
	verificationdomain "github.com/aatuh/evydence/internal/verification/domain"
	verificationquery "github.com/aatuh/evydence/internal/verification/query"
)

type merkleCreationFixtureCommands struct {
	catalogFixtureCommands
	clock application.Clock
}
type merkleCreationFixtureTransactions struct{ catalogFixtureCommands }
type merkleFixtureSigner interface {
	SignMerkleRoot(context.Context, verificationapp.SigningRequest) (verificationapp.SigningResult, error)
}
type merkleCreationFixtureTransaction struct {
	reader     verificationapp.MerkleCreationReader
	signer     merkleFixtureSigner
	integrity  app.IntegrityRepository
	signatures app.SignatureRepository
	guard      releaseBundleFixtureFence
	audit      app.AuditRepository
}
type checkpointCreationFixtureTransaction struct {
	reader    verificationapp.TransparencyCheckpointReader
	locker    verificationapp.TransparencyCheckpointScopeLocker
	integrity app.IntegrityRepository
	guard     releaseBundleFixtureFence
	audit     app.AuditRepository
}

func (f merkleCreationFixtureTransactions) ExecuteMerkleCreation(ctx context.Context, run func(context.Context, verificationapp.MerkleCreationTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return verificationapp.ErrValidation
	}
	return signingAdminFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Integrity.(verificationapp.MerkleCreationReader)
		signer, signed := r.Signatures.(merkleFixtureSigner)
		guard, guarded := r.Identity.(releaseBundleFixtureFence)
		if !ok || !signed || !guarded || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, merkleCreationFixtureTransaction{reader, signer, r.Integrity, r.Signatures, guard, r.Audit})
	}))
}
func (f merkleCreationFixtureTransactions) ExecuteTransparencyCheckpoint(ctx context.Context, run func(context.Context, verificationapp.TransparencyCheckpointTransaction) error) error {
	if ctx == nil || run == nil || f.commandLedger(ctx) == nil {
		return verificationapp.ErrValidation
	}
	return signingAdminFixtureError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		reader, ok := r.Integrity.(verificationapp.TransparencyCheckpointReader)
		locker, locked := r.Integrity.(verificationapp.TransparencyCheckpointScopeLocker)
		guard, guarded := r.Identity.(releaseBundleFixtureFence)
		if !ok || !locked || !guarded || r.Audit == nil {
			return app.ErrValidation
		}
		return run(ctx, checkpointCreationFixtureTransaction{reader, locker, r.Integrity, guard, r.Audit})
	}))
}
func (t merkleCreationFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return signingAdminFixtureAuthorize(ctx, a, r, t.guard, verificationquery.NewMerkleCreationAuthorizer())
}
func (t checkpointCreationFixtureTransaction) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	return signingAdminFixtureAuthorize(ctx, a, r, t.guard, verificationquery.NewTransparencyCheckpointAuthorizer())
}
func (t merkleCreationFixtureTransaction) LockMerkleCreationView(ctx context.Context, tenant string) (verificationapp.MerkleCreationView, error) {
	v, err := t.reader.LockMerkleCreationView(ctx, tenant)
	return v, signingAdminFixtureError(err)
}
func (t merkleCreationFixtureTransaction) ReadMerkleCreationLeaves(ctx context.Context, tenant string, from, to int64) ([]verificationapp.AuditChainLeaf, error) {
	v, err := t.reader.ReadMerkleCreationLeaves(ctx, tenant, from, to)
	return v, signingAdminFixtureError(err)
}
func (t merkleCreationFixtureTransaction) SignMerkleRoot(ctx context.Context, r verificationapp.SigningRequest) (verificationapp.SigningResult, error) {
	v, err := t.signer.SignMerkleRoot(ctx, r)
	return v, signingAdminFixtureError(err)
}
func (t merkleCreationFixtureTransaction) InsertSigningKey(ctx context.Context, p verificationapp.PreparedSigningKey) error {
	v := signingKeyFromQuery(p.Key)
	v.Private = p.PrivateMaterial
	return signingAdminFixtureError(t.signatures.InsertSigningKey(ctx, v))
}
func (t merkleCreationFixtureTransaction) InsertSignature(ctx context.Context, s verificationdomain.Signature) error {
	return signingAdminFixtureError(t.signatures.InsertSignature(ctx, domain.Signature(s)))
}
func (t merkleCreationFixtureTransaction) InsertMerkleBatch(ctx context.Context, b verificationdomain.MerkleBatch) error {
	return signingAdminFixtureError(t.integrity.InsertMerkleBatch(ctx, domain.MerkleBatch(b)))
}
func (t checkpointCreationFixtureTransaction) LockTransparencyCheckpointScope(ctx context.Context, tenant, id string) error {
	return signingAdminFixtureError(t.locker.LockTransparencyCheckpointScope(ctx, tenant, id))
}
func (t checkpointCreationFixtureTransaction) ReadTransparencyCheckpointSource(ctx context.Context, tenant, id string) (verificationapp.TransparencyCheckpointSource, error) {
	v, err := t.reader.ReadTransparencyCheckpointSource(ctx, tenant, id)
	return v, signingAdminFixtureError(err)
}
func (t checkpointCreationFixtureTransaction) InsertTransparencyCheckpoint(ctx context.Context, v verificationdomain.TransparencyCheckpoint) error {
	return signingAdminFixtureError(t.integrity.InsertTransparencyCheckpoint(ctx, domain.TransparencyCheckpoint(v)))
}
func (t merkleCreationFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return signingAdminFixtureAudit(ctx, t.audit, e)
}
func (t checkpointCreationFixtureTransaction) AppendAudit(ctx context.Context, e application.AuditEvent) (application.AuditReceipt, error) {
	return signingAdminFixtureAudit(ctx, t.audit, e)
}
func (f merkleCreationFixtureCommands) merkleCommands() (*verificationapp.MerkleCreationCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	if f.clock != nil {
		clock = f.clock
	}
	return verificationapp.NewMerkleCreationCommands(verificationapp.MerkleCreationConfig{Transactions: merkleCreationFixtureTransactions{f.catalogFixtureCommands}, Authorizer: verificationquery.NewMerkleCreationAuthorizer(), Clock: clock, IDs: ids})
}
func (f merkleCreationFixtureCommands) checkpointCommands() (*verificationapp.TransparencyCheckpointCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(false)
	if f.clock != nil {
		clock = f.clock
	}
	return verificationapp.NewTransparencyCheckpointCommands(verificationapp.TransparencyCheckpointConfig{Transactions: merkleCreationFixtureTransactions{f.catalogFixtureCommands}, Authorizer: verificationquery.NewTransparencyCheckpointAuthorizer(), Hasher: releaseBundleVerificationFixtureHasher{}, Clock: clock, IDs: ids})
}
func (f merkleCreationFixtureCommands) AuthorizeMerkleCreation(ctx context.Context, a domain.Actor) error {
	c, err := f.merkleCommands()
	if err != nil {
		return err
	}
	return mapMerkleFixtureGuardError(c.AuthorizeMerkleCreation(ctx, a))
}
func (f merkleCreationFixtureCommands) CreateMerkleBatch(ctx context.Context, a domain.Actor, in verificationapp.CreateMerkleBatchInput) (verificationdomain.MerkleBatch, error) {
	c, err := f.merkleCommands()
	if err != nil {
		return verificationdomain.MerkleBatch{}, err
	}
	v, err := c.CreateMerkleBatch(ctx, a, in)
	return v, mapVerificationCommandError(err)
}
func (f merkleCreationFixtureCommands) AuthorizeTransparencyCheckpoint(ctx context.Context, a domain.Actor, id string) error {
	c, err := f.checkpointCommands()
	if err != nil {
		return err
	}
	return mapMerkleFixtureGuardError(c.AuthorizeTransparencyCheckpoint(ctx, a, id))
}

// Preserve the fixture's existing application authorization classes while
// translating repository/domain failures at the adapter boundary.
func mapMerkleFixtureGuardError(err error) error {
	if errors.Is(err, application.ErrForbidden) || errors.Is(err, application.ErrUnauthorized) {
		return err
	}
	return mapVerificationCommandError(err)
}

func createMerkleBatchFixture(ctx context.Context, ledger *repositoryFixture, actor domain.Actor, at time.Time) (domain.MerkleBatch, error) {
	f := merkleCreationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if !at.IsZero() {
		f.clock = application.ClockFunc(func() time.Time { return at })
	}
	v, err := f.CreateMerkleBatch(ctx, actor, verificationapp.CreateMerkleBatchInput{})
	return domain.MerkleBatch(v), err
}
func createTransparencyCheckpointFixture(ctx context.Context, ledger *repositoryFixture, actor domain.Actor, in verificationapp.CreateTransparencyCheckpointInput, at time.Time) (domain.TransparencyCheckpoint, error) {
	f := merkleCreationFixtureCommands{catalogFixtureCommands: catalogFixtureCommands{ledger: ledger}}
	if !at.IsZero() {
		f.clock = application.ClockFunc(func() time.Time { return at })
	}
	v, err := f.CreateTransparencyCheckpoint(ctx, actor, in)
	return domain.TransparencyCheckpoint(v), err
}
func (f merkleCreationFixtureCommands) CreateTransparencyCheckpoint(ctx context.Context, a domain.Actor, in verificationapp.CreateTransparencyCheckpointInput) (verificationdomain.TransparencyCheckpoint, error) {
	c, err := f.checkpointCommands()
	if err != nil {
		return verificationdomain.TransparencyCheckpoint{}, err
	}
	v, err := c.CreateTransparencyCheckpoint(ctx, a, in)
	return v, mapVerificationCommandError(err)
}
