package httpapi

import (
	"context"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// Focused document composition reuses the real current evidence-creation ports.
// Object store and clock are explicit, never recovered from Ledger state.
type securityDocumentNativeFixture struct {
	evidenceCreationNativeFixture
	objects app.ObjectStore
	clock   application.Clock
}

func (f securityDocumentNativeFixture) authorizer() (application.Authorizer, error) {
	artifacts, err := releasequery.NewArtifactSecurityWriteAuthorizer(f)
	if err != nil {
		return nil, err
	}
	return evidencequery.NewSecurityDocumentAuthorizer(f, artifacts)
}
func (f securityDocumentNativeFixture) Authorize(ctx context.Context, a domain.Actor, r application.AuthorizationRequest) error {
	auth, err := f.authorizer()
	if err != nil {
		return err
	}
	return auth.Authorize(ctx, a, r)
}
func (f securityDocumentNativeFixture) ValidateArtifactReference(ctx context.Context, tenant, id, digest string) error {
	if digest == "" {
		return f.ValidateArtifactIdentity(ctx, tenant, id)
	}
	if f.readOnly {
		panic("security preflight read artifact digest")
	}
	return f.evidenceCreationNativeFixture.ValidateArtifactReference(ctx, tenant, id, digest)
}
func (f securityDocumentNativeFixture) ExecuteSecurityDocument(ctx context.Context, run func(context.Context, evidenceapp.SecurityDocumentTransaction) error) error {
	if ctx == nil || run == nil {
		return evidenceapp.ErrValidation
	}
	return fixtureIngestionError(f.commandLedger(ctx).ExecuteUnitOfWork(ctx, func(ctx context.Context, r app.Repositories) error {
		if r.Evidence == nil || r.Risk == nil || r.Audit == nil || r.Outbox == nil || r.Payloads == nil {
			return app.ErrValidation
		}
		bound := f
		bound.repositories = &r
		return run(ctx, bound)
	}))
}
func (f securityDocumentNativeFixture) InsertSecurityScan(ctx context.Context, v evidencedomain.SecurityScan) error {
	if f.readOnly || f.repositories == nil {
		panic("security preflight/unbound scan insert")
	}
	return fixtureIngestionError(f.repositories.Risk.InsertSecurityScan(ctx, domain.SecurityScanFromContext(v)))
}
func (f securityDocumentNativeFixture) InsertManualSecurityDocument(ctx context.Context, v evidencedomain.ManualSecurityDocument) error {
	if f.readOnly || f.repositories == nil {
		panic("security preflight/unbound document insert")
	}
	return fixtureIngestionError(f.repositories.Risk.InsertManualSecurityDocument(ctx, domain.ManualSecurityDocumentFromContext(v)))
}
func (f securityDocumentNativeFixture) StagePayload(ctx context.Context, tenant, media, digest string, raw []byte) (evidenceapp.StagedPayload, error) {
	if f.readOnly {
		panic("security preflight staged object bytes")
	}
	if ctx == nil {
		return evidenceapp.StagedPayload{}, evidenceapp.ErrValidation
	}
	if err := ctx.Err(); err != nil {
		return evidenceapp.StagedPayload{}, err
	}
	source := app.BytesPayloadSource(raw)
	if source.Digest != digest {
		return evidenceapp.StagedPayload{}, evidenceapp.ErrValidation
	}
	// Native composition permits absent object storage for typed local fixtures;
	// it never pretends those metadata-only records have durable payload bytes.
	if f.objects == nil {
		return evidenceapp.StagedPayload{}, nil
	}
	objects, ok := f.objects.(app.PayloadObjectStore)
	if !ok {
		return evidenceapp.StagedPayload{}, evidenceapp.ErrConflict
	}
	p, err := app.StageObjectPayload(ctx, objects, tenant, media, source, f.clock.Now())
	if err != nil {
		return evidenceapp.StagedPayload{}, fixtureIngestionError(err)
	}
	return evidenceapp.StagedPayload{TenantID: p.TenantID, Digest: p.Digest, Size: p.Size, MediaType: p.MediaType, StagingKey: p.StagingKey, FinalKey: p.FinalKey, Status: string(p.Status), CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}, nil
}
func (f ingestionFixtureCommands) nativeSecurityDocuments(readOnly bool) (*evidenceapp.SecurityDocumentCommands, error) {
	clock, ids := questionnaireNativeFixtureClockIDs(readOnly)
	if !readOnly {
		clock = application.ClockFunc(func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) })
		if f.clock != nil {
			clock = f.clock
		}
	}
	ports := securityDocumentNativeFixture{evidenceCreationNativeFixture: evidenceCreationNativeFixture{catalogFixtureCommands: f.catalogFixtureCommands, readOnly: readOnly}, objects: f.objects, clock: clock}
	auth, err := ports.authorizer()
	if err != nil {
		return nil, err
	}
	return evidenceapp.NewSecurityDocumentCommands(evidenceapp.SecurityDocumentCommandConfig{Authorizer: auth, Transactions: ports, Objects: ports, Canonicalizer: ports, CanonicalizationProfile: evidencedomain.EvidenceCanonicalizationProfileVersion, Clock: clock, IDs: ids})
}
func (s *Server) bindSecurityDocumentFixtureResources(objects app.ObjectStore, clock application.Clock) {
	if f, ok := s.securityDocumentCommands.(ingestionFixtureCommands); ok {
		f.objects, f.clock = objects, clock
		s.securityDocumentCommands = f
	}
}
