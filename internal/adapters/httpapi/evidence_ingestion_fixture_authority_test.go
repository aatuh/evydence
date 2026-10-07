package httpapi

import (
	"context"
	"errors"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/application"
	"github.com/aatuh/evydence/internal/domain"
	evidenceapp "github.com/aatuh/evydence/internal/evidence/app"
	evidencedomain "github.com/aatuh/evydence/internal/evidence/domain"
	evidencequery "github.com/aatuh/evydence/internal/evidence/query"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

// Guard-only test wiring reads current fixture records and applies the actual
// native authorizers. It does not emulate PostgreSQL ownership locks. Fresh
// writes use separate, real isolated Ledger commands, never these capabilities.
type ingestionFixtureAuthority struct{ catalogFixtureCommands }

func fixtureOwnerReader(tenant string) domain.Actor {
	return domain.Actor{TenantID: tenant, KeyID: "fixture-owner-reader", Scopes: []string{"product:read", "release:read", "evidence:read"}}
}

func (f ingestionFixtureAuthority) ResolveEvidenceCreationScope(ctx context.Context, tenant string, refs application.ResourceReferences) (application.ResourceReferences, error) {
	if refs != (application.ResourceReferences{ProductID: refs.ProductID, ProjectID: refs.ProjectID, ReleaseID: refs.ReleaseID}) {
		return application.ResourceReferences{}, evidencequery.ErrValidation
	}
	ledger, reader := f.commandLedger(ctx), fixtureOwnerReader(tenant)
	product := refs.ProductID
	if refs.ProjectID != "" {
		project, err := ledger.GetProject(ctx, reader, refs.ProjectID)
		if err != nil {
			return application.ResourceReferences{}, err
		}
		if product != "" && product != project.ProductID {
			return application.ResourceReferences{}, app.ErrNotFound
		}
		product = project.ProductID
	}
	if refs.ReleaseID != "" {
		release, err := ledger.GetRelease(ctx, reader, refs.ReleaseID)
		if err != nil {
			return application.ResourceReferences{}, err
		}
		if product != "" && product != release.ProductID {
			return application.ResourceReferences{}, app.ErrNotFound
		}
		product = release.ProductID
	}
	if product != "" {
		if _, err := ledger.GetProduct(ctx, reader, product); err != nil {
			return application.ResourceReferences{}, err
		}
	}
	refs.ProductID = product
	return refs, nil
}

func (f ingestionFixtureAuthority) GetArtifactPoint(ctx context.Context, request releasequery.ArtifactReadRequest) (releasequery.ArtifactPoint, error) {
	actor := domain.Actor{TenantID: request.TenantID, UserID: "fixture-artifact-reader", Scopes: []string{app.ScopeEvidenceRead}}
	if request.TenantWide {
		actor.UserID, actor.KeyID = "", "fixture-owner-reader"
	} else {
		for _, values := range []struct {
			kind string
			ids  []string
		}{{"product", request.AllowedProductIDs}, {"project", request.AllowedProjectIDs}, {"release", request.AllowedReleaseIDs}} {
			for _, id := range values.ids {
				actor.ResourceGrants = append(actor.ResourceGrants, domain.ResourceGrant{ResourceType: values.kind, ResourceID: id, Scopes: []string{app.ScopeEvidenceRead}})
			}
		}
	}
	value, err := f.commandLedger(ctx).GetArtifact(ctx, actor, request.ID)
	if err != nil {
		return releasequery.ArtifactPoint{}, err
	}
	return releasequery.ArtifactPoint{Artifact: artifactFixtureModel(value), Visible: true}, nil
}

func (f ingestionFixtureAuthority) authorizer(security bool) (application.Authorizer, error) {
	if security {
		artifacts, err := releasequery.NewArtifactSecurityWriteAuthorizer(f)
		if err != nil {
			return nil, err
		}
		return evidencequery.NewSecurityDocumentAuthorizer(f, artifacts)
	}
	artifacts, err := releasequery.NewArtifactWriteAuthorizer(f)
	if err != nil {
		return nil, err
	}
	return evidencequery.NewEvidenceCreationAuthorizer(f, artifacts)
}

func (f ingestionFixtureAuthority) ValidateScope(ctx context.Context, tenant string, scope evidenceapp.EvidenceScope) error {
	if scope.AllowPendingDeployment {
		return evidencequery.ErrValidation
	}
	_, err := f.ResolveEvidenceCreationScope(ctx, tenant, application.ResourceReferences{ProductID: scope.ProductID, ProjectID: scope.ProjectID, ReleaseID: scope.ReleaseID, BuildID: scope.BuildID, DeploymentID: scope.DeploymentID})
	return err
}
func (f ingestionFixtureAuthority) ValidateArtifactReference(ctx context.Context, tenant, id, digest string) error {
	value, err := f.commandLedger(ctx).GetArtifact(ctx, fixtureOwnerReader(tenant), id)
	if err != nil {
		return err
	}
	if digest != "" && value.Digest != digest {
		return app.ErrNotFound
	}
	return nil
}

// Native replay guards must never reach any effect capability, clock or ID
// generator. These fail loudly instead of silently accepting fake writes.
type ingestionFixtureGuardEffects struct{}

func (ingestionFixtureGuardEffects) InsertEvidence(context.Context, evidencedomain.EvidenceItem) error {
	panic("ingestion guard attempted a write")
}
func (ingestionFixtureGuardEffects) RecordStagedPayload(context.Context, evidenceapp.StagedPayload) error {
	panic("ingestion guard recorded a payload")
}
func (ingestionFixtureGuardEffects) AppendAudit(context.Context, application.AuditEvent) (application.AuditReceipt, error) {
	panic("ingestion guard appended audit")
}
func (ingestionFixtureGuardEffects) EnqueueOutbox(context.Context, application.OutboxEvent) error {
	panic("ingestion guard enqueued a job")
}
func (ingestionFixtureGuardEffects) InsertSBOM(context.Context, evidencedomain.SBOM) error {
	panic("ingestion guard inserted SBOM")
}
func (ingestionFixtureGuardEffects) InsertVEXDocument(context.Context, evidencedomain.VEXDocument) error {
	panic("ingestion guard inserted VEX")
}
func (ingestionFixtureGuardEffects) InsertVEXImportReport(context.Context, evidencedomain.VEXImportReport) error {
	panic("ingestion guard inserted report")
}
func (ingestionFixtureGuardEffects) InsertOpenAPIContract(context.Context, evidencedomain.OpenAPIContract) error {
	panic("ingestion guard inserted contract")
}
func (ingestionFixtureGuardEffects) InsertVulnerabilityScan(context.Context, evidencedomain.VulnerabilityScan) error {
	panic("ingestion guard inserted scan")
}
func (ingestionFixtureGuardEffects) InsertSecurityScan(context.Context, evidencedomain.SecurityScan) error {
	panic("ingestion guard inserted security scan")
}
func (ingestionFixtureGuardEffects) InsertManualSecurityDocument(context.Context, evidencedomain.ManualSecurityDocument) error {
	panic("ingestion guard inserted document")
}
func (ingestionFixtureGuardEffects) InsertSBOMDiff(context.Context, evidencedomain.SBOMDiff) error {
	panic("ingestion guard inserted SBOM diff")
}
func (ingestionFixtureGuardEffects) InsertContractDiff(context.Context, evidencedomain.ContractDiff) error {
	panic("ingestion guard inserted contract diff")
}
func (ingestionFixtureGuardEffects) StagePayload(context.Context, string, string, string, []byte) (evidenceapp.StagedPayload, error) {
	panic("ingestion guard staged payload")
}
func (ingestionFixtureGuardEffects) StagePayloadSource(context.Context, string, string, evidenceapp.PayloadSource) (evidenceapp.StagedPayload, error) {
	panic("ingestion guard staged source")
}
func (ingestionFixtureGuardEffects) ValidateStagedPayload(context.Context, evidenceapp.StagedPayload) error {
	panic("ingestion guard inspected staged payload")
}
func (ingestionFixtureGuardEffects) HashEvidence(context.Context, evidencedomain.EvidenceItem) (string, error) {
	panic("ingestion guard computed hash")
}
func ingestionFixtureGuardClock() time.Time { panic("ingestion guard read clock") }
func ingestionFixtureGuardID(string) string { panic("ingestion guard allocated ID") }

type ingestionFixtureGuardTransaction struct {
	ingestionFixtureAuthority
	application.Authorizer
	ingestionFixtureGuardEffects
}

func (t ingestionFixtureGuardTransaction) ValidateScope(ctx context.Context, tenant string, scope evidenceapp.EvidenceScope) error {
	return t.ingestionFixtureAuthority.ValidateScope(ctx, tenant, scope)
}
func (t ingestionFixtureGuardTransaction) ValidateArtifactReference(ctx context.Context, tenant, id, digest string) error {
	return t.ingestionFixtureAuthority.ValidateArtifactReference(ctx, tenant, id, digest)
}
func (t ingestionFixtureGuardTransaction) Authorize(ctx context.Context, actor domain.Actor, request application.AuthorizationRequest) error {
	return t.Authorizer.Authorize(ctx, actor, request)
}

type ingestionFixtureGuardRunner struct {
	ingestionFixtureAuthority
	security bool
}

func (f ingestionFixtureGuardRunner) transaction() (ingestionFixtureGuardTransaction, error) {
	authorizer, err := f.authorizer(f.security)
	return ingestionFixtureGuardTransaction{ingestionFixtureAuthority: f.ingestionFixtureAuthority, Authorizer: authorizer}, err
}

func (f ingestionFixtureGuardRunner) ExecuteSBOMIngestion(ctx context.Context, run func(context.Context, evidenceapp.SBOMIngestionTransaction) error) error {
	tx, err := f.transaction()
	if err != nil {
		return err
	}
	return run(ctx, tx)
}
func (f ingestionFixtureGuardRunner) ExecuteVEXIngestion(ctx context.Context, run func(context.Context, evidenceapp.VEXIngestionTransaction) error) error {
	tx, err := f.transaction()
	if err != nil {
		return err
	}
	return run(ctx, tx)
}
func (f ingestionFixtureGuardRunner) ExecuteVulnerabilityScanIngestion(ctx context.Context, run func(context.Context, evidenceapp.VulnerabilityScanIngestionTransaction) error) error {
	tx, err := f.transaction()
	if err != nil {
		return err
	}
	return run(ctx, tx)
}
func (f ingestionFixtureGuardRunner) ExecuteOpenAPIIngestion(ctx context.Context, run func(context.Context, evidenceapp.OpenAPIIngestionTransaction) error) error {
	tx, err := f.transaction()
	if err != nil {
		return err
	}
	return run(ctx, tx)
}
func (f ingestionFixtureGuardRunner) ExecuteSecurityDocument(ctx context.Context, run func(context.Context, evidenceapp.SecurityDocumentTransaction) error) error {
	tx, err := f.transaction()
	if err != nil {
		return err
	}
	return run(ctx, tx)
}

func fixtureIngestionError(err error) error {
	if errors.Is(err, app.ErrForbidden) {
		return application.ErrForbidden
	}
	if errors.Is(err, app.ErrNotFound) || errors.Is(err, evidencequery.ErrNotFound) {
		return evidenceapp.ErrNotFound
	}
	if errors.Is(err, app.ErrValidation) || errors.Is(err, evidencequery.ErrValidation) {
		return evidenceapp.ErrValidation
	}
	if errors.Is(err, app.ErrConflict) || errors.Is(err, evidencequery.ErrConflict) {
		return evidenceapp.ErrConflict
	}
	return err
}
