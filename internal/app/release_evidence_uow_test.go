package app

import (
	"context"
	"errors"
	"testing"

	"github.com/aatuh/evydence/internal/domain"
)

type commitFailingUnitOfWorkFactory struct {
	inner UnitOfWorkFactory
}

func (f commitFailingUnitOfWorkFactory) BeginUnitOfWork(ctx context.Context) (UnitOfWork, error) {
	uow, err := f.inner.BeginUnitOfWork(ctx)
	if err != nil {
		return nil, err
	}
	return commitFailingUnitOfWork{UnitOfWork: uow}, nil
}

type commitFailingUnitOfWork struct {
	UnitOfWork
}

func (commitFailingUnitOfWork) Commit(context.Context) error {
	return errors.New("forced unit-of-work commit failure")
}

var errInjectedRepositoryFailure = errors.New("forced transactional repository failure")

type repositoryFailingUnitOfWorkFactory struct {
	inner    UnitOfWorkFactory
	decorate func(Repositories) Repositories
}

func (f repositoryFailingUnitOfWorkFactory) BeginUnitOfWork(ctx context.Context) (UnitOfWork, error) {
	uow, err := f.inner.BeginUnitOfWork(ctx)
	if err != nil {
		return nil, err
	}
	return repositoryFailingUnitOfWork{UnitOfWork: uow, decorate: f.decorate}, nil
}

type repositoryFailingUnitOfWork struct {
	UnitOfWork
	decorate func(Repositories) Repositories
}

func (u repositoryFailingUnitOfWork) Repositories() Repositories {
	return u.decorate(u.UnitOfWork.Repositories())
}

type failingReleaseCatalogRepository struct{ ReleaseCatalogRepository }

func (failingReleaseCatalogRepository) InsertProduct(context.Context, domain.Product) error {
	return errInjectedRepositoryFailure
}

func (failingReleaseCatalogRepository) InsertProject(context.Context, domain.Project) error {
	return errInjectedRepositoryFailure
}

func (failingReleaseCatalogRepository) InsertRelease(context.Context, domain.Release) error {
	return errInjectedRepositoryFailure
}

func (failingReleaseCatalogRepository) UpdateReleaseState(context.Context, domain.Release, string) error {
	return errInjectedRepositoryFailure
}

func (failingReleaseCatalogRepository) InsertArtifact(context.Context, domain.Artifact) error {
	return errInjectedRepositoryFailure
}

func (failingReleaseCatalogRepository) InsertReleaseCandidate(context.Context, domain.ReleaseCandidate) error {
	return errInjectedRepositoryFailure
}

func (failingReleaseCatalogRepository) UpdateReleaseCandidateState(context.Context, domain.ReleaseCandidate, string) error {
	return errInjectedRepositoryFailure
}

type failingEvidenceRepository struct{ EvidenceRepository }

func (failingEvidenceRepository) InsertEvidence(context.Context, domain.EvidenceItem) error {
	return errInjectedRepositoryFailure
}

func (failingEvidenceRepository) UpdateEvidenceLinks(context.Context, domain.EvidenceItem) error {
	return errInjectedRepositoryFailure
}

func (failingEvidenceRepository) RecordSupersession(context.Context, domain.EvidenceItem, domain.EvidenceItem) error {
	return errInjectedRepositoryFailure
}

func (failingEvidenceRepository) AppendLifecycle(context.Context, domain.EvidenceLifecycleEvent) error {
	return errInjectedRepositoryFailure
}

func newReleaseEvidenceUnitOfWorkFixture(t *testing.T, factory UnitOfWorkFactory) (*Ledger, *MemoryUnitOfWorkFactory, domain.Actor) {
	t.Helper()
	ctx := context.Background()
	bootstrapFactory := factory
	if failing, ok := factory.(commitFailingUnitOfWorkFactory); ok {
		bootstrapFactory = failing.inner
	}
	ledger := NewLedger(Config{APIKeyPepper: "test-pepper", Now: fixedNow, UnitOfWork: bootstrapFactory})
	tenant, _, secret, err := ledger.BootstrapTenant(ctx, "Tenant", "admin", []string{"*"})
	if err != nil {
		t.Fatalf("bootstrap tenant: %v", err)
	}
	actor, err := ledger.Authenticate(ctx, secret)
	if err != nil {
		t.Fatalf("authenticate actor: %v", err)
	}
	memory, memoryOK := bootstrapFactory.(*MemoryUnitOfWorkFactory)
	if !memoryOK {
		t.Fatalf("fixture requires a memory unit of work, got %T", bootstrapFactory)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("bootstrap snapshot: %v", err)
	}
	if _, ok := snapshot.Tenants[tenant.ID]; !ok {
		if err := ExecuteUnitOfWork(ctx, memory, func(ctx context.Context, repos Repositories) error {
			return repos.Identity.InsertTenant(ctx, tenant)
		}); err != nil {
			t.Fatalf("seed unit-of-work tenant: %v", err)
		}
	}
	ledger.unitOfWork = factory
	return ledger, memory, actor
}

func TestReleaseEvidenceWritesUseUnitOfWorkAndPublishCacheAfterCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)

	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	project, err := ledger.CreateProject(ctx, actor, product.ID, "API")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "payments", "application/vnd.oci.image.manifest.v1+json", sampleDigest("payments"), 42)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{
		ProductID:   product.ID,
		ProjectID:   project.ID,
		ReleaseID:   release.ID,
		Type:        "build",
		Title:       "Payments build",
		PayloadHash: sampleDigest("payments-build"),
	})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	lifecycle, err := ledger.RecordEvidenceLifecycleEvent(ctx, actor, evidence.ID, RecordEvidenceLifecycleInput{Action: lifecycleAmendment, Reason: "corrected source metadata"})
	if err != nil {
		t.Fatalf("record evidence lifecycle event: %v", err)
	}

	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, ok := snapshot.Products[product.ID]; !ok {
		t.Fatal("committed product is missing from the unit-of-work repository")
	}
	if _, ok := snapshot.Projects[project.ID]; !ok {
		t.Fatal("committed project is missing from the unit-of-work repository")
	}
	if _, ok := snapshot.Releases[release.ID]; !ok {
		t.Fatal("committed release is missing from the unit-of-work repository")
	}
	if _, ok := snapshot.Artifacts[artifact.ID]; !ok {
		t.Fatal("committed artifact is missing from the unit-of-work repository")
	}
	storedEvidence, ok := snapshot.Evidence[evidence.ID]
	if !ok || storedEvidence.ChainEntryID == "" {
		t.Fatalf("committed evidence must include its committed audit entry: %#v", storedEvidence)
	}
	entries := snapshot.AuditEntries[actor.TenantID]
	if _, ok := snapshot.EvidenceLifecycle[lifecycle.ID]; !ok {
		t.Fatal("committed lifecycle event is missing from the unit-of-work repository")
	}
	if len(entries) != 7 || entries[5].ID != storedEvidence.ChainEntryID {
		t.Fatalf("domain and audit writes were not committed together: %#v", entries)
	}
	if ledger.products[product.ID] != product || (ledger.evidence[evidence.ID]).ChainEntryID != storedEvidence.ChainEntryID {
		t.Fatal("process cache was not refreshed from committed transaction results")
	}
}

func TestReleaseEvidenceWriteDoesNotPublishBeforeUnitOfWorkCommit(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, commitFailingUnitOfWorkFactory{inner: memory})
	beforeEntries := len(ledger.chain[actor.TenantID])

	if _, err := ledger.CreateProduct(ctx, actor, "Payments", "payments"); err == nil {
		t.Fatal("expected forced unit-of-work commit failure")
	}
	if len(ledger.products) != 0 {
		t.Fatalf("failed transaction published a product in process state: %#v", ledger.products)
	}
	if got := len(ledger.chain[actor.TenantID]); got != beforeEntries {
		t.Fatalf("failed transaction published an audit entry: before=%d after=%d", beforeEntries, got)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if len(snapshot.Products) != 0 || len(snapshot.AuditEntries[actor.TenantID]) != beforeEntries {
		t.Fatalf("failed transaction committed repository state: %#v", snapshot)
	}
}

func TestReleaseEvidenceRepositoryFailuresRollbackEveryReleaseEvidenceFamily(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	project, err := ledger.CreateProject(ctx, actor, product.ID, "API")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	_, err = ledger.RegisterArtifact(ctx, actor, "payments", "application/json", sampleDigest("artifact"), 1)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	evidence, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ProductID: product.ID, ProjectID: project.ID, ReleaseID: release.ID, Type: "build", Title: "first", PayloadHash: sampleDigest("first")})
	if err != nil {
		t.Fatalf("create evidence: %v", err)
	}
	replacement, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ReleaseID: release.ID, Type: "build", Title: "replacement", PayloadHash: sampleDigest("replacement")})
	if err != nil {
		t.Fatalf("create replacement evidence: %v", err)
	}
	candidate, err := ledger.CreateReleaseCandidate(ctx, actor, CreateReleaseCandidateInput{ReleaseID: release.ID, Name: "candidate"})
	if err != nil {
		t.Fatalf("create release candidate: %v", err)
	}
	baseline, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("baseline snapshot: %v", err)
	}

	failReleaseCatalog := func(repositories Repositories) Repositories {
		repositories.ReleaseCatalog = failingReleaseCatalogRepository{ReleaseCatalogRepository: repositories.ReleaseCatalog}
		return repositories
	}
	failEvidence := func(repositories Repositories) Repositories {
		repositories.Evidence = failingEvidenceRepository{EvidenceRepository: repositories.Evidence}
		return repositories
	}
	mustFail := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, errInjectedRepositoryFailure) {
			t.Fatalf("%s err=%v, want injected repository failure", name, err)
		}
	}

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: failReleaseCatalog}
	_, err = ledger.CreateProduct(ctx, actor, "Failed product", "failed-product")
	mustFail("create product", err)
	_, err = ledger.CreateProject(ctx, actor, product.ID, "Failed project")
	mustFail("create project", err)
	_, err = ledger.CreateRelease(ctx, actor, product.ID, "2.0.0")
	mustFail("create release", err)
	_, err = ledger.FreezeRelease(ctx, actor, release.ID, release.Revision)
	mustFail("freeze release", err)
	_, err = ledger.RegisterArtifact(ctx, actor, "failed", "application/json", sampleDigest("x"), 1)
	mustFail("register artifact", err)
	_, err = ledger.CreateReleaseCandidate(ctx, actor, CreateReleaseCandidateInput{ReleaseID: release.ID, Name: "failed candidate"})
	mustFail("create release candidate", err)
	_, err = ledger.UpdateReleaseCandidateState(ctx, actor, candidate.ID, candidatePromoted, "promote", candidate.Revision)
	mustFail("update release candidate", err)

	ledger.unitOfWork = repositoryFailingUnitOfWorkFactory{inner: memory, decorate: failEvidence}
	_, err = ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ReleaseID: release.ID, Type: "build", Title: "failed evidence", PayloadHash: sampleDigest("failed-evidence")})
	mustFail("create evidence", err)
	_, err = ledger.LinkEvidence(ctx, actor, evidence.ID, "product", product.ID)
	mustFail("link evidence", err)
	_, err = ledger.SupersedeEvidence(ctx, actor, evidence.ID, replacement.ID, "corrected")
	mustFail("supersede evidence", err)
	_, err = ledger.RecordEvidenceLifecycleEvent(ctx, actor, evidence.ID, RecordEvidenceLifecycleInput{Action: lifecycleAmendment, Reason: "corrected"})
	mustFail("record evidence lifecycle", err)

	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot after failures: %v", err)
	}
	if len(snapshot.Products) != len(baseline.Products) || len(snapshot.Projects) != len(baseline.Projects) || len(snapshot.Releases) != len(baseline.Releases) || len(snapshot.Artifacts) != len(baseline.Artifacts) || len(snapshot.Evidence) != len(baseline.Evidence) || len(snapshot.ReleaseCandidates) != len(baseline.ReleaseCandidates) || len(snapshot.EvidenceLifecycle) != len(baseline.EvidenceLifecycle) || len(snapshot.AuditEntries[actor.TenantID]) != len(baseline.AuditEntries[actor.TenantID]) {
		t.Fatalf("repository failure published transactional state: before=%#v after=%#v", baseline, snapshot)
	}
	if ledger.releases[release.ID].State != "draft" || ledger.evidence[evidence.ID].SupersededBy != "" || len(ledger.evidence[evidence.ID].RelatedEvidenceRefs) != 0 || ledger.candidates[candidate.ID].State != candidateOpen {
		t.Fatalf("repository failure mutated process cache: release=%#v evidence=%#v candidate=%#v", ledger.releases[release.ID], ledger.evidence[evidence.ID], ledger.candidates[candidate.ID])
	}
}

func TestReleaseEvidenceReleaseTransitionsUseUnitOfWork(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	frozen, err := ledger.FreezeRelease(ctx, actor, release.ID, release.Revision)
	if err != nil {
		t.Fatalf("freeze release: %v", err)
	}
	approved, err := ledger.ApproveRelease(ctx, actor, release.ID, frozen.Revision)
	if err != nil {
		t.Fatalf("approve release: %v", err)
	}

	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if stored := snapshot.Releases[release.ID]; stored.State != "approved" || stored.ApprovedAt == nil {
		t.Fatalf("release transition did not commit through the unit of work: %#v", stored)
	}
	if len(snapshot.AuditEntries[actor.TenantID]) != 5 {
		t.Fatalf("release transition audit entries were not committed: %#v", snapshot.AuditEntries[actor.TenantID])
	}
	if ledger.releases[release.ID].State != approved.State {
		t.Fatal("process release cache was not updated after the committed transition")
	}
}

func TestReleaseEvidenceLinksAndSupersessionUseUnitOfWork(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	first, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ReleaseID: release.ID, Type: "build", Title: "first", PayloadHash: sampleDigest("first")})
	if err != nil {
		t.Fatalf("create first evidence: %v", err)
	}
	replacement, err := ledger.CreateEvidence(ctx, actor, CreateEvidenceInput{ReleaseID: release.ID, Type: "build", Title: "replacement", PayloadHash: sampleDigest("replacement")})
	if err != nil {
		t.Fatalf("create replacement evidence: %v", err)
	}
	if _, err := ledger.LinkEvidence(ctx, actor, first.ID, "product", product.ID); err != nil {
		t.Fatalf("link evidence: %v", err)
	}
	if _, err := ledger.SupersedeEvidence(ctx, actor, first.ID, replacement.ID, "corrected build metadata"); err != nil {
		t.Fatalf("supersede evidence: %v", err)
	}

	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	storedFirst := snapshot.Evidence[first.ID]
	storedReplacement := snapshot.Evidence[replacement.ID]
	if storedFirst.SupersededBy != replacement.ID || storedReplacement.Supersedes != first.ID {
		t.Fatalf("supersession was not atomically persisted: first=%#v replacement=%#v", storedFirst, storedReplacement)
	}
	if len(storedFirst.RelatedEvidenceRefs) != 1 || storedFirst.RelatedEvidenceRefs[0].ID != product.ID {
		t.Fatalf("link was not persisted through the transaction repository: %#v", storedFirst.RelatedEvidenceRefs)
	}
	if len(snapshot.AuditEntries[actor.TenantID]) != 7 {
		t.Fatalf("link and supersession audit entries are missing: %#v", snapshot.AuditEntries[actor.TenantID])
	}
}

func TestReleaseEvidenceSBOMUsesOneUnitOfWorkForEvidenceAuditAndOutbox(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	artifact, err := ledger.RegisterArtifact(ctx, actor, "payments", "application/json", sampleDigest("artifact"), 42)
	if err != nil {
		t.Fatalf("register artifact: %v", err)
	}
	sbom, err := ledger.UploadSBOM(ctx, actor, release.ID, artifact.ID, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"openssl","version":"3.1.0"}]}`))
	if err != nil {
		t.Fatalf("upload SBOM: %v", err)
	}

	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	stored, ok := snapshot.SBOMs[sbom.ID]
	if !ok || stored.EvidenceID == "" || snapshot.Evidence[stored.EvidenceID].ChainEntryID == "" {
		t.Fatalf("SBOM and backing evidence were not committed together: sbom=%#v evidence=%#v", stored, snapshot.Evidence[stored.EvidenceID])
	}
	if len(snapshot.OutboxJobs) != 1 || len(snapshot.AuditEntries[actor.TenantID]) != 6 {
		t.Fatalf("SBOM outbox/audit effects were not atomically committed: jobs=%#v audit=%#v", snapshot.OutboxJobs, snapshot.AuditEntries[actor.TenantID])
	}
}

func TestReleaseEvidenceScanAndOpenAPIUseOneUnitOfWork(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{"scanner":"grype","target_ref":"pkg:oci/payments","release_id":"`+release.ID+`","findings":[{"vulnerability":"CVE-2026-1000","severity":"high"}]}`))
	if err != nil {
		t.Fatalf("upload vulnerability scan: %v", err)
	}
	contract, err := ledger.UploadOpenAPIContract(ctx, actor, product.ID, release.ID, "v1", []byte(`{"openapi":"3.1.0","info":{"title":"Payments","version":"1"},"paths":{"/health":{"get":{"responses":{"200":{"description":"ok"}}}}}}`))
	if err != nil {
		t.Fatalf("upload OpenAPI contract: %v", err)
	}

	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if stored, ok := snapshot.VulnerabilityScans[scan.ID]; !ok || stored.EvidenceID == "" || snapshot.Evidence[stored.EvidenceID].ChainEntryID == "" {
		t.Fatalf("scan and backing evidence were not committed together: scan=%#v", stored)
	}
	if stored, ok := snapshot.OpenAPIContracts[contract.ID]; !ok || stored.EvidenceID == "" || snapshot.Evidence[stored.EvidenceID].ChainEntryID == "" {
		t.Fatalf("contract and backing evidence were not committed together: contract=%#v", stored)
	}
	if len(snapshot.OutboxJobs) != 2 || len(snapshot.AuditEntries[actor.TenantID]) != 7 {
		t.Fatalf("parser outbox/audit effects were not atomically committed: jobs=%#v audit=%#v", snapshot.OutboxJobs, snapshot.AuditEntries[actor.TenantID])
	}
}

func TestReleaseEvidenceVEXUsesOneUnitOfWorkForDecisionEffects(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{"scanner":"grype","target_ref":"pkg:oci/payments","release_id":"`+release.ID+`","findings":[{"vulnerability":"CVE-2026-1000","component":"pkg:apk/openssl@3.1.0","severity":"high"}]}`))
	if err != nil {
		t.Fatalf("upload vulnerability scan: %v", err)
	}
	vex, err := ledger.UploadVEX(ctx, actor, release.ID, "", openVEXFixture(t, []map[string]any{
		openVEXStatementFixture("CVE-2026-1000", []map[string]any{{"@id": "pkg:apk/openssl@3.1.0"}}, decisionStatusNotAffected, "component_not_present"),
	}))
	if err != nil {
		t.Fatalf("upload VEX: %v", err)
	}

	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if stored, ok := snapshot.VEXDocuments[vex.ID]; !ok || stored.EvidenceID == "" || snapshot.Evidence[stored.EvidenceID].ChainEntryID == "" {
		t.Fatalf("VEX and backing evidence were not committed together: vex=%#v", stored)
	}
	if len(snapshot.VEXImportReports) != 1 || len(snapshot.Decisions) != 1 {
		t.Fatalf("VEX report/decision effects were not transactionally committed: reports=%#v decisions=%#v", snapshot.VEXImportReports, snapshot.Decisions)
	}
	if len(snapshot.OutboxJobs) != 2 || len(snapshot.AuditEntries[actor.TenantID]) != 8 {
		t.Fatalf("VEX outbox/audit effects were not transactionally committed: scan=%#v jobs=%#v audit=%#v", scan, snapshot.OutboxJobs, snapshot.AuditEntries[actor.TenantID])
	}
}

func TestReleaseEvidenceReleaseCandidateUsesUnitOfWork(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	candidate, err := ledger.CreateReleaseCandidate(ctx, actor, CreateReleaseCandidateInput{ReleaseID: release.ID, Name: "release candidate"})
	if err != nil {
		t.Fatalf("create release candidate: %v", err)
	}
	promoted, err := ledger.UpdateReleaseCandidateState(ctx, actor, candidate.ID, candidatePromoted, "approved for promotion", candidate.Revision)
	if err != nil {
		t.Fatalf("promote release candidate: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if stored := snapshot.ReleaseCandidates[candidate.ID]; stored.State != candidatePromoted || stored.PromotedAt == nil {
		t.Fatalf("candidate state was not committed through the unit of work: %#v", stored)
	}
	if len(snapshot.AuditEntries[actor.TenantID]) != 5 || ledger.candidates[candidate.ID].State != promoted.State {
		t.Fatalf("candidate audit/cache state was not committed together: audit=%#v candidate=%#v", snapshot.AuditEntries[actor.TenantID], ledger.candidates[candidate.ID])
	}
}

func TestReleaseEvidenceVEXSupersedesDecisionWithinUnitOfWork(t *testing.T) {
	ctx := context.Background()
	memory := NewMemoryUnitOfWorkFactory()
	ledger, _, actor := newReleaseEvidenceUnitOfWorkFixture(t, memory)
	product, err := ledger.CreateProduct(ctx, actor, "Payments", "payments")
	if err != nil {
		t.Fatalf("create product: %v", err)
	}
	release, err := ledger.CreateRelease(ctx, actor, product.ID, "1.0.0")
	if err != nil {
		t.Fatalf("create release: %v", err)
	}
	scan, err := ledger.UploadVulnerabilityScan(ctx, actor, []byte(`{"scanner":"grype","target_ref":"pkg:oci/payments","release_id":"`+release.ID+`","findings":[{"vulnerability":"CVE-2026-1000","component":"pkg:apk/openssl@3.1.0","severity":"high"}]}`))
	if err != nil {
		t.Fatalf("upload vulnerability scan: %v", err)
	}
	original, err := ledger.CreateVulnerabilityDecision(ctx, actor, scan.Findings[0].ID, CreateVulnerabilityDecisionInput{Status: decisionStatusAffected, Justification: "initial analysis"})
	if err != nil {
		t.Fatalf("create initial decision: %v", err)
	}
	if _, err := ledger.UploadVEX(ctx, actor, release.ID, "", openVEXFixture(t, []map[string]any{
		openVEXStatementFixture("CVE-2026-1000", []map[string]any{{"@id": "pkg:apk/openssl@3.1.0"}}, decisionStatusNotAffected, "component_not_present"),
	})); err != nil {
		t.Fatalf("upload superseding VEX: %v", err)
	}
	snapshot, err := memory.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	storedOriginal := snapshot.Decisions[original.ID]
	if storedOriginal.SupersededBy == "" || len(snapshot.Decisions) != 2 {
		t.Fatalf("VEX supersession was not atomic: original=%#v decisions=%#v", storedOriginal, snapshot.Decisions)
	}
	if len(snapshot.OutboxJobs) != 2 || len(snapshot.AuditEntries[actor.TenantID]) != 10 {
		t.Fatalf("VEX decision audit/outbox effects were not committed: jobs=%#v audit=%#v", snapshot.OutboxJobs, snapshot.AuditEntries[actor.TenantID])
	}
}
