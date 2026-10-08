package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aatuh/evydence/internal/app"
	"github.com/aatuh/evydence/internal/domain"
	releasedomain "github.com/aatuh/evydence/internal/release/domain"
	releasequery "github.com/aatuh/evydence/internal/release/query"
)

type evidenceFlowFixtureClock struct {
	at    time.Time
	calls int
}

func (c *evidenceFlowFixtureClock) Now() time.Time { c.calls++; return c.at }

func seedEvidenceFlowFixtureRows(t *testing.T, ledger *app.Ledger, owner operationsFixtureScope) {
	t.Helper()
	at := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	private := strings.Repeat("private-flow-metadata", 4000)
	j := domain.Project{ID: owner.product.ID + "-flow-project", TenantID: owner.actor.TenantID, ProductID: owner.product.ID, Name: private, CreatedAt: at}
	a := domain.Artifact{ID: owner.product.ID + "-flow-artifact-a", TenantID: owner.actor.TenantID, Name: private, MediaType: "application/octet-stream", Digest: "sha256:" + strings.Repeat("a", 64), Size: 42, CreatedAt: at}
	b := a
	b.ID += "-b"
	b.Digest = "sha256:" + strings.Repeat("b", 64)
	build := domain.BuildRun{ID: owner.product.ID + "-flow-build", TenantID: owner.actor.TenantID, ProjectID: j.ID, ReleaseID: owner.release.ID, Provider: "generic_ci", CommitSHA: strings.Repeat("a", 40), Status: "passed", StartedAt: at, SourceIdentity: map[string]any{"private": private}, Outputs: []domain.BuildOutput{{ArtifactID: a.ID, Digest: a.Digest}, {ArtifactID: b.ID, Digest: b.Digest}}, SchemaVersion: domain.BuildRunSchemaVersion, CreatedAt: at}
	if err := ledger.ExecuteUnitOfWork(t.Context(), func(ctx context.Context, r app.Repositories) error {
		if err := r.ReleaseCatalog.InsertProject(ctx, j); err != nil {
			return err
		}
		if err := r.ReleaseCatalog.InsertArtifact(ctx, a); err != nil {
			return err
		}
		if err := r.ReleaseCatalog.InsertArtifact(ctx, b); err != nil {
			return err
		}
		if err := r.Builds.InsertBuildRun(ctx, build); err != nil {
			return err
		}
		if err := r.Evidence.InsertSBOM(ctx, domain.SBOM{ID: owner.product.ID + "-flow-sbom", TenantID: owner.actor.TenantID, EvidenceID: owner.evidence.ID, ReleaseID: owner.release.ID, ArtifactID: a.ID, Format: "cyclonedx", Components: []domain.SBOMComponent{{Name: private}}, CreatedAt: at}); err != nil {
			return err
		}
		if err := r.Evidence.InsertVulnerabilityScan(ctx, domain.VulnerabilityScan{ID: owner.product.ID + "-flow-scan", TenantID: owner.actor.TenantID, EvidenceID: owner.evidence.ID, ReleaseID: owner.release.ID, Scanner: "generic", TargetRef: private, Findings: []domain.VulnerabilityFinding{{Component: private}}, CreatedAt: at}); err != nil {
			return err
		}
		return r.Packages.InsertReleaseBundle(ctx, domain.ReleaseBundle{ID: owner.product.ID + "-flow-bundle", TenantID: owner.actor.TenantID, ReleaseID: owner.release.ID, State: "created", Manifest: map[string]any{"private": private}, ManifestHash: "sha256:" + strings.Repeat("c", 64), CreatedAt: at})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceFlowNativeFixtureUsesCurrentScalarCountsGrantsAndExplicitClock(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	clock := &evidenceFlowFixtureClock{at: time.Date(2026, 10, 8, 16, 0, 0, 0, time.UTC)}
	forbidAggregateClock := false
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time {
		if forbidAggregateClock {
			panic("flow query consulted aggregate clock")
		}
		return clock.at.Add(-time.Hour)
	}})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	foreign := seedOperationsFixtureScope(t, ledger, "Foreign")
	seedEvidenceFlowFixtureRows(t, ledger, owner)
	seedEvidenceFlowFixtureRows(t, ledger, foreign)
	human := domain.Actor{TenantID: owner.actor.TenantID, UserID: "human", Scopes: []string{"release:read"}, ResourceGrants: []domain.ResourceGrant{{ResourceType: "release", ResourceID: owner.release.ID, Scopes: []string{"release:read"}}}}
	auth := &configuredAuthenticator{actor: human}
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: auth})
	if err != nil {
		t.Fatal(err)
	}
	server.bindEvidenceFlowFixtureClock(clock)
	forbidAggregateClock = true
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	begins := factory.beginCalls
	path := "/v1/releases/" + owner.release.ID + "/evidence-flow/start"
	out := postJSON(t, server, "fixture", path, "not-an-idempotent-write", map[string]any{}, http.StatusOK)
	counts := map[string]int{"artifact_refs": 2, "passed_builds": 1, "build_attestations": 0, "sboms": 1, "vulnerability_scans": 1, "vex_documents": 0, "vulnerability_decisions": 0, "release_bundles": 1, "customer_packages": 0}
	// The shared vocabulary assembler is unchanged; expected counts, parent
	// coordinates and time here are independent of the repository/fixture.
	want := domain.ReleaseEvidenceFlowFromContextModel(releasequery.AssembleEvidenceFlow(owner.release.ID, owner.product.ID, counts, clock.at))
	wantJSON, err := json.Marshal(map[string]any{"data": want, "meta": map[string]string{"api_version": "v1"}})
	if err != nil {
		t.Fatal(err)
	}
	assertTrustHTTPReplay(t, string(wantJSON), out)
	if clock.calls != 1 || factory.beginCalls != begins+1 || strings.Contains(out, "private-flow-metadata") || strings.Contains(out, foreign.actor.TenantID) {
		t.Fatal("plan consulted extra state/resources or exposed row metadata", out)
	}
	auth.actor.ResourceGrants = nil
	postJSON(t, server, "fixture", path, "denied", map[string]any{}, http.StatusForbidden)
	auth.actor = human
	postJSON(t, server, "fixture", "/v1/releases/"+foreign.release.ID+"/evidence-flow/start", "foreign", map[string]any{}, http.StatusNotFound)
	auth.actor.Scopes = nil
	begins = factory.beginCalls
	postJSON(t, server, "fixture", path, "scope", map[string]any{}, http.StatusForbidden)
	if factory.beginCalls != begins {
		t.Fatal("missing read scope reached count repository")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if v, err := server.evidenceFlowQuery.Plan(ctx, human, owner.release.ID); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(v, releasedomain.ReleaseEvidenceFlow{}) {
		t.Fatal("cancelled flow returned partial projection", v, err)
	}
	if clock.calls != 1 {
		t.Fatal("denied/foreign/cancelled flow consulted clock")
	}
	rebound := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory, Now: func() time.Time { panic("rebound aggregate clock") }})
	server.bindLegacyLedgerFixture(rebound)
	server.authn = auth
	auth.actor = human
	second := postJSON(t, server, "fixture", path, "still-read-only", map[string]any{}, http.StatusOK)
	assertTrustHTTPReplay(t, out, second)
	if clock.calls != 2 {
		t.Fatal("rebind lost explicit live clock")
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("flow/denied/cancelled requests changed stored state or reserved replay", err)
	}
}

func TestEvidenceFlowNativeFixtureDiscardsCountsOnCommitFailureBeforeClock(t *testing.T) {
	factory := &operatorQueryFailureFactory{base: app.NewMemoryUnitOfWorkFactory()}
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test", UnitOfWork: factory})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	seedEvidenceFlowFixtureRows(t, ledger, owner)
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	clock := &evidenceFlowFixtureClock{at: time.Date(2026, 10, 8, 16, 0, 0, 0, time.UTC)}
	server.bindEvidenceFlowFixtureClock(clock)
	before, err := factory.base.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	factory.fail = true
	rollbacks := factory.rollbacks
	path := "/v1/releases/" + owner.release.ID + "/evidence-flow/start"
	out := postJSON(t, server, "fixture", path, "no-replay-reservation", map[string]any{}, http.StatusInternalServerError)
	var problem map[string]any
	if err := json.Unmarshal([]byte(out), &problem); err != nil {
		t.Fatal(err)
	}
	if factory.rollbacks != rollbacks+1 || problem["instance"] != path || problem["data"] != nil || strings.Contains(out, "private-query") || strings.Contains(out, "artifact_refs") || clock.calls != 0 {
		t.Fatal("failed flow commit leaked counts or consulted clock", out)
	}
	if v, err := server.evidenceFlowQuery.Plan(t.Context(), owner.actor, owner.release.ID); err == nil || !reflect.DeepEqual(v, releasedomain.ReleaseEvidenceFlow{}) {
		t.Fatal("failed flow returned partial DTO", v, err)
	}
	reader := server.evidenceFlowQuery.(evidenceFlowFixture)
	if v, err := reader.ReadEvidenceFlowSnapshot(t.Context(), owner.actor.TenantID, owner.release.ID); err == nil || !reflect.DeepEqual(v, releasequery.EvidenceFlowSnapshot{}) {
		t.Fatal("failed snapshot commit returned partial counters", v, err)
	}
	after, err := factory.base.Snapshot()
	if err != nil || !reflect.DeepEqual(before, after) || clock.calls != 0 {
		t.Fatal("failed flow committed state or reached clock", err)
	}
}

func TestEvidenceFlowNativeFixtureRequiresRepositoryAndPreservesExplicitQueryPorts(t *testing.T) {
	ledger := newLegacyLedgerFixture(app.Config{APIKeyPepper: "test"})
	owner := seedOperationsFixtureScope(t, ledger, "Owner")
	server, err := newLegacyServerFixtureWithOptions(ledger, ServerOptions{Authenticator: &configuredAuthenticator{actor: owner.actor}})
	if err != nil {
		t.Fatal(err)
	}
	clock := &evidenceFlowFixtureClock{}
	server.bindEvidenceFlowFixtureClock(clock)
	if v, err := server.evidenceFlowQuery.Plan(t.Context(), owner.actor, owner.release.ID); !errors.Is(err, app.ErrValidation) || !reflect.DeepEqual(v, releasedomain.ReleaseEvidenceFlow{}) || clock.calls != 0 {
		t.Fatal("missing repository fell back to cached aggregate plan", v, err)
	}
	mock := &evidenceFlowQueryFake{}
	server.evidenceFlowQuery = mock
	server.bindCatalogQueryFixturePorts(ledger)
	server.bindEvidenceFlowFixtureClock(clock)
	if server.evidenceFlowQuery != mock {
		t.Fatal("fixture rebinding replaced explicit query port")
	}
}
